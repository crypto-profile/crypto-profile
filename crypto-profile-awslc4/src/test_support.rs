//! Test infrastructure: in-memory certificates and an in-process handshake. Not shipped behaviour.
use crate::signature::KeyPair;
use crate::tls::{Policy, client_builder, server_builder, server_cert_verifier_builder};
use crate::{CipherSuite, KxGroup, Resolved, SignatureAlgorithm, TlsSignatureScheme, TlsVersion};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::SingleCertAndKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::sync::{Arc, Mutex};

/// The FIPS module's crypto library name, from aws-lc-rs's link metadata; a dynamic build loads
/// `lib{FIPS_LIBRARY}.so` (Linux) or `lib{FIPS_LIBRARY}.dylib` (macOS).
pub const FIPS_LIBRARY: &str = env!("CRYPTO_PROFILE_FIPS_LIBRARY");

/// What a completed handshake negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// The protocol version.
    pub version: TlsVersion,
    /// The cipher suite.
    pub suite: CipherSuite,
    /// The key-exchange group.
    pub kx: KxGroup,
    /// The scheme the server signed the handshake with.
    pub scheme: TlsSignatureScheme,
}

/// A WebPKI server verifier that records the scheme of the handshake signature it checks.
#[derive(Debug)]
struct SchemeRecorder {
    inner: Arc<WebPkiServerVerifier>,
    seen: Arc<Mutex<Option<SignatureScheme>>>,
}

impl SchemeRecorder {
    fn record(&self, scheme: SignatureScheme) {
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(scheme);
    }
}

impl ServerCertVerifier for SchemeRecorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.record(dss.scheme);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.record(dss.scheme);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

fn deliver<D: std::ops::DerefMut<Target = rustls::ConnectionCommon<S>>, S: rustls::SideData>(
    to: &mut D,
    mut bytes: &[u8],
) -> Result<(), String> {
    // `read_tls` takes at most one 4096-byte read per call, so a larger flight is fed in a loop.
    while !bytes.is_empty() {
        if to.read_tls(&mut bytes).map_err(|x| x.to_string())? == 0 {
            return Err("peer stopped reading".to_string());
        }
        to.process_new_packets().map_err(|x| x.to_string())?;
    }
    Ok(())
}

fn pump(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Result<(), String> {
    while client.is_handshaking() || server.is_handshaking() {
        let mut to_server = Vec::new();
        client
            .write_tls(&mut to_server)
            .map_err(|x| x.to_string())?;
        deliver(server, &to_server)?;
        let mut to_client = Vec::new();
        server
            .write_tls(&mut to_client)
            .map_err(|x| x.to_string())?;
        deliver(client, &to_client)?;
        if to_server.is_empty() && to_client.is_empty() {
            return Err("handshake stalled".to_string());
        }
    }
    Ok(())
}

/// Runs a full in-process handshake: a P-384 CA issues a `localhost` leaf whose key is a fresh
/// `key`; the server is built on `server`, the client on `client`.
pub fn handshake(
    client: &Policy,
    server: &Policy,
    key: SignatureAlgorithm,
) -> Result<Negotiated, String> {
    handshake_with_ca(client, server, SignatureAlgorithm::EcdsaP384Sha384, key)
}

/// Runs a full in-process handshake: a CA whose key is a fresh `ca` issues a `localhost` leaf
/// whose key is a fresh `key`; the server is built on `server`, the client on `client`.
pub fn handshake_with_ca(
    client: &Policy,
    server: &Policy,
    ca: SignatureAlgorithm,
    key: SignatureAlgorithm,
) -> Result<Negotiated, String> {
    run(client, ca, key, |chain, leaf_key| {
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.pkcs8_der().to_vec().into());
        server_builder(server)
            .map_err(|x| x.to_string())?
            .with_no_client_auth()
            .with_single_cert(chain, der)
            .map_err(|x| x.to_string())
    })
}

/// Runs a full in-process handshake whose server installs its `key` leaf through
/// [`Resolved::certified_key`]: a P-384 CA issues a `localhost` leaf whose key is a fresh `key`;
/// the server is built on `server.tls`, the client on `client`.
pub fn handshake_certified(
    client: &Policy,
    server: &Resolved,
    key: SignatureAlgorithm,
) -> Result<Negotiated, String> {
    run(
        client,
        SignatureAlgorithm::EcdsaP384Sha384,
        key,
        |chain, leaf_key| {
            let certified = server
                .certified_key(chain, leaf_key)
                .map_err(|x| x.to_string())?;
            Ok(server_builder(&server.tls)
                .map_err(|x| x.to_string())?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified))))
        },
    )
}

fn run(
    client: &Policy,
    ca: SignatureAlgorithm,
    key: SignatureAlgorithm,
    serve: impl FnOnce(Vec<CertificateDer<'static>>, &KeyPair) -> Result<rustls::ServerConfig, String>,
) -> Result<Negotiated, String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let ca_key = KeyPair::generate(ca).map_err(|x| e(&x))?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|x| e(&x))?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|x| e(&x))?;
    let issuer = rcgen::Issuer::new(ca_params, &ca_key);
    let leaf_key = KeyPair::generate(key).map_err(|x| e(&x))?;
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|x| e(&x))?
        .signed_by(&leaf_key, &issuer)
        .map_err(|x| e(&x))?;
    let chain = vec![leaf.der().clone(), ca_cert.der().clone()];
    let server_cfg = serve(chain, &leaf_key)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).map_err(|x| e(&x))?;
    let seen = Arc::new(Mutex::new(None));
    let recorder = SchemeRecorder {
        inner: server_cert_verifier_builder(Arc::new(roots), client)
            .map_err(|x| e(&x))?
            .build()
            .map_err(|x| e(&x))?,
        seen: Arc::clone(&seen),
    };
    let client_cfg = client_builder(client)
        .map_err(|x| e(&x))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(recorder))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").map_err(|x| e(&x))?;
    let mut c = rustls::ClientConnection::new(Arc::new(client_cfg), name).map_err(|x| e(&x))?;
    let mut s = rustls::ServerConnection::new(Arc::new(server_cfg)).map_err(|x| e(&x))?;
    pump(&mut c, &mut s)?;
    let version = match c.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => TlsVersion::Tls12,
        Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
        other => return Err(format!("unexpected version {other:?}")),
    };
    let suite_cp = u16::from_be_bytes(
        c.negotiated_cipher_suite()
            .ok_or("no suite")?
            .suite()
            .to_array(),
    );
    let suite = CipherSuite::ALL
        .into_iter()
        .find(|x| x.iana() == suite_cp)
        .ok_or(format!("unknown suite {suite_cp:#06x}"))?;
    let group_cp = u16::from_be_bytes(
        c.negotiated_key_exchange_group()
            .ok_or("no group")?
            .name()
            .to_array(),
    );
    let kx = KxGroup::ALL
        .into_iter()
        .find(|x| x.iana() == group_cp)
        .ok_or(format!("unknown group {group_cp:#06x}"))?;
    let scheme_cp = seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .map(|s| u16::from_be_bytes(s.to_array()))
        .ok_or("no handshake signature")?;
    let scheme = TlsSignatureScheme::ALL
        .into_iter()
        .find(|x| x.iana() == scheme_cp)
        .ok_or(format!("unknown scheme {scheme_cp:#06x}"))?;
    Ok(Negotiated {
        version,
        suite,
        kx,
        scheme,
    })
}
