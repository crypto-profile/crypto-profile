//! Test infrastructure: in-memory certificates and an in-process handshake. Not shipped behaviour.
use crate::signature::KeyPair;
use crate::tls::{Policy, client_builder, server_builder, server_cert_verifier_builder};
use crate::{CipherSuite, KxGroup, Resolved, SignatureAlgorithm, TlsSignatureScheme, TlsVersion};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::SingleCertAndKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::sync::{Arc, Mutex};

/// The FIPS module's crypto library name, from aws-lc-rs's link metadata; a dynamic build loads
/// `lib{FIPS_LIBRARY}.so` (Linux) or `lib{FIPS_LIBRARY}.dylib` (macOS).
pub const FIPS_LIBRARY: &str = env!("CRYPTO_PROFILE_FIPS_LIBRARY");

/// What a completed handshake negotiated.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Negotiated {
    /// The protocol version.
    pub version: TlsVersion,
    /// The cipher suite.
    pub suite: CipherSuite,
    /// The key-exchange group.
    pub kx: KxGroup,
    /// The scheme the server signed the handshake with.
    pub scheme: TlsSignatureScheme,
    /// The client's [`rustls::CommonState::handshake_kind`].
    pub kind: rustls::HandshakeKind,
}

/// A server verifier that records the scheme of the handshake signature it checks.
#[derive(Debug)]
struct SchemeRecorder {
    inner: Arc<dyn ServerCertVerifier>,
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

/// A CA and a `localhost` leaf it issued.
pub struct Pki {
    /// A store holding the CA alone.
    pub roots: rustls::RootCertStore,
    /// The CA's certificate.
    pub ca: CertificateDer<'static>,
    /// The leaf, then the CA.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's key.
    pub key: KeyPair,
}

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

/// A fresh CA whose key is `ca` and a `localhost` leaf whose key is `key`.
pub fn pki(ca: SignatureAlgorithm, key: SignatureAlgorithm) -> Result<Pki, String> {
    let ca_key = KeyPair::generate(ca).map_err(e)?;
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "crypto-profile test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).map_err(e)?;
    let issuer = rcgen::Issuer::new(ca_params, &ca_key);
    let leaf_key = KeyPair::generate(key).map_err(e)?;
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(e)?
        .signed_by(&leaf_key, &issuer)
        .map_err(e)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).map_err(e)?;
    Ok(Pki {
        roots,
        ca: ca_cert.der().clone(),
        chain: vec![leaf.der().clone(), ca_cert.der().clone()],
        key: leaf_key,
    })
}

/// `inner`, recording the scheme of each handshake signature it checks into the returned cell.
pub fn recording(
    inner: Arc<dyn ServerCertVerifier>,
) -> (
    Arc<dyn ServerCertVerifier>,
    Arc<Mutex<Option<SignatureScheme>>>,
) {
    let seen = Arc::new(Mutex::new(None));
    let recorder = SchemeRecorder {
        inner,
        seen: Arc::clone(&seen),
    };
    (Arc::new(recorder), seen)
}

/// An in-memory handshake; the wire codepoints of the version, suite, group and the server's
/// handshake-signature scheme recorded in `seen`, and the client's handshake kind.
pub fn drive(
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
    seen: &Mutex<Option<SignatureScheme>>,
) -> Result<([u16; 4], rustls::HandshakeKind), String> {
    let name = rustls::pki_types::ServerName::try_from("localhost").map_err(e)?;
    let mut c = rustls::ClientConnection::new(Arc::new(client), name).map_err(e)?;
    let mut s = rustls::ServerConnection::new(Arc::new(server)).map_err(e)?;
    pump(&mut c, &mut s)?;
    let version = u16::from_be_bytes(c.protocol_version().ok_or("no version")?.to_array());
    let suite = u16::from_be_bytes(
        c.negotiated_cipher_suite()
            .ok_or("no suite")?
            .suite()
            .to_array(),
    );
    let group = u16::from_be_bytes(
        c.negotiated_key_exchange_group()
            .ok_or("no group")?
            .name()
            .to_array(),
    );
    let scheme = seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .map(|s| u16::from_be_bytes(s.to_array()))
        .ok_or("no handshake signature")?;
    let kind = c.handshake_kind().ok_or("no handshake kind")?;
    Ok(([version, suite, group, scheme], kind))
}

fn run(
    client: &Policy,
    ca: SignatureAlgorithm,
    key: SignatureAlgorithm,
    serve: impl FnOnce(Vec<CertificateDer<'static>>, &KeyPair) -> Result<rustls::ServerConfig, String>,
) -> Result<Negotiated, String> {
    let p = pki(ca, key)?;
    let server_cfg = serve(p.chain.clone(), &p.key)?;
    let (verifier, seen) = recording(
        server_cert_verifier_builder(Arc::new(p.roots), client)
            .map_err(e)?
            .build()
            .map_err(e)?,
    );
    let client_cfg = client_builder(client)
        .map_err(e)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let ([version_cp, suite_cp, group_cp, scheme_cp], kind) = drive(client_cfg, server_cfg, &seen)?;
    let version = TlsVersion::ALL
        .into_iter()
        .find(|x| x.iana() == version_cp)
        .ok_or(format!("unexpected version {version_cp:#06x}"))?;
    let suite = CipherSuite::ALL
        .into_iter()
        .find(|x| x.iana() == suite_cp)
        .ok_or(format!("unknown suite {suite_cp:#06x}"))?;
    let kx = KxGroup::ALL
        .into_iter()
        .find(|x| x.iana() == group_cp)
        .ok_or(format!("unknown group {group_cp:#06x}"))?;
    let scheme = TlsSignatureScheme::ALL
        .into_iter()
        .find(|x| x.iana() == scheme_cp)
        .ok_or(format!("unknown scheme {scheme_cp:#06x}"))?;
    Ok(Negotiated {
        version,
        suite,
        kx,
        scheme,
        kind,
    })
}

/// A configurable certification path and private key used by the shared conformance suite.
pub struct PeerCertificatePki {
    opposite: Option<Box<PeerCertificatePki>>,
    /// Trust anchors for this path.
    pub roots: rustls::RootCertStore,
    /// Leaf followed by supplied intermediates.
    pub chain: Vec<CertificateDer<'static>>,
    /// Private key corresponding to the leaf.
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
    /// Baseline revocation information for the path.
    pub crls: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
}

/// Generates a path with independently selected root, optional intermediate and leaf keys.
pub fn peer_certificate_pki(
    root: SignatureAlgorithm,
    intermediate: Option<SignatureAlgorithm>,
    leaf: SignatureAlgorithm,
) -> Result<PeerCertificatePki, String> {
    peer_pki(root, intermediate, leaf, None)
}

fn peer_pki(
    root: SignatureAlgorithm,
    intermediate: Option<SignatureAlgorithm>,
    leaf: SignatureAlgorithm,
    fixture: Option<PeerCertificateFixture>,
) -> Result<PeerCertificatePki, String> {
    let root_key = KeyPair::generate(root).map_err(e)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "conformance root");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let sha256 = PeerSha256(&root_key);
    let root_cert = if matches!(fixture, Some(PeerCertificateFixture::RootSha256)) {
        params.self_signed(&sha256).map_err(e)?
    } else {
        params.self_signed(&root_key).map_err(e)?
    };
    let issuer = rcgen::Issuer::new(params.clone(), &root_key);
    let intermediate_key = intermediate.map(KeyPair::generate).transpose().map_err(e)?;
    let mut chain = Vec::new();
    let intermediate_params = intermediate_key
        .as_ref()
        .map(|_| {
            let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
            p.distinguished_name
                .push(rcgen::DnType::CommonName, "conformance intermediate");
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            Ok::<_, String>(p)
        })
        .transpose()?;
    let intermediate_issuer = intermediate_params
        .as_ref()
        .zip(intermediate_key.as_ref())
        .map(|(p, k)| rcgen::Issuer::new(p.clone(), k));
    let leaf_key = KeyPair::generate(leaf).map_err(e)?;
    let name = if matches!(fixture, Some(PeerCertificateFixture::WrongName)) {
        "other.invalid"
    } else {
        "localhost"
    };
    let mut leaf_params = rcgen::CertificateParams::new(vec![name.into()]).map_err(e)?;
    leaf_params.serial_number = Some(rcgen::SerialNumber::from(42));
    if matches!(fixture, Some(PeerCertificateFixture::Expired)) {
        leaf_params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, intermediate_issuer.as_ref().unwrap_or(&issuer))
        .map_err(e)?;
    let mut der = leaf_cert.der().to_vec();
    if matches!(fixture, Some(PeerCertificateFixture::Tampered)) {
        let last = der.len() - 1;
        der[last] ^= 1;
    }
    chain.push(CertificateDer::from(der));
    if let Some((p, k)) = intermediate_params.zip(intermediate_key.as_ref()) {
        chain.push(p.signed_by(k, &issuer).map_err(e)?.der().clone());
    }
    let mut roots = rustls::RootCertStore::empty();
    if matches!(fixture, Some(PeerCertificateFixture::Untrusted)) {
        roots = pki(
            SignatureAlgorithm::EcdsaP384Sha384,
            SignatureAlgorithm::EcdsaP384Sha384,
        )?
        .roots;
    } else {
        roots.add(root_cert.der().clone()).map_err(e)?;
    }
    let mut crls = Vec::new();
    if matches!(
        fixture,
        Some(PeerCertificateFixture::Sha256Crl | PeerCertificateFixture::RevokedSha256Crl)
    ) {
        let crl_issuer = rcgen::Issuer::new(params, &sha256);
        crls.push(
            rcgen::CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2020, 1, 1),
                next_update: rcgen::date_time_ymd(2040, 1, 1),
                crl_number: rcgen::SerialNumber::from(1),
                issuing_distribution_point: None,
                revoked_certs: if matches!(fixture, Some(PeerCertificateFixture::RevokedSha256Crl))
                {
                    vec![rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from(42),
                        revocation_time: rcgen::date_time_ymd(2020, 1, 1),
                        reason_code: None,
                        invalidity_date: None,
                    }]
                } else {
                    vec![]
                },
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(&crl_issuer)
            .map_err(e)?
            .der()
            .clone(),
        );
    }
    Ok(PeerCertificatePki {
        opposite: None,
        roots,
        chain,
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.pkcs8_der().to_vec().into()),
        crls,
    })
}

/// Special paths for baseline and strict certificate-validation regressions.
#[derive(Clone, Copy)]
pub enum PeerCertificateFixture {
    /// A compliant root key with a SHA-256 self-signature.
    RootSha256,
    /// An unrevoked SHA-384 path with a SHA-256 CRL.
    Sha256Crl,
    /// A revoked SHA-384 path with a SHA-256 CRL.
    RevokedSha256Crl,
    /// A separately generated 8192-bit RSA leaf.
    Rsa8192Leaf,
    /// A selected noncompliant path with a compliant alternative.
    SelectedBadPath,
    /// A selected compliant path with an unused noncompliant alternative.
    SelectedGoodPath,
    /// A leaf naming a different server.
    WrongName,
    /// An expired leaf.
    Expired,
    /// A path outside the configured trust anchors.
    Untrusted,
    /// A leaf with a corrupted signature.
    Tampered,
}

/// Generates a named regression path with a 3072-bit RSA root and P-384 leaf.
pub fn peer_certificate_fixture(
    fixture: PeerCertificateFixture,
) -> Result<PeerCertificatePki, String> {
    if matches!(
        fixture,
        PeerCertificateFixture::SelectedBadPath | PeerCertificateFixture::SelectedGoodPath
    ) {
        return peer_selected_path(matches!(fixture, PeerCertificateFixture::SelectedBadPath));
    }
    if matches!(fixture, PeerCertificateFixture::Rsa8192Leaf) {
        let mut p = peer_certificate_pki(
            SignatureAlgorithm::Rsa3072Sha384,
            None,
            SignatureAlgorithm::Rsa3072Sha384,
        )?;
        let issuer_key = KeyPair::generate(SignatureAlgorithm::Rsa3072Sha384).map_err(e)?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&issuer_key).map_err(e)?;
        let issuer = rcgen::Issuer::new(params, &issuer_key);
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from(
            crypto_profile::__test_data::RSA8192_PKCS8.to_vec(),
        );
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA384)
            .map_err(e)?;
        let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
            .map_err(e)?
            .signed_by(&key, &issuer)
            .map_err(e)?;
        p.roots = rustls::RootCertStore::empty();
        p.roots.add(root.der().clone()).map_err(e)?;
        p.chain = vec![leaf.der().clone()];
        p.key = rustls::pki_types::PrivateKeyDer::Pkcs8(der);
        return Ok(p);
    }
    let mut pki = peer_pki(
        SignatureAlgorithm::Rsa3072Sha384,
        None,
        SignatureAlgorithm::EcdsaP384Sha384,
        Some(fixture),
    )?;
    if matches!(
        fixture,
        PeerCertificateFixture::RevokedSha256Crl
            | PeerCertificateFixture::WrongName
            | PeerCertificateFixture::Expired
            | PeerCertificateFixture::Untrusted
            | PeerCertificateFixture::Tampered
    ) {
        pki.opposite = Some(Box::new(peer_certificate_pki(
            SignatureAlgorithm::EcdsaP384Sha384,
            None,
            SignatureAlgorithm::EcdsaP384Sha384,
        )?));
    }
    Ok(pki)
}

struct PeerSha256<'a>(&'a KeyPair);
impl rcgen::PublicKeyData for PeerSha256<'_> {
    fn der_bytes(&self) -> &[u8] {
        rcgen::PublicKeyData::der_bytes(self.0)
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}
impl rcgen::SigningKey for PeerSha256<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let key = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(self.0.pkcs8_der())
            .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?;
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            msg,
            &mut signature,
        )
        .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature)
    }
}

/// Builds fresh mutual-authentication configurations, restricting only the detecting endpoint.
/// Each call creates independent session stores; permissive sessions are never reused by strict configurations.
pub fn peer_certificate_configs(
    policy: &Policy,
    server_checks_client: bool,
    pki: &PeerCertificatePki,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), String> {
    let (mut client, mut server) =
        peer_certificate_default_session_configs(policy, server_checks_client, pki)?;
    client.resumption = rustls::client::Resumption::disabled();
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    Ok((client, server))
}

/// Builds mutual-authentication configurations with the default session storage and ticketer.
pub fn peer_certificate_default_session_configs(
    policy: &Policy,
    server_checks_client: bool,
    pki: &PeerCertificatePki,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), String> {
    use crate::tls::{client_cert_verifier_builder, strict_client_builder, strict_server_builder};
    let mut baseline = policy.clone();
    baseline.peer_certificate_rule = None;
    baseline.cipher_suites = CipherSuite::ALL
        .into_iter()
        .filter(|s| policy.versions.contains(&s.version()))
        .collect();
    let cp = if server_checks_client {
        &baseline
    } else {
        policy
    };
    let sp = if server_checks_client {
        policy
    } else {
        &baseline
    };
    let opposite = pki.opposite.as_deref().unwrap_or(pki);
    let (client_pki, server_pki) = if server_checks_client {
        (pki, opposite)
    } else {
        (opposite, pki)
    };
    let cv = server_cert_verifier_builder(Arc::new(server_pki.roots.clone()), cp)
        .map_err(e)?
        .with_crls(server_pki.crls.clone())
        .build()
        .map_err(e)?;
    let sv = client_cert_verifier_builder(Arc::new(client_pki.roots.clone()), sp)
        .map_err(e)?
        .with_crls(client_pki.crls.clone())
        .build()
        .map_err(e)?;
    let cb = if cp.peer_certificate_rule.is_some() {
        strict_client_builder(cp, cv).map_err(e)?
    } else {
        client_builder(cp)
            .map_err(e)?
            .dangerous()
            .with_custom_certificate_verifier(cv)
    };
    let sb = if sp.peer_certificate_rule.is_some() {
        strict_server_builder(sp, sv).map_err(e)?
    } else {
        server_builder(sp).map_err(e)?.with_client_cert_verifier(sv)
    };
    let certified = |pki: &PeerCertificatePki| -> Result<_, String> {
        let key = crate::tls::load_private_key(&baseline, pki.key.clone_key()).map_err(e)?;
        Ok(Arc::new(rustls::sign::CertifiedKey::new(
            pki.chain.clone(),
            key,
        )))
    };
    let client =
        cb.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified(client_pki)?)));
    let server = sb.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified(server_pki)?)));
    Ok((client, server))
}

/// Drives mutual authentication and retains the local detecting endpoint's typed error.
/// The boolean is true for errors detected by the server.
pub fn drive_typed(
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
) -> Result<(), (bool, rustls::Error)> {
    let mut c = rustls::ClientConnection::new(
        Arc::new(client),
        ServerName::try_from("localhost")
            .map_err(|error| (false, rustls::Error::General(error.to_string())))?,
    )
    .map_err(|e| (false, e))?;
    let mut s = rustls::ServerConnection::new(Arc::new(server)).map_err(|e| (true, e))?;
    for _flight in 0..100 {
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(());
        }
        let mut to_server = Vec::new();
        c.write_tls(&mut to_server)
            .map_err(|e| (false, rustls::Error::General(e.to_string())))?;
        let mut bytes = to_server.as_slice();
        while !bytes.is_empty() {
            s.read_tls(&mut bytes)
                .map_err(|e| (true, rustls::Error::General(e.to_string())))?;
            s.process_new_packets().map_err(|e| (true, e))?;
        }
        let mut to_client = Vec::new();
        s.write_tls(&mut to_client)
            .map_err(|e| (true, rustls::Error::General(e.to_string())))?;
        let mut bytes = to_client.as_slice();
        while !bytes.is_empty() {
            c.read_tls(&mut bytes)
                .map_err(|e| (false, rustls::Error::General(e.to_string())))?;
            c.process_new_packets().map_err(|e| (false, e))?;
        }
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    Err((false, rustls::Error::General("handshake stalled".into())))
}

fn peer_selected_path(bad_first: bool) -> Result<PeerCertificatePki, String> {
    let ca_params = |name: &str| {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(e)?;
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        Ok::<_, String>(p)
    };
    let good_key = KeyPair::generate(SignatureAlgorithm::EcdsaP384Sha384).map_err(e)?;
    let bad_key = KeyPair::generate(SignatureAlgorithm::EcdsaP256Sha256).map_err(e)?;
    let gp = ca_params("good root")?;
    let bp = ca_params("bad root")?;
    let gr = gp.self_signed(&good_key).map_err(e)?;
    let br = bp.self_signed(&bad_key).map_err(e)?;
    let gi = rcgen::Issuer::new(gp, &good_key);
    let bi = rcgen::Issuer::new(bp, &bad_key);
    let ik = KeyPair::generate(SignatureAlgorithm::EcdsaP384Sha384).map_err(e)?;
    let ip = ca_params("shared intermediate")?;
    let good = ip.signed_by(&ik, &gi).map_err(e)?;
    let bad = ip.signed_by(&ik, &bi).map_err(e)?;
    let ii = rcgen::Issuer::new(ip, &ik);
    let key = KeyPair::generate(SignatureAlgorithm::EcdsaP384Sha384).map_err(e)?;
    let leaf = rcgen::CertificateParams::new(vec!["localhost".into()])
        .map_err(e)?
        .signed_by(&key, &ii)
        .map_err(e)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(gr.der().clone()).map_err(e)?;
    roots.add(br.der().clone()).map_err(e)?;
    let chain = if bad_first {
        vec![leaf.der().clone(), bad.der().clone(), good.der().clone()]
    } else {
        vec![leaf.der().clone(), good.der().clone(), bad.der().clone()]
    };
    let crls = [&gi, &bi, &ii]
        .into_iter()
        .map(|issuer| {
            rcgen::CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2020, 1, 1),
                next_update: rcgen::date_time_ymd(2040, 1, 1),
                crl_number: rcgen::SerialNumber::from(1),
                issuing_distribution_point: None,
                revoked_certs: vec![],
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(issuer)
            .map(|crl| crl.der().clone())
            .map_err(e)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PeerCertificatePki {
        opposite: None,
        roots,
        chain,
        key: rustls::pki_types::PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into()),
        crls,
    })
}
