//! Test infrastructure: in-memory certificates and an in-process handshake. Not shipped behaviour.
use crate::signature::KeyPair;
use crate::tls::{Policy, client_builder, server_builder};
use crate::{CipherSuite, KxGroup, SignatureAlgorithm, TlsVersion};
use std::sync::Arc;

/// What a completed handshake negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// The protocol version.
    pub version: TlsVersion,
    /// The cipher suite.
    pub suite: CipherSuite,
    /// The key-exchange group.
    pub kx: KxGroup,
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
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let ca_key = KeyPair::generate(SignatureAlgorithm::EcdsaP384Sha384).map_err(|x| e(&x))?;
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
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.pkcs8_der().to_vec().into());
    let server_cfg = server_builder(server)
        .map_err(|x| e(&x))?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .map_err(|x| e(&x))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).map_err(|x| e(&x))?;
    let client_cfg = client_builder(client)
        .map_err(|x| e(&x))?
        .with_root_certificates(roots)
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
    Ok(Negotiated { version, suite, kx })
}
