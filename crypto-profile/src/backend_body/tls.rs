//! TLS configuration from a [`Policy`]: which versions, cipher suites, key-exchange groups and
//! handshake signature schemes a provider carries, in preference order.
use crate::{
    Algorithm, CipherSuite as C, CryptoError, Family, KxGroup as K, TlsError,
    TlsSignatureScheme as T, TlsVersion as V, ensure,
};
use rustls::crypto::{CryptoProvider, KeyProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// What a TLS configuration may use: versions, suites and groups in preference order, and a set
/// of signature schemes. No list may name an entry twice.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Policy {
    /// Protocol versions.
    pub versions: Vec<V>,
    /// Cipher suites; a suite whose version is not in `versions` is not offered.
    pub cipher_suites: Vec<C>,
    /// Key-exchange groups.
    pub kx_groups: Vec<K>,
    /// Handshake signature schemes: those this side accepts from its peer, and those a key loaded
    /// through this policy's provider signs with. Certificate-chain signature algorithms are not
    /// restricted. A provider carries them in [`TlsSignatureScheme::preference`](T::preference) order,
    /// the order every profile lists them in, whatever order they are given in.
    pub signature_schemes: Vec<T>,
    /// Canonical peer-certificate restrictions; hand-written policies default to none.
    pub peer_certificate_rule: Option<crypto_profile::PeerCertificateRuleId>,
}

pub(crate) use crate::provider::assembly::group as rustls_group;
pub(crate) use crate::provider::assembly::suite as rustls_suite;

fn rustls_scheme(t: T) -> rustls::SignatureScheme {
    use rustls::SignatureScheme as R;
    match t {
        T::EcdsaNistp256Sha256 => R::ECDSA_NISTP256_SHA256,
        T::EcdsaNistp384Sha384 => R::ECDSA_NISTP384_SHA384,
        T::EcdsaNistp521Sha512 => R::ECDSA_NISTP521_SHA512,
        T::Ed25519 => R::ED25519,
        T::RsaPssSha256 => R::RSA_PSS_SHA256,
        T::RsaPssSha384 => R::RSA_PSS_SHA384,
        T::RsaPssSha512 => R::RSA_PSS_SHA512,
        T::RsaPkcs1Sha256 => R::RSA_PKCS1_SHA256,
        T::RsaPkcs1Sha384 => R::RSA_PKCS1_SHA384,
        T::RsaPkcs1Sha512 => R::RSA_PKCS1_SHA512,
        T::MlDsa87 => R::ML_DSA_87,
    }
}

fn rustls_version(v: V) -> &'static rustls::SupportedProtocolVersion {
    match v {
        V::Tls12 => &rustls::version::TLS12,
        V::Tls13 => &rustls::version::TLS13,
    }
}

fn base_provider() -> CryptoProvider {
    crate::provider::assembly::full()
}

type SchemeMapping = (
    rustls::SignatureScheme,
    &'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
);

fn select_schemes(
    base: &[SchemeMapping],
    schemes: &[T],
) -> Result<Vec<SchemeMapping>, CryptoError> {
    schemes
        .iter()
        .map(|t| {
            base.iter()
                .find(|(s, _)| *s == rustls_scheme(*t))
                .copied()
                .ok_or(CryptoError::Unavailable(Algorithm::Scheme(*t)))
        })
        .collect()
}

#[derive(Debug)]
struct PolicyKey {
    inner: Arc<dyn SigningKey>,
    schemes: &'static [rustls::SignatureScheme],
}

impl SigningKey for PolicyKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        let allowed: Vec<_> = offered
            .iter()
            .copied()
            .filter(|s| self.schemes.contains(s))
            .collect();
        self.inner.choose_scheme(&allowed)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[derive(Debug)]
struct PolicyKeyProvider {
    base: &'static dyn KeyProvider,
    schemes: &'static [rustls::SignatureScheme],
}

impl KeyProvider for PolicyKeyProvider {
    #[expect(clippy::disallowed_methods)]
    fn load_private_key(
        &self,
        der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Ok(Arc::new(PolicyKey {
            inner: self.base.load_private_key(der)?,
            schemes: self.schemes,
        }))
    }

    fn fips(&self) -> bool {
        self.base.fips()
    }
}

struct SchemeSet {
    bits: u16,
    ordered: Vec<T>,
}

fn scheme_set(schemes: &[T]) -> Result<SchemeSet, CryptoError> {
    let mut bits = 0u16;
    for t in schemes {
        let bit = 1u16 << t.preference();
        if bits & bit != 0 {
            return Err(CryptoError::PolicyDuplicate(Algorithm::Scheme(*t)));
        }
        bits |= bit;
    }
    let mut ordered = schemes.to_vec();
    ordered.sort_by_key(|t| t.preference());
    Ok(SchemeSet { bits, ordered })
}

#[derive(Clone, Copy)]
struct Tables {
    verification: &'static WebPkiSupportedAlgorithms,
    keys: &'static PolicyKeyProvider,
}

static TABLES: OnceLock<Mutex<HashMap<u16, Tables>>> = OnceLock::new();

#[cfg(test)]
fn cache_len() -> usize {
    TABLES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

fn tables(set: &SchemeSet) -> Result<Tables, CryptoError> {
    let mut cache = TABLES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(t) = cache.get(&set.bits).copied() {
        return Ok(t);
    }
    let base = base_provider();
    let verify = base.signature_verification_algorithms;
    let mapping = select_schemes(verify.mapping, &set.ordered)?;
    let t = Tables {
        verification: Box::leak(Box::new(WebPkiSupportedAlgorithms {
            all: verify.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        })),
        keys: Box::leak(Box::new(PolicyKeyProvider {
            base: base.key_provider,
            schemes: Box::leak(set.ordered.iter().map(|t| rustls_scheme(*t)).collect()),
        })),
    };
    cache.insert(set.bits, t);
    Ok(t)
}

fn no_duplicate<X: Copy + PartialEq>(
    xs: &[X],
    algorithm: fn(X) -> Algorithm,
) -> Result<(), CryptoError> {
    for (i, x) in xs.iter().enumerate() {
        if xs[..i].contains(x) {
            return Err(CryptoError::PolicyDuplicate(algorithm(*x)));
        }
    }
    Ok(())
}

fn validate(
    p: &Policy,
    available: impl Fn(Algorithm) -> Result<(), CryptoError>,
) -> Result<SchemeSet, CryptoError> {
    if p.versions.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::Version));
    }
    if p.kx_groups.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::KxGroup));
    }
    if p.signature_schemes.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::SignatureScheme));
    }
    no_duplicate(&p.versions, Algorithm::Protocol)?;
    no_duplicate(&p.cipher_suites, Algorithm::Cipher)?;
    no_duplicate(&p.kx_groups, Algorithm::Kx)?;
    let schemes = scheme_set(&p.signature_schemes)?;
    for v in &p.versions {
        available(Algorithm::Protocol(*v))?;
    }
    for c in &p.cipher_suites {
        available(Algorithm::Cipher(*c))?;
    }
    for k in &p.kx_groups {
        available(Algorithm::Kx(*k))?;
    }
    for t in &p.signature_schemes {
        available(Algorithm::Scheme(*t))?;
    }
    Ok(schemes)
}

/// A provider carrying exactly `p`. It refuses, in this order: an empty version, group or scheme
/// list; a duplicate entry in any list, naming the first one found in versions, suites, groups,
/// then schemes; an unavailable algorithm; and a suite list left empty once suites of unlisted
/// versions are dropped. A key loaded through its key provider signs only with a scheme in
/// `p.signature_schemes`.
pub fn crypto_provider(p: &Policy) -> Result<CryptoProvider, CryptoError> {
    let schemes = validate(p, ensure)?;
    let suites: Vec<_> = p
        .cipher_suites
        .iter()
        .filter(|c| p.versions.contains(&c.version()))
        .map(|c| rustls_suite(*c))
        .collect();
    if suites.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::CipherSuite));
    }
    let tables = tables(&schemes)?;
    Ok(CryptoProvider {
        cipher_suites: suites,
        kx_groups: p.kx_groups.iter().map(|k| rustls_group(*k)).collect(),
        signature_verification_algorithms: *tables.verification,
        key_provider: tables.keys,
        ..base_provider()
    })
}

fn versions(p: &Policy) -> Vec<&'static rustls::SupportedProtocolVersion> {
    p.versions.iter().map(|v| rustls_version(*v)).collect()
}

/// A client configuration builder on `p`.
#[expect(clippy::disallowed_methods)]
pub fn client_builder(
    p: &Policy,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, CryptoError> {
    rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
        .with_protocol_versions(&versions(p))
        .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))
}

/// A server configuration builder on `p`.
#[expect(clippy::disallowed_methods)]
pub fn server_builder(
    p: &Policy,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, CryptoError> {
    rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
        .with_protocol_versions(&versions(p))
        .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))
}

/// Installs a provider for `p` as the process default; refuses if one is already installed.
pub fn install_default(p: &Policy) -> Result<(), CryptoError> {
    crypto_provider(p)?
        .install_default()
        .map_err(|_| CryptoError::Tls(TlsError::DefaultProviderInstalled))
}

/// Refuses a provider that does not carry exactly `p`'s suites and groups in order and its
/// schemes in [`TlsSignatureScheme::preference`](T::preference) order, or whose key provider is not the one
/// `crypto_provider(p)` carries.
pub fn assert_provider_matches(provider: &CryptoProvider, p: &Policy) -> Result<(), CryptoError> {
    let want = crypto_provider(p)?;
    let suites = |x: &CryptoProvider| {
        x.cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect::<Vec<_>>()
    };
    let groups = |x: &CryptoProvider| x.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>();
    let schemes = |x: &CryptoProvider| {
        x.signature_verification_algorithms
            .mapping
            .iter()
            .map(|(s, _)| *s)
            .collect::<Vec<_>>()
    };
    if suites(provider) == suites(&want)
        && groups(provider) == groups(&want)
        && schemes(provider) == schemes(&want)
        && std::ptr::addr_eq(provider.key_provider, want.key_provider)
    {
        Ok(())
    } else {
        Err(CryptoError::PolicyDrift)
    }
}

/// Loads a private key into a signing key that signs only with a scheme in
/// `p.signature_schemes`. The key's algorithm is not checked against any profile;
/// `Resolved::certified_key` checks it.
#[expect(clippy::disallowed_methods)]
pub fn load_private_key(
    p: &Policy,
    der: PrivateKeyDer<'static>,
) -> Result<Arc<dyn SigningKey>, CryptoError> {
    crypto_provider(p)?
        .key_provider
        .load_private_key(der)
        .map_err(|_| CryptoError::Tls(TlsError::PrivateKey))
}

/// A WebPKI client-certificate verifier builder over `roots` on `p`.
#[expect(clippy::disallowed_methods)]
pub fn client_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
    p: &Policy,
) -> Result<rustls::server::ClientCertVerifierBuilder, CryptoError> {
    Ok(rustls::server::WebPkiClientVerifier::builder_with_provider(
        roots,
        Arc::new(crypto_provider(p)?),
    ))
}

/// A WebPKI server-certificate verifier builder over `roots` on `p`.
#[expect(clippy::disallowed_methods)]
pub fn server_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
    p: &Policy,
) -> Result<rustls::client::ServerCertVerifierBuilder, CryptoError> {
    Ok(rustls::client::WebPkiServerVerifier::builder_with_provider(
        roots,
        Arc::new(crypto_provider(p)?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Negotiated, handshake};
    use crate::{
        CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
        TlsVersion as V,
    };
    use rustls::client::danger::ServerCertVerifier;
    use std::sync::Arc;

    fn available_schemes() -> Vec<T> {
        T::ALL
            .into_iter()
            .filter(|s| crate::capability(crate::MODULE, Algorithm::Scheme(*s)).available)
            .collect()
    }

    fn policy(versions: &[V], suites: &[C], kx: &[K], schemes: &[T]) -> Policy {
        Policy {
            peer_certificate_rule: None,
            versions: versions.to_vec(),
            cipher_suites: suites.to_vec(),
            kx_groups: kx.to_vec(),
            signature_schemes: schemes
                .iter()
                .copied()
                .filter(|s| crate::capability(crate::MODULE, Algorithm::Scheme(*s)).available)
                .collect(),
        }
    }

    fn one13(k: K) -> Policy {
        policy(&[V::Tls13], &[C::Tls13Aes256GcmSha384], &[k], &T::ALL)
    }

    fn cp(bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }

    #[test]
    fn a_hybrid_offer_completes_on_its_classical_component() {
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1MlKem1024, K::Secp384r1],
            &T::ALL,
        );
        let n = handshake(&client, &one13(K::Secp384r1), S::EcdsaP384Sha384).unwrap();
        assert_eq!(n.kx.iana(), 0x0018);
        assert_eq!(n.kind, rustls::HandshakeKind::Full);
    }

    #[test]
    fn a_retry_into_secp384r1mlkem1024_completes() {
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1, K::Secp384r1MlKem1024],
            &T::ALL,
        );
        let n = handshake(&client, &one13(K::Secp384r1MlKem1024), S::EcdsaP384Sha384).unwrap();
        assert_eq!(n.kx.iana(), 0x11ED);
        assert_eq!(n.kind, rustls::HandshakeKind::FullWithHelloRetryRequest);
    }

    #[test]
    fn every_mapping_carries_its_registry_codepoint() {
        for c in C::ALL {
            assert_eq!(cp(rustls_suite(c).suite().to_array()), c.iana(), "{c:?}");
        }
        for k in K::ALL {
            assert_eq!(cp(rustls_group(k).name().to_array()), k.iana(), "{k:?}");
        }
        for t in T::ALL {
            assert_eq!(cp(rustls_scheme(t).to_array()), t.iana(), "{t:?}");
        }
        for v in V::ALL {
            assert_eq!(cp(rustls_version(v).version.to_array()), v.iana(), "{v:?}");
        }
    }

    #[test]
    fn a_scheme_missing_from_the_base_mapping_is_refused() {
        let base = base_provider().signature_verification_algorithms.mapping;
        let names = |m: &[SchemeMapping]| m.iter().map(|(s, _)| *s).collect::<Vec<_>>();
        assert_eq!(
            names(&select_schemes(base, &[T::Ed25519, T::EcdsaNistp384Sha384]).unwrap()),
            [
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384
            ]
        );
        let without: Vec<SchemeMapping> = base
            .iter()
            .filter(|(s, _)| *s != rustls::SignatureScheme::ED25519)
            .copied()
            .collect();
        assert_eq!(
            select_schemes(&without, &[T::EcdsaNistp384Sha384, T::Ed25519]).err(),
            Some(CryptoError::Unavailable(Algorithm::Scheme(T::Ed25519)))
        );
    }

    #[test]
    fn a_server_config_with_x25519_is_not_fips() {
        let key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into());
        let fips = server_builder(&one13(K::Secp384r1))
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der.clone_key())
            .unwrap();
        assert_eq!(crate::fips::assert_fips_server_config(&fips), Ok(()));
        let x = server_builder(&one13(K::X25519))
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der)
            .unwrap();
        assert_eq!(
            crate::fips::assert_fips_server_config(&x),
            Err(CryptoError::NotFips)
        );
    }

    #[test]
    fn verifiers_carry_the_policys_schemes_in_the_canonical_order() {
        let key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(params.self_signed(&key).unwrap().der().clone())
            .unwrap();
        let roots = Arc::new(roots);
        let p = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::Ed25519, T::EcdsaNistp384Sha384],
        );
        let want = [T::EcdsaNistp384Sha384.iana(), T::Ed25519.iana()];
        let server_v = server_cert_verifier_builder(roots.clone(), &p)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            server_v
                .supported_verify_schemes()
                .iter()
                .map(|s| cp(s.to_array()))
                .collect::<Vec<_>>(),
            want
        );
        let client_v = client_cert_verifier_builder(roots, &p)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            client_v
                .supported_verify_schemes()
                .iter()
                .map(|s| cp(s.to_array()))
                .collect::<Vec<_>>(),
            want
        );
    }

    #[test]
    fn an_empty_family_is_refused() {
        let p = one13(K::Secp384r1);
        for (fam, q) in [
            (
                Family::Version,
                Policy {
                    versions: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::CipherSuite,
                Policy {
                    cipher_suites: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::KxGroup,
                Policy {
                    kx_groups: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::SignatureScheme,
                Policy {
                    signature_schemes: vec![],
                    ..p.clone()
                },
            ),
        ] {
            assert_eq!(
                crypto_provider(&q).err(),
                Some(CryptoError::PolicyEmpty(fam))
            );
        }
    }

    #[test]
    fn a_suite_without_its_version_is_refused() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls12EcdheRsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::RsaPssSha384],
        );
        assert_eq!(
            crypto_provider(&q).err(),
            Some(CryptoError::PolicyEmpty(Family::CipherSuite))
        );
    }

    #[test]
    fn the_provider_carries_exactly_the_policy_in_order() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384, C::Tls13Aes128GcmSha256],
            &[K::MlKem1024, K::Secp384r1],
            &[T::EcdsaNistp384Sha384, T::Ed25519],
        );
        let p = crypto_provider(&q).unwrap();
        assert_eq!(
            p.cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect::<Vec<_>>(),
            [
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            ]
        );
        assert_eq!(
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            [rustls::NamedGroup::MLKEM1024, rustls::NamedGroup::secp384r1]
        );
        assert_eq!(
            p.signature_verification_algorithms
                .mapping
                .iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>(),
            [
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519
            ]
        );
        assert_eq!(assert_provider_matches(&p, &q), Ok(()));
    }

    #[test]
    fn drift_in_any_one_family_is_refused() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384],
        );
        let p = crypto_provider(&q).unwrap();
        for other in [
            Policy {
                cipher_suites: vec![C::Tls13Aes128GcmSha256],
                ..q.clone()
            },
            Policy {
                kx_groups: vec![K::Secp256r1],
                ..q.clone()
            },
            Policy {
                signature_schemes: vec![T::Ed25519],
                ..q.clone()
            },
        ] {
            assert_eq!(
                assert_provider_matches(&p, &other),
                Err(CryptoError::PolicyDrift),
                "{other:?}"
            );
        }
    }

    #[test]
    fn an_approved_only_policy_is_fips_and_x25519_or_chacha_is_not() {
        let fips = one13(K::Secp384r1);
        assert!(crypto_provider(&fips).unwrap().fips());
        assert!(!crypto_provider(&one13(K::X25519)).unwrap().fips());
        let c = Policy {
            cipher_suites: vec![C::Tls13Chacha20Poly1305Sha256],
            ..fips
        };
        assert!(!crypto_provider(&c).unwrap().fips());
    }

    #[test]
    fn a_policy_with_x25519_is_not_fips() {
        let cfg = client_builder(&one13(K::X25519))
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert_eq!(
            crate::fips::assert_fips_client_config(&cfg),
            Err(CryptoError::NotFips)
        );
    }

    #[test]
    fn tls12_fips_config_requires_ems() {
        let p = policy(
            &[V::Tls12],
            &[C::Tls12EcdheEcdsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384],
        );
        let cfg = client_builder(&p)
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(cfg.require_ems);
        assert_eq!(crate::fips::assert_fips_client_config(&cfg), Ok(()));
    }

    #[test]
    fn each_group_is_the_one_negotiated() {
        for k in K::ALL {
            let n = handshake(&one13(k), &one13(k), S::EcdsaP384Sha384)
                .unwrap_or_else(|e| panic!("{k:?}: {e}"));
            assert_eq!(
                n,
                Negotiated {
                    version: V::Tls13,
                    suite: C::Tls13Aes256GcmSha384,
                    kx: k,
                    scheme: T::EcdsaNistp384Sha384,
                    kind: rustls::HandshakeKind::Full,
                }
            );
        }
    }

    #[test]
    fn each_suite_is_the_one_negotiated() {
        for s in C::ALL {
            let key = match s {
                C::Tls12EcdheRsaAes256GcmSha384
                | C::Tls12EcdheRsaAes128GcmSha256
                | C::Tls12EcdheRsaChacha20Poly1305Sha256 => S::Rsa2048Sha384,
                C::Tls13Aes256GcmSha384
                | C::Tls13Aes128GcmSha256
                | C::Tls13Chacha20Poly1305Sha256
                | C::Tls12EcdheEcdsaAes256GcmSha384
                | C::Tls12EcdheEcdsaAes128GcmSha256
                | C::Tls12EcdheEcdsaChacha20Poly1305Sha256 => S::EcdsaP384Sha384,
            };
            let p = policy(&[s.version()], &[s], &[K::Secp384r1], &T::ALL);
            let n = handshake(&p, &p, key).unwrap_or_else(|e| panic!("{s:?}: {e}"));
            let scheme = match key {
                S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => T::RsaPssSha512,
                S::MlDsa87
                | S::EcdsaP256Sha256
                | S::EcdsaP384Sha384
                | S::EcdsaP521Sha384
                | S::EcdsaP521Sha512
                | S::Ed25519 => key.tls_scheme(),
            };
            assert_eq!(
                n,
                Negotiated {
                    version: s.version(),
                    suite: s,
                    kx: K::Secp384r1,
                    scheme,
                    kind: rustls::HandshakeKind::Full,
                },
                "{s:?}"
            );
        }
    }

    #[test]
    fn every_key_algorithm_authenticates_a_tls13_server() {
        for a in S::ALL {
            if !crate::capability(crate::MODULE, Algorithm::Signature(a)).available {
                assert_eq!(
                    crate::signature::KeyPair::generate(a).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(a)))
                );
                continue;
            }
            let n = handshake(&one13(K::Secp384r1), &one13(K::Secp384r1), a)
                .unwrap_or_else(|e| panic!("{a}: {e}"));
            let full_offer = match a {
                S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => T::RsaPssSha512,
                S::MlDsa87
                | S::EcdsaP256Sha256
                | S::EcdsaP384Sha384
                | S::EcdsaP521Sha384
                | S::EcdsaP521Sha512
                | S::Ed25519 => a.tls_scheme(),
            };
            assert_eq!(n.scheme, full_offer, "{a}");
        }
    }

    #[test]
    fn a_one_scheme_offer_gets_that_scheme() {
        let rsa = [T::RsaPssSha256, T::RsaPssSha384, T::RsaPssSha512];
        let cases = S::ALL
            .into_iter()
            .map(|a| (a, a.tls_scheme()))
            .chain(rsa.into_iter().map(|t| (S::Rsa2048Sha384, t)));
        for (a, t) in cases {
            if !crate::capability(crate::MODULE, Algorithm::Signature(a)).available {
                assert_eq!(
                    crate::signature::KeyPair::generate(a).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(a)))
                );
                continue;
            }
            let client = policy(
                &[V::Tls13],
                &[C::Tls13Aes256GcmSha384],
                &[K::Secp384r1],
                &[t],
            );
            let n = handshake(&client, &one13(K::Secp384r1), a)
                .unwrap_or_else(|e| panic!("{a} {t:?}: {e}"));
            assert_eq!(n.scheme, t, "{a}");
        }
    }

    #[test]
    fn a_policy_mismatch_fails_the_handshake() {
        let server = one13(K::Secp384r1);
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes128GcmSha256],
            &[K::Secp384r1],
            &T::ALL,
        );
        assert_eq!(
            handshake(&client, &server, S::EcdsaP384Sha384),
            Err("peer is incompatible: NoCipherSuitesInCommon".to_string())
        );
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::Ed25519],
        );
        assert_eq!(
            handshake(&client, &server, S::EcdsaP384Sha384),
            Err("peer is incompatible: NoSignatureSchemesInCommon".to_string())
        );
    }

    fn chosen(p: &Policy, a: S, offered: &[T]) -> Option<u16> {
        let key = crate::signature::KeyPair::generate(a).unwrap();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into());
        let offered: Vec<_> = offered.iter().map(|t| rustls_scheme(*t)).collect();
        load_private_key(p, der)
            .unwrap()
            .choose_scheme(&offered)
            .map(|s| cp(s.scheme().to_array()))
    }

    #[test]
    fn a_loaded_key_signs_only_with_a_scheme_the_policy_lists() {
        let rsa = |schemes: &[T]| {
            policy(
                &[V::Tls13],
                &[C::Tls13Aes256GcmSha384],
                &[K::Secp384r1],
                schemes,
            )
        };
        let offer = [T::RsaPssSha512, T::RsaPssSha384, T::RsaPssSha256];
        let a = S::Rsa3072Sha384;
        assert_eq!(chosen(&rsa(&T::ALL), a, &offer), Some(0x0806));
        assert_eq!(chosen(&rsa(&[T::RsaPssSha384]), a, &offer), Some(0x0805));
        assert_eq!(
            chosen(&rsa(&[T::RsaPssSha256, T::RsaPssSha384]), a, &offer),
            Some(0x0805)
        );
        assert_eq!(chosen(&rsa(&[T::RsaPkcs1Sha384]), a, &offer), None);
        if crate::capability(crate::MODULE, Algorithm::Scheme(T::MlDsa87)).available {
            assert_eq!(
                chosen(&rsa(&[T::MlDsa87]), S::EcdsaP384Sha384, &T::ALL),
                None
            );
        } else {
            let mut unavailable = rsa(&[T::Ed25519]);
            unavailable.signature_schemes = vec![T::MlDsa87];
            assert_eq!(
                crypto_provider(&unavailable).err(),
                Some(CryptoError::Unavailable(Algorithm::Scheme(T::MlDsa87)))
            );
        }
    }

    #[derive(Debug)]
    struct NotFips;

    impl KeyProvider for NotFips {
        fn load_private_key(
            &self,
            _: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
            Err(rustls::Error::General("not used".to_string()))
        }
    }

    fn keys(schemes: &[T]) -> &'static PolicyKeyProvider {
        tables(&scheme_set(schemes).unwrap()).unwrap().keys
    }

    #[test]
    fn the_key_provider_is_fips_exactly_when_its_base_is() {
        let wrap = |base: &'static dyn KeyProvider| PolicyKeyProvider { base, schemes: &[] };
        assert!(!wrap(&NotFips).fips());
        assert!(wrap(base_provider().key_provider).fips());
        assert!(keys(&available_schemes()).fips());
    }

    #[test]
    fn a_provider_with_another_key_provider_is_drift() {
        let p = one13(K::Secp384r1);
        let stock = CryptoProvider {
            key_provider: base_provider().key_provider,
            ..crypto_provider(&p).unwrap()
        };
        assert_eq!(
            assert_provider_matches(&stock, &p),
            Err(CryptoError::PolicyDrift)
        );
        let other = CryptoProvider {
            key_provider: keys(&[T::Ed25519]),
            ..crypto_provider(&p).unwrap()
        };
        assert_eq!(
            assert_provider_matches(&other, &p),
            Err(CryptoError::PolicyDrift)
        );
    }

    fn subsets() -> impl Iterator<Item = Vec<T>> {
        (1u16..1 << available_schemes().len()).map(|m| {
            available_schemes()
                .into_iter()
                .enumerate()
                .filter(|(i, _)| m & (1 << i) != 0)
                .map(|(_, t)| t)
                .collect()
        })
    }

    fn with_schemes(schemes: Vec<T>) -> Policy {
        Policy {
            signature_schemes: schemes,
            ..one13(K::Secp384r1)
        }
    }

    #[test]
    fn the_first_duplicate_in_any_list_is_refused_in_family_order() {
        let p = one13(K::Secp384r1);
        let versions = Policy {
            versions: vec![V::Tls13, V::Tls12, V::Tls13],
            cipher_suites: vec![C::Tls13Aes256GcmSha384, C::Tls13Aes256GcmSha384],
            ..p.clone()
        };
        let suites = Policy {
            cipher_suites: vec![
                C::Tls13Aes256GcmSha384,
                C::Tls13Aes128GcmSha256,
                C::Tls13Aes128GcmSha256,
                C::Tls13Aes256GcmSha384,
            ],
            kx_groups: vec![K::Secp384r1, K::Secp384r1],
            ..p.clone()
        };
        let groups = Policy {
            kx_groups: vec![K::MlKem1024, K::Secp384r1, K::MlKem1024],
            signature_schemes: vec![T::Ed25519, T::Ed25519],
            ..p.clone()
        };
        for (q, a) in [
            (versions, Algorithm::Protocol(V::Tls13)),
            (suites, Algorithm::Cipher(C::Tls13Aes128GcmSha256)),
            (groups, Algorithm::Kx(K::MlKem1024)),
        ] {
            assert_eq!(
                crypto_provider(&q).err(),
                Some(CryptoError::PolicyDuplicate(a)),
                "{q:?}"
            );
        }
    }

    #[test]
    fn a_duplicate_is_refused_before_an_unavailable_algorithm() {
        let p = one13(K::Secp384r1);
        let none = |a: Algorithm| Err(CryptoError::Unavailable(a));
        for (q, a) in [
            (
                Policy {
                    versions: vec![V::Tls13, V::Tls13],
                    ..p.clone()
                },
                Algorithm::Protocol(V::Tls13),
            ),
            (
                Policy {
                    cipher_suites: vec![C::Tls13Aes256GcmSha384; 2],
                    ..p.clone()
                },
                Algorithm::Cipher(C::Tls13Aes256GcmSha384),
            ),
            (
                Policy {
                    kx_groups: vec![K::Secp384r1; 2],
                    ..p.clone()
                },
                Algorithm::Kx(K::Secp384r1),
            ),
            (
                Policy {
                    signature_schemes: vec![T::MlDsa87; 2],
                    ..p.clone()
                },
                Algorithm::Scheme(T::MlDsa87),
            ),
        ] {
            assert_eq!(
                validate(&q, none).err(),
                Some(CryptoError::PolicyDuplicate(a)),
                "{q:?}"
            );
        }
        assert_eq!(
            validate(&p, none).err(),
            Some(CryptoError::Unavailable(Algorithm::Protocol(V::Tls13)))
        );
    }

    #[test]
    fn a_duplicate_scheme_is_refused_where_the_policy_enters() {
        let roots = Arc::new(rustls::RootCertStore::empty());
        let dup = with_schemes(vec![T::Ed25519, T::EcdsaNistp384Sha384, T::Ed25519]);
        let want = Some(CryptoError::PolicyDuplicate(Algorithm::Scheme(T::Ed25519)));
        assert_eq!(crypto_provider(&dup).err(), want);
        assert_eq!(client_builder(&dup).err(), want);
        assert_eq!(server_builder(&dup).err(), want);
        assert_eq!(
            server_cert_verifier_builder(roots.clone(), &dup).err(),
            want
        );
        assert_eq!(client_cert_verifier_builder(roots, &dup).err(), want);
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(b"not a key".to_vec().into());
        assert_eq!(load_private_key(&dup, der).err(), want);
    }

    #[test]
    fn a_permuted_policy_builds_the_same_provider() {
        let q = with_schemes(vec![T::Ed25519, T::RsaPssSha384, T::EcdsaNistp384Sha384]);
        let r = with_schemes(vec![T::RsaPssSha384, T::EcdsaNistp384Sha384, T::Ed25519]);
        assert_eq!(
            assert_provider_matches(&crypto_provider(&q).unwrap(), &r),
            Ok(())
        );
    }

    #[test]
    fn retained_cache_state_is_bounded_by_the_distinct_scheme_sets() {
        for s in subsets() {
            crypto_provider(&with_schemes(s)).unwrap();
        }
        let sets = (1 << available_schemes().len()) - 1;
        assert_eq!(cache_len(), sets);
        for s in subsets() {
            let mut rev = s.clone();
            rev.reverse();
            let mut rot = s.clone();
            rot.rotate_left(1);
            crypto_provider(&with_schemes(rev)).unwrap();
            crypto_provider(&with_schemes(rot)).unwrap();
            crypto_provider(&with_schemes(s.clone())).unwrap();
            let mut dup = s.clone();
            dup.push(s[0]);
            assert_eq!(
                crypto_provider(&with_schemes(dup)).err(),
                Some(CryptoError::PolicyDuplicate(Algorithm::Scheme(s[0])))
            );
        }
        assert_eq!(cache_len(), sets);
    }

    #[test]
    fn load_private_key_refuses_garbage() {
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(b"not a key".to_vec().into());
        assert_eq!(
            load_private_key(&one13(K::Secp384r1), der).err(),
            Some(CryptoError::Tls(TlsError::PrivateKey))
        );
    }

    #[test]
    fn an_ml_dsa_44_or_65_key_loads_but_no_policy_signs_with_it() {
        for (fixture, scheme) in [
            (
                super::super::backend::MlDsa::fixture44(),
                rustls::SignatureScheme::ML_DSA_44,
            ),
            (
                super::super::backend::MlDsa::fixture65(),
                rustls::SignatureScheme::ML_DSA_65,
            ),
        ] {
            assert_eq!(
                fixture.is_some(),
                crate::capability(crate::MODULE, Algorithm::Signature(S::MlDsa87)).available
            );
            let Some(pkcs8) = fixture else {
                assert_eq!(
                    super::super::backend::MlDsa::generate().err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(S::MlDsa87)))
                );
                continue;
            };
            let der = PrivateKeyDer::Pkcs8(pkcs8.to_vec().into());
            let key = load_private_key(&one13(K::Secp384r1), der).unwrap();
            assert!(
                key.choose_scheme(&[scheme, rustls::SignatureScheme::ML_DSA_87])
                    .is_none(),
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn the_base_provider_draws_randomness_and_loads_keys_through_the_crates_own_provider() {
        let base = base_provider();
        assert_eq!(format!("{:?}", base.secure_random), "Rng");
        assert_eq!(format!("{:?}", base.key_provider), "Keys");
    }
}
