//! TLS configuration from a [`Policy`]: which versions, cipher suites, key-exchange groups and
//! handshake signature schemes a provider carries, in preference order.
use crate::{
    Algorithm, CipherSuite as C, CryptoError, Family, KxGroup as K, TlsError,
    TlsSignatureScheme as T, TlsVersion as V, ensure,
};
use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// What a TLS configuration may use, each list in preference order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Policy {
    /// Protocol versions.
    pub versions: Vec<V>,
    /// Cipher suites; a suite whose version is not in `versions` is not offered.
    pub cipher_suites: Vec<C>,
    /// Key-exchange groups.
    pub kx_groups: Vec<K>,
    /// Handshake signature schemes this side accepts from its peer. Neither certificate-chain
    /// signature algorithms nor the scheme a local signing key chooses are restricted.
    pub signature_schemes: Vec<T>,
}

pub(crate) fn rustls_suite(c: C) -> rustls::SupportedCipherSuite {
    match c {
        C::Tls13Aes256GcmSha384 => cipher_suite::TLS13_AES_256_GCM_SHA384,
        C::Tls13Aes128GcmSha256 => cipher_suite::TLS13_AES_128_GCM_SHA256,
        C::Tls13Chacha20Poly1305Sha256 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        C::Tls12EcdheEcdsaAes256GcmSha384 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        C::Tls12EcdheEcdsaAes128GcmSha256 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        C::Tls12EcdheEcdsaChacha20Poly1305Sha256 => {
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        C::Tls12EcdheRsaAes256GcmSha384 => cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        C::Tls12EcdheRsaAes128GcmSha256 => cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        C::Tls12EcdheRsaChacha20Poly1305Sha256 => {
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
    }
}

pub(crate) fn rustls_group(k: K) -> &'static dyn SupportedKxGroup {
    match k {
        K::MlKem1024 => kx_group::MLKEM1024,
        K::X25519MlKem768 => kx_group::X25519MLKEM768,
        K::Secp256r1MlKem768 => kx_group::SECP256R1MLKEM768,
        K::Secp384r1 => kx_group::SECP384R1,
        K::Secp256r1 => kx_group::SECP256R1,
        K::X25519 => kx_group::X25519,
    }
}

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

#[expect(clippy::disallowed_methods)]
fn base_provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
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

fn verification_algorithms(schemes: &[T]) -> Result<WebPkiSupportedAlgorithms, CryptoError> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<T>, &'static WebPkiSupportedAlgorithms>>> =
        OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(w) = cache.get(schemes).copied() {
        return Ok(*w);
    }
    let base = base_provider().signature_verification_algorithms;
    let mapping = select_schemes(base.mapping, schemes)?;
    let w: &'static WebPkiSupportedAlgorithms = Box::leak(Box::new(WebPkiSupportedAlgorithms {
        all: base.all,
        mapping: Box::leak(mapping.into_boxed_slice()),
    }));
    cache.insert(schemes.to_vec(), w);
    Ok(*w)
}

/// A provider carrying exactly `p`, refusing an empty family or an unavailable algorithm.
pub fn crypto_provider(p: &Policy) -> Result<CryptoProvider, CryptoError> {
    if p.versions.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::Version));
    }
    if p.kx_groups.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::KxGroup));
    }
    if p.signature_schemes.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::SignatureScheme));
    }
    for v in &p.versions {
        ensure(Algorithm::Protocol(*v))?;
    }
    for c in &p.cipher_suites {
        ensure(Algorithm::Cipher(*c))?;
    }
    for k in &p.kx_groups {
        ensure(Algorithm::Kx(*k))?;
    }
    for t in &p.signature_schemes {
        ensure(Algorithm::Scheme(*t))?;
    }
    let suites: Vec<_> = p
        .cipher_suites
        .iter()
        .filter(|c| p.versions.contains(&c.version()))
        .map(|c| rustls_suite(*c))
        .collect();
    if suites.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::CipherSuite));
    }
    Ok(CryptoProvider {
        cipher_suites: suites,
        kx_groups: p.kx_groups.iter().map(|k| rustls_group(*k)).collect(),
        signature_verification_algorithms: verification_algorithms(&p.signature_schemes)?,
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

/// Refuses a provider that does not carry exactly `p`'s suites, groups and schemes, in order.
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
    {
        Ok(())
    } else {
        Err(CryptoError::PolicyDrift)
    }
}

/// Loads a private key into a signing key. The key's algorithm is not checked against a policy
/// in round 1; `docs/usage.md` names this.
#[expect(clippy::disallowed_methods)]
pub fn load_private_key(
    der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, CryptoError> {
    base_provider()
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

    fn policy(versions: &[V], suites: &[C], kx: &[K], schemes: &[T]) -> Policy {
        Policy {
            versions: versions.to_vec(),
            cipher_suites: suites.to_vec(),
            kx_groups: kx.to_vec(),
            signature_schemes: schemes.to_vec(),
        }
    }

    fn one13(k: K) -> Policy {
        policy(&[V::Tls13], &[C::Tls13Aes256GcmSha384], &[k], &T::ALL)
    }

    fn cp(bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
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
    fn verifiers_carry_the_policys_schemes() {
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
        let want: Vec<u16> = p.signature_schemes.iter().map(|t| t.iana()).collect();
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
                },
                "{s:?}"
            );
        }
    }

    #[test]
    fn every_key_algorithm_authenticates_a_tls13_server() {
        for a in S::ALL {
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

    #[test]
    fn load_private_key_refuses_garbage() {
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(b"not a key".to_vec().into());
        assert_eq!(
            load_private_key(der).err(),
            Some(CryptoError::Tls(TlsError::PrivateKey))
        );
    }
}
