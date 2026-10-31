/// Identity-check conformance cases instantiated by every backend.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_peer_identity_tests {
    ($b:ident) => {
        mod peer_identity {
            use rustls::CertificateError as CE;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};
            use $b::rcgen;
            use $b::test_support::{self, IdentityPki};
            use $b::tls::{self, Policy};
            use $b::{
                CryptoError, KxGroup as K, Options, PeerCertificateViolation, PeerKey,
                Profile as P, SignatureAlgorithm as S, TlsError, TlsSignatureScheme as T,
                TlsVersion as V, resolve,
            };

            fn unknown_issuer(e: &rustls::Error) -> bool {
                matches!(e, rustls::Error::InvalidCertificate(CE::UnknownIssuer))
            }
            fn wrong_purpose(e: &rustls::Error) -> bool {
                matches!(
                    e,
                    rustls::Error::InvalidCertificate(
                        CE::InvalidPurpose | CE::InvalidPurposeContext { .. }
                    )
                )
            }
            fn revoked(e: &rustls::Error) -> bool {
                matches!(e, rustls::Error::InvalidCertificate(CE::Revoked))
            }
            fn cnsa1_refuses_rsa_2048(e: &rustls::Error) -> bool {
                let rustls::Error::InvalidCertificate(CE::Other(rustls::OtherError(cause))) = e
                else {
                    return false;
                };
                cause.downcast_ref::<TlsError>()
                    == Some(&TlsError::PeerCertificate {
                        profile: P::Cnsa1,
                        violation: PeerCertificateViolation::LeafKey(PeerKey::Rsa(2048)),
                    })
            }

            const A: &str = "spiffe://example.org/a";
            const B: &str = "spiffe://example.org/b";

            #[derive(Debug)]
            pub(super) struct ExactUri {
                want: &'static str,
                pub(super) calls: AtomicUsize,
            }

            impl ExactUri {
                pub(super) fn new(want: &'static str) -> Arc<Self> {
                    Arc::new(Self {
                        want,
                        calls: AtomicUsize::new(0),
                    })
                }
                pub(super) fn calls(&self) -> usize {
                    self.calls.load(Ordering::SeqCst)
                }
            }

            impl tls::PeerIdentity for ExactUri {
                fn check(&self, leaf: &tls::PeerLeaf<'_>) -> Result<(), rustls::Error> {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    match leaf.uri_names()?.as_slice() {
                        [one] if *one == self.want => Ok(()),
                        _ => Err(rustls::Error::General(format!("peer is not {}", self.want))),
                    }
                }
            }

            fn refusal(want: &str) -> rustls::Error {
                rustls::Error::General(format!("peer is not {want}"))
            }

            pub(super) fn policy(strict: bool) -> Policy {
                let mut p = resolve(
                    P::Preferred,
                    Options {
                        peer_certificates_match_profile: strict,
                        ..Options::default()
                    },
                )
                .unwrap()
                .tls;
                p.versions = vec![V::Tls13];
                p.cipher_suites.retain(|s| s.version() == V::Tls13);
                p.kx_groups = vec![K::Secp384r1];
                p.signature_schemes = vec![T::EcdsaNistp384Sha384];
                p
            }

            fn cnsa1_rsa() -> Policy {
                let mut p = resolve(
                    P::Cnsa1,
                    Options {
                        peer_certificates_match_profile: true,
                        ..Options::default()
                    },
                )
                .unwrap()
                .tls;
                p.versions = vec![V::Tls13];
                p.cipher_suites.retain(|s| s.version() == V::Tls13);
                p.kx_groups = vec![K::Secp384r1];
                p.signature_schemes = vec![T::EcdsaNistp384Sha384, T::RsaPssSha384];
                p
            }

            fn uri(s: &str) -> rcgen::SanType {
                rcgen::SanType::URI(s.try_into().unwrap())
            }

            pub(super) fn leaf(
                sans: Vec<rcgen::SanType>,
                eku: rcgen::ExtendedKeyUsagePurpose,
            ) -> IdentityPki {
                test_support::identity_pki(S::EcdsaP384Sha384, sans, vec![eku], false).unwrap()
            }

            /// The client checks the server's identity; `trust` is the client's view of the CA.
            /// The server runs `p` without its rule, so it can sign with any leaf `p` admits and
            /// every refusal comes from the client's verifier.
            pub(super) fn server_identity_configs(
                p: &Policy,
                server: &IdentityPki,
                trust: &IdentityPki,
                check: Option<Arc<dyn tls::PeerIdentity>>,
            ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), CryptoError> {
                let mut builder =
                    tls::server_cert_verifier_builder(Arc::new(trust.roots.clone()), p)?
                        .with_crls(trust.crls.clone());
                if let Some(check) = check {
                    builder = builder.with_peer_identity(check);
                }
                let verifier = builder.build().unwrap();
                let client = if p.peer_certificate_rule.is_some() {
                    tls::strict_client_builder(p, verifier)?
                } else {
                    tls::client_builder(p)?
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                }
                .with_no_client_auth();
                let mut sp = p.clone();
                sp.peer_certificate_rule = None;
                let server = tls::server_builder(&sp)?
                    .with_no_client_auth()
                    .with_single_cert(server.chain.clone(), server.key.clone_key())
                    .unwrap();
                Ok((client, server))
            }

            /// A `localhost` server leaf. Build it once per test and pass it to every
            /// `client_identity_configs` call, so each client trusts each server.
            pub(super) fn host() -> IdentityPki {
                test_support::identity_pki(
                    S::EcdsaP384Sha384,
                    vec![rcgen::SanType::DnsName("localhost".try_into().unwrap())],
                    vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
                    false,
                )
                .unwrap()
            }

            /// The server checks the client's identity and presents `host`.
            pub(super) fn client_identity_configs(
                p: &Policy,
                host: &IdentityPki,
                client: &IdentityPki,
                trust: &IdentityPki,
                check: Option<Arc<dyn tls::PeerIdentity>>,
            ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), CryptoError> {
                let mut builder =
                    tls::client_cert_verifier_builder(Arc::new(trust.roots.clone()), p)?
                        .with_crls(trust.crls.clone());
                if let Some(check) = check {
                    builder = builder.with_peer_identity(check);
                }
                let verifier = builder.build().unwrap();
                let server = if p.peer_certificate_rule.is_some() {
                    tls::strict_server_builder(p, verifier)?
                } else {
                    tls::server_builder(p)?.with_client_cert_verifier(verifier)
                }
                .with_single_cert(host.chain.clone(), host.key.clone_key())
                .unwrap();
                let mut cp = p.clone();
                cp.peer_certificate_rule = None;
                let to_host = tls::server_cert_verifier_builder(Arc::new(host.roots.clone()), &cp)?
                    .build()
                    .unwrap();
                let client = tls::client_builder(&cp)?
                    .dangerous()
                    .with_custom_certificate_verifier(to_host)
                    .with_client_auth_cert(client.chain.clone(), client.key.clone_key())
                    .unwrap();
                Ok((client, server))
            }

            fn server_side() -> rcgen::ExtendedKeyUsagePurpose {
                rcgen::ExtendedKeyUsagePurpose::ServerAuth
            }
            fn client_side() -> rcgen::ExtendedKeyUsagePurpose {
                rcgen::ExtendedKeyUsagePurpose::ClientAuth
            }

            #[test]
            fn a_matching_server_identity_completes_under_both_builders() {
                let pki = leaf(vec![uri(A)], server_side());
                for strict in [false, true] {
                    let check = ExactUri::new(A);
                    let (c, s) =
                        server_identity_configs(&policy(strict), &pki, &pki, Some(check.clone()))
                            .unwrap();
                    test_support::drive_typed(c, s).unwrap();
                    assert_eq!(check.calls(), 1, "strict={strict}");
                }
            }

            #[test]
            fn a_mismatched_server_identity_is_refused_with_the_checks_own_error() {
                let pki = leaf(vec![uri(B)], server_side());
                for strict in [false, true] {
                    let (c, s) = server_identity_configs(
                        &policy(strict),
                        &pki,
                        &pki,
                        Some(ExactUri::new(A)),
                    )
                    .unwrap();
                    let (by_server, error) = test_support::drive_typed(c, s).unwrap_err();
                    assert!(!by_server);
                    assert_eq!(error, refusal(A), "strict={strict}");
                }
            }

            #[test]
            fn the_identity_check_replaces_the_server_name_check() {
                let pki = leaf(
                    vec![
                        rcgen::SanType::DnsName("elsewhere.example".try_into().unwrap()),
                        uri(A),
                    ],
                    server_side(),
                );
                let (c, s) =
                    server_identity_configs(&policy(false), &pki, &pki, Some(ExactUri::new(A)))
                        .unwrap();
                test_support::drive_typed(c, s).unwrap();
                let (c, s) = server_identity_configs(&policy(false), &pki, &pki, None).unwrap();
                let (_, error) = test_support::drive_typed(c, s).unwrap_err();
                assert!(
                    matches!(
                        error,
                        rustls::Error::InvalidCertificate(
                            rustls::CertificateError::NotValidForName
                                | rustls::CertificateError::NotValidForNameContext { .. }
                        )
                    ),
                    "{error:?}"
                );
            }

            #[test]
            fn the_server_identity_check_is_never_reached_when_a_crate_check_fails() {
                let good = leaf(vec![uri(A)], server_side());
                let stranger = leaf(vec![uri(A)], server_side());
                let wrong_eku = leaf(vec![uri(A)], client_side());
                let revoked_leaf = test_support::identity_pki(
                    S::EcdsaP384Sha384,
                    vec![uri(A)],
                    vec![server_side()],
                    true,
                )
                .unwrap();
                let rsa = test_support::identity_pki(
                    S::Rsa2048Sha384,
                    vec![uri(A)],
                    vec![server_side()],
                    false,
                )
                .unwrap();
                let cases: [(
                    &str,
                    Policy,
                    &IdentityPki,
                    &IdentityPki,
                    fn(&rustls::Error) -> bool,
                ); 4] = [
                    (
                        "untrusted CA",
                        policy(false),
                        &stranger,
                        &good,
                        unknown_issuer,
                    ),
                    (
                        "no serverAuth EKU",
                        policy(false),
                        &wrong_eku,
                        &wrong_eku,
                        wrong_purpose,
                    ),
                    (
                        "revoked",
                        policy(false),
                        &revoked_leaf,
                        &revoked_leaf,
                        revoked,
                    ),
                    (
                        "cnsa1 rule refuses RSA-2048",
                        cnsa1_rsa(),
                        &rsa,
                        &rsa,
                        cnsa1_refuses_rsa_2048,
                    ),
                ];
                for (name, p, server, trust, expected) in cases {
                    let check = ExactUri::new(A);
                    let (c, s) =
                        server_identity_configs(&p, server, trust, Some(check.clone())).unwrap();
                    let (by_server, error) = test_support::drive_typed(c, s).unwrap_err();
                    assert!(!by_server, "{name}");
                    assert!(expected(&error), "{name}: {error:?}");
                    assert_eq!(check.calls(), 0, "{name}");
                }
            }

            #[test]
            fn the_client_identity_check_adds_to_the_crate_checks() {
                let host = host();
                let good = leaf(vec![uri(A)], client_side());
                for strict in [false, true] {
                    let check = ExactUri::new(A);
                    let (c, s) = client_identity_configs(
                        &policy(strict),
                        &host,
                        &good,
                        &good,
                        Some(check.clone()),
                    )
                    .unwrap();
                    test_support::drive_typed(c, s).unwrap();
                    assert_eq!(check.calls(), 1, "strict={strict}");
                }
                let other = leaf(vec![uri(B)], client_side());
                let (c, s) = client_identity_configs(
                    &policy(true),
                    &host,
                    &other,
                    &other,
                    Some(ExactUri::new(A)),
                )
                .unwrap();
                let (by_server, error) = test_support::drive_typed(c, s).unwrap_err();
                assert!(by_server);
                assert_eq!(error, refusal(A));
                let stranger = leaf(vec![uri(A)], client_side());
                let wrong_eku = leaf(vec![uri(A)], server_side());
                let revoked_leaf = test_support::identity_pki(
                    S::EcdsaP384Sha384,
                    vec![uri(A)],
                    vec![client_side()],
                    true,
                )
                .unwrap();
                let rsa = test_support::identity_pki(
                    S::Rsa2048Sha384,
                    vec![uri(A)],
                    vec![client_side()],
                    false,
                )
                .unwrap();
                let cases: [(
                    &str,
                    Policy,
                    &IdentityPki,
                    &IdentityPki,
                    fn(&rustls::Error) -> bool,
                ); 4] = [
                    (
                        "untrusted CA",
                        policy(false),
                        &stranger,
                        &good,
                        unknown_issuer,
                    ),
                    (
                        "no clientAuth EKU",
                        policy(false),
                        &wrong_eku,
                        &wrong_eku,
                        wrong_purpose,
                    ),
                    (
                        "revoked",
                        policy(false),
                        &revoked_leaf,
                        &revoked_leaf,
                        revoked,
                    ),
                    (
                        "cnsa1 rule refuses RSA-2048, strict server",
                        cnsa1_rsa(),
                        &rsa,
                        &rsa,
                        cnsa1_refuses_rsa_2048,
                    ),
                ];
                for (name, p, client, trust, expected) in cases {
                    let check = ExactUri::new(A);
                    let (c, s) =
                        client_identity_configs(&p, &host, client, trust, Some(check.clone()))
                            .unwrap();
                    let (by_server, error) = test_support::drive_typed(c, s).unwrap_err();
                    assert!(by_server, "{name}");
                    assert!(expected(&error), "{name}: {error:?}");
                    assert_eq!(check.calls(), 0, "{name}");
                }
            }

            #[test]
            fn identity_bearing_handles_meet_the_strict_builders_as_identity_free_ones_do() {
                let pki = leaf(vec![uri(A)], server_side());
                let strict = policy(true);
                let mut wider = strict.clone();
                wider.signature_schemes = vec![T::EcdsaNistp384Sha384, T::EcdsaNistp256Sha256];
                let server = tls::server_cert_verifier_builder(Arc::new(pki.roots.clone()), &wider)
                    .unwrap()
                    .with_peer_identity(ExactUri::new(A))
                    .build()
                    .unwrap();
                assert!(matches!(
                    tls::strict_client_builder(&strict, server).err(),
                    Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier { .. }))
                ));
                let client = tls::client_cert_verifier_builder(Arc::new(pki.roots.clone()), &wider)
                    .unwrap()
                    .with_peer_identity(ExactUri::new(A))
                    .build()
                    .unwrap();
                assert!(matches!(
                    tls::strict_server_builder(&strict, client).err(),
                    Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier { .. }))
                ));
                let server =
                    tls::server_cert_verifier_builder(Arc::new(pki.roots.clone()), &strict)
                        .unwrap()
                        .with_peer_identity(ExactUri::new(A))
                        .build()
                        .unwrap();
                assert!(tls::strict_client_builder(&strict, server).is_ok());
                let client =
                    tls::client_cert_verifier_builder(Arc::new(pki.roots.clone()), &strict)
                        .unwrap()
                        .with_peer_identity(ExactUri::new(A))
                        .build()
                        .unwrap();
                assert!(tls::strict_server_builder(&strict, client).is_ok());
            }

            #[test]
            fn a_second_identity_check_replaces_the_first() {
                let pki = leaf(vec![uri(A)], server_side());
                let first = ExactUri::new(B);
                let second = ExactUri::new(A);
                let verifier =
                    tls::server_cert_verifier_builder(Arc::new(pki.roots.clone()), &policy(false))
                        .unwrap()
                        .with_peer_identity(first.clone())
                        .with_peer_identity(second.clone())
                        .build()
                        .unwrap();
                let client = tls::client_builder(&policy(false))
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth();
                let (_, server) =
                    server_identity_configs(&policy(false), &pki, &pki, None).unwrap();
                test_support::drive_typed(client, server).unwrap();
                assert_eq!((first.calls(), second.calls()), (0, 1));
            }
        }
    };
}
