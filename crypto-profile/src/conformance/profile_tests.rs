/// The profile tests that `conformance_tests!` expands.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_profile_tests {
    ($b:ident) => {
        mod peer_certificates {
            $crate::__conformance_peer_certificate_tests!($b);
        }
        use std::sync::Arc;
        use $b::signature::KeyPair;
        use $b::test_support::{Negotiated, handshake, handshake_certified, handshake_with_ca};
        use $b::tls::{Policy, client_builder, server_builder};
        use $b::*;
        use $b::{
            CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
            TlsVersion as V,
        };
        use $crate::conformance::golden::{GOLDEN, expected};
        use $crate::conformance::{__peer_schemes, __unlisted_key};

        const PQ: Options = Options {
            peer_certificates_match_profile: false,
            pq_key_exchange_required: true,
        };
        const NO_GROUP: &str = "peer is incompatible: NoKxGroupsInCommon";
        const NO_SUITE: &str = "peer is incompatible: NoCipherSuitesInCommon";
        const NO_SCHEME: &str = "peer is incompatible: NoSignatureSchemesInCommon";
        const NO_TLS12: &str = "peer is incompatible: Tls12NotOfferedOrEnabled";
        const PKCS1: [u16; 3] = [0x0401, 0x0501, 0x0601];

        fn err<X>(s: &str) -> Result<X, String> {
            Err(s.to_string())
        }

        fn peer(v: V, c: C, k: &[K]) -> Policy {
            Policy {
                peer_certificate_rule: None,
                versions: vec![v],
                cipher_suites: vec![c],
                kx_groups: k.to_vec(),
                signature_schemes: __peer_schemes(MODULE),
            }
        }

        fn tls13(k: &[K]) -> Policy {
            peer(V::Tls13, C::Tls13Aes256GcmSha384, k)
        }

        fn tls12() -> Policy {
            peer(V::Tls12, C::Tls12EcdheEcdsaAes256GcmSha384, &[K::Secp384r1])
        }

        fn served(
            client: &Policy,
            server: &Resolved,
            pick: fn(Negotiated) -> u16,
        ) -> Result<u16, String> {
            let key = if server.keys.contains(&S::EcdsaP384Sha384) {
                S::EcdsaP384Sha384
            } else {
                server.keys[0]
            };
            handshake_certified(client, server, key).map(pick)
        }

        fn pkcs1(client: &Resolved, v: V) -> Policy {
            Policy {
                versions: client
                    .tls
                    .versions
                    .iter()
                    .copied()
                    .filter(|x| *x == v)
                    .collect(),
                signature_schemes: client
                    .tls
                    .signature_schemes
                    .iter()
                    .copied()
                    .filter(|t| PKCS1.contains(&t.iana()))
                    .collect(),
                ..client.tls.clone()
            }
        }

        fn has_pkcs1(r: &Resolved) -> bool {
            r.tls
                .signature_schemes
                .iter()
                .any(|t| PKCS1.contains(&t.iana()))
        }

        fn admitted(p: Profile, o: Options) -> Option<Resolved> {
            match (resolve(p, o), expected(MODULE, p, o)) {
                (Ok(r), Ok(_)) => Some(r),
                (got, want) => {
                    assert_eq!(got.err(), want.err(), "{p} {o}");
                    None
                }
            }
        }

        fn open_peer() -> Resolved {
            let s = Profile::Unrestricted.spec();
            let on = |a: Algorithm| capability(MODULE, a).available;
            Resolved {
                profile: Profile::Unrestricted,
                options: Options::default(),
                excluded: expected(MODULE, Profile::Unrestricted, Options::default())
                    .unwrap()
                    .excluded
                    .to_vec(),
                tls: Policy {
                    peer_certificate_rule: None,
                    versions: s
                        .versions
                        .iter()
                        .copied()
                        .filter(|x| on(Algorithm::Protocol(*x)))
                        .collect(),
                    cipher_suites: s
                        .cipher_suites
                        .iter()
                        .copied()
                        .filter(|x| on(Algorithm::Cipher(*x)))
                        .collect(),
                    kx_groups: s
                        .kx_groups
                        .iter()
                        .copied()
                        .filter(|x| on(Algorithm::Kx(*x)))
                        .collect(),
                    signature_schemes: s
                        .signature_schemes
                        .iter()
                        .copied()
                        .filter(|x| on(Algorithm::Scheme(*x)))
                        .collect(),
                },
                keys: s
                    .key_algorithms
                    .iter()
                    .copied()
                    .filter(|x| on(Algorithm::Signature(*x)))
                    .collect(),
            }
        }

        fn verifies(client: &Policy, key: S) -> Result<u16, String> {
            handshake(client, &open_peer().tls, key).map(|n| n.scheme.iana())
        }

        #[test]
        fn the_open_peer_is_unrestricted_where_it_resolves() {
            if let Some(u) = admitted(Profile::Unrestricted, Options::default()) {
                assert_eq!(open_peer(), u);
            }
        }

        #[test]
        fn resolve_matches_the_golden_tables() {
            let (mut compared, mut refused) = (0, 0);
            for p in Profile::ALL {
                for pq in [false, true] {
                    let options = Options {
                        peer_certificates_match_profile: false,
                        pq_key_exchange_required: pq,
                    };
                    let got = resolve(p, options);
                    match expected(MODULE, p, options) {
                        Err(e) => {
                            assert_eq!(got, Err(e), "{p} {options}");
                            refused += 1;
                        }
                        Ok(g) => {
                            let r = got.expect("the profile resolves");
                            assert_eq!(
                                r.tls.versions.iter().map(|x| x.iana()).collect::<Vec<_>>(),
                                g.versions,
                                "{p} {options}"
                            );
                            assert_eq!(
                                r.tls
                                    .cipher_suites
                                    .iter()
                                    .map(|x| x.iana())
                                    .collect::<Vec<_>>(),
                                g.suites,
                                "{p} {options}"
                            );
                            assert_eq!(
                                r.tls.kx_groups.iter().map(|x| x.iana()).collect::<Vec<_>>(),
                                g.groups,
                                "{p} {options}"
                            );
                            assert_eq!(
                                r.tls
                                    .signature_schemes
                                    .iter()
                                    .map(|x| x.iana())
                                    .collect::<Vec<_>>(),
                                g.schemes,
                                "{p} {options}"
                            );
                            assert_eq!(
                                r.keys.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                                g.keys,
                                "{p} {options}"
                            );
                            assert_eq!(r.excluded, g.excluded, "{p} {options}");
                            compared += 1;
                        }
                    }
                }
            }
            assert_eq!(compared + refused, GOLDEN.len());
            assert_eq!(
                compared,
                GOLDEN
                    .iter()
                    .filter(|g| {
                        expected(
                            MODULE,
                            g.profile,
                            Options {
                                peer_certificates_match_profile: false,
                                pq_key_exchange_required: g.pq,
                            },
                        )
                        .is_ok()
                    })
                    .count()
            );
        }

        #[test]
        fn unrestricted_vs_fips1403() {
            let d = Options::default();
            let (u, f) = (
                admitted(Profile::Unrestricted, d),
                admitted(Profile::Fips1403, d),
            );
            let x25519 = tls13(&[K::X25519]);
            let chacha = peer(V::Tls13, C::Tls13Chacha20Poly1305Sha256, &[K::Secp384r1]);
            if let Some(u) = &u {
                assert_eq!(served(&x25519, u, |n| n.kx.iana()), Ok(0x001D));
                assert_eq!(served(&chacha, u, |n| n.suite.iana()), Ok(0x1303));
            }
            if let Some(f) = &f {
                assert_eq!(served(&x25519, f, |n| n.kx.iana()), err(NO_GROUP));
                assert_eq!(served(&chacha, f, |n| n.suite.iana()), err(NO_SUITE));
            }
        }

        #[test]
        fn fips1403_vs_fips1402() {
            let d = Options::default();
            let (a, b) = (
                admitted(Profile::Fips1403, d),
                admitted(Profile::Fips1402, d),
            );
            if let Some(a) = &a {
                for (group, cp) in [(K::MlKem1024, 0x0202), (K::X25519MlKem768, 0x11EC)] {
                    assert_eq!(served(&tls13(&[group]), a, |n| n.kx.iana()), Ok(cp));
                }
                assert_eq!(a.admit_key(S::Ed25519), Ok(()));
                if MODULE.line == ModuleLine::AwsLcFips4 {
                    assert_eq!(a.admit_key(S::MlDsa87), Ok(()));
                    assert_eq!(verifies(&a.tls, S::MlDsa87), Ok(0x0906));
                } else {
                    assert_eq!(
                        a.admit_key(S::MlDsa87),
                        Err(CryptoError::KeyNotInProfile {
                            profile: Profile::Fips1403,
                            algorithm: S::MlDsa87,
                        })
                    );
                    assert_eq!(
                        verifies(&a.tls, S::MlDsa87),
                        __unlisted_key(MODULE, S::MlDsa87, NO_SCHEME)
                    );
                }
                assert_eq!(verifies(&a.tls, S::Ed25519), Ok(0x0807));
            }
            if let Some(b) = &b {
                for (group, _) in [(K::MlKem1024, 0x0202), (K::X25519MlKem768, 0x11EC)] {
                    assert_eq!(served(&tls13(&[group]), b, |n| n.kx.iana()), err(NO_GROUP));
                }
                for key in [S::Ed25519, S::MlDsa87] {
                    assert_eq!(
                        b.admit_key(key),
                        Err(CryptoError::KeyNotInProfile {
                            profile: Profile::Fips1402,
                            algorithm: key
                        })
                    );
                }
                assert_eq!(
                    verifies(&b.tls, S::MlDsa87),
                    __unlisted_key(MODULE, S::MlDsa87, NO_SCHEME)
                );
                assert_eq!(verifies(&b.tls, S::Ed25519), err(NO_SCHEME));
            }
        }

        #[test]
        fn preferred_vs_fips1403() {
            let d = Options::default();
            let (p, f) = (
                admitted(Profile::Preferred, d),
                admitted(Profile::Fips1403, d),
            );
            if let Some(f) = &f {
                assert_eq!(served(&tls12(), f, |n| n.version.iana()), Ok(0x0303));
                assert_eq!(verifies(&f.tls, S::Ed25519), Ok(0x0807));
                for key in [S::Ed25519, S::Rsa2048Sha384] {
                    assert_eq!(f.admit_key(key), Ok(()));
                }
                assert_eq!(verifies(&pkcs1(f, V::Tls12), S::Rsa3072Sha384), Ok(0x0601));
            }
            if let Some(p) = &p {
                assert_eq!(served(&tls12(), p, |n| n.version.iana()), err(NO_TLS12));
                assert_eq!(verifies(&p.tls, S::Ed25519), err(NO_SCHEME));
                for key in [S::Ed25519, S::Rsa2048Sha384] {
                    assert_eq!(
                        p.admit_key(key),
                        Err(CryptoError::KeyNotInProfile {
                            profile: Profile::Preferred,
                            algorithm: key
                        })
                    );
                }
                assert!(!has_pkcs1(p));
            }
        }

        #[test]
        fn cnsa2_vs_cnsa1() {
            let d = Options::default();
            let (two, one) = (admitted(Profile::Cnsa2, d), admitted(Profile::Cnsa1, d));
            let mlkem = tls13(&[K::MlKem1024]);
            let p384 = tls13(&[K::Secp384r1]);
            if let Some(two) = &two {
                assert_eq!(served(&mlkem, two, |n| n.kx.iana()), Ok(0x0202));
                assert_eq!(served(&p384, two, |n| n.kx.iana()), err(NO_GROUP));
                assert_eq!(verifies(&two.tls, S::MlDsa87), Ok(0x0906));
                assert_eq!(two.admit_key(S::MlDsa87), Ok(()));
                assert_eq!(served(&tls12(), two, |n| n.version.iana()), err(NO_TLS12));
            }
            if let Some(one) = &one {
                assert_eq!(served(&mlkem, one, |n| n.kx.iana()), err(NO_GROUP));
                assert_eq!(served(&p384, one, |n| n.kx.iana()), Ok(0x0018));
                assert_eq!(
                    verifies(&one.tls, S::MlDsa87),
                    __unlisted_key(MODULE, S::MlDsa87, NO_SCHEME)
                );
                assert_eq!(
                    one.admit_key(S::MlDsa87),
                    Err(CryptoError::KeyNotInProfile {
                        profile: Profile::Cnsa1,
                        algorithm: S::MlDsa87
                    })
                );
                assert_eq!(served(&tls12(), one, |n| n.version.iana()), Ok(0x0303));
            }
        }

        #[test]
        fn cnsa1_vs_fips1402() {
            let d = Options::default();
            let (one, f) = (admitted(Profile::Cnsa1, d), admitted(Profile::Fips1402, d));
            let p256 = tls13(&[K::Secp256r1]);
            let aes128 = peer(V::Tls13, C::Tls13Aes128GcmSha256, &[K::Secp384r1]);
            if let Some(f) = &f {
                assert_eq!(served(&p256, f, |n| n.kx.iana()), Ok(0x0017));
                assert_eq!(served(&aes128, f, |n| n.suite.iana()), Ok(0x1301));
                assert_eq!(f.admit_key(S::Rsa2048Sha384), Ok(()));
            }
            if let Some(one) = &one {
                assert_eq!(served(&p256, one, |n| n.kx.iana()), err(NO_GROUP));
                assert_eq!(served(&aes128, one, |n| n.suite.iana()), err(NO_SUITE));
                assert_eq!(
                    one.admit_key(S::Rsa2048Sha384),
                    Err(CryptoError::KeyNotInProfile {
                        profile: Profile::Cnsa1,
                        algorithm: S::Rsa2048Sha384
                    })
                );
                assert_eq!(
                    verifies(&pkcs1(one, V::Tls12), S::Rsa3072Sha384),
                    Ok(0x0501)
                );
            }
        }

        #[test]
        fn bsi_vs_fips1402() {
            let d = Options::default();
            let (b, f) = (admitted(Profile::Bsi, d), admitted(Profile::Fips1402, d));
            if let Some(f) = &f {
                assert_eq!(f.admit_key(S::Rsa3072Sha384), Ok(()));
                assert_eq!(verifies(&pkcs1(f, V::Tls12), S::Rsa3072Sha384), Ok(0x0601));
                assert!(has_pkcs1(f));
            }
            if let Some(b) = &b {
                assert_eq!(
                    b.admit_key(S::Rsa3072Sha384),
                    Err(CryptoError::KeyNotInProfile {
                        profile: Profile::Bsi,
                        algorithm: S::Rsa3072Sha384
                    })
                );
                assert!(!has_pkcs1(b));
            }
        }

        #[test]
        fn bsi_vs_preferred() {
            let d = Options::default();
            let (b, p) = (admitted(Profile::Bsi, d), admitted(Profile::Preferred, d));
            let hybrid = tls13(&[K::X25519MlKem768]);
            if let Some(b) = &b {
                assert_eq!(served(&tls12(), b, |n| n.version.iana()), Ok(0x0303));
                assert_eq!(served(&hybrid, b, |n| n.kx.iana()), err(NO_GROUP));
                assert_eq!(
                    verifies(&b.tls, S::MlDsa87),
                    __unlisted_key(MODULE, S::MlDsa87, NO_SCHEME)
                );
                assert_eq!(
                    b.admit_key(S::MlDsa87),
                    Err(CryptoError::KeyNotInProfile {
                        profile: Profile::Bsi,
                        algorithm: S::MlDsa87
                    })
                );
            }
            if let Some(p) = &p {
                assert_eq!(served(&tls12(), p, |n| n.version.iana()), err(NO_TLS12));
                assert_eq!(served(&hybrid, p, |n| n.kx.iana()), Ok(0x11EC));
                if MODULE.line == ModuleLine::AwsLcFips4 {
                    assert_eq!(verifies(&p.tls, S::MlDsa87), Ok(0x0906));
                    assert_eq!(p.admit_key(S::MlDsa87), Ok(()));
                } else {
                    assert_eq!(
                        verifies(&p.tls, S::MlDsa87),
                        __unlisted_key(MODULE, S::MlDsa87, NO_SCHEME)
                    );
                    assert_eq!(
                        p.admit_key(S::MlDsa87),
                        Err(CryptoError::KeyNotInProfile {
                            profile: Profile::Preferred,
                            algorithm: S::MlDsa87,
                        })
                    );
                }
            }
        }

        #[test]
        fn a_tls13_pkcs1_only_policy_is_refused_at_build() {
            if let Some(f) = admitted(Profile::Fips1403, Options::default()) {
                assert_eq!(
                    tls::crypto_provider(&pkcs1(&f, V::Tls13)).err(),
                    Some(CryptoError::PolicyVersionUnusable {
                        version: V::Tls13,
                        family: Family::SignatureScheme
                    })
                );
            }
        }

        #[test]
        fn every_resolved_profile_builds_a_provider() {
            for p in Profile::ALL {
                for o in [Options::default(), PQ] {
                    if let Some(r) = admitted(p, o) {
                        assert_eq!(tls::crypto_provider(&r.tls).err(), None, "{p} {o}");
                    }
                }
            }
        }

        #[test]
        fn preferred_with_the_option_refuses_a_classical_only_peer() {
            if let Some(p) = admitted(Profile::Preferred, PQ) {
                let classical = tls13(&[K::Secp384r1, K::Secp256r1, K::X25519]);
                assert_eq!(served(&classical, &p, |n| n.kx.iana()), err(NO_GROUP));
                let hybrid = tls13(&[K::Secp256r1MlKem768]);
                assert_eq!(served(&hybrid, &p, |n| n.kx.iana()), Ok(0x11EB));
            }
        }

        #[test]
        fn cnsa2_with_the_option_is_cnsa2() {
            let (a, b) = (
                admitted(Profile::Cnsa2, Options::default()),
                admitted(Profile::Cnsa2, PQ),
            );
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!((a.tls, a.keys), (b.tls, b.keys));
            }
        }

        #[test]
        fn the_option_refuses_a_tls12_peer() {
            if let Some(f) = admitted(Profile::Fips1403, PQ) {
                assert_eq!(served(&tls12(), &f, |n| n.version.iana()), err(NO_TLS12));
            }
        }

        #[test]
        fn the_option_removes_the_pkcs1_schemes() {
            for p in [Profile::Unrestricted, Profile::Fips1403] {
                if let Some(r) = admitted(p, Options::default()) {
                    assert!(has_pkcs1(&r), "{p}");
                }
                if let Some(r) = admitted(p, PQ) {
                    assert!(!has_pkcs1(&r), "{p}");
                }
            }
        }

        #[test]
        fn profiles_mix_per_connection_in_one_process() {
            let d = Options::default();
            let (p, f) = (
                admitted(Profile::Preferred, d),
                admitted(Profile::Fips1402, d),
            );
            let cp = |n: Negotiated| {
                (
                    n.version.iana(),
                    n.suite.iana(),
                    n.kx.iana(),
                    n.scheme.iana(),
                )
            };
            std::thread::scope(|s| {
                let a = p
                    .as_ref()
                    .zip(f.as_ref())
                    .map(|(p, f)| s.spawn(move || handshake(&f.tls, &p.tls, S::EcdsaP384Sha384)));
                let b = f
                    .as_ref()
                    .map(|f| s.spawn(move || handshake(&f.tls, &f.tls, S::Rsa3072Sha384)));
                let c = p
                    .as_ref()
                    .map(|p| s.spawn(move || handshake(&p.tls, &p.tls, S::MlDsa87)));
                if let Some(a) = a {
                    assert_eq!(
                        a.join().unwrap().map(cp),
                        Ok((0x0304, 0x1302, 0x0018, 0x0503))
                    );
                }
                if let Some(b) = b {
                    assert_eq!(
                        b.join().unwrap().map(cp),
                        Ok((0x0304, 0x1302, 0x0018, 0x0806))
                    );
                }
                if let Some(c) = c {
                    assert_eq!(
                        c.join().unwrap().map(cp),
                        if MODULE.line == ModuleLine::AwsLcFips4 {
                            Ok((0x0304, 0x1302, 0x0202, 0x0906))
                        } else {
                            Err(CryptoError::Unavailable(Algorithm::Signature(S::MlDsa87))
                                .to_string())
                        }
                    );
                }
            });
        }

        #[test]
        fn rustls_classifies_every_profile_but_unrestricted_as_fips() {
            for p in Profile::ALL {
                let Some(r) = admitted(p, Options::default()) else {
                    continue;
                };
                let fips = match p {
                    Profile::Unrestricted => false,
                    Profile::Preferred
                    | Profile::Cnsa2
                    | Profile::Cnsa1
                    | Profile::Bsi
                    | Profile::Fips1403
                    | Profile::Fips1402 => true,
                };
                let cfg = client_builder(&r.tls)
                    .unwrap()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth();
                assert_eq!((cfg.fips(), cfg.require_ems), (fips, fips), "{p}");
                assert_eq!(
                    $b::fips::assert_fips_client_config(&cfg).is_ok(),
                    fips,
                    "{p}"
                );
                let srv = server_builder(&r.tls)
                    .unwrap()
                    .with_no_client_auth()
                    .with_cert_resolver(
                        Arc::new(rustls::server::ResolvesServerCertUsingSni::new()),
                    );
                assert_eq!((srv.fips(), srv.require_ems), (fips, fips), "{p}");
                assert_eq!(
                    $b::fips::assert_fips_server_config(&srv).is_ok(),
                    fips,
                    "{p}"
                );
            }
        }

        #[test]
        fn a_profile_does_not_restrict_the_chain_signature() {
            if let Some(f) = admitted(Profile::Fips1402, Options::default()) {
                let n = handshake_with_ca(&f.tls, &open_peer().tls, S::Ed25519, S::EcdsaP384Sha384)
                    .unwrap();
                assert_eq!(n.scheme.iana(), 0x0503);
            }
        }

        #[test]
        fn cnsa1_signs_only_with_a_scheme_it_lists() {
            let one = admitted(Profile::Cnsa1, Options::default());
            let permissive = Policy {
                signature_schemes: vec![T::RsaPssSha512, T::RsaPssSha384],
                ..tls13(&[K::Secp384r1])
            };
            let outside = Policy {
                signature_schemes: vec![T::RsaPssSha512, T::RsaPssSha256],
                ..tls13(&[K::Secp384r1])
            };
            let scheme = |client: &Policy, server: &Policy| {
                handshake(client, server, S::Rsa3072Sha384).map(|n| n.scheme.iana())
            };
            if let Some(one) = &one {
                assert_eq!(scheme(&permissive, &one.tls), Ok(0x0805));
                assert_eq!(scheme(&outside, &one.tls), err(NO_SCHEME));
            }
            assert_eq!(scheme(&outside, &open_peer().tls), Ok(0x0806));
        }

        #[test]
        fn a_certified_key_signs_only_with_a_scheme_the_profile_lists() {
            let one = admitted(Profile::Cnsa1, Options::default());
            let permissive = Policy {
                signature_schemes: vec![T::RsaPssSha512, T::RsaPssSha384],
                ..tls13(&[K::Secp384r1])
            };
            let outside = Policy {
                signature_schemes: vec![T::RsaPssSha512, T::RsaPssSha256],
                ..tls13(&[K::Secp384r1])
            };
            let scheme = |client: &Policy, server: &Resolved| {
                handshake_certified(client, server, S::Rsa3072Sha384).map(|n| n.scheme.iana())
            };
            if let Some(one) = &one {
                assert_eq!(scheme(&permissive, one), Ok(0x0805));
                assert_eq!(scheme(&outside, one), err(NO_SCHEME));
            }
            assert_eq!(scheme(&outside, &open_peer()), Ok(0x0806));
        }

        #[test]
        fn certified_key_refuses_a_key_the_profile_does_not_admit() -> Result<(), CryptoError> {
            let d = Options::default();
            let key = KeyPair::generate(S::EcdsaP384Sha384)?;
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let chain = vec![cert.der().clone()];
            if let Some(two) = admitted(Profile::Cnsa2, d) {
                assert_eq!(
                    two.certified_key(chain.clone(), &key).err(),
                    Some(CryptoError::KeyNotInProfile {
                        profile: Profile::Cnsa2,
                        algorithm: S::EcdsaP384Sha384
                    })
                );
            }
            if let Some(one) = admitted(Profile::Cnsa1, d) {
                assert!(one.certified_key(chain.clone(), &key).is_ok());
                let other = KeyPair::generate(S::EcdsaP384Sha384)?;
                for c in [chain, vec![]] {
                    assert_eq!(
                        one.certified_key(c, &other).err(),
                        Some(CryptoError::Tls(TlsError::KeyMismatch))
                    );
                }
            }
            Ok(())
        }
    };
}
