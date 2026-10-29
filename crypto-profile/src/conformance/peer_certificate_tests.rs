/// Peer-certificate conformance cases instantiated by every backend.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_peer_certificate_tests {
    ($b:ident) => {
        use std::sync::Arc;
        use $b::*;
        use $b::{KxGroup as K, SignatureAlgorithm as S,
            TlsSignatureScheme as T, TlsVersion as V, Profile as P,
            PeerCertificateViolation as E, PeerKey as Key, PeerCurve as EC,
            CertificateSignature as CS, HashAlgorithm as H, MlDsaParameterSet as ML};
        use $b::tls::{self, Policy};
        use $b::test_support::{self, PeerCertificatePki, PeerCertificateFixture as F};

        fn certificate_policy(profile: P, strict: bool, version: V, scheme: T) -> Policy {
            let mut policy = resolve(profile, Options {
                peer_certificates_match_profile: strict,
                ..Options::default()
            }).unwrap().tls;
            policy.versions = vec![version];
            policy.cipher_suites.retain(|suite| suite.version() == version);
            policy.kx_groups = vec![K::Secp384r1];
            assert!(policy.signature_schemes.contains(&scheme), "{profile:?}: {scheme:?}");
            policy.signature_schemes = vec![scheme];
            policy
        }

        fn assert_peer_certificate_refusal(error: rustls::Error, profile: P, violation: E) {
            let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                rustls::OtherError(cause))) = error else {
                panic!("missing typed certificate refusal: {error:?}");
            };
            assert_eq!(cause.downcast_ref::<TlsError>(),
                Some(&TlsError::PeerCertificate { profile, violation }));
        }

        fn certificate_case(pki: &PeerCertificatePki, profile: P, version: V,
            scheme: T, violation: Option<E>) {
            for direction in [false, true] {
                for strict in [false, true] {
                    let policy = certificate_policy(profile, strict, version, scheme);
                    let (client, server) = test_support::peer_certificate_configs(
                        &policy, direction, pki).unwrap();
                    let result = test_support::drive_typed(client, server);
                    if let Some(expected) = violation.filter(|_| strict) {
                        let (detector, error) = result.unwrap_err();
                        assert_eq!(detector, direction);
                        assert_peer_certificate_refusal(error, profile, expected);
                    } else {
                        result.unwrap_or_else(|error| panic!(
                            "{profile:?}/{version:?}/server_checks_client={direction}/strict={strict}: {error:?}"));
                    }
                }
            }
        }

        #[test]
        fn peer_certificate_default_session_isolation() {
            fn connect(client: Arc<rustls::ClientConfig>, server: Arc<rustls::ServerConfig>) -> Result<rustls::HandshakeKind, rustls::Error> {
                let mut c = rustls::ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
                let mut s = rustls::ServerConnection::new(server).unwrap();
                for _flight in 0..100 {
                    let mut wire = Vec::new();
                    c.write_tls(&mut wire).unwrap();
                    s.read_tls(&mut wire.as_slice()).unwrap();
                    s.process_new_packets()?;
                    wire.clear();
                    s.write_tls(&mut wire).unwrap();
                    c.read_tls(&mut wire.as_slice()).unwrap();
                    c.process_new_packets()?;
                    if !c.is_handshaking() && !s.is_handshaking() {
                        return Ok(s.handshake_kind().unwrap());
                    }
                }
                panic!("resumption handshake stalled");
            }
            for version in [V::Tls12, V::Tls13] {
                let pki = issued(S::Rsa3072Sha384, None, S::Rsa2048Sha384);
                let permissive = certificate_policy(P::Cnsa1, false, version, T::RsaPssSha384);
                let strict = certificate_policy(P::Cnsa1, true, version, T::RsaPssSha384);
                let (client, server) = test_support::peer_certificate_default_session_configs(&permissive, true, &pki).unwrap();
                let client = Arc::new(client);
                let server = Arc::new(server);
                assert_eq!(connect(client.clone(), server.clone()).unwrap(), rustls::HandshakeKind::Full);
                assert_eq!(connect(client.clone(), server).unwrap(), rustls::HandshakeKind::Resumed);
                let (_, strict_server) = test_support::peer_certificate_default_session_configs(&strict, true, &pki).unwrap();
                assert_peer_certificate_refusal(connect(client, Arc::new(strict_server)).unwrap_err(), P::Cnsa1, E::LeafKey(Key::Rsa(2048)));
                let compliant = issued(S::Rsa3072Sha384, None, S::Rsa3072Sha384);
                let (client, server) = test_support::peer_certificate_default_session_configs(&strict, true, &compliant).unwrap();
                let client = Arc::new(client);
                let server = Arc::new(server);
                assert_eq!(connect(client.clone(), server.clone()).unwrap(), rustls::HandshakeKind::Full);
                assert_eq!(connect(client, server).unwrap(), rustls::HandshakeKind::Resumed);
            }
        }

        fn issued(root: S, intermediate: Option<S>, leaf: S) -> PeerCertificatePki {
            test_support::peer_certificate_pki(root, intermediate, leaf).unwrap()
        }
        #[test]
        fn peer_certificate_cnsa1_rsa2048_tls12() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa2048Sha384),
                P::Cnsa1, V::Tls12, T::RsaPssSha384, Some(E::LeafKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_cnsa1_rsa2048_tls13() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa2048Sha384),
                P::Cnsa1, V::Tls13, T::RsaPssSha384, Some(E::LeafKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_cnsa1_p384() {
            certificate_case(&issued(S::EcdsaP384Sha384, None, S::EcdsaP384Sha384),
                P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, None);
        }
        #[test]
        fn peer_certificate_preferred_larger_rsa() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa4096Sha384),
                P::Preferred, V::Tls13, T::RsaPssSha384, None);
        }
        #[test]
        fn peer_certificate_preferred_small_rsa() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa2048Sha384),
                P::Preferred, V::Tls13, T::RsaPssSha384, Some(E::LeafKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_bsi_larger_rsa() {
            certificate_case(&issued(S::EcdsaP384Sha384, None, S::Rsa4096Sha384),
                P::Bsi, V::Tls13, T::RsaPssSha384, None);
        }
        #[test]
        fn peer_certificate_bsi_small_rsa() {
            certificate_case(&issued(S::EcdsaP384Sha384, None, S::Rsa2048Sha384),
                P::Bsi, V::Tls13, T::RsaPssSha384, Some(E::LeafKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_bsi_pkcs1_retired() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::EcdsaP384Sha384),
                P::Bsi, V::Tls13, T::EcdsaNistp384Sha384, Some(E::ChainSignature(CS::RsaPkcs1(H::Sha384))));
        }
        #[test]
        fn peer_certificate_cnsa1_small_intermediate() {
            certificate_case(&issued(S::Rsa3072Sha384, Some(S::Rsa2048Sha384), S::EcdsaP384Sha384),
                P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, Some(E::IssuerKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_cnsa1_pkcs1_tls12() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa3072Sha384),
                P::Cnsa1, V::Tls12, T::RsaPssSha384, None);
        }
        #[test]
        fn peer_certificate_cnsa1_pkcs1_tls13() {
            certificate_case(&issued(S::Rsa3072Sha384, None, S::Rsa3072Sha384),
                P::Cnsa1, V::Tls13, T::RsaPssSha384, None);
        }
        #[test]
        fn peer_certificate_cnsa1_small_anchor() {
            certificate_case(&issued(S::Rsa2048Sha384, None, S::EcdsaP384Sha384),
                P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, Some(E::IssuerKey(Key::Rsa(2048))));
        }
        #[test]
        fn peer_certificate_cnsa1_p256_ca() {
            certificate_case(&issued(S::EcdsaP256Sha256, None, S::EcdsaP384Sha384),
                P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, Some(E::ChainSignature(CS::Ecdsa(EC::P256,H::Sha256))));
        }
        #[test]
        fn peer_certificate_unrestricted_ed25519() {
            certificate_case(&issued(S::Ed25519, None, S::Ed25519),
                P::Unrestricted, V::Tls13, T::Ed25519, None);
        }
        #[test]
        fn peer_certificate_fips1403_ed25519_updated() {
            certificate_case(&issued(S::Ed25519, None, S::Ed25519),
                P::Fips1403, V::Tls13, T::Ed25519, None);
        }
        #[test]
        fn peer_certificate_fips1402_ed25519_chain() {
            certificate_case(&issued(S::Ed25519, None, S::EcdsaP384Sha384),
                P::Fips1402, V::Tls13, T::EcdsaNistp384Sha384, Some(E::ChainSignature(CS::Ed25519)));
        }
        #[test]
        fn peer_certificate_preferred_ed25519_chain() {
            certificate_case(&issued(S::Ed25519, None, S::EcdsaP384Sha384),
                P::Preferred, V::Tls13, T::EcdsaNistp384Sha384, Some(E::ChainSignature(CS::Ed25519)));
        }
        #[test]
        fn peer_certificate_fips1402_rsa2048() {
            certificate_case(&issued(S::Rsa2048Sha384, None, S::Rsa2048Sha384),
                P::Fips1402, V::Tls13, T::RsaPssSha384, None);
        }
        #[test]
        fn peer_certificate_rsa8192() {
            let pki = test_support::peer_certificate_fixture(F::Rsa8192Leaf).unwrap();
            certificate_case(&pki, P::Cnsa1, V::Tls13, T::RsaPssSha384, Some(E::LeafKey(Key::Rsa(8192))));
        }
        #[test]
        fn peer_certificate_root_self_signature() {
            let pki = test_support::peer_certificate_fixture(F::RootSha256).unwrap();
            certificate_case(&pki, P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, None);
        }
        #[test]
        fn peer_certificate_sha256_crl() {
            let pki = test_support::peer_certificate_fixture(F::Sha256Crl).unwrap();
            certificate_case(&pki, P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, None);
        }
        #[test]
        fn peer_certificate_selected_bad_path() {
            let pki = test_support::peer_certificate_fixture(F::SelectedBadPath).unwrap();
            certificate_case(&pki, P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, Some(E::ChainSignature(CS::Ecdsa(EC::P256,H::Sha256))));
        }
        #[test]
        fn peer_certificate_selected_good_path() {
            let pki = test_support::peer_certificate_fixture(F::SelectedGoodPath).unwrap();
            certificate_case(&pki, P::Cnsa1, V::Tls13, T::EcdsaNistp384Sha384, None);
        }
        #[test]
        fn peer_certificate_cnsa2_classical_ca_and_pure_chain() {
            if MODULE.line == ModuleLine::AwsLcFips3 {
                for strict in [false, true] {
                    let options = Options { peer_certificates_match_profile: strict,
                        ..Options::default() };
                    assert_eq!(resolve(P::Cnsa2, options).err(), Some(CryptoError::EmptyProfile {
                        profile: P::Cnsa2, options, category: Family::SignatureScheme }));
                }
                assert_eq!(signature::KeyPair::generate(S::MlDsa87).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(S::MlDsa87))));
                return;
            }
            for (ca, expected) in [(S::EcdsaP384Sha384,
                Some(E::ChainSignature(CS::Ecdsa(EC::P384,H::Sha384)))), (S::MlDsa87, None)] {
                certificate_case(&issued(ca, None, S::MlDsa87), P::Cnsa2,
                    V::Tls13, T::MlDsa87, expected);
            }
        }

        #[test]
        fn peer_certificate_preferred_and_fips_ml_dsa_rules() {
            if MODULE.line == ModuleLine::AwsLcFips3 {
                assert!(!capability(MODULE, Algorithm::Signature(S::MlDsa87)).available);
                return;
            }
            for (profile, expected) in [(P::Preferred,
                Some(E::ChainSignature(CS::MlDsa(ML::MlDsa87)))),
                (P::Unrestricted, None), (P::Fips1403, None)] {
                certificate_case(&issued(S::MlDsa87,None,S::MlDsa87), profile,
                    V::Tls13,T::MlDsa87,expected);
            }
        }

        #[test]
        fn peer_certificate_other_ml_parameter_sets() {
            use rustls::client::danger::ServerCertVerifier;
            use rustls::server::danger::ClientCertVerifier;
            let algorithms: Vec<(&'static rcgen::SignatureAlgorithm, ML)> = $crate::__conformance_peer_ml_algorithms!($b);
            assert_eq!(algorithms.len(), if MODULE.line == ModuleLine::AwsLcFips3 { 0 } else { 2 });
            if MODULE.line == ModuleLine::AwsLcFips3 {
                assert_eq!(signature::KeyPair::generate(S::MlDsa87).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(S::MlDsa87))));
            }
            for (algorithm, parameter) in algorithms {
                let generated = rcgen::KeyPair::generate_for(algorithm);
                let key = generated.unwrap();
                let root = signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
                let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let ca = params.self_signed(&root).unwrap();
                let issuer = rcgen::Issuer::new(params, &root);
                let leaf = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap()
                    .signed_by(&key, &issuer).unwrap();
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.der().clone()).unwrap();
                for profile in [P::Unrestricted,P::Preferred,P::Fips1403,P::Fips1402,P::Bsi,P::Cnsa1,P::Cnsa2] {
                    for strict in [false,true] {
                        let policy = resolve(profile,Options { peer_certificates_match_profile: strict,
                            ..Options::default() }).unwrap().tls;
                        let cv = tls::server_cert_verifier_builder(Arc::new(roots.clone()),&policy).unwrap().build().unwrap();
                        let sv = tls::client_cert_verifier_builder(Arc::new(roots.clone()),&policy).unwrap().build().unwrap();
                        let now = rustls::pki_types::UnixTime::now();
                        let name = "localhost".try_into().unwrap();
                        let results = [cv.verify_server_cert(leaf.der(), &[], &name, &[], now).map(|_| ()),
                            sv.verify_client_cert(leaf.der(), &[], now).map(|_| ())];
                        for result in results {
                            if strict && !(profile == P::Preferred && parameter == ML::MlDsa65) {
                                assert_peer_certificate_refusal(result.unwrap_err(),profile,E::LeafKey(Key::MlDsa(parameter)));
                            } else { result.unwrap(); }
                        }
                    }
                }
                let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let ca = params.self_signed(&key).unwrap();
                let issuer = rcgen::Issuer::new(params, &key);
                let leaf = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap()
                    .signed_by(&root, &issuer).unwrap();
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.der().clone()).unwrap();
                for profile in [P::Unrestricted,P::Preferred,P::Fips1403,P::Fips1402,P::Bsi,P::Cnsa1] {
                    for strict in [false,true] {
                        let policy = resolve(profile,Options { peer_certificates_match_profile: strict,
                            ..Options::default() }).unwrap().tls;
                        let cv = tls::server_cert_verifier_builder(Arc::new(roots.clone()),&policy).unwrap().build().unwrap();
                        let sv = tls::client_cert_verifier_builder(Arc::new(roots.clone()),&policy).unwrap().build().unwrap();
                        let now = rustls::pki_types::UnixTime::now();
                        let name = "localhost".try_into().unwrap();
                        for result in [cv.verify_server_cert(leaf.der(), &[], &name, &[], now).map(|_| ()),
                            sv.verify_client_cert(leaf.der(), &[], now).map(|_| ())] {
                            if strict {
                                assert_peer_certificate_refusal(result.unwrap_err(),profile,E::ChainSignature(CS::MlDsa(parameter)));
                            } else { result.unwrap(); }
                        }
                    }
                }
            }
        }

        #[test]
        fn peer_certificate_revoked_crl_is_ordinary_in_both_directions() {
            let pki = test_support::peer_certificate_fixture(F::RevokedSha256Crl).unwrap();
            for strict in [false,true] {
                for direction in [false,true] {
                    let policy = certificate_policy(P::Cnsa1,strict,V::Tls13,T::EcdsaNistp384Sha384);
                    let (client,server) = test_support::peer_certificate_configs(&policy,direction,&pki).unwrap();
                    let (detector,error) = test_support::drive_typed(client,server).unwrap_err();
                    assert_eq!(detector,direction);
                    assert_eq!(error,rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked));
                }
            }
        }

        #[test]
        fn peer_certificate_baseline_failures_still_refuse() {
            for fixture in [F::WrongName,F::Expired,F::Untrusted,F::Tampered] {
                let pki = test_support::peer_certificate_fixture(fixture).unwrap();
                for direction in [false,true] {
                    if matches!(fixture,F::WrongName) && direction { continue; }
                    let policy = certificate_policy(P::Cnsa1,true,V::Tls13,T::EcdsaNistp384Sha384);
                    let (client,server) = test_support::peer_certificate_configs(&policy,direction,&pki).unwrap();
                    let (detector,error) = test_support::drive_typed(client,server).unwrap_err();
                    assert_eq!(detector,direction);
                    let rustls::Error::InvalidCertificate(cause) = error else { panic!("{error:?}") };
                    match fixture {
                        F::WrongName => assert!(matches!(cause,rustls::CertificateError::NotValidForNameContext { .. })),
                        F::Expired => assert!(matches!(cause,rustls::CertificateError::ExpiredContext { .. })),
                        F::Untrusted => assert_eq!(cause,rustls::CertificateError::UnknownIssuer),
                        F::Tampered => assert_eq!(cause,rustls::CertificateError::BadSignature),
                        F::RootSha256 | F::Rsa8192Leaf | F::Sha256Crl | F::RevokedSha256Crl |
                        F::SelectedBadPath | F::SelectedGoodPath => unreachable!(),
                    }
                }
            }
        }

        #[test]
        fn peer_certificate_concurrent_permissive_and_strict_stores() {
            std::thread::scope(|scope| {
                for strict in [false,true,false,true] {
                    scope.spawn(move || {
                        let pki = issued(S::EcdsaP384Sha384,None,S::Rsa2048Sha384);
                        for direction in [false,true] {
                            let policy = certificate_policy(P::Cnsa1,strict,V::Tls13,T::RsaPssSha384);
                            let (client,server) = test_support::peer_certificate_configs(&policy,direction,&pki).unwrap();
                            let result = test_support::drive_typed(client,server);
                            if strict {
                                let (detector,error) = result.unwrap_err();
                                assert_eq!(detector,direction);
                                assert_peer_certificate_refusal(error,P::Cnsa1,E::LeafKey(Key::Rsa(2048)));
                            } else { result.unwrap(); }
                        }
                    });
                }
            });
        }

        #[test]
        fn peer_certificate_options_coexist_without_changing_resolution_precedence() {
            for profile in P::ALL {
                for pq in [false,true] {
                    for strict in [false,true] {
                        let options = Options { peer_certificates_match_profile:strict,
                            pq_key_exchange_required:pq };
                        let result = resolve(profile,options);
                        if pq && [P::Cnsa1,P::Bsi,P::Fips1402].contains(&profile) {
                            assert_eq!(result.err(),Some(CryptoError::EmptyProfile {
                                profile,options,category:Family::KxGroup }));
                        } else if profile == P::Cnsa2 && MODULE.line == ModuleLine::AwsLcFips3 {
                            assert_eq!(result.err(),Some(CryptoError::EmptyProfile {
                                profile,options,category:Family::SignatureScheme }));
                        } else {
                            let resolved=result.unwrap();
                            assert_eq!(resolved.tls.peer_certificate_rule,
                                strict.then(|| peer_certificate_rule(profile).id));
                            assert_eq!(resolved.tls.kx_groups.iter().all(|g| g.is_post_quantum()),pq || profile == P::Cnsa2);
                        }
                    }
                }
            }
        }
        fn verifier_identity(policy: &Policy) -> PeerVerifierIdentity {
            PeerVerifierIdentity::Owned {
                rule: policy.peer_certificate_rule,
                handshake_schemes: policy.signature_schemes.iter()
                    .fold(0, |mask,scheme| mask | (1 << scheme.preference())),
            }
        }

        #[test]
        #[expect(clippy::disallowed_methods)]
        fn peer_certificate_completion_identity_matrix() {
            let pki = issued(S::EcdsaP384Sha384,None,S::EcdsaP384Sha384);
            let roots = Arc::new(pki.roots);
            let strict = certificate_policy(P::Cnsa1,true,V::Tls13,T::EcdsaNistp384Sha384);
            let broad = Policy { signature_schemes:vec![T::EcdsaNistp384Sha384,T::RsaPssSha256], ..strict.clone() };
            let off = Policy { peer_certificate_rule:None, ..strict.clone() };
            let other = Policy { peer_certificate_rule:Some(PeerCertificateRuleId::Preferred), ..strict.clone() };
            for (completion,built) in [(&strict,&off),(&strict,&other),(&strict,&broad),
                (&broad,&strict),(&off,&strict),(&off,&off)] {
                let expected = Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
                    expected:verifier_identity(completion), actual:verifier_identity(built) }));
                let server = tls::server_cert_verifier_builder(roots.clone(),built).unwrap().build().unwrap();
                let client = tls::client_cert_verifier_builder(roots.clone(),built).unwrap().build().unwrap();
                assert_eq!(tls::strict_client_builder(completion,server).err(),expected);
                assert_eq!(tls::strict_server_builder(completion,client).err(),expected);
            }
            let baseline_server = rustls::client::WebPkiServerVerifier::builder_with_provider(
                roots.clone(),Arc::new(tls::crypto_provider(&off).unwrap())).build().unwrap();
            let baseline_client = rustls::server::WebPkiClientVerifier::builder_with_provider(
                roots.clone(),Arc::new(tls::crypto_provider(&off).unwrap())).build().unwrap();
            let expected = Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
                expected:verifier_identity(&strict),actual:PeerVerifierIdentity::Opaque }));
            assert_eq!(tls::strict_client_builder(&strict,baseline_server).err(),expected);
            assert_eq!(tls::strict_server_builder(&strict,baseline_client).err(),expected);
            for policy in [&strict,&broad,&other] {
                assert_eq!(tls::client_builder(policy).err(),Some(CryptoError::Tls(
                    TlsError::StrictBuilderRequired { entry_point:"strict_client_builder" })));
                assert_eq!(tls::server_builder(policy).err(),Some(CryptoError::Tls(
                    TlsError::StrictBuilderRequired { entry_point:"strict_server_builder" })));
                let mut canonical = policy.clone();
                canonical.signature_schemes.reverse();
                assert!(tls::strict_client_builder(policy,
                    tls::server_cert_verifier_builder(roots.clone(),&canonical).unwrap().build().unwrap()).is_ok());
                assert!(tls::strict_server_builder(policy,
                    tls::client_cert_verifier_builder(roots.clone(),&canonical).unwrap().build().unwrap()).is_ok());
            }
            assert!(tls::client_builder(&off).is_ok());
            assert!(tls::server_builder(&off).is_ok());
        }
    };
}

/// Selects certificate fixture algorithms available on each backend line.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_peer_ml_algorithms {
    (crypto_profile_awslc4) => {
        vec![
            (&rcgen::PKCS_ML_DSA_44, ML::MlDsa44),
            (&rcgen::PKCS_ML_DSA_65, ML::MlDsa65),
        ]
    };
    (crypto_profile_awslc3) => {
        Vec::new()
    };
}
