/// The ECDH and sealed-box tests that `conformance_tests!` expands.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_key_agreement_tests {
    ($b:ident) => {
        use $b::KeyAgreementAlgorithm as E;
        use $b::*;
        use $crate::conformance::golden::KEY_AGREEMENT_GOLDEN;
        use $crate::conformance::{__fixed_len_scalar, __hex};

        const ORDER_P256: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        const ORDER_P384: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
        const ORDER_P521: &str = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
        const SPKI_P256_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
        const SPKI_X25519_PREFIX: &str = "302a300506032b656e032100";

        fn unhex(s: &str) -> Vec<u8> {
            __hex::decode(s).unwrap()
        }

        fn hkdf(algorithm: KdfAlgorithm, info: &[u8]) -> kdf::Spec<'_> {
            kdf::Spec::Hkdf {
                algorithm,
                salt: None,
                info,
            }
        }

        fn scalar_len(k: E) -> usize {
            match k {
                E::EcdhP256 | E::X25519 => 32,
                E::EcdhP384 => 48,
                E::EcdhP521 => 66,
                _ => panic!("{k:?}: no scalar length"),
            }
        }

        fn one(k: E) -> Vec<u8> {
            __fixed_len_scalar(&[1], scalar_len(k))
        }

        fn bytes(d: Result<kdf::DerivedKey, CryptoError>) -> Result<Vec<u8>, CryptoError> {
            d.map(|d| d.as_bytes().to_vec())
        }

        fn unrestricted() -> Admitted {
            admit(Profile::Unrestricted, Options::default())
        }

        fn fips() -> Admitted {
            admit(Profile::Fips1403, Options::default())
        }

        #[test]
        fn conformance_key_agreement_takes_only_the_raw_point() {
            let a = unrestricted();
            let spec = hkdf(KdfAlgorithm::HkdfSha256, b"format");
            let key = ecdh::StaticKey::from_scalar(&a, E::EcdhP256, &one(E::EcdhP256)).unwrap();
            let peer = ecdh::StaticKey::from_scalar(&a, E::EcdhP256, &__fixed_len_scalar(&[2], 32))
                .unwrap();
            let point = peer.public_key();
            assert!(key.agree(point, &spec, 32).is_ok());
            let parity = point[64] & 1;
            let mut compressed = vec![0x02 | parity];
            compressed.extend_from_slice(&point[1..33]);
            let mut hybrid = vec![0x06 | parity];
            hybrid.extend_from_slice(&point[1..]);
            let mut spki = unhex(SPKI_P256_PREFIX);
            spki.extend_from_slice(point);
            let refused = Err(CryptoError::KeyAgreementPeerKey {
                algorithm: E::EcdhP256,
            });
            for bad in [compressed, hybrid, spki, point[..64].to_vec(), vec![]] {
                assert_eq!(bytes(key.agree(&bad, &spec, 32)), refused, "{bad:02x?}");
                assert_eq!(
                    test_support::ecdh_shared_secret(&key, &bad).map(|z| z.to_vec()),
                    refused
                );
            }
            let x = ecdh::StaticKey::from_scalar(&a, E::X25519, &[9; 32]).unwrap();
            let x_peer = ecdh::StaticKey::from_scalar(&a, E::X25519, &[7; 32]).unwrap();
            assert!(x.agree(x_peer.public_key(), &spec, 32).is_ok());
            let mut x_spki = unhex(SPKI_X25519_PREFIX);
            x_spki.extend_from_slice(x_peer.public_key());
            let mut long = x_peer.public_key().to_vec();
            long.push(0);
            for bad in [x_spki, long, x_peer.public_key()[..31].to_vec()] {
                assert_eq!(
                    bytes(x.agree(&bad, &spec, 32)),
                    Err(CryptoError::KeyAgreementPeerKey {
                        algorithm: E::X25519
                    }),
                    "{bad:02x?}"
                );
            }
        }

        #[test]
        fn conformance_key_agreement_refusal_matrix() {
            for &(p, admitted) in KEY_AGREEMENT_GOLDEN {
                for unclassified in [false, true] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    assert_eq!(a.key_agreements(), admitted, "{p} {o}");
                    for &k in KeyAgreementAlgorithm::ALL {
                        let want = if admitted.contains(&k) {
                            Ok(k)
                        } else {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::KeyAgreement(k),
                            })
                        };
                        assert_eq!(
                            ecdh::EphemeralKey::generate(&a, k).map(|e| e.algorithm()),
                            want,
                            "{p} {o} {k:?}"
                        );
                        assert_eq!(
                            ecdh::StaticKey::from_scalar(&a, k, &one(k)).map(|s| s.algorithm()),
                            want,
                            "{p} {o} {k:?}"
                        );
                    }
                }
            }
        }

        #[test]
        fn conformance_ecdh_agrees_in_both_roles_under_each_admitted_pair() {
            for &(p, curves) in KEY_AGREEMENT_GOLDEN {
                let a = admit(p, Options::default());
                for &k in curves {
                    let recipient = ecdh::StaticKey::from_scalar(&a, k, &one(k)).unwrap();
                    for &d in a.kdfs() {
                        let spec = super::kdf_spec(d, b"both roles");
                        let sender = ecdh::EphemeralKey::generate(&a, k).unwrap();
                        assert_eq!(sender.public_key().len(), recipient.public_key().len());
                        let ephemeral = sender.public_key().to_vec();
                        let sent = bytes(sender.agree(recipient.public_key(), &spec, 64));
                        let received = bytes(recipient.agree(&ephemeral, &spec, 64));
                        assert_eq!(sent.as_ref().map(Vec::len), Ok(64), "{p} {k:?} {d:?}");
                        assert_eq!(sent, received, "{p} {k:?} {d:?}");
                    }
                }
            }
        }

        #[test]
        fn conformance_key_agreement_refusals_come_in_order() {
            let cnsa1 = admit(Profile::Cnsa1, Options::default());
            let key = ecdh::StaticKey::from_scalar(&cnsa1, E::EcdhP384, &one(E::EcdhP384)).unwrap();
            let peer = ecdh::EphemeralKey::generate(&cnsa1, E::EcdhP384)
                .unwrap()
                .public_key()
                .to_vec();
            let mut compressed = vec![0x02 | (peer[96] & 1)];
            compressed.extend_from_slice(&peer[1..49]);
            let k384 = KdfAlgorithm::HkdfSha384;
            let refusals = |spec: &kdf::Spec<'_>, peer: &[u8], len| {
                let ephemeral = ecdh::EphemeralKey::generate(&cnsa1, E::EcdhP384).unwrap();
                let got = bytes(key.agree(peer, spec, len)).map(|d| d.len());
                let from_ephemeral = bytes(ephemeral.agree(peer, spec, len)).map(|d| d.len());
                assert_eq!(from_ephemeral, got, "{spec:?}");
                got
            };
            assert_eq!(
                refusals(&hkdf(KdfAlgorithm::OneStepSha512, b""), &compressed, 0),
                Err(CryptoError::KdfSpecMismatch {
                    algorithm: KdfAlgorithm::OneStepSha512
                })
            );
            assert_eq!(
                refusals(&hkdf(KdfAlgorithm::HkdfSha512, b""), &compressed, 0),
                Err(CryptoError::NotInProfile {
                    profile: Profile::Cnsa1,
                    algorithm: Algorithm::Kdf(KdfAlgorithm::HkdfSha512),
                })
            );
            assert_eq!(
                refusals(&hkdf(k384, b""), &compressed, 0),
                Err(CryptoError::KdfInfoEmpty {
                    profile: Profile::Cnsa1
                })
            );
            assert_eq!(
                refusals(&hkdf(k384, b"x"), &compressed, 0),
                Err(CryptoError::KdfOutputLength {
                    algorithm: k384,
                    bytes: 0,
                    max_bytes: 12240,
                })
            );
            assert_eq!(
                refusals(&hkdf(k384, b"x"), &compressed, 32),
                Err(CryptoError::KeyAgreementPeerKey {
                    algorithm: E::EcdhP384
                })
            );
            assert_eq!(refusals(&hkdf(k384, b"x"), &peer, 32), Ok(32));
            let bsi = admit(Profile::Bsi, Options::default());
            let not_admitted = Err(CryptoError::NotInProfile {
                profile: Profile::Bsi,
                algorithm: Algorithm::KeyAgreement(E::EcdhP384),
            });
            assert_eq!(
                ecdh::StaticKey::from_scalar(&bsi, E::EcdhP384, &[0; 48]).map(|_| ()),
                not_admitted
            );
            assert_eq!(
                ecdh::StaticKey::from_pkcs8_der(&bsi, E::EcdhP384, b"").map(|_| ()),
                not_admitted
            );
        }

        #[test]
        fn conformance_static_keys_are_imported_exactly() {
            let a = unrestricted();
            for (k, order, s) in [
                (E::EcdhP256, ORDER_P256, SignatureAlgorithm::EcdsaP256Sha256),
                (E::EcdhP384, ORDER_P384, SignatureAlgorithm::EcdsaP384Sha384),
                (E::EcdhP521, ORDER_P521, SignatureAlgorithm::EcdsaP521Sha512),
            ] {
                let len = scalar_len(k);
                let refused = Err(CryptoError::KeyAgreementPrivateKey { algorithm: k });
                let mut below = unhex(order);
                assert_eq!(below.len(), len);
                below[len - 1] -= 1;
                assert!(ecdh::StaticKey::from_scalar(&a, k, &below).is_ok(), "{k:?}");
                for bad in [
                    vec![1; len - 1],
                    vec![1; len + 1],
                    vec![0; len],
                    unhex(order),
                    vec![0xff; len],
                ] {
                    assert_eq!(
                        ecdh::StaticKey::from_scalar(&a, k, &bad).map(|_| ()),
                        refused,
                        "{k:?} {bad:02x?}"
                    );
                }
                let pair = signature::KeyPair::generate(s).unwrap();
                let key = ecdh::StaticKey::from_pkcs8_der(&a, k, pair.to_pkcs8_der()).unwrap();
                assert_eq!(key.public_key(), pair.public_key(), "{k:?}");
                assert_eq!(key.algorithm(), k);
                let der = pair.to_pkcs8_der();
                for bad in [&der[..der.len() - 1], b"not a key", b""] {
                    assert_eq!(
                        ecdh::StaticKey::from_pkcs8_der(&a, k, bad).map(|_| ()),
                        refused,
                        "{k:?}"
                    );
                }
                for &other in KeyAgreementAlgorithm::ALL {
                    if other != k {
                        assert_eq!(
                            ecdh::StaticKey::from_pkcs8_der(&a, other, der).map(|_| ()),
                            Err(CryptoError::KeyAgreementPrivateKey { algorithm: other }),
                            "{k:?} as {other:?}"
                        );
                    }
                }
            }
            let x_refused = Err(CryptoError::KeyAgreementPrivateKey {
                algorithm: E::X25519,
            });
            for bad in [vec![9; 31], vec![9; 33]] {
                assert_eq!(
                    ecdh::StaticKey::from_scalar(&a, E::X25519, &bad).map(|_| ()),
                    x_refused
                );
            }
            let ed = signature::KeyPair::generate(SignatureAlgorithm::Ed25519).unwrap();
            assert_eq!(
                ecdh::StaticKey::from_pkcs8_der(&a, E::X25519, ed.to_pkcs8_der()).map(|_| ()),
                x_refused
            );
        }

        #[test]
        fn conformance_ecdh_keys_print_no_key_material() {
            let a = fips();
            let s = ecdh::StaticKey::from_scalar(&a, E::EcdhP384, &one(E::EcdhP384)).unwrap();
            assert_eq!(format!("{s:?}"), "StaticKey(ecdh-p384, ..)");
            let e = ecdh::EphemeralKey::generate(&a, E::EcdhP256).unwrap();
            assert_eq!(format!("{e:?}"), "EphemeralKey(ecdh-p256, ..)");
            assert_eq!(e.algorithm(), E::EcdhP256);
            assert_eq!(e.public_key().len(), 65);
            assert_eq!(e.public_key()[0], 0x04);
        }
    };
}
