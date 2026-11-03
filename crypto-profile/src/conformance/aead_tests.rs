/// The AEAD tests that `conformance_tests!` expands.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_aead_tests {
    ($b:ident) => {
        use $b::AeadAlgorithm as D;
        use $b::*;
        use $crate::conformance::{__wycheproof_aead_cases, vectors};

        fn unrestricted() -> Admitted {
            admit(Profile::Unrestricted, Options::default())
        }

        fn wycheproof_opens(d: D, file: &str, key_bits: u64) -> (usize, usize, usize) {
            let a = unrestricted();
            let cases = __wycheproof_aead_cases(file, key_bits, 96, 128);
            let (mut valid, mut invalid) = (0, 0);
            for c in &cases {
                let nonce: [u8; aead::NONCE_LEN] = c.iv.as_slice().try_into().unwrap();
                let k = aead::Key::new(&a, d, &c.key)
                    .unwrap_or_else(|e| panic!("{d:?} tcId {}: {e}", c.tc_id));
                let mut buf = c.ct_tag.clone();
                let opened = k
                    .open_in_place(&nonce, &c.aad, &mut buf)
                    .map(|p| p.to_vec());
                match c.result.as_str() {
                    "valid" => {
                        valid += 1;
                        assert_eq!(opened, Ok(c.msg.clone()), "{d:?} tcId {}", c.tc_id);
                    }
                    "invalid" => {
                        invalid += 1;
                        assert_eq!(opened, Err(CryptoError::AeadOpen), "{d:?} tcId {}", c.tc_id);
                    }
                    other => panic!("{d:?} tcId {}: unknown result {other:?}", c.tc_id),
                }
            }
            let v: $crate::conformance::__serde_json::Value =
                $crate::conformance::__serde_json::from_str(file).unwrap();
            let all = v["testGroups"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g["tests"].as_array().unwrap().len())
                .sum::<usize>();
            (valid, invalid, all - cases.len())
        }

        #[test]
        fn conformance_wycheproof_aes_gcm() {
            assert_eq!(
                wycheproof_opens(D::Aes128Gcm, vectors::AES_GCM, 128),
                (40, 27, 249)
            );
            assert_eq!(
                wycheproof_opens(D::Aes256Gcm, vectors::AES_GCM, 256),
                (39, 27, 250)
            );
        }

        #[test]
        fn conformance_wycheproof_chacha20_poly1305() {
            assert_eq!(
                wycheproof_opens(D::Chacha20Poly1305, vectors::CHACHA20_POLY1305, 256),
                (256, 60, 9)
            );
        }

        #[test]
        fn conformance_aead_keys_are_refused_in_admission_length_order() {
            for &(p, admitted) in $crate::conformance::golden::AEAD_GOLDEN {
                let a = admit(p, Options::default());
                for &d in D::ALL {
                    for len in [0, d.key_len() - 1, d.key_len(), d.key_len() + 1] {
                        let want = if !admitted.contains(&d) {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Aead(d),
                            })
                        } else if len != d.key_len() {
                            Err(CryptoError::AeadKeyLength {
                                algorithm: d,
                                bytes: len,
                            })
                        } else {
                            Ok(d)
                        };
                        assert_eq!(
                            aead::Key::new(&a, d, &vec![7; len]).map(|k| k.algorithm()),
                            want,
                            "{p} {d:?} {len}"
                        );
                    }
                }
            }
        }

        #[test]
        fn conformance_aead_seals_stop_at_two_to_the_thirty_two() {
            for &d in D::ALL {
                let k = aead::Key::new(&unrestricted(), d, &vec![7; d.key_len()]).unwrap();
                test_support::aead_set_invocations(&k, (1 << 32) - 1);
                let mut buf = b"last".to_vec();
                let (nonce, tag) = k.seal_in_place(b"aad", &mut buf).unwrap();
                buf.extend_from_slice(&tag);
                let refused = Some(CryptoError::AeadLimit { algorithm: d });
                assert_eq!(k.seal_in_place(b"aad", &mut [0; 4]).err(), refused, "{d:?}");
                assert_eq!(
                    k.open_in_place(&nonce, b"aad", &mut buf)
                        .map(|p| p.to_vec()),
                    Ok(b"last".to_vec()),
                    "{d:?}"
                );
                assert_eq!(k.seal_in_place(b"", &mut []).err(), refused, "{d:?}");
            }
        }

        #[test]
        fn conformance_aead_keys_print_no_key_material() {
            for &d in D::ALL {
                let k = aead::Key::new(&unrestricted(), d, &vec![0xA5; d.key_len()]).unwrap();
                assert_eq!(format!("{k:?}"), format!("Key {{ algorithm: {d:?} }}"));
            }
        }
    };
}
