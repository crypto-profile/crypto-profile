/// The signature tests that `conformance_tests!` expands.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_signature_tests {
    ($b:ident) => {
        use $b::SignatureAlgorithm as S;
        use $b::*;
        use $crate::conformance::golden::SIGNATURE_GOLDEN;
        use $crate::conformance::{__wycheproof_pss_cases, __wycheproof_sig_cases, vectors};

        fn unrestricted() -> Admitted {
            admit(Profile::Unrestricted, Options::default())
        }

        fn available(a: S) -> bool {
            capability(MODULE, Algorithm::Signature(a)).available
        }

        struct Fixture {
            algorithm: S,
            pkcs8: Vec<u8>,
            public: Vec<u8>,
            signature: Vec<u8>,
        }

        fn fixtures() -> Vec<Fixture> {
            S::ALL
                .iter()
                .copied()
                .filter(|a| available(*a))
                .map(|algorithm| {
                    let k = signature::KeyPair::generate(&unrestricted(), algorithm)
                        .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
                    Fixture {
                        algorithm,
                        pkcs8: k.to_pkcs8_der().unwrap().to_vec(),
                        public: k.public_key().to_vec(),
                        signature: k.sign(b"m").unwrap(),
                    }
                })
                .collect()
        }

        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let n = u16::try_from(value.len()).unwrap();
            let [hi, lo] = n.to_be_bytes();
            let len = match n {
                0..=0x7f => vec![lo],
                0x80..=0xff => vec![0x81, lo],
                _ => vec![0x82, hi, lo],
            };
            [&[tag][..], &len, value].concat()
        }

        fn split(der: &[u8]) -> (u8, &[u8], &[u8]) {
            let (header, len) = match der[1] {
                n @ 0..=0x7f => (2, usize::from(n)),
                0x81 => (3, usize::from(der[2])),
                0x82 => (4, usize::from(u16::from_be_bytes([der[2], der[3]]))),
                other => panic!("length {other:#04x}"),
            };
            (der[0], &der[header..header + len], &der[header + len..])
        }

        fn fields(der: &[u8]) -> Vec<Vec<u8>> {
            let (_, mut rest, _) = split(der);
            let mut out = Vec::new();
            while !rest.is_empty() && out.len() < 8 {
                let (tag, value, next) = split(rest);
                out.push(tlv(tag, value));
                rest = next;
            }
            out
        }

        fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
            tlv(0x30, &fields.concat())
        }

        fn attributes() -> Vec<u8> {
            let attribute = |last: u8| {
                sequence(&[
                    tlv(
                        0x06,
                        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, last],
                    ),
                    tlv(0x31, &tlv(0x04, &[1, 2])),
                ])
            };
            tlv(0xa0, &[attribute(0x14), attribute(0x15)].concat())
        }

        fn spki(a: S, raw: &[u8]) -> Vec<u8> {
            let oid = |o: &[u8]| tlv(0x06, o);
            let ec_public_key = oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
            let algorithm = match a {
                S::EcdsaP256Sha256 => sequence(&[
                    ec_public_key,
                    oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
                ]),
                S::EcdsaP384Sha384 => {
                    sequence(&[ec_public_key, oid(&[0x2b, 0x81, 0x04, 0x00, 0x22])])
                }
                S::EcdsaP521Sha384 | S::EcdsaP521Sha512 => {
                    sequence(&[ec_public_key, oid(&[0x2b, 0x81, 0x04, 0x00, 0x23])])
                }
                S::Ed25519 => sequence(&[oid(&[0x2b, 0x65, 0x70])]),
                S::MlDsa87 => {
                    sequence(&[oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13])])
                }
                S::Rsa2048Sha384
                | S::Rsa3072Sha384
                | S::Rsa4096Sha384
                | S::Rsa2048Sha384Pss
                | S::Rsa3072Sha384Pss
                | S::Rsa4096Sha384Pss => sequence(&[
                    oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
                    vec![0x05, 0x00],
                ]),
                _ => panic!("{a}: no SubjectPublicKeyInfo"),
            };
            sequence(&[algorithm, tlv(0x03, &[&[0][..], raw].concat())])
        }

        #[test]
        fn conformance_wycheproof_rsa_pss() {
            let u = unrestricted();
            for (a, pkcs1, file, want) in [
                (
                    S::Rsa2048Sha384Pss,
                    S::Rsa2048Sha384,
                    vectors::RSA_PSS_2048_SHA384,
                    (95, 46),
                ),
                (
                    S::Rsa4096Sha384Pss,
                    S::Rsa4096Sha384,
                    vectors::RSA_PSS_4096_SHA384,
                    (95, 46),
                ),
            ] {
                let (mut valid, mut invalid) = (0, 0);
                for (pk, msg, sig, result, id) in __wycheproof_sig_cases(file, "publicKeyAsn", "") {
                    let verdict = signature::verify(&u, a, &pk, &msg, &sig);
                    match result.as_str() {
                        "valid" => {
                            valid += 1;
                            assert_eq!(verdict, Ok(()), "{a} tcId {id}");
                            assert_eq!(
                                signature::verify(&u, pkcs1, &pk, &msg, &sig),
                                Err(CryptoError::Verify),
                                "{pkcs1} tcId {id}"
                            );
                        }
                        "invalid" => {
                            invalid += 1;
                            assert_eq!(verdict, Err(CryptoError::Verify), "{a} tcId {id}");
                        }
                        other => panic!("{a} tcId {id}: unknown result {other:?}"),
                    }
                }
                assert_eq!((valid, invalid), want, "{a}");
            }
            let mut accepted = Vec::new();
            let cases = __wycheproof_pss_cases(vectors::RSA_PSS_MISC);
            assert_eq!(cases.len(), 150);
            for (params, (pk, msg, sig, result, id)) in cases {
                assert_eq!(result, "valid", "tcId {id}");
                match signature::verify(&u, S::Rsa2048Sha384Pss, &pk, &msg, &sig) {
                    Ok(()) => accepted.push(params),
                    Err(e) => assert_eq!(e, CryptoError::Verify, "{params} tcId {id}"),
                }
            }
            assert_eq!(accepted, ["SHA-384/SHA-384/48"]);
        }

        #[test]
        fn conformance_signature_refusal_matrix() {
            let keys = fixtures();
            for &(p, off, on) in SIGNATURE_GOLDEN {
                for (unclassified, golden) in [(false, off), (true, on)] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    for f in &keys {
                        let s = f.algorithm;
                        let want = if golden.contains(&s) {
                            Ok(())
                        } else {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Signature(s),
                            })
                        };
                        assert_eq!(
                            signature::verify(&a, s, &f.public, b"m", &f.signature),
                            want,
                            "{p} {o} {s}"
                        );
                        assert_eq!(
                            signature::KeyPair::from_pkcs8_der(&a, s, &f.pkcs8)
                                .map(|k| k.public_key().to_vec()),
                            want.map(|()| f.public.clone()),
                            "{p} {o} {s}"
                        );
                        if let Err(refused) = want {
                            assert_eq!(
                                signature::KeyPair::generate(&a, s).err(),
                                Some(refused),
                                "{p} {o} {s}"
                            );
                        }
                    }
                    for &s in S::ALL.iter().filter(|s| !available(**s)) {
                        let refused = if golden.contains(&s) {
                            CryptoError::Unavailable(Algorithm::Signature(s))
                        } else {
                            CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Signature(s),
                            }
                        };
                        assert_eq!(signature::KeyPair::generate(&a, s).err(), Some(refused));
                        assert_eq!(
                            signature::KeyPair::from_pkcs8_der(&a, s, b"").err(),
                            Some(refused)
                        );
                        assert_eq!(signature::verify(&a, s, b"", b"", b""), Err(refused));
                    }
                }
            }
        }

        #[test]
        fn conformance_a_signature_the_profile_does_not_admit_is_refused_before_its_key() {
            let cnsa2 = admit(Profile::Cnsa2, Options::default());
            let refused = CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Signature(S::EcdsaP384Sha384),
            };
            assert_eq!(
                signature::verify(&cnsa2, S::EcdsaP384Sha384, b"not a key", b"m", b""),
                Err(refused)
            );
            assert_eq!(
                signature::KeyPair::from_pkcs8_der(&cnsa2, S::EcdsaP384Sha384, b"not a key").err(),
                Some(refused)
            );
            assert_eq!(
                signature::KeyPair::generate(&cnsa2, S::EcdsaP384Sha384).err(),
                Some(refused)
            );
        }

        #[test]
        fn conformance_verify_takes_the_raw_public_key_only() {
            let u = unrestricted();
            for f in fixtures() {
                let a = f.algorithm;
                let raw = &f.public;
                assert_eq!(
                    signature::verify(&u, a, raw, b"m", &f.signature),
                    Ok(()),
                    "{a}"
                );
                let whole = spki(a, raw);
                let mut bad = vec![
                    ("SubjectPublicKeyInfo", whole.clone()),
                    (
                        "SubjectPublicKeyInfo then 01 02 03",
                        [whole, vec![1, 2, 3]].concat(),
                    ),
                    ("one byte short", raw[..raw.len() - 1].to_vec()),
                    ("one byte long", [&raw[..], &[0]].concat()),
                    ("empty", Vec::new()),
                ];
                if raw.len() % 2 == 1 && raw[0] == 0x04 {
                    let odd = raw[raw.len() - 1] & 1;
                    let x = &raw[1..raw.len().div_ceil(2)];
                    let compressed = [&[0x02 | odd][..], x].concat();
                    bad.push(("compressed", compressed.clone()));
                    let padded = [compressed, vec![0xa5; raw.len() / 2]].concat();
                    assert_eq!(padded.len(), raw.len());
                    bad.push(("compressed, padded to the uncompressed length", padded));
                    bad.push(("hybrid", [&[0x06 | odd][..], &raw[1..]].concat()));
                }
                for (why, key) in bad {
                    assert_eq!(
                        signature::verify(&u, a, &key, b"m", &f.signature),
                        Err(CryptoError::SignaturePublicKey { algorithm: a }),
                        "{a}: {why}"
                    );
                }
            }
        }

        #[test]
        fn conformance_a_key_exports_its_canonical_encoding_and_imports_again() {
            let u = unrestricted();
            for f in fixtures() {
                let a = f.algorithm;
                let fs = fields(&f.pkcs8);
                let with = sequence(&[&fs[..3], &[attributes()], &fs[3..]].concat());
                for der in [f.pkcs8.clone(), with] {
                    let k = signature::KeyPair::from_pkcs8_der(&u, a, &der)
                        .unwrap_or_else(|e| panic!("{a}: {e}"));
                    assert_eq!(k.public_key(), f.public, "{a}");
                    assert_eq!(k.to_pkcs8_der().unwrap().to_vec(), f.pkcs8, "{a}");
                    let signature = k.sign(b"again").unwrap();
                    assert_eq!(
                        signature::verify(&u, a, &f.public, b"again", &signature),
                        Ok(()),
                        "{a}"
                    );
                }
                let version = if a == S::Ed25519 { 1 } else { 0 };
                assert_eq!(fs[0], [0x02, 0x01, version], "{a}");
                if a == S::Ed25519 {
                    assert_eq!(fs.len(), 4);
                    let v1 = sequence(&[vec![0x02, 0x01, 0x00], fs[1].clone(), fs[2].clone()]);
                    let k = signature::KeyPair::from_pkcs8_der(&u, a, &v1).unwrap();
                    assert_eq!(k.to_pkcs8_der().unwrap().to_vec(), f.pkcs8);
                }
            }
        }

        #[test]
        fn conformance_key_pairs_print_no_key_material() {
            for f in fixtures() {
                let k = signature::KeyPair::from_pkcs8_der(&unrestricted(), f.algorithm, &f.pkcs8)
                    .unwrap();
                assert_eq!(format!("{k:?}"), format!("KeyPair({}, ..)", f.algorithm));
            }
        }
    };
}
