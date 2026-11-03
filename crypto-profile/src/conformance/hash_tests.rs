/// The hashing tests that `conformance_tests!` expands.
#[doc(hidden)]
#[macro_export]
macro_rules! __conformance_hash_tests {
    ($b:ident) => {
        use $b::HashAlgorithm as H;
        use $b::*;
        use $crate::conformance::{__cavp_short, vectors};

        fn unrestricted() -> Admitted {
            admit(Profile::Unrestricted, Options::default())
        }

        fn streamed(a: &Admitted, h: H, message: &[u8], chunk: usize) -> Vec<u8> {
            let mut s = digest::Hasher::new(a, h).unwrap_or_else(|e| panic!("{h:?}: {e}"));
            for c in message.chunks(chunk) {
                s.update(c);
            }
            s.finish()
        }

        #[test]
        fn conformance_cavp_short_messages() {
            let a = unrestricted();
            for (h, file, want) in [
                (H::Sha256, vectors::SHA256_SHORT, 65),
                (H::Sha384, vectors::SHA384_SHORT, 129),
                (H::Sha512, vectors::SHA512_SHORT, 129),
                (H::Sha3_256, vectors::SHA3_256_SHORT, 137),
                (H::Sha3_384, vectors::SHA3_384_SHORT, 105),
                (H::Sha3_512, vectors::SHA3_512_SHORT, 73),
            ] {
                let cases = __cavp_short(file);
                assert_eq!(cases.len(), want, "{h:?}");
                for (m, d) in cases {
                    assert_eq!(digest::digest(&a, h, &m), Ok(d.clone()), "{h:?}");
                    assert_eq!(streamed(&a, h, &m, 3), d, "{h:?}");
                }
            }
        }

        #[test]
        fn conformance_nist_hash_examples() {
            let a = unrestricted();
            let v: $crate::conformance::__serde_json::Value =
                $crate::conformance::__serde_json::from_str(vectors::NIST_HASH_EXAMPLES).unwrap();
            let mut counts = std::collections::BTreeMap::new();
            for c in v.as_array().unwrap() {
                let h: H = c["hash"].as_str().unwrap().parse().unwrap();
                let message = if let Some(text) = c["ascii"].as_str() {
                    text.as_bytes().to_vec()
                } else if let Some(hex) = c["hex"].as_str() {
                    $crate::conformance::__hex::decode(hex).unwrap()
                } else {
                    let byte =
                        $crate::conformance::__hex::decode(c["repeat"].as_str().unwrap()).unwrap();
                    vec![byte[0]; usize::try_from(c["count"].as_u64().unwrap()).unwrap()]
                };
                let want =
                    $crate::conformance::__hex::decode(c["digest"].as_str().unwrap()).unwrap();
                let source = c["source"].as_str().unwrap();
                assert_eq!(want.len(), h.output_len(), "{source}");
                assert_eq!(
                    digest::digest(&a, h, &message),
                    Ok(want.clone()),
                    "{source}"
                );
                assert_eq!(streamed(&a, h, &message, 7), want, "{source}");
                *counts.entry(h.as_str()).or_insert(0) += 1;
            }
            assert_eq!(
                counts.into_iter().collect::<Vec<_>>(),
                [
                    ("sha256", 12),
                    ("sha3-256", 2),
                    ("sha3-384", 2),
                    ("sha3-512", 2),
                    ("sha384", 11),
                    ("sha512", 11)
                ]
            );
        }

        #[test]
        fn conformance_a_hash_the_profile_does_not_admit_is_refused() {
            let cnsa2 = admit(Profile::Cnsa2, Options::default());
            for h in [H::Sha256, H::Sha3_256, H::Sha3_384, H::Sha3_512] {
                let refused = CryptoError::NotInProfile {
                    profile: Profile::Cnsa2,
                    algorithm: Algorithm::Hash(h),
                };
                assert!(digest::digest(&unrestricted(), h, b"").is_ok(), "{h:?}");
                assert_eq!(digest::digest(&cnsa2, h, b"abc"), Err(refused), "{h:?}");
                assert_eq!(digest::Hasher::new(&cnsa2, h).err(), Some(refused), "{h:?}");
            }
            let mut on = Options::default();
            on.cnsa1_unclassified_nss = true;
            let cnsa1 = admit(Profile::Cnsa1, on);
            assert_eq!(
                digest::digest(&cnsa1, H::Sha256, b"abc").map(|d| d.len()),
                Ok(32)
            );
            assert_eq!(
                digest::Hasher::new(&cnsa1, H::Sha256).map(|s| s.algorithm()),
                Ok(H::Sha256)
            );
            assert_eq!(
                digest::digest(
                    &admit(Profile::Cnsa1, Options::default()),
                    H::Sha256,
                    b"abc"
                ),
                Err(CryptoError::NotInProfile {
                    profile: Profile::Cnsa1,
                    algorithm: Algorithm::Hash(H::Sha256),
                })
            );
        }

        #[test]
        fn conformance_hasher_debug_names_the_algorithm_only() {
            let mut s = digest::Hasher::new(&unrestricted(), H::Sha512).unwrap();
            s.update(b"secret");
            assert_eq!(format!("{s:?}"), "Hasher { algorithm: Sha512 }");
        }
    };
}
