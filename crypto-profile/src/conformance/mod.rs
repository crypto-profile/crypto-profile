//! Shared conformance data and helpers for `crypto-profile` backends.

#[doc(hidden)]
pub use hex as __hex;
#[doc(hidden)]
pub use serde_json as __serde_json;

/// One Wycheproof signature case: `(public key, message, signature, result, tcId)`.
#[doc(hidden)]
pub type SigCase = (Vec<u8>, Vec<u8>, Vec<u8>, String, u64);

/// The signature-verification cases of a Wycheproof file; `pk_field` and `pk_sub` name where
/// each test group carries its raw public key.
#[doc(hidden)]
pub fn __wycheproof_sig_cases(file: &str, pk_field: &str, pk_sub: &str) -> Vec<SigCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().into_iter().flatten() {
        let pk_hex = if pk_sub.is_empty() {
            g[pk_field].as_str()
        } else {
            g[pk_field][pk_sub].as_str()
        };
        let pk = hex::decode(pk_hex.unwrap_or_default()).unwrap_or_default();
        for t in g["tests"].as_array().into_iter().flatten() {
            out.push((
                pk.clone(),
                hex::decode(t["msg"].as_str().unwrap_or_default()).unwrap_or_default(),
                hex::decode(t["sig"].as_str().unwrap_or_default()).unwrap_or_default(),
                t["result"].as_str().unwrap_or_default().to_string(),
                t["tcId"].as_u64().unwrap_or_default(),
            ));
        }
    }
    out
}

/// One Wycheproof AEAD case.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadCase {
    /// The key.
    pub key: Vec<u8>,
    /// The nonce.
    pub iv: Vec<u8>,
    /// The additional authenticated data.
    pub aad: Vec<u8>,
    /// The plaintext.
    pub msg: Vec<u8>,
    /// The ciphertext followed by the tag.
    pub ct_tag: Vec<u8>,
    /// `valid`, `invalid` or `acceptable`.
    pub result: String,
    /// The Wycheproof test-case id.
    pub tc_id: u64,
}

/// The cases of a Wycheproof AEAD file whose groups have exactly these key, IV and tag sizes in bits.
#[doc(hidden)]
pub fn __wycheproof_aead_cases(
    file: &str,
    key_bits: u64,
    iv_bits: u64,
    tag_bits: u64,
) -> Vec<AeadCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let d = |x: &serde_json::Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().into_iter().flatten() {
        let sizes = (
            g["keySize"].as_u64(),
            g["ivSize"].as_u64(),
            g["tagSize"].as_u64(),
        );
        if sizes != (Some(key_bits), Some(iv_bits), Some(tag_bits)) {
            continue;
        }
        for t in g["tests"].as_array().into_iter().flatten() {
            let mut ct_tag = d(&t["ct"]);
            ct_tag.extend_from_slice(&d(&t["tag"]));
            out.push(AeadCase {
                key: d(&t["key"]),
                iv: d(&t["iv"]),
                aad: d(&t["aad"]),
                msg: d(&t["msg"]),
                ct_tag,
                result: t["result"].as_str().unwrap_or_default().to_string(),
                tc_id: t["tcId"].as_u64().unwrap_or_default(),
            });
        }
    }
    out
}

/// `(message, digest)` pairs from a NIST CAVP `*ShortMsg.rsp` file, honouring `Len`.
#[doc(hidden)]
pub fn __cavp_short(file: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let (mut len, mut msg) = (0usize, Vec::new());
    for line in file.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Len = ") {
            len = v.parse().unwrap_or_default();
        } else if let Some(v) = line.strip_prefix("Msg = ") {
            msg = hex::decode(v).unwrap_or_default();
            msg.truncate(len / 8);
        } else if let Some(v) = line.strip_prefix("MD = ") {
            out.push((msg.clone(), hex::decode(v).unwrap_or_default()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cavp_short_honours_len() {
        let file = "[L = 32]\r\n\r\nLen = 0\r\nMsg = 00\r\nMD = aa\r\n\r\nLen = 16\r\nMsg = 0102\r\nMD = bbcc\r\n";
        assert_eq!(
            __cavp_short(file),
            vec![(vec![], vec![0xaa]), (vec![1, 2], vec![0xbb, 0xcc])]
        );
    }

    #[test]
    fn signature_cases_read_the_named_key_field() {
        let file = r#"{"testGroups":[
            {"publicKey":{"pk":"01"},"flat":"02","tests":[{"tcId":7,"msg":"03","sig":"04","result":"valid"}]},
            {"publicKey":{"pk":"05"},"flat":"06","tests":[{"tcId":8,"msg":"","sig":"07","result":"invalid"}]}
        ]}"#;
        assert_eq!(
            __wycheproof_sig_cases(file, "publicKey", "pk"),
            vec![
                (vec![1], vec![3], vec![4], "valid".to_string(), 7),
                (vec![5], vec![], vec![7], "invalid".to_string(), 8),
            ]
        );
        let flat = __wycheproof_sig_cases(file, "flat", "");
        assert_eq!(
            flat.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
            vec![vec![2], vec![6]]
        );
        assert!(__wycheproof_sig_cases("not json", "flat", "").is_empty());
    }

    #[test]
    fn aead_cases_keep_only_the_named_sizes() {
        let file = r#"{"testGroups":[
            {"keySize":128,"ivSize":96,"tagSize":128,"tests":[{"tcId":1,"key":"00","iv":"00","aad":"","msg":"","ct":"","tag":"00","result":"valid"}]},
            {"keySize":256,"ivSize":128,"tagSize":128,"tests":[{"tcId":2,"key":"00","iv":"00","aad":"","msg":"","ct":"","tag":"00","result":"valid"}]},
            {"keySize":256,"ivSize":96,"tagSize":64,"tests":[{"tcId":3,"key":"00","iv":"00","aad":"","msg":"","ct":"","tag":"00","result":"valid"}]},
            {"keySize":256,"ivSize":96,"tagSize":128,"tests":[{"tcId":4,"key":"01","iv":"02","aad":"03","msg":"04","ct":"05","tag":"06","result":"invalid"}]}
        ]}"#;
        assert_eq!(
            __wycheproof_aead_cases(file, 256, 96, 128),
            vec![AeadCase {
                key: vec![1],
                iv: vec![2],
                aad: vec![3],
                msg: vec![4],
                ct_tag: vec![5, 6],
                result: "invalid".to_string(),
                tc_id: 4,
            }]
        );
    }
}

/// Known-answer data every backend's conformance run checks.
pub mod vectors {
    /// Wycheproof ECDSA P-256 / SHA-256.
    pub const ECDSA_P256: &str = include_str!("vectors/ecdsa_secp256r1_sha256_test.json");
    /// Wycheproof ECDSA P-384 / SHA-384.
    pub const ECDSA_P384: &str = include_str!("vectors/ecdsa_secp384r1_sha384_test.json");
    /// Wycheproof ECDSA P-521 / SHA-512.
    pub const ECDSA_P521: &str = include_str!("vectors/ecdsa_secp521r1_sha512_test.json");
    /// Wycheproof Ed25519.
    pub const ED25519: &str = include_str!("vectors/ed25519_test.json");
    /// RFC 8032 Ed25519 test vectors 1-3.
    pub const ED25519_RFC8032: &str = include_str!("vectors/ed25519_rfc8032.json");
    /// Wycheproof RSA PKCS#1 v1.5, 2048-bit, SHA-384.
    pub const RSA_PKCS1_SHA384: &str = include_str!("vectors/rsa_signature_2048_sha384_test.json");
    /// Wycheproof AES-GCM.
    pub const AES_GCM: &str = include_str!("vectors/aes_gcm_test.json");
    /// NIST CAVP SHA-256 short messages.
    pub const SHA256_SHORT: &str = include_str!("vectors/SHA256ShortMsg.rsp");
    /// NIST CAVP SHA-384 short messages.
    pub const SHA384_SHORT: &str = include_str!("vectors/SHA384ShortMsg.rsp");
    /// NIST CAVP SHA-512 short messages.
    pub const SHA512_SHORT: &str = include_str!("vectors/SHA512ShortMsg.rsp");

    /// The sealed-box known-answer vectors, produced by an independent implementation.
    pub mod sealbox {
        /// The domain the known-answer blob was sealed under.
        pub const DOMAIN: &[u8] = b"maknae-seal-v1";
        /// The plaintext of the known-answer blob.
        pub const PLAINTEXT: &[u8] = b"maknae-seal known-answer plaintext";
        /// The recipient's P-384 private key as PKCS#8 DER, hex-encoded.
        pub const PRIVATE_KEY_PKCS8_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111a16403620004386e767ea5cb716c9cd620ff7342129c892a6fccefe612140c80bff59e943468019dda16e5079b0c1d9001d23a624b6dd088d0c3826394194787403e8a7d07e5e22f7e9c0b8e80fa1faff5d28b4bb597b267f0b87023ca61fc8454bddefd2e0e";
        /// The known-answer sealed blob, hex-encoded.
        pub const BLOB_HEX: &str = "01044f2bda7fd2105f8467e21f45223ad58863ffa4c084832d9f6c64ffc47fdd519727ab53cb71f9c40de24b64acde61f02fc7dce130b612fa5dbcac94573a2354fd005d8e9caefdc5fde48304474708bbd82f77e1fd2c630bea236f6f8dccc1678e000102030405060708090a0b9e5112a45c454d89052a69d413fb8bab9027d5b1ee8f724947f1375c31bf4f0cca4de10984b9e6f2057ce1ec13c1185fb116";
        /// AES-256-GCM output (ciphertext and tag), hex-encoded, under the key derived from a fixed
        /// shared secret of 48 bytes of `0x33` and the known-answer ephemeral key.
        pub const FIXED_SHARED_CT_HEX: &str = "0b97a82530c1e3b734c40e1d1bd3021ecd6c502e16d304d333ccdfdf7e0f35672a70c0815ce1d2c6c5ad3ab9c8968987c6c3";
        /// The nonce of [`FIXED_SHARED_CT_HEX`].
        pub const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        /// The additional authenticated data of the known-answer blob.
        pub fn aad() -> Vec<u8> {
            let mut out = b"maknae-seal-aad-v1".to_vec();
            for field in [
                "c-1",
                "openai",
                "gpt-5.6-luna",
                "maknae-kv/data/maknae/users/alice/openai/personal",
                "api_key",
            ] {
                out.extend_from_slice(&(field.len() as u16).to_be_bytes());
                out.extend_from_slice(field.as_bytes());
            }
            out
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::sealbox_wire::{MIN_BLOB_LEN, NONCE_LEN, VERSION};

            #[test]
            fn the_vectors_are_well_formed() {
                let blob = crate::conformance::__hex::decode(BLOB_HEX).unwrap();
                assert!(blob.len() >= MIN_BLOB_LEN);
                assert_eq!(blob[0], VERSION);
                assert_eq!(NONCE.len(), NONCE_LEN);
                assert_eq!(
                    &blob[1 + crate::sealbox_wire::EPHEMERAL_KEY_LEN
                        ..crate::sealbox_wire::HEADER_LEN],
                    &NONCE
                );
                assert_eq!(blob.len(), crate::sealbox_wire::sealed_len(PLAINTEXT.len()));
                assert_eq!(
                    crate::conformance::__hex::decode(PRIVATE_KEY_PKCS8_HEX)
                        .unwrap()
                        .len(),
                    185
                );
                assert_eq!(
                    crate::conformance::__hex::decode(FIXED_SHARED_CT_HEX)
                        .unwrap()
                        .len(),
                    PLAINTEXT.len() + 16
                );
            }

            #[test]
            fn the_aad_is_length_prefixed_fields() {
                let aad = aad();
                assert!(aad.starts_with(b"maknae-seal-aad-v1\x00\x03c-1\x00\x06openai"));
                assert!(aad.ends_with(b"\x00\x07api_key"));
            }
        }
    }
}

/// Expands, in a backend's integration test, to the conformance tests over that backend.
#[macro_export]
macro_rules! conformance_tests {
    ($b:ident) => {
        use $b::test_support::handshake;
        use $b::tls::Policy;
        use $b::*;
        use $crate::conformance::{
            __cavp_short, __wycheproof_aead_cases, __wycheproof_sig_cases, vectors,
        };

        fn policy(
            v: &[TlsVersion],
            c: &[CipherSuite],
            k: &[KxGroup],
            t: &[TlsSignatureScheme],
        ) -> Policy {
            Policy {
                versions: v.to_vec(),
                cipher_suites: c.to_vec(),
                kx_groups: k.to_vec(),
                signature_schemes: t.to_vec(),
            }
        }

        fn suite_key(c: CipherSuite) -> SignatureAlgorithm {
            match c {
                CipherSuite::Tls12EcdheRsaAes256GcmSha384
                | CipherSuite::Tls12EcdheRsaAes128GcmSha256
                | CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => {
                    SignatureAlgorithm::Rsa2048Sha384
                }
                CipherSuite::Tls13Aes256GcmSha384
                | CipherSuite::Tls13Aes128GcmSha256
                | CipherSuite::Tls13Chacha20Poly1305Sha256
                | CipherSuite::Tls12EcdheEcdsaAes256GcmSha384
                | CipherSuite::Tls12EcdheEcdsaAes128GcmSha256
                | CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256 => {
                    SignatureAlgorithm::EcdsaP384Sha384
                }
            }
        }

        // RFC 8446 §4.2.3 forbids PKCS#1 v1.5 for TLS 1.3 handshake signatures, so those schemes are exercised on TLS 1.2.
        fn scheme_setup(t: TlsSignatureScheme) -> (SignatureAlgorithm, TlsVersion, CipherSuite) {
            let t13 = (TlsVersion::Tls13, CipherSuite::Tls13Aes256GcmSha384);
            let rsa12 = (TlsVersion::Tls12, CipherSuite::Tls12EcdheRsaAes256GcmSha384);
            match t {
                TlsSignatureScheme::EcdsaNistp256Sha256 => {
                    (SignatureAlgorithm::EcdsaP256Sha256, t13.0, t13.1)
                }
                TlsSignatureScheme::EcdsaNistp384Sha384 => {
                    (SignatureAlgorithm::EcdsaP384Sha384, t13.0, t13.1)
                }
                TlsSignatureScheme::EcdsaNistp521Sha512 => {
                    (SignatureAlgorithm::EcdsaP521Sha512, t13.0, t13.1)
                }
                TlsSignatureScheme::Ed25519 => (SignatureAlgorithm::Ed25519, t13.0, t13.1),
                TlsSignatureScheme::RsaPssSha256
                | TlsSignatureScheme::RsaPssSha384
                | TlsSignatureScheme::RsaPssSha512 => {
                    (SignatureAlgorithm::Rsa2048Sha384, t13.0, t13.1)
                }
                TlsSignatureScheme::RsaPkcs1Sha256
                | TlsSignatureScheme::RsaPkcs1Sha384
                | TlsSignatureScheme::RsaPkcs1Sha512 => {
                    (SignatureAlgorithm::Rsa2048Sha384, rsa12.0, rsa12.1)
                }
                TlsSignatureScheme::MlDsa87 => (SignatureAlgorithm::MlDsa87, t13.0, t13.1),
            }
        }

        fn reference_pq_first() -> Policy {
            policy(
                &[TlsVersion::Tls13],
                &[
                    CipherSuite::Tls13Aes256GcmSha384,
                    CipherSuite::Tls13Aes128GcmSha256,
                ],
                &[
                    KxGroup::MlKem1024,
                    KxGroup::X25519MlKem768,
                    KxGroup::Secp256r1MlKem768,
                    KxGroup::Secp384r1,
                    KxGroup::Secp256r1,
                ],
                &TlsSignatureScheme::ALL,
            )
        }

        fn reference_cnsa1() -> Policy {
            policy(
                &[TlsVersion::Tls13, TlsVersion::Tls12],
                &[
                    CipherSuite::Tls13Aes256GcmSha384,
                    CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
                    CipherSuite::Tls12EcdheRsaAes256GcmSha384,
                ],
                &[KxGroup::Secp384r1],
                &TlsSignatureScheme::ALL,
            )
        }

        #[test]
        fn conformance_sha2_cavp_short_messages() {
            for (h, file) in [
                (HashAlgorithm::Sha256, vectors::SHA256_SHORT),
                (HashAlgorithm::Sha384, vectors::SHA384_SHORT),
                (HashAlgorithm::Sha512, vectors::SHA512_SHORT),
            ] {
                let cases = __cavp_short(file);
                assert!(cases.len() > 60, "{h:?}: {} cases", cases.len());
                for (m, d) in cases {
                    assert_eq!(digest::digest(h, &m), d, "{h:?}");
                }
            }
        }

        #[test]
        fn conformance_wycheproof_signatures() {
            for (a, file, field, sub) in [
                (
                    SignatureAlgorithm::EcdsaP256Sha256,
                    vectors::ECDSA_P256,
                    "publicKey",
                    "uncompressed",
                ),
                (
                    SignatureAlgorithm::EcdsaP384Sha384,
                    vectors::ECDSA_P384,
                    "publicKey",
                    "uncompressed",
                ),
                (
                    SignatureAlgorithm::EcdsaP521Sha512,
                    vectors::ECDSA_P521,
                    "publicKey",
                    "uncompressed",
                ),
                (
                    SignatureAlgorithm::Ed25519,
                    vectors::ED25519,
                    "publicKey",
                    "pk",
                ),
                (
                    SignatureAlgorithm::Rsa2048Sha384,
                    vectors::RSA_PKCS1_SHA384,
                    "publicKeyAsn",
                    "",
                ),
            ] {
                let cases = __wycheproof_sig_cases(file, field, sub);
                let (mut valid, mut invalid) = (0, 0);
                for (pk, msg, sig, result, id) in cases {
                    let ok = signature::verify(a, &pk, &msg, &sig).is_ok();
                    match result.as_str() {
                        "valid" => {
                            valid += 1;
                            if a == SignatureAlgorithm::Rsa2048Sha384 {
                                // A 2048-bit RSAPublicKey with e = 65537 is 270 DER bytes ending INTEGER 0x010001.
                                assert!(
                                    pk.len() == 270
                                        && pk.ends_with(&[0x02, 0x03, 0x01, 0x00, 0x01]),
                                    "{a} tcId {id}: not a 2048-bit e=65537 key"
                                );
                            }
                            assert!(ok, "{a} tcId {id}: valid but refused");
                        }
                        "invalid" => {
                            invalid += 1;
                            assert!(!ok, "{a} tcId {id}: invalid but accepted");
                        }
                        "acceptable" => {}
                        other => panic!("{a} tcId {id}: unknown result {other:?}"),
                    }
                }
                assert!(
                    valid >= 5 && invalid >= 10,
                    "{a}: {valid} valid, {invalid} invalid"
                );
            }
        }

        #[test]
        fn conformance_wycheproof_aes_gcm() {
            let cases = __wycheproof_aead_cases(vectors::AES_GCM, 256, 96, 128);
            let (mut valid, mut invalid) = (0, 0);
            for c in cases {
                let key: [u8; aead::KEY_LEN] = c.key.as_slice().try_into().unwrap();
                let nonce: [u8; aead::NONCE_LEN] = c.iv.as_slice().try_into().unwrap();
                let k = aead::Aes256GcmKey::new(&key).unwrap();
                let mut buf = c.ct_tag.clone();
                let opened = k
                    .open_in_place(&nonce, &c.aad, &mut buf)
                    .map(|p| p.to_vec());
                match c.result.as_str() {
                    "valid" => {
                        valid += 1;
                        assert_eq!(opened, Ok(c.msg), "tcId {}", c.tc_id);
                    }
                    "invalid" => {
                        invalid += 1;
                        assert_eq!(opened, Err(CryptoError::AeadOpen), "tcId {}", c.tc_id);
                    }
                    other => panic!("tcId {}: unknown result {other:?}", c.tc_id),
                }
            }
            assert!(
                valid >= 10 && invalid >= 10,
                "{valid} valid, {invalid} invalid"
            );
        }

        #[test]
        fn conformance_rfc8032_ed25519() {
            let v: $crate::conformance::__serde_json::Value =
                $crate::conformance::__serde_json::from_str(vectors::ED25519_RFC8032).unwrap();
            let d = |x: &$crate::conformance::__serde_json::Value| {
                $crate::conformance::__hex::decode(x.as_str().unwrap()).unwrap()
            };
            let cases = v.as_array().unwrap();
            assert_eq!(cases.len(), 3);
            for t in cases {
                assert_eq!(
                    signature::verify(
                        SignatureAlgorithm::Ed25519,
                        &d(&t["pk"]),
                        &d(&t["msg"]),
                        &d(&t["sig"])
                    ),
                    Ok(())
                );
            }
        }

        #[test]
        fn conformance_sealed_box_v1_known_answer_opens() {
            use vectors::sealbox as kat;
            let pkcs8 = $crate::conformance::__hex::decode(kat::PRIVATE_KEY_PKCS8_HEX).unwrap();
            let blob = $crate::conformance::__hex::decode(kat::BLOB_HEX).unwrap();
            let key = sealbox::PrivateKey::from_pkcs8_der(&pkcs8).unwrap();
            let opened = sealbox::open(&key, kat::DOMAIN, &kat::aad(), &blob).unwrap();
            assert_eq!(&opened[..], kat::PLAINTEXT);
        }

        #[test]
        fn conformance_capability_honesty() {
            for a in Algorithm::all() {
                let cap = capability(MODULE, a);
                match a {
                    Algorithm::Signature(s) => match sign_and_verify(s) {
                        Ok(()) => assert!(cap.available, "{a:?} works but is marked unavailable"),
                        Err(e) => assert!(
                            !cap.available && e == CryptoError::Unavailable(a),
                            "{a:?}: {e}"
                        ),
                    },
                    Algorithm::Hash(h) => {
                        assert!(cap.available, "{a:?}");
                        assert_eq!(digest::digest(h, b"").len(), h.output_len());
                    }
                    Algorithm::Kx(k) => {
                        let p = policy(
                            &[TlsVersion::Tls13],
                            &[CipherSuite::Tls13Aes256GcmSha384],
                            &[k],
                            &TlsSignatureScheme::ALL,
                        );
                        if cap.available {
                            let n = handshake(&p, &p, SignatureAlgorithm::EcdsaP384Sha384)
                                .unwrap_or_else(|e| panic!("{a:?}: {e}"));
                            assert_eq!(n.kx, k, "{a:?}");
                        } else {
                            assert_eq!(
                                tls::crypto_provider(&p).err(),
                                Some(CryptoError::Unavailable(a))
                            );
                        }
                    }
                    Algorithm::Cipher(c) => {
                        let p = policy(
                            &[c.version()],
                            &[c],
                            &[KxGroup::Secp384r1],
                            &TlsSignatureScheme::ALL,
                        );
                        if cap.available {
                            let n = handshake(&p, &p, suite_key(c))
                                .unwrap_or_else(|e| panic!("{a:?}: {e}"));
                            assert_eq!((n.version, n.suite), (c.version(), c), "{a:?}");
                        } else {
                            assert_eq!(
                                tls::crypto_provider(&p).err(),
                                Some(CryptoError::Unavailable(a))
                            );
                        }
                    }
                    Algorithm::Protocol(v) => {
                        let suites: Vec<_> = CipherSuite::ALL
                            .into_iter()
                            .filter(|c| c.version() == v)
                            .collect();
                        let p = policy(
                            &[v],
                            &suites,
                            &[KxGroup::Secp384r1],
                            &TlsSignatureScheme::ALL,
                        );
                        if cap.available {
                            let n = handshake(&p, &p, SignatureAlgorithm::EcdsaP384Sha384)
                                .unwrap_or_else(|e| panic!("{a:?}: {e}"));
                            assert_eq!(n.version, v, "{a:?}");
                        } else {
                            assert_eq!(
                                tls::crypto_provider(&p).err(),
                                Some(CryptoError::Unavailable(a))
                            );
                        }
                    }
                    Algorithm::Scheme(t) => {
                        let (key, v, c) = scheme_setup(t);
                        let server =
                            policy(&[v], &[c], &[KxGroup::Secp384r1], &TlsSignatureScheme::ALL);
                        let client = policy(&[v], &[c], &[KxGroup::Secp384r1], &[t]);
                        if cap.available {
                            handshake(&client, &server, key)
                                .unwrap_or_else(|e| panic!("{a:?}: {e}"));
                        } else {
                            assert_eq!(
                                tls::crypto_provider(&client).err(),
                                Some(CryptoError::Unavailable(a))
                            );
                        }
                    }
                }
            }
        }

        fn sign_and_verify(s: SignatureAlgorithm) -> Result<(), CryptoError> {
            let k = signature::KeyPair::generate(s)?;
            let sig = k.sign(b"m")?;
            signature::verify(s, &k.public_key(), b"m", &sig)
        }

        #[test]
        fn conformance_reference_policies_handshake() {
            let n = handshake(
                &reference_pq_first(),
                &reference_pq_first(),
                SignatureAlgorithm::EcdsaP384Sha384,
            )
            .unwrap();
            assert_eq!(
                (n.version, n.suite, n.kx),
                (
                    TlsVersion::Tls13,
                    CipherSuite::Tls13Aes256GcmSha384,
                    KxGroup::MlKem1024
                )
            );
            let n = handshake(
                &reference_cnsa1(),
                &reference_cnsa1(),
                SignatureAlgorithm::EcdsaP384Sha384,
            )
            .unwrap();
            assert_eq!(
                (n.version, n.suite),
                (TlsVersion::Tls13, CipherSuite::Tls13Aes256GcmSha384)
            );
            let legacy = policy(
                &[TlsVersion::Tls12],
                &[CipherSuite::Tls12EcdheRsaAes256GcmSha384],
                &[KxGroup::Secp384r1],
                &TlsSignatureScheme::ALL,
            );
            let n = handshake(
                &legacy,
                &reference_cnsa1(),
                SignatureAlgorithm::Rsa3072Sha384,
            )
            .unwrap();
            assert_eq!(
                (n.version, n.suite),
                (TlsVersion::Tls12, CipherSuite::Tls12EcdheRsaAes256GcmSha384)
            );
        }

        #[test]
        fn conformance_linkage_matches_the_binary() {
            if cfg!(target_os = "linux") {
                let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
                let shared = maps
                    .lines()
                    .any(|l| l.contains("libaws_lc_fips_0_14_2_crypto.so"));
                assert_eq!(shared, MODULE.linkage == Linkage::Dynamic, "{MODULE:?}");
            } else if cfg!(target_os = "macos") {
                let exe = std::env::current_exe().unwrap();
                let out = std::process::Command::new("otool")
                    .arg("-L")
                    .arg(&exe)
                    .output()
                    .unwrap();
                let shared = String::from_utf8_lossy(&out.stdout)
                    .contains("libaws_lc_fips_0_14_2_crypto.dylib");
                assert_eq!(shared, MODULE.linkage == Linkage::Dynamic, "{MODULE:?}");
            }
        }
    };
}
