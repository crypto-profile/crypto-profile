//! Shared conformance data and helpers for `crypto-profile` backends.
use crate::{Algorithm, CryptoError, Module, SignatureAlgorithm, TlsSignatureScheme, capability};

mod aead_tests;
#[doc(hidden)]
pub mod golden;
mod key_agreement_tests;
mod peer_certificate_tests;
mod peer_identity_tests;
mod profile_tests;

#[doc(hidden)]
pub use hex as __hex;
#[doc(hidden)]
pub use serde_json as __serde_json;

/// One Wycheproof signature case: `(public key, message, signature, result, tcId)`.
#[doc(hidden)]
pub type SigCase = (Vec<u8>, Vec<u8>, Vec<u8>, String, u64);

/// The signature-verification cases of a Wycheproof file; `pk_field` and `pk_sub` name where
/// each test group carries its raw public key. A case with a non-empty ML-DSA `ctx` is skipped,
/// because the backends verify under the empty context only.
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
            if !t["ctx"].as_str().unwrap_or_default().is_empty() {
                continue;
            }
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

/// The fields of a `CryptoError::EmptyProfile`, which a backend cannot build to compare against.
#[doc(hidden)]
pub fn __empty_profile(e: &CryptoError) -> Option<(crate::Profile, crate::Options, crate::Family)> {
    match *e {
        CryptoError::EmptyProfile {
            profile,
            options,
            category,
        } => Some((profile, options, category)),
        _ => None,
    }
}

/// The handshake schemes a test peer offers on `module`: every scheme the module has.
#[doc(hidden)]
pub fn __peer_schemes(module: Module) -> Vec<TlsSignatureScheme> {
    TlsSignatureScheme::ALL
        .iter()
        .copied()
        .filter(|t| capability(module, Algorithm::Scheme(*t)).available)
        .collect()
}

/// What a handshake whose server key is a fresh `key` gives when the client lists no scheme for
/// it: `no_scheme`, or, on a module without `key`, the refusal to generate that key.
#[doc(hidden)]
pub fn __unlisted_key(
    module: Module,
    key: SignatureAlgorithm,
    no_scheme: &str,
) -> Result<u16, String> {
    let a = Algorithm::Signature(key);
    if capability(module, a).available {
        Err(no_scheme.to_string())
    } else {
        Err(CryptoError::Unavailable(a).to_string())
    }
}

/// Whether `name` can be a shared library's name without its `lib` prefix and extension: not
/// empty, and no path separator or control character.
#[doc(hidden)]
pub fn __library_basename(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Linkage, ModuleLine, Options};

    const M3S: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Static,
    };
    const M3D: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Dynamic,
    };
    const M4S: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Static,
    };
    const M4D: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Dynamic,
    };

    #[test]
    fn the_profile_suite_hands_a_3x_module_only_what_it_has() {
        let ml_dsa = SignatureAlgorithm::MlDsa87;
        for m in [M3S, M3D] {
            assert!(
                __peer_schemes(m)
                    .iter()
                    .all(|t| capability(m, Algorithm::Scheme(*t)).available),
                "{m:?}"
            );
            let missing: Vec<Algorithm> = Algorithm::all()
                .into_iter()
                .filter(|a| !capability(m, *a).available)
                .collect();
            assert_eq!(
                missing,
                [
                    Algorithm::Signature(ml_dsa),
                    Algorithm::Scheme(TlsSignatureScheme::MlDsa87),
                ],
                "{m:?}"
            );
            for g in golden::GOLDEN {
                let o = Options {
                    peer_certificates_match_profile: false,
                    pq_key_exchange_required: g.pq,
                    cnsa1_unclassified_nss: false,
                };
                if let Ok(row) = golden::expected(m, g.profile, o) {
                    assert!(!row.schemes.contains(&0x0906));
                    assert!(!row.keys.contains(&"ml-dsa-87"));
                }
            }
            assert_eq!(
                __unlisted_key(m, ml_dsa, "no scheme"),
                Err("Signature(MlDsa87) is not available on this backend's module".to_string())
            );
            assert_eq!(
                __unlisted_key(m, SignatureAlgorithm::Ed25519, "no scheme"),
                Err("no scheme".to_string())
            );
        }
    }

    #[test]
    fn the_profile_suite_helpers_change_nothing_on_4x() {
        for m in [M4S, M4D] {
            assert_eq!(__peer_schemes(m), TlsSignatureScheme::ALL);
            assert_eq!(
                __unlisted_key(m, SignatureAlgorithm::MlDsa87, "no scheme"),
                Err("no scheme".to_string())
            );
        }
    }

    #[test]
    fn a_library_name_is_a_bare_basename() {
        for ok in ["aws_lc_fips_0_14_2_crypto", "crypto"] {
            assert!(__library_basename(ok), "{ok}");
        }
        for bad in ["", "a/crypto", "a\\crypto", "crypto\n", "cry\0pto"] {
            assert!(!__library_basename(bad), "{bad:?}");
        }
    }

    #[test]
    fn cavp_short_honours_len() {
        let file = "[L = 32]\r\n\r\nLen = 0\r\nMsg = 00\r\nMD = aa\r\n\r\nLen = 16\r\nMsg = 0102\r\nMD = bbcc\r\n\r\nLen = 8\r\nMsg = 0102\r\nMD = dd\r\n";
        assert_eq!(
            __cavp_short(file),
            vec![
                (vec![], vec![0xaa]),
                (vec![1, 2], vec![0xbb, 0xcc]),
                (vec![1], vec![0xdd]),
            ]
        );
    }

    #[test]
    fn signature_cases_read_the_named_key_field() {
        let file = r#"{"testGroups":[
            {"publicKey":{"pk":"01"},"flat":"02","tests":[{"tcId":7,"msg":"03","sig":"04","result":"valid"}]},
            {"publicKey":{"pk":"05"},"flat":"06","tests":[{"tcId":8,"msg":"","sig":"07","result":"invalid"},{"tcId":9,"msg":"","sig":"07","ctx":"08","result":"valid"}]}
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
    fn mac_cases_carry_their_group_tag_size() {
        assert!(__wycheproof_mac_cases("not json").is_empty());
        let mac = __wycheproof_mac_cases(vectors::HMAC_SHA384);
        assert_eq!(mac.len(), 174);
        let first = &mac[0];
        assert_eq!(
            (
                first.tc_id,
                first.tag_bits,
                first.key.len(),
                first.msg.len(),
                first.tag.len()
            ),
            (1, 384, 48, 0, 48)
        );
        assert_eq!(first.result, "valid");
        let mut sizes: Vec<u64> = mac.iter().map(|c| c.tag_bits).collect();
        sizes.dedup();
        sizes.sort_unstable();
        sizes.dedup();
        assert_eq!(sizes, [192, 384]);
        assert!(
            mac.iter()
                .all(|c| c.tag.len() as u64 * 8 == c.tag_bits || c.result == "invalid")
        );
    }

    #[test]
    fn kdf_cases_carry_every_field() {
        assert!(__wycheproof_kdf_cases("not json").is_empty());
        let kdf = __wycheproof_kdf_cases(vectors::HKDF_SHA256);
        assert_eq!(kdf.len(), 86);
        let first = &kdf[0];
        assert_eq!(
            (
                first.tc_id,
                first.ikm.len(),
                first.salt.len(),
                first.info.len(),
                first.size,
                first.okm.len()
            ),
            (1, 22, 13, 10, 42, 42)
        );
        assert_eq!(first.result, "valid");
        for (file, total, too_large) in [
            (vectors::HKDF_SHA256, 86, 8161),
            (vectors::HKDF_SHA384, 83, 12241),
            (vectors::HKDF_SHA512, 83, 16321),
        ] {
            let kdf = __wycheproof_kdf_cases(file);
            assert_eq!(kdf.len(), total);
            let invalid: Vec<&KdfCase> = kdf.iter().filter(|c| c.result == "invalid").collect();
            assert_eq!(invalid.len(), 3, "{too_large}");
            assert!(
                invalid
                    .iter()
                    .all(|c| c.size == too_large && c.okm.is_empty() && !c.info.is_empty()),
                "{too_large}"
            );
        }
    }

    #[test]
    fn ecdh_cases_carry_every_field() {
        assert!(__wycheproof_ecdh_cases("not json").is_empty());
        for (file, total, first_private) in [
            (vectors::ECDH_P256, 355, 32),
            (vectors::ECDH_P384, 790, 48),
            (vectors::ECDH_P521, 661, 66),
            (vectors::X25519, 518, 32),
        ] {
            let cases = __wycheproof_ecdh_cases(file);
            assert_eq!(cases.len(), total);
            let first = &cases[0];
            assert_eq!((first.tc_id, first.private.len()), (1, first_private));
            assert_eq!(first.result, "valid");
            assert!(!first.public.is_empty() && !first.shared.is_empty());
            assert!(!first.flags.is_empty());
        }
    }

    #[test]
    fn a_scalar_is_fixed_to_the_field_length() {
        assert_eq!(__fixed_len_scalar(&[0, 0, 1, 2], 3), [0, 1, 2]);
        assert_eq!(__fixed_len_scalar(&[1, 2], 4), [0, 0, 1, 2]);
        assert_eq!(__fixed_len_scalar(&[0, 0], 2), [0, 0]);
        assert_eq!(__fixed_len_scalar(&[3, 2, 1], 2), [3, 2, 1]);
    }

    #[test]
    fn one_step_cases_carry_every_field() {
        assert!(__acvp_one_step_cases("not json").is_empty());
        let cases = __acvp_one_step_cases(vectors::KDA_ONE_STEP);
        assert_eq!(cases.len(), 78);
        for (hash, count) in [("SHA2-256", 23), ("SHA2-384", 10), ("SHA2-512", 45)] {
            assert_eq!(
                cases.iter().filter(|c| c.hash == hash).count(),
                count,
                "{hash}"
            );
        }
        assert!(cases.iter().all(|c| !c.z.is_empty()
            && !c.fixed_info.is_empty()
            && !c.dkm.is_empty()
            && c.tc_id > 0
            && (c.source == "KDA-OneStep-Sp800-56Cr2" || c.source == "KAS-IFC-Sp800-56Br2")));
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

/// One Wycheproof MAC test.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct MacCase {
    /// The key.
    pub key: Vec<u8>,
    /// The message.
    pub msg: Vec<u8>,
    /// The expected tag, of `tag_bits` bits.
    pub tag: Vec<u8>,
    /// The group's tag size in bits.
    pub tag_bits: u64,
    /// `valid`, `invalid` or `acceptable`.
    pub result: String,
    /// The Wycheproof test-case id.
    pub tc_id: u64,
}

/// Every case of a Wycheproof MAC file, each carrying its group's tag size.
#[doc(hidden)]
pub fn __wycheproof_mac_cases(file: &str) -> Vec<MacCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let d = |x: &serde_json::Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().into_iter().flatten() {
        let tag_bits = g["tagSize"].as_u64().unwrap_or_default();
        for t in g["tests"].as_array().into_iter().flatten() {
            out.push(MacCase {
                key: d(&t["key"]),
                msg: d(&t["msg"]),
                tag: d(&t["tag"]),
                tag_bits,
                result: t["result"].as_str().unwrap_or_default().to_string(),
                tc_id: t["tcId"].as_u64().unwrap_or_default(),
            });
        }
    }
    out
}

/// One Wycheproof HKDF test.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct KdfCase {
    /// The input keying material.
    pub ikm: Vec<u8>,
    /// The salt; empty when the case has none.
    pub salt: Vec<u8>,
    /// The info.
    pub info: Vec<u8>,
    /// The output length in bytes.
    pub size: usize,
    /// The expected output; empty for an invalid case.
    pub okm: Vec<u8>,
    /// `valid` or `invalid`.
    pub result: String,
    /// The Wycheproof test-case id.
    pub tc_id: u64,
}

/// Every case of a Wycheproof HKDF file.
#[doc(hidden)]
pub fn __wycheproof_kdf_cases(file: &str) -> Vec<KdfCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let d = |x: &serde_json::Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().into_iter().flatten() {
        for t in g["tests"].as_array().into_iter().flatten() {
            out.push(KdfCase {
                ikm: d(&t["ikm"]),
                salt: d(&t["salt"]),
                info: d(&t["info"]),
                size: t["size"].as_u64().unwrap_or_default() as usize,
                okm: d(&t["okm"]),
                result: t["result"].as_str().unwrap_or_default().to_string(),
                tc_id: t["tcId"].as_u64().unwrap_or_default(),
            });
        }
    }
    out
}

/// One Wycheproof ECDH (`EcdhEcpointTest`) or X25519 (`XdhComp`) case.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct EcdhCase {
    /// The peer's public key: a SEC 1 point, or 32 bytes for X25519.
    pub public: Vec<u8>,
    /// The private key: a big-endian integer of any length, or 32 bytes for X25519.
    pub private: Vec<u8>,
    /// The shared secret; empty for an invalid case.
    pub shared: Vec<u8>,
    /// `valid`, `acceptable` or `invalid`.
    pub result: String,
    /// The case's flags.
    pub flags: Vec<String>,
    /// The Wycheproof test-case id.
    pub tc_id: u64,
}

/// Every case of a Wycheproof ECDH point or X25519 file.
#[doc(hidden)]
pub fn __wycheproof_ecdh_cases(file: &str) -> Vec<EcdhCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let d = |x: &serde_json::Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    let mut out = Vec::new();
    for g in v["testGroups"].as_array().into_iter().flatten() {
        for t in g["tests"].as_array().into_iter().flatten() {
            out.push(EcdhCase {
                public: d(&t["public"]),
                private: d(&t["private"]),
                shared: d(&t["shared"]),
                result: t["result"].as_str().unwrap_or_default().to_string(),
                flags: t["flags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect(),
                tc_id: t["tcId"].as_u64().unwrap_or_default(),
            });
        }
    }
    out
}

/// A big-endian integer as exactly `len` bytes: leading zero bytes dropped, then left-padded with
/// zeros. One that is still longer than `len` is returned unpadded.
#[doc(hidden)]
pub fn __fixed_len_scalar(integer: &[u8], len: usize) -> Vec<u8> {
    let digits = &integer[integer.iter().take_while(|b| **b == 0).count()..];
    let mut out = vec![0; len.saturating_sub(digits.len())];
    out.extend_from_slice(digits);
    out
}

/// One one-step KDF known answer, transcribed from a NIST ACVP sample.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct OneStepCase {
    /// The ACVP algorithm file it comes from.
    pub source: String,
    /// The ACVP test-case id within that file.
    pub tc_id: u64,
    /// The auxiliary hash: `SHA2-256`, `SHA2-384` or `SHA2-512`.
    pub hash: String,
    /// The shared secret.
    pub z: Vec<u8>,
    /// The fixed information, assembled from the case's fields.
    pub fixed_info: Vec<u8>,
    /// The derived keying material.
    pub dkm: Vec<u8>,
}

/// Every case of the transcribed ACVP one-step KDF file.
#[doc(hidden)]
pub fn __acvp_one_step_cases(file: &str) -> Vec<OneStepCase> {
    let v: serde_json::Value = serde_json::from_str(file).unwrap_or_default();
    let d = |x: &serde_json::Value| hex::decode(x.as_str().unwrap_or_default()).unwrap_or_default();
    v.as_array()
        .into_iter()
        .flatten()
        .map(|t| OneStepCase {
            source: t["source"].as_str().unwrap_or_default().to_string(),
            tc_id: t["tcId"].as_u64().unwrap_or_default(),
            hash: t["hash"].as_str().unwrap_or_default().to_string(),
            z: d(&t["z"]),
            fixed_info: d(&t["fixedInfo"]),
            dkm: d(&t["dkm"]),
        })
        .collect()
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
    /// Wycheproof RSA PKCS#1 v1.5, 3072-bit, SHA-384.
    pub const RSA3072_PKCS1_SHA384: &str =
        include_str!("vectors/rsa_signature_3072_sha384_test.json");
    /// Wycheproof RSA PKCS#1 v1.5, 4096-bit, SHA-384.
    pub const RSA4096_PKCS1_SHA384: &str =
        include_str!("vectors/rsa_signature_4096_sha384_test.json");
    /// Wycheproof ML-DSA-87 verification.
    pub const ML_DSA_87: &str = include_str!("vectors/mldsa_87_verify_test.json");
    /// Wycheproof AES-GCM.
    pub const AES_GCM: &str = include_str!("vectors/aes_gcm_test.json");
    /// Wycheproof ChaCha20-Poly1305.
    pub const CHACHA20_POLY1305: &str = include_str!("vectors/chacha20_poly1305_test.json");
    /// Wycheproof HMAC-SHA256.
    pub const HMAC_SHA256: &str = include_str!("vectors/hmac_sha256_test.json");
    /// Wycheproof HMAC-SHA384.
    pub const HMAC_SHA384: &str = include_str!("vectors/hmac_sha384_test.json");
    /// Wycheproof HMAC-SHA512.
    pub const HMAC_SHA512: &str = include_str!("vectors/hmac_sha512_test.json");
    /// RFC 5869 HKDF-SHA256 test cases 1-3.
    pub const HKDF_RFC5869: &str = include_str!("vectors/hkdf_rfc5869.json");
    /// Wycheproof HKDF-SHA256.
    pub const HKDF_SHA256: &str = include_str!("vectors/hkdf_sha256_test.json");
    /// Wycheproof HKDF-SHA384.
    pub const HKDF_SHA384: &str = include_str!("vectors/hkdf_sha384_test.json");
    /// Wycheproof HKDF-SHA512.
    pub const HKDF_SHA512: &str = include_str!("vectors/hkdf_sha512_test.json");
    /// Wycheproof ECDH on P-256, raw points.
    pub const ECDH_P256: &str = include_str!("vectors/ecdh_secp256r1_ecpoint_test.json");
    /// Wycheproof ECDH on P-384, raw points.
    pub const ECDH_P384: &str = include_str!("vectors/ecdh_secp384r1_ecpoint_test.json");
    /// Wycheproof ECDH on P-521, raw points.
    pub const ECDH_P521: &str = include_str!("vectors/ecdh_secp521r1_ecpoint_test.json");
    /// Wycheproof X25519.
    pub const X25519: &str = include_str!("vectors/x25519_test.json");
    /// NIST ACVP one-step KDF samples, SHA2-256, SHA2-384 and SHA2-512.
    pub const KDA_ONE_STEP: &str = include_str!("vectors/kda_onestep_acvp.json");
    /// NIST CAVP SHA-256 short messages.
    pub const SHA256_SHORT: &str = include_str!("vectors/SHA256ShortMsg.rsp");
    /// NIST CAVP SHA-384 short messages.
    pub const SHA384_SHORT: &str = include_str!("vectors/SHA384ShortMsg.rsp");
    /// NIST CAVP SHA-512 short messages.
    pub const SHA512_SHORT: &str = include_str!("vectors/SHA512ShortMsg.rsp");

    /// RFC 7518 Appendix C: ECDH-ES on P-256 with the Concat KDF (SHA-256), for A128GCM.
    pub mod rfc7518 {
        /// Alice's (the producer's) ephemeral private key `d`, big-endian.
        pub const ALICE_D_HEX: &str =
            "d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a";
        /// Alice's ephemeral public key `epk`, an uncompressed point.
        pub const ALICE_EPK_HEX: &str = "04808d060082c176eed3e776a4ac598cc8672c1779f974eecc9b03411ca5b9495d48b5bfc527dfce53d6ac7115237d031ccff87a0570b77350a9e503ee7305a69b";
        /// Bob's (the consumer's) private key `d`, big-endian.
        pub const BOB_D_HEX: &str =
            "5449836690d75caf29f0dd029ddb31b3ddb8aba9d2d515c5012465e817d4a9dc";
        /// Bob's public key, an uncompressed point.
        pub const BOB_PUBLIC_HEX: &str = "04c1e349cb61ec70248ce801034c3834e1b88ebe1161cb25af38741f785fcfc4c47bc96708ef80952b53f8d2555fe72b841ed04588628b1d378a594939500ec9c9";
        /// The shared secret Z.
        pub const Z_HEX: &str = "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4";
        /// The OtherInfo: AlgorithmID "A128GCM", PartyUInfo "Alice", PartyVInfo "Bob", SuppPubInfo 128.
        pub const OTHER_INFO_HEX: &str =
            "000000074131323847434d00000005416c69636500000003426f6200000080";
        /// The derived content-encryption key.
        pub const CEK_HEX: &str = "56aa8deaf8236d205c2228cd71a7101a";
    }

    /// RFC 9180 Appendix A, base mode: the DHKEM key pairs and shared secret of every suite the
    /// appendix carries (A.1.1, A.3.1, A.6.1).
    pub mod rfc9180 {
        /// One DHKEM base-mode case.
        #[derive(Debug, Clone, Copy)]
        pub struct Case {
            /// The section it comes from.
            pub section: &'static str,
            /// The RFC 9180 §7.1 Table 2 `kem_id`.
            pub kem_id: u16,
            /// `skEm`, the sender's ephemeral private key.
            pub sk_em_hex: &'static str,
            /// `enc`, the sender's ephemeral public key (`pkEm`).
            pub enc_hex: &'static str,
            /// `skRm`, the recipient's private key.
            pub sk_rm_hex: &'static str,
            /// `pkRm`, the recipient's public key.
            pub pk_rm_hex: &'static str,
            /// `shared_secret`, the KEM's output.
            pub shared_secret_hex: &'static str,
        }

        /// A.1.1 (DHKEM(X25519, HKDF-SHA256)), A.3.1 (DHKEM(P-256, HKDF-SHA256)) and A.6.1
        /// (DHKEM(P-521, HKDF-SHA512)). The appendix carries no DHKEM(P-384, HKDF-SHA384) case.
        pub const CASES: &[Case] = &[
            Case {
                section: "A.1.1",
                kem_id: 0x0020,
                sk_em_hex: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
                enc_hex: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
                sk_rm_hex: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
                pk_rm_hex: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
                shared_secret_hex: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
            },
            Case {
                section: "A.3.1",
                kem_id: 0x0010,
                sk_em_hex: "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
                enc_hex: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
                sk_rm_hex: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
                pk_rm_hex: "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
                shared_secret_hex: "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
            },
            Case {
                section: "A.6.1",
                kem_id: 0x0012,
                sk_em_hex: "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b",
                enc_hex: "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0",
                sk_rm_hex: "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847",
                pk_rm_hex: "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64",
                shared_secret_hex: "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818",
            },
        ];
    }

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

        /// A blob sealed by crypto-profile 0.9.0 (`crypto-profile-awslc4`), with its key.
        pub mod release_0_9_0 {
            /// The domain.
            pub const DOMAIN: &[u8] = b"crypto-profile sealbox 0.9.0 golden";
            /// The additional authenticated data.
            pub const AAD: &[u8] = b"crypto-profile 0.9.0 golden aad";
            /// The plaintext.
            pub const PLAINTEXT: &[u8] = b"sealed by crypto-profile 0.9.0";
            /// The recipient's P-384 private key as PKCS#8 DER, hex-encoded.
            pub const PRIVATE_KEY_PKCS8_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104301605a5a345ffab181ad7062a845c03e9f567a1fb169036c692f818ffc048b377ad51be14e7a8703c65e95c3fd4754403a16403620004db56e7d8b2aecccccaea62609b378fe7e2095c772ced07f13738be27fb7070727d2308a5ca587c7cacae32865fa56716a5e07ebafd8551911daefddf62e63f982969af28142b4aebec27ad6b786c80ab93018c661061f0b145736fbb263cbdc5";
            /// The sealed blob, hex-encoded.
            pub const BLOB_HEX: &str = "0104d226c2abec589372bf2eedf632418fe1507df48e39c5302d8742993fbf6677a0856e7aa80085993157fc7b0df59a3f5572a09d1b9c8ca84b63179abd57f07facfdbdffeb3f95fc4f04ed31103dcc5a4c47c1845a2ba38f82883ae8606f87ad0a9038e95c9d0ec64d31dae22c0be4dbcc60f4500c90b6ce6cedf1ffa5dbfa5e7d9c603e1e5a0ebf8db24d315ca5532c44d0d3efff55e08df522d7";
        }

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
        use $crate::conformance::{__cavp_short, __wycheproof_sig_cases, vectors};

        fn policy(
            v: &[TlsVersion],
            c: &[CipherSuite],
            k: &[KxGroup],
            t: &[TlsSignatureScheme],
        ) -> Policy {
            let mut p = Policy::default();
            p.versions = v.to_vec();
            p.cipher_suites = c.to_vec();
            p.kx_groups = k.to_vec();
            p.signature_schemes = t.to_vec();
            p
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
                _ => panic!("{c:?}: no conformance key for this suite"),
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
                _ => panic!("{t:?}: no conformance setup for this scheme"),
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
                &$crate::conformance::__peer_schemes(MODULE),
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
                &$crate::conformance::__peer_schemes(MODULE),
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
                let want = match h {
                    HashAlgorithm::Sha256 => 65,
                    HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => 129,
                    _ => panic!("{h:?}: no CAVP file"),
                };
                assert_eq!(cases.len(), want, "{h:?}");
                for (m, d) in cases {
                    assert_eq!(digest::digest(h, &m), Ok(d), "{h:?}");
                }
            }
        }

        #[test]
        fn conformance_wycheproof_signatures() {
            let p = "publicKey";
            for (a, file, field, sub, want) in [
                (
                    SignatureAlgorithm::EcdsaP256Sha256,
                    vectors::ECDSA_P256,
                    p,
                    "uncompressed",
                    (174, 310),
                ),
                (
                    SignatureAlgorithm::EcdsaP384Sha384,
                    vectors::ECDSA_P384,
                    p,
                    "uncompressed",
                    (194, 310),
                ),
                (
                    SignatureAlgorithm::EcdsaP521Sha512,
                    vectors::ECDSA_P521,
                    p,
                    "uncompressed",
                    (232, 310),
                ),
                (
                    SignatureAlgorithm::Ed25519,
                    vectors::ED25519,
                    p,
                    "pk",
                    (117, 64),
                ),
                (
                    SignatureAlgorithm::Rsa2048Sha384,
                    vectors::RSA_PKCS1_SHA384,
                    "publicKeyAsn",
                    "",
                    (7, 250),
                ),
                (
                    SignatureAlgorithm::Rsa3072Sha384,
                    vectors::RSA3072_PKCS1_SHA384,
                    "publicKeyAsn",
                    "",
                    (7, 251),
                ),
                (
                    SignatureAlgorithm::Rsa4096Sha384,
                    vectors::RSA4096_PKCS1_SHA384,
                    "publicKeyAsn",
                    "",
                    (7, 251),
                ),
                (
                    SignatureAlgorithm::MlDsa87,
                    vectors::ML_DSA_87,
                    p,
                    "",
                    (69, 165),
                ),
            ] {
                let available = capability(MODULE, Algorithm::Signature(a)).available;
                let (mut valid, mut invalid) = (0, 0);
                for (pk, msg, sig, result, id) in __wycheproof_sig_cases(file, field, sub) {
                    let verdict = signature::verify(a, &pk, &msg, &sig);
                    if !available {
                        assert_eq!(
                            verdict,
                            Err(CryptoError::Unavailable(Algorithm::Signature(a))),
                            "{a} tcId {id}"
                        );
                    }
                    let ok = verdict.is_ok();
                    match result.as_str() {
                        "valid" => {
                            valid += 1;
                            if let Some(len) = rsa_public_len(a) {
                                // An RSAPublicKey DER with e = 65537 ends with INTEGER 0x010001.
                                assert!(
                                    pk.len() == len
                                        && pk.ends_with(&[0x02, 0x03, 0x01, 0x00, 0x01]),
                                    "{a} tcId {id}: not an e=65537 key of the algorithm's size"
                                );
                            }
                            if module_refuses(a, id) {
                                assert!(
                                    !ok,
                                    "{a} tcId {id}: now accepted; drop it from module_refuses (#24)"
                                );
                            } else {
                                assert!(ok || !available, "{a} tcId {id}: valid but refused");
                            }
                        }
                        "invalid" => {
                            invalid += 1;
                            assert!(!ok, "{a} tcId {id}: invalid but accepted");
                        }
                        "acceptable" => {}
                        other => panic!("{a} tcId {id}: unknown result {other:?}"),
                    }
                }
                assert_eq!((valid, invalid), want, "{a}");
            }
        }

        // AWS-LC refuses these valid P-256 signatures on aarch64 (#24).
        fn module_refuses(a: SignatureAlgorithm, id: u64) -> bool {
            cfg!(target_arch = "aarch64")
                && matches!(a, SignatureAlgorithm::EcdsaP256Sha256)
                && matches!(id, 483 | 484)
        }

        fn rsa_public_len(a: SignatureAlgorithm) -> Option<usize> {
            match a {
                SignatureAlgorithm::Rsa2048Sha384 => Some(270),
                SignatureAlgorithm::Rsa3072Sha384 => Some(398),
                SignatureAlgorithm::Rsa4096Sha384 => Some(526),
                SignatureAlgorithm::MlDsa87
                | SignatureAlgorithm::EcdsaP256Sha256
                | SignatureAlgorithm::EcdsaP384Sha384
                | SignatureAlgorithm::EcdsaP521Sha384
                | SignatureAlgorithm::EcdsaP521Sha512
                | SignatureAlgorithm::Ed25519 => None,
                _ => panic!("{a}: no expected RSA key length"),
            }
        }

        #[test]
        fn conformance_wycheproof_hmac() {
            let a = admit(Profile::Unrestricted, Options::default());
            for (m, file) in [
                (MacAlgorithm::HmacSha256, vectors::HMAC_SHA256),
                (MacAlgorithm::HmacSha384, vectors::HMAC_SHA384),
                (MacAlgorithm::HmacSha512, vectors::HMAC_SHA512),
            ] {
                let cases = $crate::conformance::__wycheproof_mac_cases(file);
                assert_eq!(cases.len(), 174, "{m:?}");
                let (mut valid, mut invalid, mut truncated) = (0, 0, 0);
                for c in &cases {
                    let k = hmac::Key::new(&a, m, &c.key)
                        .unwrap_or_else(|e| panic!("{m:?} tcId {}: {e}", c.tc_id));
                    let tag = k.sign(&c.msg);
                    let verified = k.verify(&c.msg, &c.tag);
                    if c.tag_bits == 8 * m.tag_len() as u64 {
                        match c.result.as_str() {
                            "valid" => {
                                valid += 1;
                                assert_eq!(
                                    tag.as_ref(),
                                    c.tag.as_slice(),
                                    "{m:?} tcId {}",
                                    c.tc_id
                                );
                                assert_eq!(verified, Ok(()), "{m:?} tcId {}", c.tc_id);
                            }
                            "invalid" => {
                                invalid += 1;
                                assert_eq!(
                                    verified,
                                    Err(CryptoError::MacVerify),
                                    "{m:?} tcId {}",
                                    c.tc_id
                                );
                            }
                            other => panic!("{m:?} tcId {}: unknown result {other:?}", c.tc_id),
                        }
                    } else {
                        truncated += 1;
                        assert_eq!(
                            verified,
                            Err(CryptoError::MacVerify),
                            "{m:?} tcId {}",
                            c.tc_id
                        );
                        if c.result == "valid" {
                            assert_eq!(
                                &tag.as_ref()[..c.tag.len()],
                                c.tag.as_slice(),
                                "{m:?} tcId {}",
                                c.tc_id
                            );
                        }
                    }
                }
                assert_eq!((valid, invalid, truncated), (33, 54, 87), "{m:?}");
            }
        }

        #[test]
        fn conformance_hmac_refusal_matrix() {
            for &(p, off, on) in $crate::conformance::golden::MAC_GOLDEN {
                for (unclassified, admitted) in [(false, off), (true, on)] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    for &m in MacAlgorithm::ALL {
                        let want = if admitted.contains(&m) {
                            Ok(m)
                        } else {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Mac(m),
                            })
                        };
                        assert_eq!(
                            hmac::Key::new(&a, m, &[7; 32]).map(|k| k.algorithm()),
                            want,
                            "{p} {o} {m:?}"
                        );
                    }
                }
            }
        }

        #[test]
        fn conformance_aead_refusal_matrix() {
            for &(p, admitted) in $crate::conformance::golden::AEAD_GOLDEN {
                for unclassified in [false, true] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    assert_eq!(a.aeads(), admitted, "{p} {o}");
                    for &d in AeadAlgorithm::ALL {
                        let want = if admitted.contains(&d) {
                            Ok(())
                        } else {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Aead(d),
                            })
                        };
                        assert_eq!(a.admit_aead(d), want, "{p} {o} {d:?}");
                        assert_eq!(
                            aead::Key::new(&a, d, &vec![7; d.key_len()]).map(|k| k.algorithm()),
                            want.map(|()| d),
                            "{p} {o} {d:?}"
                        );
                    }
                }
            }
        }

        #[test]
        fn conformance_hash_refusal_matrix() {
            for &(p, off, on) in $crate::conformance::golden::HASH_GOLDEN {
                for (unclassified, admitted) in [(false, off), (true, on)] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    assert_eq!(a.hashes(), admitted, "{p} {o}");
                    for &h in HashAlgorithm::ALL {
                        let want = if admitted.contains(&h) {
                            Ok(())
                        } else {
                            Err(CryptoError::NotInProfile {
                                profile: p,
                                algorithm: Algorithm::Hash(h),
                            })
                        };
                        assert_eq!(a.admit_hash(h), want, "{p} {o} {h:?}");
                    }
                }
            }
        }

        #[test]
        fn conformance_rfc5869_hkdf() {
            let v: $crate::conformance::__serde_json::Value =
                $crate::conformance::__serde_json::from_str(vectors::HKDF_RFC5869).unwrap();
            let d = |x: &$crate::conformance::__serde_json::Value| {
                $crate::conformance::__hex::decode(x.as_str().unwrap()).unwrap()
            };
            let cases = v.as_array().unwrap();
            assert_eq!(cases.len(), 3);
            let mut on = Options::default();
            on.cnsa1_unclassified_nss = true;
            let mut profiles = 0;
            for &p in Profile::ALL {
                let a = admit(p, on);
                if !a.kdfs().contains(&KdfAlgorithm::HkdfSha256) {
                    continue;
                }
                profiles += 1;
                for t in cases {
                    let (salt, info) = (d(&t["salt"]), d(&t["info"]));
                    let spec = kdf::Spec::Hkdf {
                        algorithm: KdfAlgorithm::HkdfSha256,
                        salt: Some(&salt),
                        info: &info,
                    };
                    let got = kdf::derive(
                        &a,
                        &d(&t["ikm"]),
                        &spec,
                        t["len"].as_u64().unwrap() as usize,
                    )
                    .map(|k| k.as_bytes().to_vec());
                    let want = if info.is_empty() && p != Profile::Unrestricted {
                        Err(CryptoError::KdfInfoEmpty { profile: p })
                    } else {
                        Ok(d(&t["okm"]))
                    };
                    assert_eq!(got, want, "{p} case {}", t["case"]);
                }
            }
            assert_eq!(profiles, 6);
        }

        #[test]
        fn conformance_wycheproof_hkdf() {
            let mut on = Options::default();
            on.cnsa1_unclassified_nss = true;
            for (k, file, total, valid, empty_info, profiles) in [
                (
                    KdfAlgorithm::HkdfSha256,
                    vectors::HKDF_SHA256,
                    86,
                    83,
                    31,
                    6,
                ),
                (
                    KdfAlgorithm::HkdfSha384,
                    vectors::HKDF_SHA384,
                    83,
                    80,
                    30,
                    7,
                ),
                (
                    KdfAlgorithm::HkdfSha512,
                    vectors::HKDF_SHA512,
                    83,
                    80,
                    30,
                    6,
                ),
            ] {
                let cases = $crate::conformance::__wycheproof_kdf_cases(file);
                assert_eq!(cases.len(), total, "{k:?}");
                let mut exercised = 0;
                for &p in Profile::ALL {
                    let a = admit(p, on);
                    if !a.kdfs().contains(&k) {
                        continue;
                    }
                    exercised += 1;
                    let (mut derived, mut refused_info, mut too_long) = (0, 0, 0);
                    for c in &cases {
                        let spec = kdf::Spec::Hkdf {
                            algorithm: k,
                            salt: Some(&c.salt),
                            info: &c.info,
                        };
                        let got =
                            kdf::derive(&a, &c.ikm, &spec, c.size).map(|d| d.as_bytes().to_vec());
                        match c.result.as_str() {
                            "valid" if c.info.is_empty() && p != Profile::Unrestricted => {
                                refused_info += 1;
                                assert_eq!(
                                    got,
                                    Err(CryptoError::KdfInfoEmpty { profile: p }),
                                    "{p} {k:?} tcId {}",
                                    c.tc_id
                                );
                            }
                            "valid" => {
                                derived += 1;
                                assert_eq!(got, Ok(c.okm.clone()), "{p} {k:?} tcId {}", c.tc_id);
                            }
                            "invalid" => {
                                too_long += 1;
                                assert_eq!(
                                    got,
                                    Err(CryptoError::KdfOutputLength {
                                        algorithm: k,
                                        bytes: c.size,
                                        max_bytes: k.max_output_len(),
                                    }),
                                    "{p} {k:?} tcId {}",
                                    c.tc_id
                                );
                            }
                            other => panic!("{k:?} tcId {}: unknown result {other:?}", c.tc_id),
                        }
                    }
                    let want = if p == Profile::Unrestricted {
                        (valid, 0, 3)
                    } else {
                        (valid - empty_info, empty_info, 3)
                    };
                    assert_eq!((derived, refused_info, too_long), want, "{p} {k:?}");
                }
                assert_eq!(exercised, profiles, "{k:?}");
            }
        }

        fn kdf_spec(k: KdfAlgorithm, info: &[u8]) -> kdf::Spec<'_> {
            match k {
                KdfAlgorithm::HkdfSha256 | KdfAlgorithm::HkdfSha384 | KdfAlgorithm::HkdfSha512 => {
                    kdf::Spec::Hkdf {
                        algorithm: k,
                        salt: None,
                        info,
                    }
                }
                KdfAlgorithm::OneStepSha256
                | KdfAlgorithm::OneStepSha384
                | KdfAlgorithm::OneStepSha512 => kdf::Spec::OneStep {
                    algorithm: k,
                    fixed_info: info,
                },
                _ => panic!("{k:?}: no specification for this KDF"),
            }
        }

        fn other_kind(k: KdfAlgorithm, info: &[u8]) -> kdf::Spec<'_> {
            match kdf_spec(k, info) {
                kdf::Spec::Hkdf { .. } => kdf::Spec::OneStep {
                    algorithm: k,
                    fixed_info: info,
                },
                kdf::Spec::OneStep { .. } => kdf::Spec::Hkdf {
                    algorithm: k,
                    salt: None,
                    info,
                },
                other => panic!("{other:?}: no other kind"),
            }
        }

        #[test]
        fn conformance_kdf_refusal_matrix() {
            for &(p, off, on) in $crate::conformance::golden::KDF_GOLDEN {
                for (unclassified, admitted) in [(false, off), (true, on)] {
                    let mut o = Options::default();
                    o.cnsa1_unclassified_nss = unclassified;
                    let a = admit(p, o);
                    assert_eq!(a.kdfs(), admitted, "{p} {o}");
                    for &k in KdfAlgorithm::ALL {
                        let derive = |spec: &kdf::Spec<'_>| {
                            kdf::derive(&a, &[7; 32], spec, 32).map(|d| d.as_bytes().len())
                        };
                        let not_admitted = Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Kdf(k),
                        });
                        let (want, want_empty) = if !admitted.contains(&k) {
                            (not_admitted, not_admitted)
                        } else if p == Profile::Unrestricted {
                            (Ok(32), Ok(32))
                        } else {
                            (Ok(32), Err(CryptoError::KdfInfoEmpty { profile: p }))
                        };
                        assert_eq!(derive(&kdf_spec(k, b"matrix")), want, "{p} {o} {k:?}");
                        assert_eq!(derive(&kdf_spec(k, b"")), want_empty, "{p} {o} {k:?}");
                        assert_eq!(
                            derive(&other_kind(k, b"matrix")),
                            Err(CryptoError::KdfSpecMismatch { algorithm: k }),
                            "{p} {o} {k:?}"
                        );
                        assert_eq!(
                            derive(&kdf::Spec::Dhkem { algorithm: k }),
                            Err(CryptoError::KdfSpecMismatch { algorithm: k }),
                            "{p} {o} {k:?} DHKEM"
                        );
                    }
                }
            }
        }

        #[test]
        fn conformance_one_step_bounds_under_every_profile() {
            for &p in Profile::ALL {
                let a = admit(p, Options::default());
                for &k in KdfAlgorithm::ALL {
                    let one_step = matches!(kdf_spec(k, b""), kdf::Spec::OneStep { .. });
                    if !one_step || !a.kdfs().contains(&k) {
                        continue;
                    }
                    let derive = |secret: &[u8], info: &[u8], len| {
                        kdf::derive(&a, secret, &kdf_spec(k, info), len).map(|d| d.as_bytes().len())
                    };
                    let empty_info = if p == Profile::Unrestricted {
                        Ok(32)
                    } else {
                        Err(CryptoError::KdfInfoEmpty { profile: p })
                    };
                    assert_eq!(derive(&[7; 32], b"", 32), empty_info, "{p} {k:?}");
                    for len in [0, (1 << 30) + 1] {
                        assert_eq!(
                            derive(&[7; 32], b"x", len),
                            Err(CryptoError::KdfOutputLength {
                                algorithm: k,
                                bytes: len,
                                max_bytes: 1 << 30,
                            }),
                            "{p} {k:?}"
                        );
                    }
                    assert_eq!(
                        derive(&[], b"x", 32),
                        Err(CryptoError::KdfSecretEmpty),
                        "{p} {k:?}"
                    );
                    assert_eq!(derive(&[7; 32], b"x", 1), Ok(1), "{p} {k:?}");
                }
            }
        }

        #[test]
        fn conformance_acvp_one_step_kdf() {
            let a = admit(Profile::Fips1403, Options::default());
            let cases = $crate::conformance::__acvp_one_step_cases(vectors::KDA_ONE_STEP);
            let mut counts = [0; 3];
            for c in &cases {
                let (k, i) = match c.hash.as_str() {
                    "SHA2-256" => (KdfAlgorithm::OneStepSha256, 0),
                    "SHA2-384" => (KdfAlgorithm::OneStepSha384, 1),
                    "SHA2-512" => (KdfAlgorithm::OneStepSha512, 2),
                    other => panic!("{} tcId {}: {other}", c.source, c.tc_id),
                };
                counts[i] += 1;
                let spec = kdf::Spec::OneStep {
                    algorithm: k,
                    fixed_info: &c.fixed_info,
                };
                assert_eq!(
                    kdf::derive(&a, &c.z, &spec, c.dkm.len()).map(|d| d.as_bytes().to_vec()),
                    Ok(c.dkm.clone()),
                    "{} tcId {}",
                    c.source,
                    c.tc_id
                );
            }
            assert_eq!(counts, [23, 10, 45]);
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
            let a = admit(Profile::Fips1403, Options::default());
            let key = sealbox::PrivateKey::from_pkcs8_der(&a, &pkcs8).unwrap();
            let opened = sealbox::open(&a, &key, kat::DOMAIN, &kat::aad(), &blob).unwrap();
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
                        assert_eq!(digest::digest(h, b"").map(|d| d.len()), Ok(h.output_len()));
                    }
                    Algorithm::Mac(m) => {
                        assert!(cap.available, "{m:?}");
                        let key = hmac::Key::new(
                            &admit(Profile::Unrestricted, Options::default()),
                            m,
                            &[7; 32],
                        )
                        .unwrap_or_else(|e| panic!("{m:?}: {e}"));
                        assert_eq!(key.sign(b"").as_ref().len(), m.tag_len(), "{m:?}");
                    }
                    Algorithm::Kdf(k) => {
                        assert!(cap.available, "{k:?}");
                        let unrestricted = admit(Profile::Unrestricted, Options::default());
                        let spec = match k {
                            KdfAlgorithm::HkdfSha256
                            | KdfAlgorithm::HkdfSha384
                            | KdfAlgorithm::HkdfSha512 => kdf::Spec::Hkdf {
                                algorithm: k,
                                salt: None,
                                info: b"capability",
                            },
                            KdfAlgorithm::OneStepSha256
                            | KdfAlgorithm::OneStepSha384
                            | KdfAlgorithm::OneStepSha512 => kdf::Spec::OneStep {
                                algorithm: k,
                                fixed_info: b"capability",
                            },
                            _ => panic!("{k:?}: no capability check for this KDF"),
                        };
                        let len = k.max_output_len().min(16320);
                        let key = kdf::derive(&unrestricted, &[7; 32], &spec, len)
                            .unwrap_or_else(|e| panic!("{k:?}: {e}"));
                        assert_eq!(key.as_bytes().len(), len, "{k:?}");
                    }
                    Algorithm::KeyAgreement(k) => {
                        assert!(cap.available, "{k:?}");
                        let unrestricted = admit(Profile::Unrestricted, Options::default());
                        let spec = kdf::Spec::Hkdf {
                            algorithm: KdfAlgorithm::HkdfSha256,
                            salt: None,
                            info: b"capability",
                        };
                        let recipient = ecdh::EphemeralKey::generate(&unrestricted, k)
                            .unwrap_or_else(|e| panic!("{k:?}: {e}"));
                        let sender = ecdh::EphemeralKey::generate(&unrestricted, k)
                            .unwrap_or_else(|e| panic!("{k:?}: {e}"));
                        let to_recipient = recipient.public_key().to_vec();
                        let to_sender = sender.public_key().to_vec();
                        let sent = sender.agree(&to_recipient, &spec, 32).unwrap();
                        let received = recipient.agree(&to_sender, &spec, 32).unwrap();
                        assert_eq!(sent.as_bytes(), received.as_bytes(), "{k:?}");
                    }
                    Algorithm::Aead(d) => {
                        assert!(cap.available, "{d:?}");
                        let unrestricted = admit(Profile::Unrestricted, Options::default());
                        let key = aead::Key::new(&unrestricted, d, &vec![7; d.key_len()])
                            .unwrap_or_else(|e| panic!("{d:?}: {e}"));
                        let mut buf = b"capability".to_vec();
                        let (nonce, tag) = key.seal_in_place(b"", &mut buf).unwrap();
                        buf.extend_from_slice(&tag);
                        let opened = key.open_in_place(&nonce, b"", &mut buf).unwrap();
                        assert_eq!(opened, b"capability", "{d:?}");
                    }
                    Algorithm::Kx(k) => {
                        let p = policy(
                            &[TlsVersion::Tls13],
                            &[CipherSuite::Tls13Aes256GcmSha384],
                            &[k],
                            &$crate::conformance::__peer_schemes(MODULE),
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
                            &$crate::conformance::__peer_schemes(MODULE),
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
                            .iter()
                            .copied()
                            .filter(|c| c.version() == v)
                            .collect();
                        let p = policy(
                            &[v],
                            &suites,
                            &[KxGroup::Secp384r1],
                            &$crate::conformance::__peer_schemes(MODULE),
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
                        let server = policy(
                            &[v],
                            &[c],
                            &[KxGroup::Secp384r1],
                            &$crate::conformance::__peer_schemes(MODULE),
                        );
                        let client = policy(&[v], &[c], &[KxGroup::Secp384r1], &[t]);
                        if cap.available {
                            let n = handshake(&client, &server, key)
                                .unwrap_or_else(|e| panic!("{a:?}: {e}"));
                            assert_eq!(n.scheme, t, "{a:?}");
                        } else {
                            assert_eq!(
                                tls::crypto_provider(&client).err(),
                                Some(CryptoError::Unavailable(a))
                            );
                        }
                    }
                    _ => panic!("{a:?}: no capability check for this family"),
                }
            }
        }

        fn sign_and_verify(s: SignatureAlgorithm) -> Result<(), CryptoError> {
            let k = signature::KeyPair::generate(s)?;
            let sig = k.sign(b"m")?;
            signature::verify(s, k.public_key(), b"m", &sig)
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
                (n.version, n.suite, n.kx),
                (
                    TlsVersion::Tls13,
                    CipherSuite::Tls13Aes256GcmSha384,
                    KxGroup::Secp384r1
                )
            );
            let legacy = policy(
                &[TlsVersion::Tls12],
                &[CipherSuite::Tls12EcdheRsaAes256GcmSha384],
                &[KxGroup::Secp384r1],
                &$crate::conformance::__peer_schemes(MODULE),
            );
            let n = handshake(
                &legacy,
                &reference_cnsa1(),
                SignatureAlgorithm::Rsa3072Sha384,
            )
            .unwrap();
            assert_eq!(
                (n.version, n.suite, n.kx),
                (
                    TlsVersion::Tls12,
                    CipherSuite::Tls12EcdheRsaAes256GcmSha384,
                    KxGroup::Secp384r1
                )
            );
        }

        #[test]
        fn conformance_runtime_release_matches_the_selected_line() {
            let expected = if MODULE.line == ModuleLine::AwsLcFips3 {
                "3.6.0"
            } else {
                assert_eq!(MODULE.line, ModuleLine::AwsLcFips4);
                "4.2.0"
            };
            assert_eq!(awslc_version(), expected);
        }

        #[test]
        fn conformance_linkage_matches_the_binary() {
            if let Ok(intended) = std::env::var("AWS_LC_FIPS_SYS_STATIC") {
                let expected = match intended.as_str() {
                    "1" => Linkage::Static,
                    "0" => Linkage::Dynamic,
                    other => panic!("invalid intended linkage: {other:?}"),
                };
                assert_eq!(MODULE.linkage, expected, "{MODULE:?}");
            }
            let lib = test_support::FIPS_LIBRARY;
            assert!($crate::conformance::__library_basename(lib), "{lib:?}");
            let named = |path: Option<&str>, file: &str| {
                path.and_then(|p| p.rsplit('/').next()) == Some(file)
            };
            if cfg!(target_os = "linux") {
                let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
                let file = format!("lib{lib}.so");
                let shared = maps
                    .lines()
                    .any(|l| named(l.split_whitespace().nth(5), &file));
                assert_eq!(shared, MODULE.linkage == Linkage::Dynamic, "{MODULE:?}");
            } else if cfg!(target_os = "macos") {
                let exe = std::env::current_exe().unwrap();
                let out = std::process::Command::new("otool")
                    .arg("-L")
                    .arg(&exe)
                    .output()
                    .unwrap();
                let file = format!("lib{lib}.dylib");
                let shared = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|l| named(l.split_whitespace().next(), &file));
                assert_eq!(shared, MODULE.linkage == Linkage::Dynamic, "{MODULE:?}");
            } else {
                panic!("no linkage check for this target");
            }
        }

        mod conformance_profiles {
            $crate::__conformance_profile_tests!($b);
        }

        mod conformance_key_agreement {
            $crate::__conformance_key_agreement_tests!($b);
        }

        mod conformance_aead {
            $crate::__conformance_aead_tests!($b);
        }
    };
}
