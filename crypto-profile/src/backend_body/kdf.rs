//! Key derivation under a profile: HKDF (RFC 5869; SP 800-56C Rev. 2 §5) and the hash-based
//! one-step KDF (SP 800-56C Rev. 2 §4.1, option 1).
use crate::{Admitted, CryptoError};
use aws_lc_rs::kdf::{SskdfDigestAlgorithm, SskdfDigestAlgorithmId, get_sskdf_digest_algorithm};
use crypto_profile::{Algorithm, HashAlgorithm, KdfAlgorithm, kdf_info_may_be_empty};
use std::fmt;
use zeroize::Zeroizing;

fn hkdf_alg(k: KdfAlgorithm) -> Result<aws_lc_rs::hkdf::Algorithm, CryptoError> {
    match k {
        KdfAlgorithm::HkdfSha256 => Ok(aws_lc_rs::hkdf::HKDF_SHA256),
        KdfAlgorithm::HkdfSha384 => Ok(aws_lc_rs::hkdf::HKDF_SHA384),
        KdfAlgorithm::HkdfSha512 => Ok(aws_lc_rs::hkdf::HKDF_SHA512),
        KdfAlgorithm::OneStepSha256 | KdfAlgorithm::OneStepSha384 | KdfAlgorithm::OneStepSha512 => {
            Err(CryptoError::KdfSpecMismatch { algorithm: k })
        }
        _ => Err(CryptoError::Unavailable(Algorithm::Kdf(k))),
    }
}

fn one_step_alg(k: KdfAlgorithm) -> Result<&'static SskdfDigestAlgorithm, CryptoError> {
    let id = match k {
        KdfAlgorithm::OneStepSha256 => SskdfDigestAlgorithmId::Sha256,
        KdfAlgorithm::OneStepSha384 => SskdfDigestAlgorithmId::Sha384,
        KdfAlgorithm::OneStepSha512 => SskdfDigestAlgorithmId::Sha512,
        KdfAlgorithm::HkdfSha256 | KdfAlgorithm::HkdfSha384 | KdfAlgorithm::HkdfSha512 => {
            return Err(CryptoError::KdfSpecMismatch { algorithm: k });
        }
        _ => return Err(CryptoError::Unavailable(Algorithm::Kdf(k))),
    };
    get_sskdf_digest_algorithm(id).ok_or(CryptoError::Unavailable(Algorithm::Kdf(k)))
}

const ZERO_SALT: [u8; 64] = [0; 64];

const _: () = match HashAlgorithm::ALL {
    [a, b, c] => {
        assert!(a.output_len() <= ZERO_SALT.len());
        assert!(b.output_len() <= ZERO_SALT.len());
        assert!(c.output_len() <= ZERO_SALT.len());
    }
    _ => panic!("a new HashAlgorithm: check ZERO_SALT covers its output length"),
};

struct Len(usize);

impl aws_lc_rs::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derived keying material, zeroized on drop. `Debug` prints its length only.
pub struct DerivedKey(Zeroizing<Vec<u8>>);

impl DerivedKey {
    /// The derived bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKey")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A key derivation: the KDF and every input but the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Spec<'a> {
    /// RFC 5869 HKDF (SP 800-56C Rev. 2 §5) in one call: extract, then expand. The pseudorandom
    /// key never leaves the module. `salt` `None` or empty is RFC 5869's default, HashLen zero
    /// bytes. `salt` and `info` are treated as non-secret: the module's binding copies them without
    /// wiping. `info` binds the key to its use: a purpose label, the parties' identifiers, the
    /// public keys each contributed.
    Hkdf {
        /// An HKDF algorithm.
        algorithm: KdfAlgorithm,
        /// The salt.
        salt: Option<&'a [u8]>,
        /// The context and application-specific information.
        info: &'a [u8],
    },
    /// The one-step KDF of SP 800-56C Rev. 2 §4.1 with a hash (option 1): `H(counter || secret ||
    /// fixed_info)` for each 32-bit big-endian counter from 1, truncated to the output length. The
    /// RFC 7518 Concat KDF is this function. `fixed_info` is treated as non-secret and binds the key
    /// to its use, as `info` does for HKDF; the caller encodes it (SP 800-56C Rev. 2 §4.2).
    OneStep {
        /// A one-step algorithm.
        algorithm: KdfAlgorithm,
        /// The fixed information.
        fixed_info: &'a [u8],
    },
}

/// The KDF `spec` names. Refuses one whose algorithm is not of the spec's kind
/// (`CryptoError::KdfSpecMismatch`).
pub(crate) fn matched(spec: &Spec<'_>) -> Result<KdfAlgorithm, CryptoError> {
    match *spec {
        Spec::Hkdf { algorithm, .. } => hkdf_alg(algorithm).map(|_| algorithm),
        Spec::OneStep { algorithm, .. } => one_step_alg(algorithm).map(|_| algorithm),
    }
}

/// The profile's rules for `spec`, after [`matched`]: the KDF's admission
/// (`Admitted::admit_kdf`), an empty `info` or `fixed_info` unless `kdf_info_may_be_empty`, and
/// an output outside `1..=algorithm.max_output_len()` bytes.
pub(crate) fn admitted(a: &Admitted, spec: &Spec<'_>, len: usize) -> Result<(), CryptoError> {
    let (algorithm, info) = match *spec {
        Spec::Hkdf {
            algorithm, info, ..
        } => (algorithm, info),
        Spec::OneStep {
            algorithm,
            fixed_info,
        } => (algorithm, fixed_info),
    };
    a.admit_kdf(algorithm)?;
    if info.is_empty() && !kdf_info_may_be_empty(a.profile()) {
        return Err(CryptoError::KdfInfoEmpty {
            profile: a.profile(),
        });
    }
    output_len(algorithm, len)
}

fn output_len(algorithm: KdfAlgorithm, len: usize) -> Result<(), CryptoError> {
    let max_bytes = algorithm.max_output_len();
    if len == 0 || len > max_bytes {
        return Err(CryptoError::KdfOutputLength {
            algorithm,
            bytes: len,
            max_bytes,
        });
    }
    Ok(())
}

/// Derives `len` bytes from `secret` as `spec` says. Refuses, in this order: a `spec` whose
/// algorithm is not of its kind (`CryptoError::KdfSpecMismatch`); an algorithm `a`'s profile does
/// not admit, or its module line lacks (`Admitted::admit_kdf`); an empty `info` or `fixed_info`
/// unless `kdf_info_may_be_empty`; an output outside `1..=algorithm.max_output_len()` bytes; an
/// empty `secret`.
pub fn derive(
    a: &Admitted,
    secret: &[u8],
    spec: &Spec<'_>,
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    matched(spec)?;
    admitted(a, spec, len)?;
    compute(secret, spec, len)
}

/// `spec` over `secret` without a profile's admission or `info` rule, for derivations inside the
/// crate; callers run [`matched`] and [`admitted`] first.
pub(crate) fn compute(
    secret: &[u8],
    spec: &Spec<'_>,
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    match *spec {
        Spec::Hkdf {
            algorithm,
            salt,
            info,
        } => extract_and_expand(algorithm, secret, salt, info, len),
        Spec::OneStep {
            algorithm,
            fixed_info,
        } => one_step(algorithm, secret, fixed_info, len),
    }
}

/// HKDF without a profile's admission or `info` rule, for derivations inside the crate. Refuses a
/// one-step algorithm, then an output outside `1..=algorithm.max_output_len()` bytes, then an empty
/// `secret`. Callers apply the profile's `info` rule (`kdf_info_may_be_empty`) first: an empty
/// `info` reaches the module's non-approved service.
pub(crate) fn extract_and_expand(
    algorithm: KdfAlgorithm,
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    let hkdf = hkdf_alg(algorithm)?;
    output_len(algorithm, len)?;
    if secret.is_empty() {
        return Err(CryptoError::KdfSecretEmpty);
    }
    let prk = aws_lc_rs::hkdf::Salt::new(hkdf, salt_for(algorithm, salt)).extract(secret);
    let info = [info];
    let okm = prk
        .expand(&info, Len(len))
        .map_err(|_| CryptoError::Primitive)?;
    let mut out = Zeroizing::new(vec![0; len]);
    okm.fill(&mut out[..]).map_err(|_| CryptoError::Primitive)?;
    Ok(DerivedKey(out))
}

fn one_step(
    algorithm: KdfAlgorithm,
    secret: &[u8],
    fixed_info: &[u8],
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    let digest = one_step_alg(algorithm)?;
    output_len(algorithm, len)?;
    if secret.is_empty() {
        return Err(CryptoError::KdfSecretEmpty);
    }
    let mut out = Zeroizing::new(vec![0; len]);
    aws_lc_rs::kdf::sskdf_digest(digest, secret, fixed_info, &mut out[..])
        .map_err(|_| CryptoError::Primitive)?;
    Ok(DerivedKey(out))
}

// The module marks an HKDF call with an empty salt non-approved; HashLen zeros give the same PRK.
fn salt_for(algorithm: KdfAlgorithm, salt: Option<&[u8]>) -> &[u8] {
    match salt {
        Some(s) if !s.is_empty() => s,
        _ => &ZERO_SALT[..algorithm.hash().output_len()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, Options, Profile, admit};
    use KdfAlgorithm as K;
    use crypto_profile::conformance::__hex;

    fn on() -> Options {
        let mut o = Options::default();
        o.cnsa1_unclassified_nss = true;
        o
    }

    fn hkdf<'a>(algorithm: KdfAlgorithm, salt: Option<&'a [u8]>, info: &'a [u8]) -> Spec<'a> {
        Spec::Hkdf {
            algorithm,
            salt,
            info,
        }
    }

    fn under(
        p: Profile,
        k: KdfAlgorithm,
        secret: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        derive(
            &admit(p, Options::default()),
            secret,
            &hkdf(k, None, info),
            len,
        )
        .map(|d| d.as_bytes().to_vec())
    }

    fn rfc_case_3_okm() -> Vec<u8> {
        __hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap()
    }

    const HKDF: [KdfAlgorithm; 3] = [K::HkdfSha256, K::HkdfSha384, K::HkdfSha512];

    #[test]
    fn refusals_come_in_mismatch_admission_info_length_secret_order() {
        for k in [K::OneStepSha256, K::OneStepSha384, K::OneStepSha512] {
            assert_eq!(
                under(Profile::Cnsa2, k, b"", b"", 0),
                Err(CryptoError::KdfSpecMismatch { algorithm: k })
            );
            assert_eq!(
                extract_and_expand(k, b"", None, b"", 0).err(),
                Some(CryptoError::KdfSpecMismatch { algorithm: k })
            );
        }
        assert_eq!(
            under(Profile::Cnsa2, K::HkdfSha256, b"", b"", 0),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Kdf(K::HkdfSha256),
            })
        );
        assert_eq!(
            under(Profile::Fips1403, K::HkdfSha256, b"", b"", 0),
            Err(CryptoError::KdfInfoEmpty {
                profile: Profile::Fips1403
            })
        );
        assert_eq!(
            under(Profile::Unrestricted, K::HkdfSha256, b"", b"", 0),
            Err(CryptoError::KdfOutputLength {
                algorithm: K::HkdfSha256,
                bytes: 0,
                max_bytes: 8160,
            })
        );
        assert_eq!(
            under(Profile::Fips1403, K::HkdfSha256, b"", b"x", 32),
            Err(CryptoError::KdfSecretEmpty)
        );
    }

    #[test]
    fn an_empty_info_derives_under_unrestricted_only() {
        for &p in Profile::ALL {
            let got = under(p, K::HkdfSha384, &[7; 32], b"", 48);
            if p == Profile::Unrestricted {
                assert_eq!(got.map(|v| v.len()), Ok(48));
            } else {
                assert_eq!(got, Err(CryptoError::KdfInfoEmpty { profile: p }), "{p}");
            }
            assert_eq!(
                under(p, K::HkdfSha384, &[7; 32], b"purpose", 48).map(|v| v.len()),
                Ok(48),
                "{p}"
            );
        }
    }

    #[test]
    fn output_length_is_one_to_255_hash_lengths() {
        for k in HKDF {
            let max = k.max_output_len();
            assert_eq!(max, 255 * k.hash().output_len());
            for len in [1, 257, max] {
                assert_eq!(
                    under(Profile::Fips1403, k, &[7; 32], b"x", len).map(|v| v.len()),
                    Ok(len),
                    "{k:?} {len}"
                );
            }
            for len in [0, max + 1] {
                assert_eq!(
                    under(Profile::Fips1403, k, &[7; 32], b"x", len),
                    Err(CryptoError::KdfOutputLength {
                        algorithm: k,
                        bytes: len,
                        max_bytes: max,
                    }),
                    "{k:?} {len}"
                );
            }
        }
    }

    #[test]
    fn a_secret_of_any_nonzero_length_derives() {
        for len in [1, 27, 257, 300] {
            assert!(under(Profile::Fips1403, K::HkdfSha256, &vec![7; len], b"x", 32).is_ok());
        }
        assert_eq!(
            under(Profile::Fips1403, K::HkdfSha256, &[], b"x", 32),
            Err(CryptoError::KdfSecretEmpty)
        );
    }

    #[test]
    fn an_empty_or_absent_salt_becomes_hash_length_zeros_before_the_module() {
        for &k in KdfAlgorithm::ALL {
            let zeros = vec![0; k.hash().output_len()];
            assert_eq!(salt_for(k, None), zeros.as_slice(), "{k:?}");
            assert_eq!(salt_for(k, Some(&[])), zeros.as_slice(), "{k:?}");
            assert_eq!(salt_for(k, Some(&[1, 2])), [1, 2], "{k:?}");
        }
    }

    #[test]
    fn the_salt_default_is_rfc_5869s() {
        let a = admit(Profile::Fips1403, Options::default());
        for (k, block) in [
            (K::HkdfSha256, 64),
            (K::HkdfSha384, 128),
            (K::HkdfSha512, 128),
        ] {
            let with = |salt: Option<&[u8]>| {
                derive(&a, &[7; 32], &hkdf(k, salt, b"x"), 64)
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            };
            let none = with(None);
            assert_eq!(with(Some(&[])), none, "{k:?}");
            assert_eq!(with(Some(&vec![0; k.hash().output_len()])), none, "{k:?}");
            assert_eq!(with(Some(&vec![0; block])), none, "{k:?}");
            assert_ne!(with(Some(&[1])), none, "{k:?}");
        }
        assert_eq!(
            derive(
                &admit(Profile::Unrestricted, Options::default()),
                &[0x0b; 22],
                &hkdf(K::HkdfSha256, None, b""),
                42
            )
            .unwrap()
            .as_bytes(),
            rfc_case_3_okm()
        );
    }

    #[test]
    fn rfc_5869_test_case_1_derives_under_hkdf_sha256() {
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let a = admit(Profile::Fips1403, Options::default());
        assert_eq!(
            derive(&a, &[0x0b; 22], &hkdf(K::HkdfSha256, Some(&salt), &info), 42)
                .unwrap()
                .as_bytes(),
            __hex::decode(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
            .unwrap()
        );
    }

    #[test]
    fn the_unclassified_nss_option_admits_hkdf_sha256_under_cnsa1_only() {
        assert!(
            derive(
                &admit(Profile::Cnsa1, on()),
                &[7; 32],
                &hkdf(K::HkdfSha256, None, b"x"),
                32
            )
            .is_ok()
        );
        assert_eq!(
            under(Profile::Cnsa1, K::HkdfSha256, &[7; 32], b"x", 32),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa1,
                algorithm: Algorithm::Kdf(K::HkdfSha256),
            })
        );
        assert_eq!(
            derive(
                &admit(Profile::Cnsa2, on()),
                &[7; 32],
                &hkdf(K::HkdfSha256, None, b"x"),
                32
            )
            .err(),
            Some(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Kdf(K::HkdfSha256),
            })
        );
    }

    #[test]
    fn the_core_takes_any_info_and_keeps_the_rfc_bounds() {
        assert_eq!(
            extract_and_expand(K::HkdfSha256, &[0x0b; 22], None, b"", 42)
                .unwrap()
                .as_bytes(),
            rfc_case_3_okm()
        );
        assert_eq!(
            extract_and_expand(K::HkdfSha256, &[7], None, b"", 0).err(),
            Some(CryptoError::KdfOutputLength {
                algorithm: K::HkdfSha256,
                bytes: 0,
                max_bytes: 8160,
            })
        );
        assert_eq!(
            extract_and_expand(K::HkdfSha256, &[], None, b"", 32).err(),
            Some(CryptoError::KdfSecretEmpty)
        );
    }

    #[test]
    fn debug_shows_no_derived_bytes() {
        let d = derive(
            &admit(Profile::Unrestricted, Options::default()),
            &[7; 32],
            &hkdf(K::HkdfSha384, None, b"x"),
            32,
        )
        .unwrap();
        assert_eq!(format!("{d:?}"), "DerivedKey { len: 32 }");
    }

    fn one_step<'a>(algorithm: KdfAlgorithm, fixed_info: &'a [u8]) -> Spec<'a> {
        Spec::OneStep {
            algorithm,
            fixed_info,
        }
    }

    const ONE_STEP: [KdfAlgorithm; 3] = [K::OneStepSha256, K::OneStepSha384, K::OneStepSha512];

    fn rfc_7518_z() -> Vec<u8> {
        vec![
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ]
    }

    fn rfc_7518_other_info() -> Vec<u8> {
        vec![
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99, 101, 0, 0, 0, 3,
            66, 111, 98, 0, 0, 0, 128,
        ]
    }

    #[test]
    fn the_one_step_kdf_is_rfc_7518s_concat_kdf() {
        let a = admit(Profile::Fips1403, Options::default());
        let other_info = rfc_7518_other_info();
        assert_eq!(
            derive(
                &a,
                &rfc_7518_z(),
                &one_step(K::OneStepSha256, &other_info),
                16
            )
            .unwrap()
            .as_bytes(),
            [
                86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
            ]
        );
    }

    #[test]
    fn a_spec_of_the_other_kind_is_refused_before_admission() {
        for k in HKDF {
            assert_eq!(
                derive(
                    &admit(Profile::Cnsa2, Options::default()),
                    b"",
                    &one_step(k, b""),
                    0
                )
                .err(),
                Some(CryptoError::KdfSpecMismatch { algorithm: k })
            );
            assert_eq!(
                one_step_core(k, b"", b"", 0).err(),
                Some(CryptoError::KdfSpecMismatch { algorithm: k })
            );
        }
        for k in ONE_STEP {
            assert_eq!(matched(&one_step(k, b"x")), Ok(k), "{k:?}");
            assert_eq!(
                matched(&hkdf(k, None, b"x")),
                Err(CryptoError::KdfSpecMismatch { algorithm: k })
            );
        }
        for k in HKDF {
            assert_eq!(matched(&hkdf(k, None, b"x")), Ok(k), "{k:?}");
        }
    }

    fn one_step_core(
        k: KdfAlgorithm,
        secret: &[u8],
        fixed_info: &[u8],
        len: usize,
    ) -> Result<DerivedKey, CryptoError> {
        super::one_step(k, secret, fixed_info, len)
    }

    #[test]
    fn one_step_refusals_come_in_admission_info_length_secret_order() {
        let derive_under = |p: Profile, k: KdfAlgorithm, secret: &[u8], info: &[u8], len| {
            derive(
                &admit(p, Options::default()),
                secret,
                &one_step(k, info),
                len,
            )
            .map(|d| d.as_bytes().len())
        };
        for p in [Profile::Cnsa2, Profile::Cnsa1, Profile::Bsi] {
            assert_eq!(
                derive_under(p, K::OneStepSha384, b"", b"", 0),
                Err(CryptoError::NotInProfile {
                    profile: p,
                    algorithm: Algorithm::Kdf(K::OneStepSha384),
                })
            );
        }
        assert_eq!(
            derive_under(Profile::Fips1403, K::OneStepSha384, b"", b"", 0),
            Err(CryptoError::KdfInfoEmpty {
                profile: Profile::Fips1403
            })
        );
        assert_eq!(
            derive_under(Profile::Unrestricted, K::OneStepSha384, b"", b"", 0),
            Err(CryptoError::KdfOutputLength {
                algorithm: K::OneStepSha384,
                bytes: 0,
                max_bytes: 1 << 30,
            })
        );
        assert_eq!(
            derive_under(
                Profile::Fips1403,
                K::OneStepSha384,
                b"",
                b"x",
                (1 << 30) + 1
            ),
            Err(CryptoError::KdfOutputLength {
                algorithm: K::OneStepSha384,
                bytes: (1 << 30) + 1,
                max_bytes: 1 << 30,
            })
        );
        assert_eq!(
            derive_under(Profile::Fips1403, K::OneStepSha384, b"", b"x", 48),
            Err(CryptoError::KdfSecretEmpty)
        );
        assert_eq!(
            derive_under(Profile::Unrestricted, K::OneStepSha384, &[7; 32], b"", 48),
            Ok(48)
        );
    }

    #[test]
    fn the_one_step_core_keeps_its_bounds_and_takes_any_fixed_info() {
        for k in ONE_STEP {
            assert_eq!(
                one_step_core(k, &[7; 32], b"", 0).err(),
                Some(CryptoError::KdfOutputLength {
                    algorithm: k,
                    bytes: 0,
                    max_bytes: 1 << 30,
                })
            );
            assert_eq!(
                one_step_core(k, &[7; 32], b"", (1 << 30) + 1).err(),
                Some(CryptoError::KdfOutputLength {
                    algorithm: k,
                    bytes: (1 << 30) + 1,
                    max_bytes: 1 << 30,
                })
            );
            assert_eq!(
                one_step_core(k, &[], b"", 32).err(),
                Some(CryptoError::KdfSecretEmpty)
            );
            for len in [1, k.hash().output_len() + 1, 1000] {
                assert_eq!(
                    one_step_core(k, &[7; 32], b"", len).map(|d| d.as_bytes().len()),
                    Ok(len),
                    "{k:?} {len}"
                );
            }
        }
    }

    #[test]
    fn compute_dispatches_on_the_spec_kind() {
        let info = rfc_7518_other_info();
        assert_eq!(
            compute(&rfc_7518_z(), &one_step(K::OneStepSha256, &info), 16)
                .unwrap()
                .as_bytes()[..2],
            [86, 170]
        );
        assert_eq!(
            compute(&[0x0b; 22], &hkdf(K::HkdfSha256, None, b""), 42)
                .unwrap()
                .as_bytes(),
            rfc_case_3_okm()
        );
    }
}
