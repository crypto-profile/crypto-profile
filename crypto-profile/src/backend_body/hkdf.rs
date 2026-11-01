//! HKDF (RFC 5869; SP 800-56C Rev. 2 §5) under a profile.
use crate::{Admitted, CryptoError};
use crypto_profile::{KdfAlgorithm, kdf_info_may_be_empty};
use std::fmt;
use zeroize::Zeroizing;

const fn alg(k: KdfAlgorithm) -> aws_lc_rs::hkdf::Algorithm {
    match k {
        KdfAlgorithm::HkdfSha256 => aws_lc_rs::hkdf::HKDF_SHA256,
        KdfAlgorithm::HkdfSha384 => aws_lc_rs::hkdf::HKDF_SHA384,
        KdfAlgorithm::HkdfSha512 => aws_lc_rs::hkdf::HKDF_SHA512,
    }
}

const ZERO_SALT: [u8; 64] = [0; 64];

const _: () = {
    let mut i = 0;
    while i < KdfAlgorithm::ALL.len() {
        assert!(KdfAlgorithm::ALL[i].hash().output_len() <= ZERO_SALT.len());
        i += 1;
    }
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

/// RFC 5869 HKDF (SP 800-56C Rev. 2 §5) in one call: extract, then expand. The pseudorandom key
/// never leaves the module. `salt` `None` or empty is RFC 5869's default, HashLen zero bytes.
/// `salt` and `info` are treated as non-secret: the module's binding copies them without wiping.
/// `info` binds the key to its use: a purpose label, the parties' identifiers, the public keys
/// each contributed. Refuses, in this order: an algorithm `a`'s profile does not admit, or its
/// module line lacks (`Admitted::admit_kdf`); an empty `info` unless `kdf_info_may_be_empty`; an
/// output outside `1..=algorithm.max_output_len()` bytes; an empty `secret`.
pub fn derive(
    a: &Admitted,
    algorithm: KdfAlgorithm,
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    check(a, algorithm, info)?;
    extract_and_expand(algorithm, secret, salt, info, len)
}

fn check(a: &Admitted, algorithm: KdfAlgorithm, info: &[u8]) -> Result<(), CryptoError> {
    a.admit_kdf(algorithm)?;
    if info.is_empty() && !kdf_info_may_be_empty(a.profile()) {
        return Err(CryptoError::KdfInfoEmpty {
            profile: a.profile(),
        });
    }
    Ok(())
}

/// HKDF without a profile's admission or `info` rule, for derivations inside the crate. Refuses
/// an output outside `1..=algorithm.max_output_len()` bytes, then an empty `secret`. Callers apply
/// the profile's `info` rule (`kdf_info_may_be_empty`) first: an empty `info` reaches the module's
/// non-approved service.
pub(crate) fn extract_and_expand(
    algorithm: KdfAlgorithm,
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    let max_bytes = algorithm.max_output_len();
    if len == 0 || len > max_bytes {
        return Err(CryptoError::KdfOutputLength {
            algorithm,
            bytes: len,
            max_bytes,
        });
    }
    if secret.is_empty() {
        return Err(CryptoError::KdfSecretEmpty);
    }
    let prk = aws_lc_rs::hkdf::Salt::new(alg(algorithm), salt_for(algorithm, salt)).extract(secret);
    let info = [info];
    let okm = prk
        .expand(&info, Len(len))
        .map_err(|_| CryptoError::Primitive)?;
    let mut out = Zeroizing::new(vec![0; len]);
    okm.fill(&mut out[..]).map_err(|_| CryptoError::Primitive)?;
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

    const ON: Options = Options {
        peer_certificates_match_profile: false,
        pq_key_exchange_required: false,
        cnsa1_unclassified_nss: true,
    };

    fn under(
        p: Profile,
        k: KdfAlgorithm,
        secret: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        derive(&admit(p, Options::default()), k, secret, None, info, len)
            .map(|d| d.as_bytes().to_vec())
    }

    fn rfc_case_3_okm() -> Vec<u8> {
        __hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap()
    }

    #[test]
    fn refusals_come_in_admission_info_length_secret_order() {
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
        for p in Profile::ALL {
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
        for k in KdfAlgorithm::ALL {
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
        for k in KdfAlgorithm::ALL {
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
                derive(&a, k, &[7; 32], salt, b"x", 64)
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
                K::HkdfSha256,
                &[0x0b; 22],
                None,
                b"",
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
            derive(&a, K::HkdfSha256, &[0x0b; 22], Some(&salt), &info, 42)
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
                &admit(Profile::Cnsa1, ON),
                K::HkdfSha256,
                &[7; 32],
                None,
                b"x",
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
                &admit(Profile::Cnsa2, ON),
                K::HkdfSha256,
                &[7; 32],
                None,
                b"x",
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
            K::HkdfSha384,
            &[7; 32],
            None,
            b"x",
            32,
        )
        .unwrap();
        assert_eq!(format!("{d:?}"), "DerivedKey { len: 32 }");
    }
}
