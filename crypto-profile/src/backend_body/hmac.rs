//! HMAC (FIPS 198-1) under a profile.
use crate::{Admitted, CryptoError};
use crypto_profile::{MAC_KEY_MAX_BITS, MacAlgorithm, mac_key_floor_bits};
use std::fmt;

const fn alg(m: MacAlgorithm) -> aws_lc_rs::hmac::Algorithm {
    match m {
        MacAlgorithm::HmacSha256 => aws_lc_rs::hmac::HMAC_SHA256,
        MacAlgorithm::HmacSha384 => aws_lc_rs::hmac::HMAC_SHA384,
        MacAlgorithm::HmacSha512 => aws_lc_rs::hmac::HMAC_SHA512,
    }
}

/// An HMAC key whose algorithm and length the profile admits. Its key material is held in the
/// module's HMAC context, which the module clears on drop. Its methods panic only if that context
/// fails.
pub struct Key {
    key: aws_lc_rs::hmac::Key,
    algorithm: MacAlgorithm,
}

/// A full-length HMAC tag. [`Key::verify`] is the only constant-time comparison; comparing
/// `as_ref()` bytes directly is not.
pub struct Tag(aws_lc_rs::hmac::Tag);

impl Key {
    /// A key for `algorithm`. Refuses an algorithm `a`'s profile does not admit, then a key
    /// outside `mac_key_floor_bits(a.profile)..=MAC_KEY_MAX_BITS`. Panics only if the module
    /// fails to initialise the HMAC context.
    pub fn new(a: &Admitted, algorithm: MacAlgorithm, key: &[u8]) -> Result<Key, CryptoError> {
        check(a, algorithm, key)?;
        Ok(Key {
            key: aws_lc_rs::hmac::Key::new(alg(algorithm), key),
            algorithm,
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> MacAlgorithm {
        self.algorithm
    }

    /// The full-length tag over `data`.
    pub fn sign(&self, data: &[u8]) -> Tag {
        Tag(aws_lc_rs::hmac::sign(&self.key, data))
    }

    /// Checks `tag` over `data` in constant time; refuses a tag of any other length.
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
        aws_lc_rs::hmac::verify(&self.key, data, tag).map_err(|_| CryptoError::MacVerify)
    }
}

fn check(a: &Admitted, algorithm: MacAlgorithm, key: &[u8]) -> Result<(), CryptoError> {
    a.admit_mac(algorithm)?;
    let min_bits = mac_key_floor_bits(a.profile);
    if key.len() < min_bits.div_ceil(8) || key.len() > MAC_KEY_MAX_BITS / 8 {
        return Err(CryptoError::MacKeyLength {
            profile: a.profile,
            bytes: key.len(),
            min_bits,
            max_bits: MAC_KEY_MAX_BITS,
        });
    }
    Ok(())
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tag")
            .field("len", &self.0.as_ref().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Algorithm, Options, Profile, admit};
    use MacAlgorithm as M;

    fn key(p: Profile, m: MacAlgorithm, len: usize) -> Result<Key, CryptoError> {
        Key::new(&admit(p, Options::default()), m, &vec![7; len])
    }

    #[test]
    fn admission_is_checked_before_length() {
        assert_eq!(
            key(Profile::Cnsa2, M::HmacSha256, 1).err(),
            Some(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Mac(M::HmacSha256),
            })
        );
    }

    #[test]
    fn the_unclassified_nss_option_admits_hmac_sha256_under_cnsa1_only() {
        let on = Options {
            cnsa1_unclassified_nss: true,
            ..Options::default()
        };
        assert!(Key::new(&admit(Profile::Cnsa1, on), M::HmacSha256, &[7; 32]).is_ok());
        assert_eq!(
            key(Profile::Cnsa1, M::HmacSha256, 32).err(),
            Some(CryptoError::NotInProfile {
                profile: Profile::Cnsa1,
                algorithm: Algorithm::Mac(M::HmacSha256),
            })
        );
        assert_eq!(
            Key::new(&admit(Profile::Cnsa2, on), M::HmacSha256, &[7; 32]).err(),
            Some(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Mac(M::HmacSha256),
            })
        );
    }

    #[test]
    fn key_length_is_bounded_by_the_profile_and_the_module() {
        let refused = |p, bytes, min_bits| {
            Some(CryptoError::MacKeyLength {
                profile: p,
                bytes,
                min_bits,
                max_bits: 524_288,
            })
        };
        assert_eq!(
            key(Profile::Bsi, M::HmacSha384, 15).err(),
            refused(Profile::Bsi, 15, 128)
        );
        assert!(key(Profile::Bsi, M::HmacSha384, 16).is_ok());
        assert_eq!(
            key(Profile::Fips1403, M::HmacSha384, 13).err(),
            refused(Profile::Fips1403, 13, 112)
        );
        assert!(key(Profile::Fips1403, M::HmacSha384, 14).is_ok());
        assert!(key(Profile::Unrestricted, M::HmacSha512, 65_536).is_ok());
        assert_eq!(
            key(Profile::Unrestricted, M::HmacSha512, 65_537).err(),
            refused(Profile::Unrestricted, 65_537, 112)
        );
    }

    #[test]
    fn a_tag_verifies_only_whole_and_unaltered() {
        for m in MacAlgorithm::ALL {
            let k = key(Profile::Unrestricted, m, 32).unwrap();
            assert_eq!(k.algorithm(), m);
            let tag = k.sign(b"policy").as_ref().to_vec();
            assert_eq!(tag.len(), m.tag_len());
            assert_eq!(k.verify(b"policy", &tag), Ok(()));
            let mut flipped = tag.clone();
            flipped[0] ^= 1;
            let other = MacAlgorithm::ALL.into_iter().find(|o| *o != m).unwrap();
            let other_tag = key(Profile::Unrestricted, other, 32)
                .unwrap()
                .sign(b"policy")
                .as_ref()
                .to_vec();
            for bad in [
                flipped,
                tag[..tag.len() - 1].to_vec(),
                [tag.as_slice(), &[0]].concat(),
                other_tag,
            ] {
                assert_eq!(
                    k.verify(b"policy", &bad),
                    Err(CryptoError::MacVerify),
                    "{m:?}"
                );
            }
            assert_eq!(k.verify(b"policy!", &tag), Err(CryptoError::MacVerify));
        }
    }

    #[test]
    fn debug_shows_no_key_or_tag_bytes() {
        let k = key(Profile::Unrestricted, M::HmacSha384, 32).unwrap();
        assert_eq!(format!("{k:?}"), "Key { algorithm: HmacSha384 }");
        assert_eq!(format!("{:?}", k.sign(b"x")), "Tag { len: 48 }");
    }
}
