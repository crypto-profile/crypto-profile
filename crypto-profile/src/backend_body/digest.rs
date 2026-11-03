//! Hashing under a profile: SHA-2 (FIPS 180-4) and SHA-3 (FIPS 202), full-length digests only.
use crate::{Admitted, CryptoError};
use aws_lc_rs::digest::{Algorithm as ModuleAlgorithm, Context};
use crypto_profile::{Algorithm, HashAlgorithm};
use std::fmt;

fn module_algorithm(h: HashAlgorithm) -> Result<&'static ModuleAlgorithm, CryptoError> {
    match h {
        HashAlgorithm::Sha256 => Ok(&aws_lc_rs::digest::SHA256),
        HashAlgorithm::Sha384 => Ok(&aws_lc_rs::digest::SHA384),
        HashAlgorithm::Sha512 => Ok(&aws_lc_rs::digest::SHA512),
        HashAlgorithm::Sha3_256 => Ok(&aws_lc_rs::digest::SHA3_256),
        HashAlgorithm::Sha3_384 => Ok(&aws_lc_rs::digest::SHA3_384),
        HashAlgorithm::Sha3_512 => Ok(&aws_lc_rs::digest::SHA3_512),
        _ => Err(CryptoError::Unavailable(Algorithm::Hash(h))),
    }
}

fn check(a: &Admitted, h: HashAlgorithm) -> Result<(), CryptoError> {
    a.admit_hash(h)
}

/// The full-length digest of `data` under `h`. Refuses, in order, a hash `a`'s profile does not
/// admit or its module line lacks (`Admitted::admit_hash`) and one this backend does not
/// implement (`CryptoError::Unavailable`). Panics only if the module's digest context fails.
pub fn digest(a: &Admitted, h: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check(a, h)?;
    Ok(aws_lc_rs::digest::digest(module_algorithm(h)?, data)
        .as_ref()
        .to_vec())
}

/// An incremental hash under a profile. It is not `Clone`, and `Debug` names its algorithm only.
pub struct Hasher {
    algorithm: HashAlgorithm,
    context: Context,
}

impl Hasher {
    /// A hasher for `h`. Refuses, in order, a hash `a`'s profile does not admit or its module line
    /// lacks (`Admitted::admit_hash`) and one this backend does not implement
    /// (`CryptoError::Unavailable`). Panics only if the module fails to initialise the digest
    /// context.
    pub fn new(a: &Admitted, h: HashAlgorithm) -> Result<Hasher, CryptoError> {
        check(a, h)?;
        Ok(Hasher {
            algorithm: h,
            context: Context::new(module_algorithm(h)?),
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Feeds `data`. Panics only if the module's digest context fails, or if the bytes fed in
    /// total pass `u64::MAX`, where aws-lc-rs stops. A SHA-256 hasher fed 2^61 bytes or more, past
    /// FIPS 180-4's limit, then gives a non-conforming digest from `finish`: the module's bit count
    /// wraps silently.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// The full-length digest of everything fed. Panics only if the module's digest context fails.
    pub fn finish(self) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Profile, admit};
    use HashAlgorithm as H;

    fn unrestricted() -> Admitted {
        admit(Profile::Unrestricted, Options::default())
    }

    fn block_len(h: HashAlgorithm) -> usize {
        match h {
            H::Sha256 => 64,
            H::Sha384 | H::Sha512 => 128,
            H::Sha3_256 => 136,
            H::Sha3_384 => 104,
            H::Sha3_512 => 72,
            other => panic!("{other:?}: no block length"),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_hash_the_profile_does_not_admit_is_refused() {
        let cnsa2 = admit(Profile::Cnsa2, Options::default());
        for h in [H::Sha256, H::Sha3_256, H::Sha3_384, H::Sha3_512] {
            let refused = CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Hash(h),
            };
            assert!(module_algorithm(h).is_ok(), "{h:?}");
            assert_eq!(check(&cnsa2, h), Err(refused), "{h:?}");
            assert_eq!(digest(&cnsa2, h, b"abc"), Err(refused), "{h:?}");
            assert_eq!(Hasher::new(&cnsa2, h).err(), Some(refused), "{h:?}");
        }
        let without = unrestricted().without(Algorithm::Hash(H::Sha384));
        assert_eq!(
            digest(&without, H::Sha384, b""),
            Err(CryptoError::NotInProfile {
                profile: Profile::Unrestricted,
                algorithm: Algorithm::Hash(H::Sha384),
            })
        );
        for &h in HashAlgorithm::ALL {
            assert_eq!(check(&unrestricted(), h), Ok(()), "{h:?}");
            assert_eq!(Hasher::new(&unrestricted(), h).unwrap().algorithm(), h);
        }
    }

    #[test]
    fn each_hash_is_its_modules_algorithm_at_full_length() {
        for &h in HashAlgorithm::ALL {
            let m = module_algorithm(h).unwrap();
            assert_eq!(
                (m.output_len(), m.block_len()),
                (h.output_len(), block_len(h)),
                "{h:?}"
            );
            assert_eq!(
                digest(&unrestricted(), h, b"x").unwrap().len(),
                h.output_len()
            );
        }
    }

    #[test]
    fn abc_known_answers() {
        let a = unrestricted();
        for (h, want) in [
            (
                H::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                H::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                H::Sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ] {
            assert_eq!(hex(&digest(&a, h, b"abc").unwrap()), want, "{h:?}");
        }
    }

    #[test]
    fn streaming_equals_one_shot_across_every_block_boundary() {
        let a = unrestricted();
        for &h in HashAlgorithm::ALL {
            let b = block_len(h);
            let message: Vec<u8> = (0..3 * b + 5).map(|i| (i * 7 + 3) as u8).collect();
            let whole = digest(&a, h, &message).unwrap();
            for split in [0, 1, b - 1, b, b + 1] {
                let mut s = Hasher::new(&a, h).unwrap();
                s.update(&message[..split]);
                s.update(&message[split..]);
                assert_eq!(s.finish(), whole, "{h:?} split at {split}");
            }
            let mut s = Hasher::new(&a, h).unwrap();
            for chunk in message.chunks(b - 1) {
                s.update(chunk);
            }
            assert_eq!(s.finish(), whole, "{h:?} in chunks of {}", b - 1);
            let mut s = Hasher::new(&a, h).unwrap();
            s.update(&[]);
            assert_eq!(s.finish(), digest(&a, h, b"").unwrap(), "{h:?} empty");
        }
    }

    #[test]
    fn debug_names_the_algorithm_only() {
        let mut s = Hasher::new(&unrestricted(), H::Sha3_384).unwrap();
        s.update(b"secret");
        assert_eq!(format!("{s:?}"), "Hasher { algorithm: Sha3_384 }");
    }
}
