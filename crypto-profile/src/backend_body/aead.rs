//! AEAD (RFC 5116) under a profile: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, each with a
//! 96-bit nonce the crate's module call chooses and a 128-bit tag.
use crate::{Admitted, CryptoError, random};
use aws_lc_rs::aead::{
    AES_128_GCM, AES_256_GCM, Aad, Algorithm as ModuleAlgorithm, CHACHA20_POLY1305, LessSafeKey,
    Nonce, RandomizedNonceKey, UnboundKey,
};
use crypto_profile::{AeadAlgorithm, Algorithm};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// The nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// The authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// SP 800-38D §8.3 (p. 21): at most 2^32 invocations of the authenticated encryption function per
/// key when the IV comes from an RBG.
const INVOCATION_LIMIT: u64 = 1 << 32;

enum Sealer {
    Module(RandomizedNonceKey),
    Drawn,
}

/// An AEAD key the profile admits. It seals under nonces chosen inside its own module call, never
/// the caller's, and refuses its 2^32 + 1th seal with `CryptoError::AeadLimit`. It opens under
/// the nonce stored beside a ciphertext. It is not `Clone`, so its seal count cannot be copied.
/// Its key schedule is held in the module's AEAD contexts, which the module clears on drop.
pub struct Key {
    algorithm: AeadAlgorithm,
    sealer: Sealer,
    opener: LessSafeKey,
    invocations: AtomicU64,
}

fn check(a: &Admitted, algorithm: AeadAlgorithm, key: &[u8]) -> Result<(), CryptoError> {
    a.admit_aead(algorithm)?;
    if key.len() != algorithm.key_len() {
        return Err(CryptoError::AeadKeyLength {
            algorithm,
            bytes: key.len(),
        });
    }
    Ok(())
}

fn module_algorithm(d: AeadAlgorithm) -> Result<(&'static ModuleAlgorithm, bool), CryptoError> {
    match d {
        AeadAlgorithm::Aes128Gcm => Ok((&AES_128_GCM, true)),
        AeadAlgorithm::Aes256Gcm => Ok((&AES_256_GCM, true)),
        AeadAlgorithm::Chacha20Poly1305 => Ok((&CHACHA20_POLY1305, false)),
        _ => Err(CryptoError::Unavailable(Algorithm::Aead(d))),
    }
}

fn build(algorithm: AeadAlgorithm, key: &[u8]) -> Result<Key, CryptoError> {
    let (alg, module_nonce) = module_algorithm(algorithm)?;
    let opener = UnboundKey::new(alg, key).map_err(|_| CryptoError::AeadKey)?;
    let sealer = if module_nonce {
        Sealer::Module(RandomizedNonceKey::new(alg, key).map_err(|_| CryptoError::AeadKey)?)
    } else {
        Sealer::Drawn
    };
    Ok(Key {
        algorithm,
        sealer,
        opener: LessSafeKey::new(opener),
        invocations: AtomicU64::new(0),
    })
}

fn plaintext_fits(algorithm: AeadAlgorithm, len: usize) -> Result<(), CryptoError> {
    if len as u64 > algorithm.max_plaintext_len() {
        return Err(CryptoError::AeadPlaintextLength {
            algorithm,
            bytes: len,
        });
    }
    Ok(())
}

impl Key {
    /// A key for `algorithm`. Refuses, in order: an algorithm `a`'s profile does not admit or its
    /// module line lacks (`Admitted::admit_aead`); a key that is not `algorithm.key_len()` bytes
    /// (`CryptoError::AeadKeyLength`); a key the module refuses (`CryptoError::AeadKey`).
    pub fn new(a: &Admitted, algorithm: AeadAlgorithm, key: &[u8]) -> Result<Key, CryptoError> {
        check(a, algorithm, key)?;
        build(algorithm, key)
    }

    /// The algorithm.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Encrypts `buf` in place and returns the nonce and the tag, which the caller stores beside
    /// the ciphertext. AES-GCM draws the nonce inside the module's seal (FIPS 140-3 IG C.H
    /// Scenario 2); ChaCha20-Poly1305 draws it from the module's DRBG. Refuses, in order: a
    /// plaintext longer than `algorithm.max_plaintext_len()` (`CryptoError::AeadPlaintextLength`);
    /// a 2^32 + 1th seal (`CryptoError::AeadLimit`); a module failure (`CryptoError::AeadSeal`, or
    /// `CryptoError::Random`). A seal refused after the length check still counts toward the
    /// limit.
    pub fn seal_in_place(
        &self,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), CryptoError> {
        self.reserve(buf.len())?;
        let (nonce, tag) = match &self.sealer {
            Sealer::Module(k) => {
                let (nonce, tag) = k
                    .seal_in_place_separate_tag(Aad::from(aad), buf)
                    .map_err(|_| CryptoError::AeadSeal)?;
                (*nonce.as_ref(), tag)
            }
            Sealer::Drawn => {
                let mut nonce = [0u8; NONCE_LEN];
                random::fill(&mut nonce)?;
                let tag = self
                    .opener
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad),
                        buf,
                    )
                    .map_err(|_| CryptoError::AeadSeal)?;
                (nonce, tag)
            }
        };
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag.as_ref());
        Ok((nonce, t))
    }

    /// Authenticates and decrypts `buf`, the ciphertext followed by its tag, in place, and returns
    /// the plaintext prefix. Refuses a buffer shorter than the tag, and anything that does not
    /// authenticate under this key, `nonce` and `aad`, with `CryptoError::AeadOpen`. Opening does
    /// not count toward the seal limit.
    pub fn open_in_place<'b>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &'b mut [u8],
    ) -> Result<&'b mut [u8], CryptoError> {
        self.opener
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), buf)
            .map_err(|_| CryptoError::AeadOpen)
    }

    fn reserve(&self, len: usize) -> Result<(), CryptoError> {
        plaintext_fits(self.algorithm, len)?;
        self.invocations
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < INVOCATION_LIMIT).then_some(n + 1)
            })
            .map(|_| ())
            .map_err(|_| CryptoError::AeadLimit {
                algorithm: self.algorithm,
            })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_invocations(&self, n: u64) {
        self.invocations.store(n, Ordering::SeqCst);
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Profile, admit};
    use AeadAlgorithm as D;
    use std::collections::HashSet;

    fn unrestricted() -> Admitted {
        admit(Profile::Unrestricted, Options::default())
    }

    fn key(d: AeadAlgorithm) -> Key {
        Key::new(&unrestricted(), d, &vec![7; d.key_len()]).unwrap()
    }

    fn sealed(k: &Key, aad: &[u8], plain: &[u8]) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut buf = plain.to_vec();
        let (nonce, tag) = k.seal_in_place(aad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        (nonce, buf)
    }

    fn open(
        k: &Key,
        n: &[u8; NONCE_LEN],
        aad: &[u8],
        mut b: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        k.open_in_place(n, aad, &mut b).map(|p| p.to_vec())
    }

    fn count(k: &Key) -> u64 {
        k.invocations.load(Ordering::SeqCst)
    }

    #[test]
    fn refusals_come_in_admission_then_length_order() {
        let cnsa2 = admit(Profile::Cnsa2, Options::default());
        for (d, len) in [
            (D::Aes128Gcm, 16),
            (D::Aes128Gcm, 3),
            (D::Chacha20Poly1305, 3),
        ] {
            assert_eq!(
                Key::new(&cnsa2, d, &vec![7; len]).err(),
                Some(CryptoError::NotInProfile {
                    profile: Profile::Cnsa2,
                    algorithm: Algorithm::Aead(d),
                }),
                "{d:?} {len}"
            );
        }
        for &d in AeadAlgorithm::ALL {
            for len in [0, d.key_len() - 1, d.key_len() + 1, 24] {
                let refused = CryptoError::AeadKeyLength {
                    algorithm: d,
                    bytes: len,
                };
                assert_eq!(
                    check(&unrestricted(), d, &vec![7; len]),
                    Err(refused),
                    "{d:?} {len}"
                );
                assert_eq!(
                    Key::new(&unrestricted(), d, &vec![7; len]).err(),
                    Some(refused)
                );
            }
            assert_eq!(check(&unrestricted(), d, &vec![7; d.key_len()]), Ok(()));
            assert_eq!(key(d).algorithm(), d);
        }
    }

    #[test]
    fn every_algorithm_round_trips_and_refuses_every_alteration() {
        for &d in AeadAlgorithm::ALL {
            let k = key(d);
            let other = Key::new(&unrestricted(), d, &vec![8; d.key_len()]).unwrap();
            for plain in [
                &b""[..],
                b"x",
                b"plaintext of more than one block, to cross a boundary",
            ] {
                let (n, buf) = sealed(&k, b"aad", plain);
                assert_eq!(buf.len(), plain.len() + TAG_LEN);
                assert_eq!(
                    open(&k, &n, b"aad", buf.clone()),
                    Ok(plain.to_vec()),
                    "{d:?}"
                );
                for i in 0..buf.len() {
                    let mut t = buf.clone();
                    t[i] ^= 1;
                    assert_eq!(
                        open(&k, &n, b"aad", t),
                        Err(CryptoError::AeadOpen),
                        "{d:?} {i}"
                    );
                }
                for i in 0..NONCE_LEN {
                    let mut m = n;
                    m[i] ^= 1;
                    assert_eq!(
                        open(&k, &m, b"aad", buf.clone()),
                        Err(CryptoError::AeadOpen)
                    );
                }
                for aad in [&b"aaD"[..], b"", b"aad!"] {
                    assert_eq!(open(&k, &n, aad, buf.clone()), Err(CryptoError::AeadOpen));
                }
                assert_eq!(
                    open(&other, &n, b"aad", buf.clone()),
                    Err(CryptoError::AeadOpen)
                );
            }
            for len in 0..TAG_LEN {
                assert_eq!(
                    open(&k, &[0; NONCE_LEN], b"", vec![0; len]),
                    Err(CryptoError::AeadOpen),
                    "{d:?} {len}"
                );
            }
        }
    }

    #[test]
    fn a_seal_never_repeats_a_nonce_across_two_to_the_sixteen_seals() {
        for &d in AeadAlgorithm::ALL {
            let k = key(d);
            let mut seen = HashSet::new();
            for _ in 0..1 << 16 {
                let (n, _) = k.seal_in_place(b"", &mut []).unwrap();
                assert!(seen.insert(n), "{d:?} repeated {n:02x?}");
            }
        }
    }

    #[test]
    fn the_limit_is_two_to_the_thirty_two_seals() {
        for &d in AeadAlgorithm::ALL {
            let k = key(d);
            k.set_invocations(INVOCATION_LIMIT - 2);
            sealed(&k, b"aad", b"next to last");
            assert_eq!(count(&k), INVOCATION_LIMIT - 1);
            let (n, buf) = sealed(&k, b"aad", b"last");
            assert_eq!(count(&k), INVOCATION_LIMIT);
            let refused = Some(CryptoError::AeadLimit { algorithm: d });
            assert_eq!(k.seal_in_place(b"aad", &mut [0; 4]).err(), refused, "{d:?}");
            assert_eq!(k.seal_in_place(b"", &mut []).err(), refused, "{d:?}");
            assert_eq!(open(&k, &n, b"aad", buf), Ok(b"last".to_vec()), "{d:?}");
            assert_eq!(count(&k), INVOCATION_LIMIT);
        }
    }

    #[test]
    fn a_reserved_seal_is_spent_and_an_open_spends_nothing() {
        let k = key(D::Aes256Gcm);
        let (n, buf) = sealed(&k, b"", b"x");
        assert_eq!(count(&k), 1);
        for _ in 0..3 {
            open(&k, &n, b"", buf.clone()).unwrap();
            assert_eq!(open(&k, &n, b"!", buf.clone()), Err(CryptoError::AeadOpen));
        }
        assert_eq!(count(&k), 1);
        k.set_invocations(INVOCATION_LIMIT - 1);
        assert_eq!(k.reserve(1), Ok(()));
        assert_eq!(
            k.seal_in_place(b"", &mut [0]).err(),
            Some(CryptoError::AeadLimit {
                algorithm: D::Aes256Gcm
            })
        );
    }

    #[test]
    fn concurrent_seals_never_pass_the_limit() {
        const THREADS: usize = 16;
        const LEFT: u64 = 5;
        for &d in AeadAlgorithm::ALL {
            let k = key(d);
            k.set_invocations(INVOCATION_LIMIT - LEFT);
            let results: Vec<Result<(), CryptoError>> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..THREADS)
                    .map(|_| {
                        s.spawn(|| {
                            (0..4)
                                .map(|_| k.seal_in_place(b"", &mut [0; 8]).map(|_| ()))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            });
            let sealed = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(sealed as u64, LEFT, "{d:?}");
            assert!(
                results
                    .iter()
                    .filter(|r| r.is_err())
                    .all(|r| *r == Err(CryptoError::AeadLimit { algorithm: d })),
                "{d:?}"
            );
            assert_eq!(count(&k), INVOCATION_LIMIT);
        }
    }

    #[test]
    fn plaintext_bounds_are_checked_before_the_counter() {
        for &d in AeadAlgorithm::ALL {
            let max = usize::try_from(d.max_plaintext_len()).unwrap();
            assert_eq!(plaintext_fits(d, max), Ok(()));
            assert_eq!(plaintext_fits(d, 0), Ok(()));
            let refused = Err(CryptoError::AeadPlaintextLength {
                algorithm: d,
                bytes: max + 1,
            });
            assert_eq!(plaintext_fits(d, max + 1), refused);
            let k = key(d);
            assert_eq!(k.reserve(max + 1), refused);
            assert_eq!(count(&k), 0);
            k.set_invocations(INVOCATION_LIMIT);
            assert_eq!(k.reserve(max + 1), refused);
            assert_eq!(k.reserve(max), Err(CryptoError::AeadLimit { algorithm: d }));
        }
    }

    #[test]
    fn debug_shows_no_key_material() {
        assert_eq!(
            format!("{:?}", key(D::Aes256Gcm)),
            "Key { algorithm: Aes256Gcm }"
        );
        assert_eq!(
            format!("{:?}", key(D::Chacha20Poly1305)),
            "Key { algorithm: Chacha20Poly1305 }"
        );
    }

    #[test]
    fn the_wire_lengths_are_the_modules() {
        assert_eq!(NONCE_LEN, aws_lc_rs::aead::NONCE_LEN);
        assert_eq!(TAG_LEN, aws_lc_rs::aead::MAX_TAG_LEN);
        assert_eq!(crypto_profile::sealbox_wire::NONCE_LEN, NONCE_LEN);
        assert_eq!(crypto_profile::sealbox_wire::TAG_LEN, TAG_LEN);
        for &d in AeadAlgorithm::ALL {
            let (alg, _) = module_algorithm(d).unwrap();
            assert_eq!(
                (alg.key_len(), alg.tag_len(), alg.nonce_len()),
                (d.key_len(), TAG_LEN, NONCE_LEN),
                "{d:?}"
            );
        }
    }

    #[test]
    fn only_aes_gcm_seals_inside_the_module() {
        for &d in AeadAlgorithm::ALL {
            let inside = matches!(key(d).sealer, Sealer::Module(_));
            assert_eq!(inside, d != D::Chacha20Poly1305, "{d:?}");
            assert_eq!(module_algorithm(d).unwrap().1, inside, "{d:?}");
        }
    }
}
