//! Hashing.
use crypto_profile::{Algorithm, CryptoError, HashAlgorithm};

fn alg(h: HashAlgorithm) -> Result<&'static aws_lc_rs::digest::Algorithm, CryptoError> {
    match h {
        HashAlgorithm::Sha256 => Ok(&aws_lc_rs::digest::SHA256),
        HashAlgorithm::Sha384 => Ok(&aws_lc_rs::digest::SHA384),
        HashAlgorithm::Sha512 => Ok(&aws_lc_rs::digest::SHA512),
        _ => Err(CryptoError::Unavailable(Algorithm::Hash(h))),
    }
}

/// The digest of `data`. Refuses a hash this backend does not implement with
/// `CryptoError::Unavailable`.
pub fn digest(h: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(aws_lc_rs::digest::digest(alg(h)?, data).as_ref().to_vec())
}

/// An incremental hash.
pub struct Hasher(aws_lc_rs::digest::Context);

impl Hasher {
    /// A hasher for `h`. Refuses a hash this backend does not implement with
    /// `CryptoError::Unavailable`.
    pub fn new(h: HashAlgorithm) -> Result<Self, CryptoError> {
        Ok(Hasher(aws_lc_rs::digest::Context::new(alg(h)?)))
    }

    /// Feeds `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything fed.
    pub fn finish(self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

/// The SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref());
    out
}

/// The lowercase hexadecimal SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abc_known_answers() {
        assert_eq!(
            hex(&digest(HashAlgorithm::Sha256, b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&digest(HashAlgorithm::Sha384, b"abc").unwrap()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(&digest(HashAlgorithm::Sha512, b"abc").unwrap()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn streaming_equals_one_shot() {
        for &h in HashAlgorithm::ALL {
            let mut s = Hasher::new(h).unwrap();
            s.update(b"a");
            s.update(b"bc");
            assert_eq!(Ok(s.finish()), digest(h, b"abc"), "{h:?}");
        }
    }

    #[test]
    fn sha256_shorthands_agree() {
        assert_eq!(
            Ok(sha256(b"abc").to_vec()),
            digest(HashAlgorithm::Sha256, b"abc")
        );
        assert_eq!(
            sha256_hex(b"abc"),
            hex(&digest(HashAlgorithm::Sha256, b"abc").unwrap())
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
