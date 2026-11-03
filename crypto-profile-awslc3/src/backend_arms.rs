use crate::{Algorithm, CryptoError, SignatureAlgorithm};
use aws_lc_rs::signature as sig;
use zeroize::Zeroizing;

pub(crate) struct MlDsa;

/// An ML-DSA-87 key, which this module line never makes: every constructor refuses.
pub(crate) struct MlDsaKey(());

fn unavailable<T>() -> Result<T, CryptoError> {
    Err(CryptoError::Unavailable(Algorithm::Signature(
        SignatureAlgorithm::MlDsa87,
    )))
}

impl MlDsa {
    pub(crate) fn generate() -> Result<MlDsaKey, CryptoError> {
        unavailable().map(MlDsaKey)
    }
    pub(crate) fn from_pkcs8(_: &[u8]) -> Result<MlDsaKey, CryptoError> {
        unavailable().map(MlDsaKey)
    }
    pub(crate) fn verifier() -> Result<&'static dyn sig::VerificationAlgorithm, CryptoError> {
        Err(CryptoError::Unavailable(Algorithm::Signature(
            SignatureAlgorithm::MlDsa87,
        )))
    }
    pub(crate) fn rcgen_alg() -> Result<&'static rcgen::SignatureAlgorithm, CryptoError> {
        Err(CryptoError::Unavailable(Algorithm::Signature(
            SignatureAlgorithm::MlDsa87,
        )))
    }
    #[cfg(test)]
    pub(crate) fn fixture44() -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    #[cfg(test)]
    pub(crate) fn fixture65() -> Option<Zeroizing<Vec<u8>>> {
        None
    }
}

impl MlDsaKey {
    pub(crate) fn public_key(&self) -> Result<Vec<u8>, CryptoError> {
        unavailable()
    }
    pub(crate) fn sign(&self, _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unavailable()
    }
    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        unavailable()
    }
}

#[cfg(test)]
pub(crate) fn csr_oracle(
    a: SignatureAlgorithm,
) -> Result<&'static dyn rustls::pki_types::SignatureVerificationAlgorithm, CryptoError> {
    Ok(match a {
        SignatureAlgorithm::MlDsa87 => {
            return Err(CryptoError::Unavailable(Algorithm::Signature(
                SignatureAlgorithm::MlDsa87,
            )));
        }
        SignatureAlgorithm::EcdsaP256Sha256 => crate::provider::verify::ECDSA_P256_SHA256,
        SignatureAlgorithm::EcdsaP384Sha384 => crate::provider::verify::ECDSA_P384_SHA384,
        SignatureAlgorithm::EcdsaP521Sha384 => crate::provider::verify::ECDSA_P521_SHA384,
        SignatureAlgorithm::EcdsaP521Sha512 => crate::provider::verify::ECDSA_P521_SHA512,
        SignatureAlgorithm::Ed25519 => crate::provider::verify::ED25519,
        SignatureAlgorithm::Rsa2048Sha384
        | SignatureAlgorithm::Rsa3072Sha384
        | SignatureAlgorithm::Rsa4096Sha384 => crate::provider::verify::RSA_PKCS1_2048_8192_SHA384,
        _ => return Err(CryptoError::Unavailable(Algorithm::Signature(a))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_facade_operation_refuses_the_unavailable_key() {
        let unavailable =
            CryptoError::Unavailable(Algorithm::Signature(SignatureAlgorithm::MlDsa87));
        assert_eq!(MlDsa::generate().err(), Some(unavailable));
        assert_eq!(MlDsa::from_pkcs8(b"invalid").err(), Some(unavailable));
        assert_eq!(MlDsa::verifier().err(), Some(unavailable));
        assert_eq!(MlDsa::rcgen_alg().err(), Some(unavailable));
        assert_eq!(
            csr_oracle(SignatureAlgorithm::MlDsa87).err(),
            Some(unavailable)
        );
        assert!(MlDsa::fixture44().is_none());
        assert!(MlDsa::fixture65().is_none());
        let key = MlDsaKey(());
        assert_eq!(key.public_key(), Err(unavailable));
        assert_eq!(key.sign(b"message"), Err(unavailable));
        assert_eq!(key.to_pkcs8_der(), Err(unavailable));
    }
}
