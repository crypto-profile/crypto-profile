use crate::{Algorithm, CryptoError, SignatureAlgorithm};
use aws_lc_rs::signature as sig;
use zeroize::Zeroizing;

pub(crate) struct MlDsa;
impl MlDsa {
    pub(crate) fn generate() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Err(CryptoError::Unavailable(Algorithm::Signature(
            SignatureAlgorithm::MlDsa87,
        )))
    }
    pub(crate) fn public_key(_: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Unavailable(Algorithm::Signature(
            SignatureAlgorithm::MlDsa87,
        )))
    }
    pub(crate) fn sign(_: &[u8], _: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Unavailable(Algorithm::Signature(
            SignatureAlgorithm::MlDsa87,
        )))
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_facade_operation_refuses_the_unavailable_key() {
        let unavailable =
            CryptoError::Unavailable(Algorithm::Signature(SignatureAlgorithm::MlDsa87));
        assert_eq!(MlDsa::generate(), Err(unavailable));
        assert_eq!(MlDsa::public_key(b"invalid"), Err(unavailable));
        assert_eq!(MlDsa::sign(b"invalid", b"message"), Err(unavailable));
        assert_eq!(MlDsa::verifier().err(), Some(unavailable));
        assert_eq!(MlDsa::rcgen_alg().err(), Some(unavailable));
        assert_eq!(
            csr_oracle(SignatureAlgorithm::MlDsa87).err(),
            Some(unavailable)
        );
        assert!(MlDsa::fixture44().is_none());
        assert!(MlDsa::fixture65().is_none());
    }
}
