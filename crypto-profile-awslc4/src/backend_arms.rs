use crate::{Algorithm, CryptoError, SignatureAlgorithm};
use aws_lc_rs::signature::{self as sig, KeyPair as _};
use zeroize::Zeroizing;

pub(crate) struct MlDsa;

impl MlDsa {
    pub(crate) fn generate() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc = sig::PqdsaKeyPair::generate(&sig::ML_DSA_87_SIGNING)
            .and_then(|k| k.to_pkcs8v1())
            .map_err(|_| {
                CryptoError::KeyGeneration(Algorithm::Signature(SignatureAlgorithm::MlDsa87))
            })?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    pub(crate) fn public_key(der: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, der)
            .map_err(|_| CryptoError::PrivateKey)?
            .public_key()
            .as_ref()
            .to_vec())
    }

    pub(crate) fn sign(der: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, der)
            .map_err(|_| CryptoError::PrivateKey)?;
        let mut out = vec![0u8; sig::ML_DSA_87_SIGNING.signature_len()];
        let n = key.sign(msg, &mut out).map_err(|_| CryptoError::Sign)?;
        out.truncate(n);
        Ok(out)
    }

    pub(crate) fn verifier() -> Result<&'static dyn sig::VerificationAlgorithm, CryptoError> {
        Ok(&sig::ML_DSA_87)
    }

    pub(crate) fn rcgen_alg() -> Result<&'static rcgen::SignatureAlgorithm, CryptoError> {
        Ok(&rcgen::PKCS_ML_DSA_87)
    }

    #[cfg(test)]
    pub(crate) fn fixture44() -> Option<Zeroizing<Vec<u8>>> {
        let doc = sig::PqdsaKeyPair::generate(&sig::ML_DSA_44_SIGNING)
            .ok()?
            .to_pkcs8v1()
            .ok()?;
        Some(Zeroizing::new(doc.as_ref().to_vec()))
    }

    #[cfg(test)]
    pub(crate) fn fixture65() -> Option<Zeroizing<Vec<u8>>> {
        let doc = sig::PqdsaKeyPair::generate(&sig::ML_DSA_65_SIGNING)
            .ok()?
            .to_pkcs8v1()
            .ok()?;
        Some(Zeroizing::new(doc.as_ref().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_roundtrip_and_refusals() {
        let der = MlDsa::generate().unwrap();
        let public = MlDsa::public_key(&der).unwrap();
        let signature = MlDsa::sign(&der, b"message").unwrap();
        assert_eq!(signature.len(), 4627);
        let verifier = sig::UnparsedPublicKey::new(MlDsa::verifier().unwrap(), public);
        assert!(verifier.verify(b"message", &signature).is_ok());
        assert!(verifier.verify(b"different", &signature).is_err());
        assert_eq!(MlDsa::public_key(b"invalid"), Err(CryptoError::PrivateKey));
        assert_eq!(
            MlDsa::sign(b"invalid", b"message"),
            Err(CryptoError::PrivateKey)
        );
        assert_eq!(MlDsa::rcgen_alg().unwrap(), &rcgen::PKCS_ML_DSA_87);
    }

    #[test]
    fn optional_fixtures_have_the_requested_algorithms() {
        for (der, algorithm) in [
            (MlDsa::fixture44().unwrap(), &sig::ML_DSA_44_SIGNING),
            (MlDsa::fixture65().unwrap(), &sig::ML_DSA_65_SIGNING),
        ] {
            assert!(sig::PqdsaKeyPair::from_pkcs8(algorithm, &der).is_ok());
            assert!(sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, &der).is_err());
        }
    }
}
