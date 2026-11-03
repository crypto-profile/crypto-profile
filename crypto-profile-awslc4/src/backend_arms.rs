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
            .map_err(|_| CryptoError::SignaturePrivateKey {
                algorithm: SignatureAlgorithm::MlDsa87,
            })?
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
pub(crate) fn csr_oracle(
    a: SignatureAlgorithm,
) -> Result<&'static dyn rustls::pki_types::SignatureVerificationAlgorithm, CryptoError> {
    Ok(match a {
        SignatureAlgorithm::MlDsa87 => webpki::aws_lc_rs::ML_DSA_87,
        SignatureAlgorithm::EcdsaP256Sha256 => webpki::aws_lc_rs::ECDSA_P256_SHA256,
        SignatureAlgorithm::EcdsaP384Sha384 => webpki::aws_lc_rs::ECDSA_P384_SHA384,
        SignatureAlgorithm::EcdsaP521Sha384 => webpki::aws_lc_rs::ECDSA_P521_SHA384,
        SignatureAlgorithm::EcdsaP521Sha512 => webpki::aws_lc_rs::ECDSA_P521_SHA512,
        SignatureAlgorithm::Ed25519 => webpki::aws_lc_rs::ED25519,
        SignatureAlgorithm::Rsa2048Sha384
        | SignatureAlgorithm::Rsa3072Sha384
        | SignatureAlgorithm::Rsa4096Sha384 => webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
        _ => return Err(CryptoError::Unavailable(Algorithm::Signature(a))),
    })
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
        assert_eq!(
            MlDsa::public_key(b"invalid"),
            Err(CryptoError::SignaturePrivateKey {
                algorithm: SignatureAlgorithm::MlDsa87
            })
        );
        assert_eq!(
            MlDsa::sign(b"invalid", b"message"),
            Err(CryptoError::PrivateKey)
        );
        assert_eq!(MlDsa::rcgen_alg().unwrap(), &rcgen::PKCS_ML_DSA_87);
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let n = u16::try_from(value.len()).unwrap();
        let [hi, lo] = n.to_be_bytes();
        let len = match n {
            0..=0x7f => vec![lo],
            0x80..=0xff => vec![0x81, lo],
            _ => vec![0x82, hi, lo],
        };
        [&[tag][..], &len, value].concat()
    }

    // RFC 9881 §6 forms of one ML-DSA-87 key, rebuilt around the crate's own seed-form PKCS#8.
    struct Forms {
        public: Vec<u8>,
        seed: Vec<u8>,
        expanded: Vec<u8>,
    }

    impl Forms {
        fn of(der: &[u8]) -> Self {
            use aws_lc_rs::encoding::{AsRawBytes, PqdsaPrivateKeyRaw};
            let key = sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, der).unwrap();
            let raw: PqdsaPrivateKeyRaw<'static> = key.private_key().as_raw_bytes().unwrap();
            assert_eq!(&der[..22], ML_DSA_87_SEED_PREFIX);
            Self {
                public: key.public_key().as_ref().to_vec(),
                seed: der[22..].to_vec(),
                expanded: raw.as_ref().to_vec(),
            }
        }

        fn key(&self, private_key: &[u8], public_key: Option<&[u8]>) -> Vec<u8> {
            let version = [0x02, 0x01, u8::from(public_key.is_some())];
            let algorithm = tlv(0x30, &tlv(0x06, &ML_DSA_87_OID));
            let public = public_key.map_or(Vec::new(), |k| tlv(0x81, &[&[0][..], k].concat()));
            tlv(
                0x30,
                &[&version[..], &algorithm, &tlv(0x04, private_key), &public].concat(),
            )
        }
    }

    const ML_DSA_87_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
    const ML_DSA_87_SEED_PREFIX: &[u8] = &[
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x13, 0x04, 0x22, 0x80, 0x20,
    ];

    #[test]
    fn an_ml_dsa_key_outside_rfc_9881_is_refused_and_every_form_it_defines_is_taken() {
        use crate::signature::KeyPair;
        let a = SignatureAlgorithm::MlDsa87;
        let refused = Some(CryptoError::SignaturePrivateKey { algorithm: a });
        let generated = KeyPair::generate(a).unwrap();
        let f = Forms::of(generated.to_pkcs8_der());
        let other = Forms::of(KeyPair::generate(a).unwrap().to_pkcs8_der());
        let seed = tlv(0x80, &f.seed);
        let both = tlv(0x30, &[tlv(0x04, &f.seed), tlv(0x04, &f.expanded)].concat());
        for der in [
            f.key(&seed, None),
            f.key(&both, None),
            f.key(&seed, Some(&f.public)),
            f.key(&both, Some(&f.public)),
        ] {
            let k = KeyPair::from_pkcs8_der(a, &der).unwrap();
            assert_eq!(k.public_key(), generated.public_key());
        }
        for (why, der) in [
            ("expandedKey alone", f.key(&tlv(0x04, &f.expanded), None)),
            (
                "seed then 05 00",
                f.key(&[&seed[..], &[0x05, 0x00]].concat(), None),
            ),
            (
                "both then 05 00",
                f.key(&[&both[..], &[0x05, 0x00]].concat(), None),
            ),
            (
                "publicKey of another key",
                f.key(&seed, Some(&other.public)),
            ),
            (
                "both, expandedKey of another key",
                f.key(
                    &tlv(
                        0x30,
                        &[tlv(0x04, &f.seed), tlv(0x04, &other.expanded)].concat(),
                    ),
                    None,
                ),
            ),
        ] {
            assert_eq!(KeyPair::from_pkcs8_der(a, &der).err(), refused, "{why}");
        }
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
