//! Signature keys: generation, signing, verification, and the SubjectPublicKeyInfo shape check.
use crate::{Algorithm, CryptoError, SignatureAlgorithm as S, ensure};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self as sig, KeyPair as _};
use std::fmt;
use zeroize::Zeroizing;

const ID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const ID_ED25519: &str = "1.3.101.112";
const ID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const SECP256R1: &str = "1.2.840.10045.3.1.7";
const SECP384R1: &str = "1.3.132.0.34";
const SECP521R1: &str = "1.3.132.0.35";

/// The SubjectPublicKeyInfo algorithm parameters, as far as [`matches_spki`] reads them.
#[derive(Debug, PartialEq, Eq)]
pub enum SpkiParams {
    /// The parameters field is omitted.
    Absent,
    /// The parameters field is an ASN.1 NULL.
    Null,
    /// A named-curve OID, in dotted form.
    NamedCurve(String),
    /// Any other parameters encoding.
    Other,
}

enum Kind {
    Ecdsa {
        signing: &'static sig::EcdsaSigningAlgorithm,
        verifying: &'static sig::EcdsaVerificationAlgorithm,
        curve: &'static str,
        public_len: usize,
    },
    Ed25519,
    Rsa {
        size: rcgen::RsaKeySize,
        modulus_len: usize,
        public_len: usize,
    },
    MlDsa87,
}

fn kind(a: S) -> Kind {
    match a {
        S::MlDsa87 => Kind::MlDsa87,
        S::EcdsaP256Sha256 => Kind::Ecdsa {
            signing: &sig::ECDSA_P256_SHA256_ASN1_SIGNING,
            verifying: &sig::ECDSA_P256_SHA256_ASN1,
            curve: SECP256R1,
            public_len: 65,
        },
        S::EcdsaP384Sha384 => Kind::Ecdsa {
            signing: &sig::ECDSA_P384_SHA384_ASN1_SIGNING,
            verifying: &sig::ECDSA_P384_SHA384_ASN1,
            curve: SECP384R1,
            public_len: 97,
        },
        S::EcdsaP521Sha384 => Kind::Ecdsa {
            signing: &sig::ECDSA_P521_SHA384_ASN1_SIGNING,
            verifying: &sig::ECDSA_P521_SHA384_ASN1,
            curve: SECP521R1,
            public_len: 133,
        },
        S::EcdsaP521Sha512 => Kind::Ecdsa {
            signing: &sig::ECDSA_P521_SHA512_ASN1_SIGNING,
            verifying: &sig::ECDSA_P521_SHA512_ASN1,
            curve: SECP521R1,
            public_len: 133,
        },
        S::Ed25519 => Kind::Ed25519,
        S::Rsa2048Sha384 => Kind::Rsa {
            size: rcgen::RsaKeySize::_2048,
            modulus_len: 256,
            public_len: 270,
        },
        S::Rsa3072Sha384 => Kind::Rsa {
            size: rcgen::RsaKeySize::_3072,
            modulus_len: 384,
            public_len: 398,
        },
        S::Rsa4096Sha384 => Kind::Rsa {
            size: rcgen::RsaKeySize::_4096,
            modulus_len: 512,
            public_len: 526,
        },
    }
}

pub(crate) fn rcgen_alg(a: S) -> &'static rcgen::SignatureAlgorithm {
    match a {
        S::MlDsa87 => &rcgen::PKCS_ML_DSA_87,
        S::EcdsaP256Sha256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        S::EcdsaP384Sha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        S::EcdsaP521Sha384 => &rcgen::PKCS_ECDSA_P521_SHA384,
        S::EcdsaP521Sha512 => &rcgen::PKCS_ECDSA_P521_SHA512,
        S::Ed25519 => &rcgen::PKCS_ED25519,
        S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => &rcgen::PKCS_RSA_SHA384,
    }
}

/// A pure check that a parsed SubjectPublicKeyInfo is exactly this algorithm's key shape.
/// RSA lengths assume the public exponent 65537, which is what [`KeyPair::generate`] produces.
pub fn matches_spki(
    a: S,
    alg_oid: &str,
    params: &SpkiParams,
    key_len: usize,
    unused_bits: u8,
) -> bool {
    unused_bits == 0
        && match kind(a) {
            Kind::Ecdsa {
                curve, public_len, ..
            } => {
                alg_oid == ID_EC_PUBLIC_KEY
                    && *params == SpkiParams::NamedCurve(curve.to_string())
                    && key_len == public_len
            }
            Kind::Ed25519 => {
                alg_oid == ID_ED25519 && *params == SpkiParams::Absent && key_len == 32
            }
            Kind::Rsa { public_len, .. } => {
                alg_oid == ID_RSA_ENCRYPTION && *params == SpkiParams::Null && key_len == public_len
            }
            Kind::MlDsa87 => {
                alg_oid == ID_ML_DSA_87 && *params == SpkiParams::Absent && key_len == 2592
            }
        }
}

/// A signature key pair. The PKCS#8 encoding is held zeroizing.
pub struct KeyPair {
    alg: S,
    pkcs8: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair({}, ..)", self.alg)
    }
}

impl KeyPair {
    /// A new key pair of algorithm `a`.
    pub fn generate(a: S) -> Result<KeyPair, CryptoError> {
        ensure(Algorithm::Signature(a))?;
        let fail = |_| CryptoError::KeyGeneration(Algorithm::Signature(a));
        let pair = match kind(a) {
            Kind::Rsa { size, .. } => {
                rcgen::KeyPair::generate_rsa_for(rcgen_alg(a), size).map_err(fail)?
            }
            Kind::Ecdsa { .. } | Kind::Ed25519 | Kind::MlDsa87 => {
                rcgen::KeyPair::generate_for(rcgen_alg(a)).map_err(fail)?
            }
        };
        KeyPair::from_pkcs8(a, &Zeroizing::new(pair.serialize_der()))
    }

    /// Loads a PKCS#8 key, refusing one that is not of algorithm `a` (including its RSA size).
    pub fn from_pkcs8(a: S, der: &[u8]) -> Result<KeyPair, CryptoError> {
        ensure(Algorithm::Signature(a))?;
        let bad = |_| CryptoError::PrivateKey;
        let public = match kind(a) {
            Kind::Ecdsa { signing, .. } => sig::EcdsaKeyPair::from_pkcs8(signing, der)
                .map_err(bad)?
                .public_key()
                .as_ref()
                .to_vec(),
            Kind::Ed25519 => sig::Ed25519KeyPair::from_pkcs8(der)
                .map_err(bad)?
                .public_key()
                .as_ref()
                .to_vec(),
            Kind::Rsa { modulus_len, .. } => {
                let k = sig::RsaKeyPair::from_pkcs8(der).map_err(bad)?;
                if k.public_modulus_len() != modulus_len {
                    return Err(CryptoError::PrivateKey);
                }
                k.public_key().as_ref().to_vec()
            }
            Kind::MlDsa87 => sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, der)
                .map_err(bad)?
                .public_key()
                .as_ref()
                .to_vec(),
        };
        Ok(KeyPair {
            alg: a,
            pkcs8: Zeroizing::new(der.to_vec()),
            public,
        })
    }

    /// The key's algorithm.
    pub fn algorithm(&self) -> S {
        self.alg
    }

    /// The key's PKCS#8 encoding.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The raw public key: the bytes of the SubjectPublicKeyInfo `subjectPublicKey` BIT STRING.
    pub fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Signs `msg`. RSA keys sign RSASSA-PKCS1-v1_5 with SHA-384.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        let key = |_| CryptoError::PrivateKey;
        let fail = |_| CryptoError::Sign;
        match kind(self.alg) {
            Kind::Ecdsa { signing, .. } => {
                let k = sig::EcdsaKeyPair::from_pkcs8(signing, &self.pkcs8).map_err(key)?;
                Ok(k.sign(&rng, msg).map_err(fail)?.as_ref().to_vec())
            }
            Kind::Ed25519 => Ok(sig::Ed25519KeyPair::from_pkcs8(&self.pkcs8)
                .map_err(key)?
                .sign(msg)
                .as_ref()
                .to_vec()),
            Kind::Rsa { .. } => {
                let k = sig::RsaKeyPair::from_pkcs8(&self.pkcs8).map_err(key)?;
                let mut out = vec![0u8; k.public_modulus_len()];
                k.sign(&sig::RSA_PKCS1_SHA384, &rng, msg, &mut out)
                    .map_err(fail)?;
                Ok(out)
            }
            Kind::MlDsa87 => {
                let k = sig::PqdsaKeyPair::from_pkcs8(&sig::ML_DSA_87_SIGNING, &self.pkcs8)
                    .map_err(key)?;
                let mut out = vec![0u8; sig::ML_DSA_87_SIGNING.signature_len()];
                let n = k.sign(msg, &mut out).map_err(fail)?;
                out.truncate(n);
                Ok(out)
            }
        }
    }
}

impl rcgen::PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen_alg(self.alg)
    }
}

impl rcgen::SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        KeyPair::sign(self, msg).map_err(|_| rcgen::Error::RingUnspecified)
    }
}

/// Verifies `signature` over `msg` under the raw public key `public_key` of algorithm `a`,
/// refusing an RSA key whose size is not `a`'s.
pub fn verify(a: S, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    ensure(Algorithm::Signature(a))?;
    let v: &dyn sig::VerificationAlgorithm = match kind(a) {
        Kind::Ecdsa { verifying, .. } => verifying,
        Kind::Ed25519 => &sig::ED25519,
        Kind::Rsa { public_len, .. } => {
            if public_key.len() != public_len {
                return Err(CryptoError::Verify);
            }
            &sig::RSA_PKCS1_2048_8192_SHA384
        }
        Kind::MlDsa87 => &sig::ML_DSA_87,
    };
    sig::UnparsedPublicKey::new(v, public_key)
        .verify(msg, signature)
        .map_err(|_| CryptoError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::SignatureAlgorithm as S;

    #[test]
    fn every_algorithm_generates_signs_and_verifies() {
        for a in S::ALL {
            let k = KeyPair::generate(a).unwrap();
            assert_eq!(k.algorithm(), a);
            let sig = k.sign(b"message").unwrap();
            assert_eq!(verify(a, &k.public_key(), b"message", &sig), Ok(()), "{a}");
            assert_eq!(
                verify(a, &k.public_key(), b"messagE", &sig),
                Err(CryptoError::Verify),
                "{a}"
            );
        }
    }

    #[test]
    fn a_key_reloads_from_its_pkcs8() {
        for a in S::ALL {
            let k = KeyPair::generate(a).unwrap();
            let r = KeyPair::from_pkcs8(a, k.pkcs8_der()).unwrap();
            assert_eq!(r.public_key(), k.public_key(), "{a}");
        }
    }

    #[test]
    fn a_key_of_the_wrong_algorithm_or_size_is_refused() {
        let p384 = KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        assert_eq!(
            KeyPair::from_pkcs8(S::Ed25519, p384.pkcs8_der()).err(),
            Some(CryptoError::PrivateKey)
        );
        assert_eq!(
            KeyPair::from_pkcs8(S::EcdsaP384Sha384, b"not a key").err(),
            Some(CryptoError::PrivateKey)
        );
        let rsa2048 = KeyPair::generate(S::Rsa2048Sha384).unwrap();
        assert_eq!(
            KeyPair::from_pkcs8(S::Rsa3072Sha384, rsa2048.pkcs8_der()).err(),
            Some(CryptoError::PrivateKey)
        );
    }

    #[test]
    fn verify_refuses_an_rsa_key_of_the_wrong_size() {
        let k = KeyPair::generate(S::Rsa3072Sha384).unwrap();
        let sig = k.sign(b"m").unwrap();
        assert_eq!(
            verify(S::Rsa3072Sha384, &k.public_key(), b"m", &sig),
            Ok(())
        );
        assert_eq!(
            verify(S::Rsa2048Sha384, &k.public_key(), b"m", &sig),
            Err(CryptoError::Verify)
        );
    }

    #[test]
    fn rcgen_sees_our_key_and_algorithm() {
        for a in S::ALL {
            let k = KeyPair::generate(a).unwrap();
            assert_eq!(
                rcgen::PublicKeyData::der_bytes(&k),
                k.public_key().as_slice(),
                "{a}"
            );
            assert_eq!(rcgen::PublicKeyData::algorithm(&k), rcgen_alg(a), "{a}");
            let sig = rcgen::SigningKey::sign(&k, b"m").unwrap();
            assert_eq!(verify(a, &k.public_key(), b"m", &sig), Ok(()), "{a}");
        }
    }

    #[test]
    fn spki_shapes() {
        let ec = |c: &str| SpkiParams::NamedCurve(c.to_string());
        let cases = [
            (S::MlDsa87, ID_ML_DSA_87, SpkiParams::Absent, 2592),
            (S::EcdsaP256Sha256, ID_EC_PUBLIC_KEY, ec(SECP256R1), 65),
            (S::EcdsaP384Sha384, ID_EC_PUBLIC_KEY, ec(SECP384R1), 97),
            (S::EcdsaP521Sha384, ID_EC_PUBLIC_KEY, ec(SECP521R1), 133),
            (S::EcdsaP521Sha512, ID_EC_PUBLIC_KEY, ec(SECP521R1), 133),
            (S::Ed25519, ID_ED25519, SpkiParams::Absent, 32),
            (S::Rsa2048Sha384, ID_RSA_ENCRYPTION, SpkiParams::Null, 270),
            (S::Rsa3072Sha384, ID_RSA_ENCRYPTION, SpkiParams::Null, 398),
            (S::Rsa4096Sha384, ID_RSA_ENCRYPTION, SpkiParams::Null, 526),
        ];
        assert_eq!(cases.len(), S::ALL.len());
        for (a, oid, params, len) in &cases {
            assert!(matches_spki(*a, oid, params, *len, 0), "{a}");
            assert!(!matches_spki(*a, oid, params, *len, 1), "{a} unused bits");
            assert!(!matches_spki(*a, oid, params, *len + 1, 0), "{a} length");
            assert!(
                !matches_spki(*a, oid, &SpkiParams::Other, *len, 0),
                "{a} params"
            );
            assert!(!matches_spki(*a, "1.2.3", params, *len, 0), "{a} oid");
            assert_eq!(
                KeyPair::generate(*a).unwrap().public_key().len(),
                *len,
                "{a} generated length"
            );
        }
    }

    #[test]
    fn debug_never_prints_key_material() {
        let k = KeyPair::generate(S::Ed25519).unwrap();
        assert_eq!(format!("{k:?}"), "KeyPair(ed25519, ..)");
    }
}
