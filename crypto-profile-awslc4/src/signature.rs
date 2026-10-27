//! Signature keys: generation, signing, verification, and the SubjectPublicKeyInfo shape check.
use crate::{Algorithm, CryptoError, SignatureAlgorithm as S, ensure};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
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
const RSA_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

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
        size: KeySize,
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
            size: KeySize::Rsa2048,
            modulus_len: 256,
            public_len: 270,
        },
        S::Rsa3072Sha384 => Kind::Rsa {
            size: KeySize::Rsa3072,
            modulus_len: 384,
            public_len: 398,
        },
        S::Rsa4096Sha384 => Kind::Rsa {
            size: KeySize::Rsa4096,
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
/// RSA lengths assume the public exponent 65537, the only one [`KeyPair::from_pkcs8`] and
/// [`verify`] accept.
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
        let pkcs8 = match kind(a) {
            Kind::Ecdsa { signing, .. } => {
                let doc = sig::EcdsaKeyPair::generate_pkcs8(signing, &SystemRandom::new())
                    .map_err(fail)?;
                Zeroizing::new(doc.as_ref().to_vec())
            }
            Kind::Ed25519 => {
                let doc = sig::Ed25519KeyPair::generate()
                    .and_then(|k| k.to_pkcs8())
                    .map_err(fail)?;
                Zeroizing::new(doc.as_ref().to_vec())
            }
            Kind::Rsa { size, .. } => {
                let der: Pkcs8V1Der<'static> = sig::RsaKeyPair::generate(size)
                    .and_then(|k| k.as_der())
                    .map_err(fail)?;
                Zeroizing::new(der.as_ref().to_vec())
            }
            Kind::MlDsa87 => {
                let doc = sig::PqdsaKeyPair::generate(&sig::ML_DSA_87_SIGNING)
                    .and_then(|k| k.to_pkcs8v1())
                    .map_err(fail)?;
                Zeroizing::new(doc.as_ref().to_vec())
            }
        };
        KeyPair::load(a, pkcs8)
    }

    /// Loads a PKCS#8 key, refusing one that is not of algorithm `a`, including an RSA key of
    /// another size or with a public exponent other than 65537.
    pub fn from_pkcs8(a: S, der: &[u8]) -> Result<KeyPair, CryptoError> {
        ensure(Algorithm::Signature(a))?;
        KeyPair::load(a, Zeroizing::new(der.to_vec()))
    }

    fn load(a: S, pkcs8: Zeroizing<Vec<u8>>) -> Result<KeyPair, CryptoError> {
        let der = pkcs8.as_slice();
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
                if k.public_modulus_len() != modulus_len
                    || k.public_key().exponent().big_endian_without_leading_zero() != RSA_EXPONENT
                {
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
            pkcs8,
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
/// refusing an RSA key whose size is not `a`'s or whose public exponent is not 65537.
pub fn verify(a: S, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    ensure(Algorithm::Signature(a))?;
    let v: &dyn sig::VerificationAlgorithm = match kind(a) {
        Kind::Ecdsa { verifying, .. } => verifying,
        Kind::Ed25519 => &sig::ED25519,
        Kind::Rsa { public_len, .. } => {
            let exponent_ok = sig::RsaSubjectPublicKey::from_der(public_key)
                .is_ok_and(|k| k.exponent().big_endian_without_leading_zero() == RSA_EXPONENT);
            if public_key.len() != public_len || !exponent_ok {
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

    // RSA-2048 PKCS#8 keys with public exponents 3 and 65539, from `openssl genpkey` and `pkcs8 -topk8` 3.5.8.
    const RSA_E3: &str = concat!(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100d8fd53e136ac55625f59",
        "01573012c46ab1041c572526176fc86f22c516f1501193dd5187926c1d4f9fc8a60f8bba31fe73eb1c0e83e53dc6088a",
        "4650f7e487688f46838d4cf4acf9fff440a5a47fa11e078034949f886c24c852c0e52b0d81adfe779dcb4a0e35906d58",
        "3302fb2d86a074b59ea500226c37007643ce85caa2ec548f3e1e4039b1597e948d818c91af88c21fa8cbf3498a83d88e",
        "989da0f017d62c8196601cad4a91230ec2d8270d72bbd50f7041aa93fdfb3e246ca513926985143856636949cee544a3",
        "a3f2433e0c1e93e818e9ad03171e8478f104622356be223b2f5c939b40cefaf1ceb0ea1422cc8b4239218408d54d0809",
        "d5d9a3f2da89020103028201010090a8e2962472e396ea3b563a200c82f1cb5812e4c36eba4a859f6c8364a0e00bb7e8",
        "e1050c48138a6a85c40a5d26cbfef7f212b457ee292eb05c2ee0a54304f05f8457b388a31dfbfff82b19185516140500",
        "230dbfb04818858c8098c75e5673fefa6932315ece6048e57757521e59c04dce69c3556c4824aaf98289ae871746fd12",
        "cd861edf03a8a2c38eac3893166c1ce6331ee61db8bb639c86982a317976d2178571313afe3d616c295cf582589016e5",
        "21d1fd4d5abdc84f84e9c22b64308994af2ddd67b7c4dac426ff330d0a088a830e9adc21fe39942d7cb10e99a3f107a6",
        "11a90d94c78981de18c12e4db1e70a83261dc1700428e399c3196e8d7f6302818100ffbc16269e71d15462c00b3bee0f",
        "b389c42992063bb6cc8ff2d51096b2a43d4ada8b3ef0d1127cb2720dfef736f1c81e10c5183ee8bee38f10f03dced41e",
        "1441ec19d3c375f14ee1f8da6ac4958cc0d15d62b8a3a846c7d8ceace65540be96cd07a231712a656fcb4861b7b03e97",
        "f85838a24b59b19db77bb1024fd64001f03702818100d936f3ae73795a8827af2c4349a55a5cd29cca175e6628dad04e",
        "be22af01a45916d30f4581c250829ede85d57fd825c5a1f2a547c5e1124f80bce7779c333efa59bf7bdb273cec5c03a2",
        "feaee11dbc4066c0ca5dba8951ef5787cfa58b7e4a078f1fe36dd4d6a5b56fc2f1dee6079f99c2db349b3043179401a0",
        "e15d3e1cab3f02818100aa7d6419bef68b8d972ab227f40a77b12d710c0427cf330aa1e36064771828dc91b229f5e0b6",
        "fdcc4c0954a4cf4bdabeb5d8bad49b29ed0a0b4ad3df38140d81481137d7a3f63496a5e6f1d863b32b363e41d06d1ad9",
        "da9089c8998e2b29b9de0516cba0c6ee4a8785967a757f0ffae57b16dce6766924fd20ac353980014acf0281810090cf",
        "4d1ef7a63c5ac51f72d7866e3c3de1bddc0f94441b3c8adf296c74abc2e60f375f83abd6e05714945938ffe56e83c14c",
        "6e2fd940b6dfab289a4fbd777f51912a52921a289d92ad1754749613d2d599d5dc3e7c5b8bf4e505351907a986afb4bf",
        "ecf3e339c3ce4a81f694995a6a6681e7786775820fb80115eb937ebdc77f02818100b39b7d362261b1a462022ec23d0f",
        "fdd3bb098e28679a9f0b86aeccbc8c9119f79d5be66b091f5fafa012bd24d0af7cc67f0bfd36304fe5738d4eaf73ccee",
        "d144ed91eb23fe8afc26703b556ad5733e93cdb7b12f803a99dd9217040ac4498aff98135c9b01f3fe2e28a5a26f9f03",
        "8be91d0ecd2769bb4330dfa6cafa60cad481",
    );

    const RSA_E65539: &str = concat!(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100b52d51527c746c489580",
        "d3bb6e2b7cda4e8b1da14f36f44e6107fb8d9a222a1a8adea360ba95b92bb037a87bc773156f4c815c6cb0f10f3c9ff5",
        "6ce965e55cf2d8a9ea33a704d6fd54e96a92c7c5229f53e1fb3ab3d24a99837c2fabeae43cde7c1b2d0cb444b274c36e",
        "e884f38951a8e3936f238459517b0f9a226eab356f42745870043be3fac9da5b87f6e94c6e963164bdd87ccfe151a995",
        "f60fc74abed9fb6fac1a9fa9f72264198a1f682132d1f768aa520d0944d279c6a2dcb15f252f1f8ecc30ebf2a73bd2e9",
        "ed2ea2ee6d5c94dc14c1ebf9ca88fa43956ff9ef45874a449820255166a54a6f2ba24cd39921be1ad04ba53e92bd5e43",
        "afc61ee0e591020301000302820100216bf9eea3bda708e6c9d1b1ec9b2bf4da02c7ecfc50145d8079f19028b0b76643",
        "4f8c8120a860f1d66aa14b01c84ba96746df7246c5841908cf322bf01261d07f5aca6e2c13365794f558930e3549653c",
        "4fc963562656e4113f632533a383f81748d59309405892d49d25f9a4e8746124e832161d160aefecef0e70f32ebffbd7",
        "d562aceeec355db122c2d4ffb23315c6a5ff71b4be26013ca68d9cbb0a9d621c1606cd7f1c8c13275262eaa1adc6d03c",
        "86842ec9e75aef5bbd83070fddbf6db9a9b486949f7acb0f90a828deec70b03e5876009d91eacdd2ff856538bddf6d1b",
        "7c418ebd3717f31c3121264053e1a1942b8752bade7b13acf809eb26cb184302818100ffa8cc9749790b29102b5d7fb3",
        "d681d41beff632401b8632c1e1118fbf1392a47cd68ecff9b35aefd361176590f1a9fcdfe21bca9c8fcfe59808b6bab8",
        "3e78c6768d1163ed0f7e1677f32a1a1b5610e33ad3f88bd905f8ae5213f4b3243d85b1db7945133a0f1c686a4bbc46b9",
        "90d06e29e9ef0a6951c1eba448efacdb62b27b02818100b56b1d27f0b3d0e03eb19f31e11e4d0d4c3a4f0baec41ad772",
        "bba2a39b9d8fdb7498a04942cd5feb01499a1d6fbbe1e6d0d1b066b1a7d0b5393e67762f7112939a6b87243027e11413",
        "fd85103903f0736a03af13e845035e8086bb4b880935200e8b35299776fb14430e59da1e72e127410304f834e183e3c3",
        "50e9c920aba06302818054334af07f28797c94d699e2aec23d31f5b1b2a04b0e6f92cef4c51b69dba3bc73cc8b59cbaf",
        "78880da59474fd53304431ac72a3ee8eee0b5365fc851ff96b791346928392dc5eb128644494157ea349fd55329fef95",
        "d1bb6ce43dee7ac73700044a2f2a9ca27e32c5522bc743ee6f6aca5ba66119b6d95b21658587fd15d589028181008e35",
        "52f50c52f06e581a58ca21684a91e2e1b4bdbc40c9803391f7e2751f7e1cbfea3d3776557786642933f223764fccee9e",
        "f479432c11993b19f7f0bf9256a6ed022fa3914d2f0b1e224bde39f726a2255e7f2d0f769b264d31b6512caa21c4c1d8",
        "5e9d84c158c271e1744f1d1d1aa4638b614d261cadfb8b73554a085c30df02818100998ddacc484e871fa9c9cacc649d",
        "ac2738b8acad35b1ed773b2b02d23a30fe39beb3efbfe65663707b02056cdbbb777de5cfbaaf577f9aad8e702c22e4ef",
        "93ea8f8865632ca583e81c2b76e914384d27400ae0a7eb832164ae21c7ff3172dcddee4d04f10e4c04fa39289f229a5e",
        "231b1c1aa55290ba5b4e4d80e3253cc8525a",
    );

    fn der(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    #[test]
    fn an_rsa_key_whose_exponent_is_not_65537_is_refused() {
        for h in [RSA_E3, RSA_E65539] {
            let k = sig::RsaKeyPair::from_pkcs8(&der(h)).unwrap();
            assert_eq!(k.public_modulus_len(), 256);
            assert_eq!(
                KeyPair::from_pkcs8(S::Rsa2048Sha384, &der(h)).err(),
                Some(CryptoError::PrivateKey)
            );
        }
    }

    #[test]
    fn verify_refuses_an_rsa_key_whose_exponent_is_not_65537() {
        let k = sig::RsaKeyPair::from_pkcs8(&der(RSA_E65539)).unwrap();
        let mut signature = vec![0u8; k.public_modulus_len()];
        k.sign(
            &sig::RSA_PKCS1_SHA384,
            &SystemRandom::new(),
            b"m",
            &mut signature,
        )
        .unwrap();
        let public = k.public_key().as_ref();
        assert_eq!(public.len(), 270);
        assert_eq!(
            sig::UnparsedPublicKey::new(&sig::RSA_PKCS1_2048_8192_SHA384, public)
                .verify(b"m", &signature),
            Ok(())
        );
        assert_eq!(
            verify(S::Rsa2048Sha384, public, b"m", &signature),
            Err(CryptoError::Verify)
        );
    }

    #[test]
    fn debug_never_prints_key_material() {
        let k = KeyPair::generate(S::Ed25519).unwrap();
        assert_eq!(format!("{k:?}"), "KeyPair(ed25519, ..)");
    }
}
