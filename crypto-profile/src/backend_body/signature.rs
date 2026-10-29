//! Signature keys: generation, signing, verification, and the SubjectPublicKeyInfo shape check.
use super::backend::MlDsa;
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
        bits: u32,
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
            bits: 2048,
            public_len: 270,
        },
        S::Rsa3072Sha384 => Kind::Rsa {
            size: KeySize::Rsa3072,
            bits: 3072,
            public_len: 398,
        },
        S::Rsa4096Sha384 => Kind::Rsa {
            size: KeySize::Rsa4096,
            bits: 4096,
            public_len: 526,
        },
    }
}

pub(crate) fn rcgen_alg(a: S) -> Result<&'static rcgen::SignatureAlgorithm, CryptoError> {
    Ok(match a {
        S::MlDsa87 => return MlDsa::rcgen_alg(),
        S::EcdsaP256Sha256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        S::EcdsaP384Sha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        S::EcdsaP521Sha384 => &rcgen::PKCS_ECDSA_P521_SHA384,
        S::EcdsaP521Sha512 => &rcgen::PKCS_ECDSA_P521_SHA512,
        S::Ed25519 => &rcgen::PKCS_ED25519,
        S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => &rcgen::PKCS_RSA_SHA384,
    })
}

/// A pure check that a parsed SubjectPublicKeyInfo is exactly this algorithm's key shape.
/// For RSA it checks the encoded length of the `RSAPublicKey`, not the exact modulus bit
/// length; the length assumes the public exponent 65537. [`KeyPair::from_pkcs8`] and
/// [`verify`] check the exact bit length and the exponent.
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
    descriptor: &'static rcgen::SignatureAlgorithm,
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
            Kind::MlDsa87 => MlDsa::generate()?,
        };
        KeyPair::load(a, pkcs8)
    }

    /// Loads a PKCS#8 key, refusing one that is not of algorithm `a`, including an RSA key whose
    /// modulus is not exactly `a`'s bit length or whose public exponent is not 65537.
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
            Kind::Rsa { bits, .. } => {
                let k = sig::RsaKeyPair::from_pkcs8(der).map_err(bad)?;
                let public = k.public_key().as_ref();
                if !rsa_public_key_is(public, bits) {
                    return Err(CryptoError::PrivateKey);
                }
                public.to_vec()
            }
            Kind::MlDsa87 => MlDsa::public_key(der)?,
        };
        Ok(KeyPair {
            alg: a,
            pkcs8,
            public,
            descriptor: rcgen_alg(a)?,
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
            Kind::MlDsa87 => MlDsa::sign(&self.pkcs8, msg),
        }
    }
}

impl rcgen::PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.descriptor
    }
}

impl rcgen::SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        KeyPair::sign(self, msg).map_err(|_| rcgen::Error::RingUnspecified)
    }
}

fn rsa_public_key_is(public_key: &[u8], bits: u32) -> bool {
    sig::RsaParameters::public_modulus_len(public_key) == Ok(bits)
        && sig::RsaSubjectPublicKey::from_der(public_key)
            .is_ok_and(|k| k.exponent().big_endian_without_leading_zero() == RSA_EXPONENT)
}

/// Verifies `signature` over `msg` under the raw public key `public_key` of algorithm `a`,
/// refusing an RSA key whose modulus is not exactly `a`'s bit length or whose public exponent
/// is not 65537.
pub fn verify(a: S, public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    ensure(Algorithm::Signature(a))?;
    let v: &dyn sig::VerificationAlgorithm = match kind(a) {
        Kind::Ecdsa { verifying, .. } => verifying,
        Kind::Ed25519 => &sig::ED25519,
        Kind::Rsa { bits, .. } => {
            if !rsa_public_key_is(public_key, bits) {
                return Err(CryptoError::Verify);
            }
            &sig::RSA_PKCS1_2048_8192_SHA384
        }
        Kind::MlDsa87 => MlDsa::verifier()?,
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
            assert_eq!(
                rcgen::PublicKeyData::algorithm(&k),
                rcgen_alg(a).unwrap(),
                "{a}"
            );
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

    // RSA PKCS#8 keys, e = 65537, one bit either side of each size but 2,047 (aws-lc refuses it); `openssl prime` 3.5.8 primes, Python `cryptography` 43.0.0.
    const RSA_2049: &str = concat!(
        "308204c0020100300d06092a864886f70d0101010500048204aa308204a6020100028201010166bea20f552b342a1c93",
        "7118e82819370e5f63f41ee0ea6fa29f7f4eb8aeea3ea917475fb6ed74685028eb5e15cf8a6479ca06f0a34d7cc87485",
        "6d245ed0086d8fa7ed83721e765aa18073450b265bec22ff087b980677a1577f3f5a037cb4c42ecf029a5ea0dcebe4aa",
        "f04485d371aadbbaf02e16124589a4740ca20c67d1294db2c51bfbf617cf65cb9ed5c3f2c1104466ccd425131b15cae7",
        "5c4c48a9e4036ad02c6f1d646a2649914ec2422a6ce37a46ee4107f1b0e9360e56394099c827f2203be026529b1bbde7",
        "3177b77a3b98edf16e21429cc1694bd058bb06bb4a31e4ab05cd91444ceb87f795588b02e7905f0f800279871967080c",
        "67d04e6f038502030100010282010100a8ece34aed03e7105d5c604926289b96fd4195c38236ceadba99f84c8d527023",
        "096458cb8d4bcb20c37e41369076a5e822212b9b6c8a3453ffea4436781ee59911a835834bdd6445d0feb748afb3645d",
        "912d1e457494b70856372911adcaaf2422168057486fdf178519a901db3271b7ceb7fc18f773ab22e13974296a46088a",
        "87b5c948d4e889dff76f47473f4ea514d1f5662d2daf3d9ea3d85aa85f586ed4dee173d1a03d0e37e4a3f022b4daceca",
        "774d4342519e11f19d99b875182ad9a2652b47d16147fbdeb640f43371cbaaef98a5e70ad45c5ec670f56ead63b09162",
        "bd7347544cbac20eea071196c77fe99c253cb21167e7b4c647a1b317fc4cb38102818101acc11220fcbd1887f168c321",
        "afe95263326c17a97e5d18123353d937cf0fb2e40428705580a9f283b2070235b38e2b62820872d27ba726468448004f",
        "3d8b9387d72c5969a4636d6985396693c306dcec10b17ab203ce57c400b70d03ed1cfeb3bee813c1319e82c3deb62d81",
        "037078114477c9a3a3b80b88fb0ce00b6596b03902818100d632e4cc5b9f9b3b199b2dcee6b1c31006fa46731f421449",
        "4ba9f49f864debdc5be28b547a10637c57aa832d94e704a3214268da72efd34616417514fa433fb2a9fca2f26683b9ab",
        "4d49a968094be085e0f42a60c86b4e0c4af795f411b46b1efda9281283070e7688c9749a08ba472e04300ea68efd2bf2",
        "7453d2d029cf55ad028181015a5cb25781b504ef353f4b7b984f65a60b22b54ed06d4637d5cd23ca68f4a6b07b076c10",
        "369b93f57dc919a8e63fb09ea8ab488eef238dd123a5c2d240c6d3ccc62fe69f6814865bdb2b0ec9c9a06eb2299e269f",
        "4e61d016dff90083ae7660f03605e787879d24c834cf791d22f92595d578eba4cd6aadaee0187b99d95c8d4902818100",
        "8dfda6d62156a85c8118f140da84b43e07a218d96fbb2a1f7c5ce9a06633794ad64e52f669043c2ecd1e675eebfa4884",
        "ab238ec660b2c2670f91ccbf5f36fd1ebeb88e7c09a1008fa1e856b874912c0113a24805685659a2a47f83940bb881da",
        "4564c0ffa48424fe46a6e4f8c71854df183f9336ae4afdbaf78a29917c65c8f10281810112c344f953d4855ef6e3e880",
        "92324a026691b1989f0287aadb1da73471c767110892490417799e38c66436a04b6838900f71145c33c096fe2c5c87f5",
        "090805891497db1f10f83cf4854cd3f04e27d125217b485c7fd4a12a1d1fb31374258a53dc01495549cf61fc2bb2d1f9",
        "c4e0e082aa4a92894bd03947ee6b156f067312bc",
    );

    const RSA_3071: &str = concat!(
        "308206fc020100300d06092a864886f70d0101010500048206e6308206e2020100028201805f275c1e26e94fa55d1d14",
        "db6d55046af96feea3839bd44e4f453e2412bf92a89f2609b403c59d7d852203474542b53a97c9f658d73b896ef1d62e",
        "d5362cbce61fc428ff833a402a104139292c7327220956294c72f78c1a53b029287bb20f1b52d0cdcda86b007a0b71d3",
        "abecdb04405c98a870bee906b7123c6401e7db3d5cd9d6cdfc28b7b58d7abf42cce6eddd4028ac8c04cbee7413cb2c4c",
        "b7795858166300b10e698d56f455966610b064572bcc1a380fb71d938cc1f4cb6d273c7777d92b73bd370850d9ba137a",
        "c194dcab6bf6969de046b867497102a38b42ee5d223aad62a7c66aa71f1ea342d25e08f3aa61cb2d0e3d26ffb3e9ffea",
        "e9d036694b2f826ee318b592891952cae31e707357c106b0be88a11815f2f997df65dac816ecdaa0d990085211b7d85f",
        "3098fa6c734d9432e5c31d40a6e730dfd5430a35da42fbcdfff16254d5011c72fc7ee938be73e4528ca603967ea55a08",
        "32a5c95f6a18f4edc1665989b3d50dcc662eb3ac69761501de7cd5fa1fb03fc20af59491990203010001028201803e92",
        "aa9025747decb7abbd2082e84a8c7255ba2f8b077978b9c6461400c43c1468fbe19ba0735e9ac166d9930fa7cb77a983",
        "a55d4cc4991efd27a50a8ea2a2e20df7b82236d0a28b46bf2d70b70b4eaba24a27c45f420cbeef53c3ed1c52be7e705a",
        "614c21b9a3c99e270f545ae0b80dff1660862bf51f765a269e79665815252f1783c3939f2363d3595cfb53cd0e16f7e8",
        "67f76b87f68b61ab5313c057692de792f7dc0b6b67c82b5448f0269f057806b32334aa6d67af4388d0118aa0c7ca93a5",
        "eb8d0b1b1f62e0c6cb6e8f893f37bc3f5522fb700295022e954e84aa8de0213306adc63e5b580b4c84a0f701850085d1",
        "b805aa0a4359efd6c8af5d59219b3e7e464c0c996eb5dacb7ee55cc306bb5edc208a1e7bae255a7548bff47635011f81",
        "70bdd9a2aab1a2f688c88d3931359d5b1f68003d66d7467900862d88b2a43f55168d258eb1fb263423221242f3afb2bc",
        "c0d3193fc4323ae32e5b0961b4293902e9abe8784f111663f0301205dfe388c2a8efd760436b2a8e055f096346150281",
        "c100c87f0008fe700fd3859e7373505713a614d84415db0b1b18603f0532c984743337c354b19cf4d6f3975cf9845e9b",
        "0678bb0dec133fafff9e84860f94af9e8669f08a9650f436ee6d9169070583d0329942a21cf17392e0e4c5bcd3d51c57",
        "0be10387dfea77f537e2c9bf1c3a20502129da4b242772afd255d1fe57546a1c8076c33835b873231d19dd2bd448cd29",
        "278ac8c2b0b41d5fc705d5dede04d59471678386d9b90071638fc13ac08b096d3ae2eba383b28da5afdf00d007b077c4",
        "43df0281c0797ed4b6380f2456ec7eb2a0ae3ea3d4daa07e5b243ac74e4ac88d45ef777338850054a1ca15da7dd4996b",
        "16caf222924311afebd31e4e7947213734fdc1f752cbcdf837bdafcca418b362ab375d6369ff963bef10bb7a72118f07",
        "61ad2eb02c8bfbb9543438bc99f2e1229b4a7b87f8d583229fc8c2674611697308e61934ef406f4cbb5916313735bd9c",
        "426282643d8b59667e4c2410f18f6296d3ec6af39cae330920bbd8c4543e2eda56e36660be0c0c8972e91c7e323a2f15",
        "180c0c19870281c100adcdca4e01a34b54e60411b8e8f0534c29cdc057e1e6a2ba62d4bec0e4083a631bf7ec377c0493",
        "41def8ee245d8eadf182d5f2cc4ced58fe258bc17df72fc8fd9553ce32a741e7367c533b8f00513f4bb483abeb7370e4",
        "1bed7e5f73e2796306d074bd1b189a2eb41e87d9045a769c0917ff037c5ee323c6d99f4e3d132f59fd9a05e42bdd4397",
        "3a908c2a1e621b46f7fc4929bd39a98971f990958e4347c777208189c3e22a69507905615c25f3d69458090b65817d1c",
        "148933cd36a0dc36a90281c030509daa7114a470e4cf659dbc6d309d9eeba014028e555fef215dfce7c3ead019240e83",
        "e0675c6219bf80f4a9742d0759209983008bd6cd27da2fa82519938f1b792732937e6bb4fe15a8314a6d1af1b6303a59",
        "51a01c8b6c2c22d557176ffbe7170d964cc61b4a6569de673ef16d1b295d62d183f6bb37040999337abd9f6d5d846551",
        "43962db034f0d84915ffa0795107165937524862a7909f465b8814a4c4298b81b6f1f6f141614476b52bab61284d7c03",
        "746c5e4aff1466210ff967d50281c100bb896a0cfd2332d4403fa96cfd92afe589fe66470722787204c8ae1844cdb329",
        "95e681cab7071604f2a7f76aa27818e53dd0d2ba7122991fa25b37988dc7dc95362c7cded2b581e2ca13b2ce3ead7088",
        "7b81d7d3e40d3130cdc513865796a708974da4c1ac7745e52e130174423768c19e83728a9b69b4002ca35012dbf2c68a",
        "c2da0a3a1db388f740948343e2dece5750da8de1feb831e2349b089f110942d63b565f51cc738916615e7401d19e5c4d",
        "8bc211fbf19df6fa5c4a235052c84eba",
    );

    const RSA_3073: &str = concat!(
        "308206fe020100300d06092a864886f70d0101010500048206e8308206e402010002820181018622f8492f06d76ad687",
        "0c118266032c4a806e78e9714904163a0c0d460a7843628477a7852c0f74af406baa24e28902f39c12dd533a97417296",
        "9a9c38329bf0a3d4b82de4aae91dac58d06dcf871f93998f1c7574780d50c701c363b6aa8e3e484e3d5b71891725b58e",
        "625812db0321f4240aa8caaf3285d8fbdaafe2cb923f3396879177f13e68863f40aed1a391a75bcdea12d13ebfb329bb",
        "f8a51414c27dc3d02d057fd701eebe0010d27b9b3ef4b8c6f1bd43fc82db2bf9ff1314b8d2237a85a849c7969b12f08a",
        "20f2d0bd1cbd6486759a9249308bb228cd0ceb3f8d54db89b68d2900f92e4b67eea17cfc8739b92d39fdb85b54bafefd",
        "6b484799455242e831a68c3e63e4331091cf2c333051d19ff33c0cb798d416b039d419a187d99b2c6ff6acfd879014d8",
        "a836dadb4db9a86f9aa95e88ea8166ecd18117c901184635a6f4a6bcc757e0523ceb8ab4d64ccfa1cb74f16682293c64",
        "ae754f1f6849be94c23cc22402df3bba2a99afee8dd789d1add2bbe3068a74804a050566c75902030100010282018068",
        "d332952f5e8e38f5a55997c6cab4258d6b0ec3cc2d9529d4f309d3f332d2f7801c09ae6838db7a45b0707d49e5d85c83",
        "aa36e362fe862f9ea35aad88e808405334cfbbfd09f312f700f217df3ff63b09728b79ffae561d932b251dc0b1f90041",
        "1b4c9f2a556473cc619289099ff12a8957b9c97a94326606543d812ed5f5d8a77ad5b83f5b01a2c21772c0c63145ec8a",
        "dd3bfc8c5e68d1b1f000b2124035b5e70c235cabe9d06a1e8114040a143f892fb0bcb956f01d14d8af165b41211bcc9e",
        "fc4d262e381f255e798e8bbf8d6aec18f644e37888ac472bb11554c89b98df274455883f13ff18da760c2a60473d507f",
        "faf279ee9fcd0f3a9eebf5526f4c09fc46a82d54c183875a09937f33cb6a80b428474fdcf25fd41fa80d4cc0ecb0c711",
        "fed6206d11370c71cefbe8e020602faafa0a3975a6062da0f9330b6f99bdafb51022a3537bcbb32499d78b7e93cb12e0",
        "b875b4747b9e369c9648c5231fc8d1365856e0ee3ff7456cb53b742a208185846f2b6101c805c7854c76edc7e662d502",
        "81c10199ffc3090e90b31027c5a79dde0c1618280f3fd009fdd03b29fac974e7adbb49bcb962bcb24231cc5cf5cdbaf4",
        "5bd677f5535268a982b4e8a18a7512f38abbc49795cd60154019109d88ec8a68dcba2787e9c682f9cd9e863b89bb3932",
        "71ea5b7ffd43361cb91944c316156b39f039d48b49ec264cdcb01c56126f01c6266e1facfa3a1a3c25149566d9fb2622",
        "d91123405e277a1f0663efee30a5bee4d6af54ea16d503236262c728c96477dbdb71b7f25012456e7f521c6543b5925c",
        "ab60ef0281c100f39919293d0d90014e8fdc4d5f4d7a2beec12e86a23a69c084cda06ad85f224c041d6930f90f7dcb13",
        "aa226804741f704a29556eec5daa945600df9cd90e5ed9e33257e397bc367d6144487d7c74b5fc403f646a81b46c4664",
        "189158f0d8ea2f2392f646409aab2f3475af98e7a818b4d862f8972994add4eb4dc98c522f577227938039c4fcfb647b",
        "586aa1f218a914652fb02dac4ca0829fa5921eab39ff0f0a2c3bf93e7187206792428af1c41d88836b568d4ccb00faaf",
        "45794d45124c370281c10188a84ef4a493663a89ac9d7beec5aa7f56164caa0477a56e9424cfbd7b88823efb549cc055",
        "045a46fb9c997c7c3c5c2924b5b8cdedd1f54a7a336d2e4a3a4adbdbc5271ce71d2d24218b99e670c93c2b51da4d38f0",
        "dec0fc9396b3ccf287f0c7d2cb0e0c8bf3a5c49a05d35b8ef087a20c082ef6fb53bc0257586e21c7d0d454d7c809cf48",
        "5cc6dad2d6ded5c6381756a875c3df0c49857aaaa6c28611099e7f77758869ea0076d380376855f624b34354f8e496c4",
        "5d81991a4e7f5d7e0ccfd70281c100f27aaf451174f2a79a603157034ac815fb2f68f4b37f99ccfd65020dd91bb9b419",
        "547d653646695d4051d6b5dbd90b82671005eec871e45e8bcd8ac94276bf8bfc501c947c71e97b9cdaaf9dd9c9036df9",
        "3620eab3f9b8ddc8bd7bd120cd8b2f29261ce7895f6c8f2c95091a175e88595c1c087fcff023a91220f843297bde7bcf",
        "51500e313bf1b1efe5ef1f0d31e6fc5a4cc1fe74c841ee44a4377337d61f42054a4ad8ab83ae925f06841e72d258e38e",
        "8dc63618feea169f697479aa0bb0b90281c032926fa0b7eb17693ce6e78ebd24e8bf46f7be42139af9cc7a067421c0e7",
        "bddc8875650f242d7fabfe0ec37eb55ebb28cebfe475865545d136700128da01897ad663dd98f771c924ddb0cbb0aa4a",
        "77f132827c87e0a30660e51c41ce27b261d14aa78f09e969da4716c0d20cbaafa087e6020a875171080d48d91acd52ef",
        "ed0237abd301884b55221ce702c3b03e59fb3555bb592a338a9590bd1f15ce56977545baefdc6291c061eec99e55db82",
        "926793d88b3e545781ad72c184c9d7e4e179",
    );

    const RSA_4095: &str = concat!(
        "30820940020100300d06092a864886f70d01010105000482092a308209260201000282020054e85ca8475f3eb9f46bfb",
        "2cb453ca89583d1d934cb1b09970b57c4a8f47a44f3a479062b32d57afe800e19ccc8de3c81444deb234bedbf7508c34",
        "943434a721b0548d111b088fc04aa078380d306f9492d3ea7b0e30faccf78326b2260c16c556cab98ea75527a28f09a2",
        "92c71ad34be7b502c24113b23f64412a7f8be2307c111de9dc2d3490a8827eef49898fab99f2ccf2ebf20d4a69468e2e",
        "6a4d398d4c26636bd67d649c72ff15eccd2dceffcce7f2442333063af8d78dec133557569b3df85116ae761d9a48d8d4",
        "3c9099b1682a0c13e28ab11bef620e19d72191d2d2df5cfb96d3fc427e573ab8bc95513b7865ce06a52977fc7dec2c02",
        "eb96053c2f0e4d46f74471897426b839cca80e78fabaaf04c232e5892b3b00ffe0f045189050e6e7599847acd787292e",
        "a7cf69375adc751f44fababff7ee908861442780bbae813bbd90ca9a5c5e7c2ac47d4c300d7a1c75dc6bdba725c5351c",
        "13e553bd3a70236424adee6da58019c271e03e2eff35bf3c2731880ccfbda9a0b1d16dfd927266380cbc5923a660d791",
        "78a91c4106567a6ddecc262e173471ed15b861885600f3d3b6c472d1d3cf5a1c822fe65b3a2201665bad53062404a944",
        "30751a01ab9c367fa7f51da841e4e77205ecc70be8b04b0f58b6064ef566ccdb56258459a62a61c0ebd55f9cd34abb8c",
        "8ed98ef243a859e8e5c0dd51c687cbadedf68234f70203010001028202000aef96a791f1c1897fe2bc8a287bb6557449",
        "02db2b00a3e74f6e00a135cd1b6b9ced04bac1ab306516b3ae5b5cb955c23a621870c97c5fa67df860f949b41266b368",
        "6076f88d64be769e2e7dc1ad2061f97b53f31f83cd79c2d360938774fd25d3a4eebb61f004d7da267a8aff1c0464fd66",
        "0201f511cd5e7ed229e01dab3765736aefe90ce57d5046e684796b3f56f1d024f790ce2f4a0b3f2c26ec48200683ed59",
        "d6d4dc77adf2ddc9fc22fd287127fa23e904c398a4d5d225946770f25bd448ea07bfad1ec7774cb4a8b958428368102a",
        "5811509db9245ef3c3fe42739ebccc4a14997b9a3d123ab7f47d4d9a15d7cefcf73c249830ac235413d8360d5c8fe744",
        "5005fac622a18503b212ba0483d108a8ebbfbe2064038f6a9af59f95c1f8fc4be9c75899812498d5631df3444f64113b",
        "72e835d041f2256771e2d57bceb5137968549975181217ad1e85e90ff932ea091fbdd572d542328a85d1307fa97492a1",
        "52f7d2fa9df8cfb296d42ed5893349977f43094308195b79a92789dd403025084375873d899b448e168d1f46df81e210",
        "ebb053b5ce13a7c55dd05dcdc7dab7f0669486c575625e3a44c2b89808c4bd67d1548de18b881e5aea7979bf90388e9d",
        "8c4f87694f35f8b4321b0a50675d9d64decdcaf1c9eec886b0c3972d41e747d6c45d72486d68a194e6a3e57dc7c36276",
        "de44ca0cfa3b08f109d2aed037810282010100c77c957f6b638ddfb4ecd2eb71863c2aa18d0955eebaee8ed0776b8ffe",
        "f622005720847df376532e17d01ab487b2175a418aa718b943f9842c26b700ae3b6aa4f56c394cbf714441459a808c6f",
        "21c634fd837f5a663104efd0adf82db95b76b0d4822028e740ccec36ce47dcf76289ef73c3c034e0848396fcb6c98b00",
        "16b6e169d0fd37200123aadd727ccfdf72220a349f2ddf38a30ec2eeff131ccbf0342541f43f9f9bc770cc8e41a0413c",
        "105b204c7c251ef642a8e1f7e39d79eabed19ca1345391546c6c5b87a4e63076875e0e09991bc54550c952605369689b",
        "bf0f25bdc37c954059cca471ef55e876f454866a59f9f3e2e204d7dd0157ca80804837028201006cf623c4211c605729",
        "7c556da13061c42a2db4eb8eadbd1879c1d3a26af935613b58f5bab9ee42c2d20185a3ee1674f0a9f92ca2c19dd85d27",
        "826f7ff6cd1d8d92d2d6e3a588b926e70bc11da6eea0f4903fbe85fd469704cc9fe08c8adf03798fce1a4ee0795fb7b0",
        "5e3c6a75dcb488c5fe017edf2127db43d0661ccf129c91a31f735f570aba79ea87b6551655929a6d87f9eecaeaf12fa3",
        "b538d8d15329a7bacf383a8a89f3e1ee9d33a5fec2f17d55e1f9dd1d444dcd0456fd2ab0c7e2817969bec0c6f0e77cf2",
        "3a0f63e68a5b54a367abfb3b1a00c075c3adf8181af73447311c1615b57bb7a08d9c0346be005c84ceee610298454246",
        "d397fd49f199410282010013679c073c04001dfdb477c3ed541870312ccdf6acf544156253eb83a3527ff63683743fe8",
        "39df57817b7dcd87d19c11ec843742e16aaa4fe01797ff99f32fa9823217d4ce5e8f3c2630244704dc6d326462b135b2",
        "f11bc0d434c80a729862104b6ba90331938d1b812d49b245e230f6b8f516b24e10b5d82f16fcbde7b14df2d95f39f26d",
        "cb8e93a55ce8a533e01f4d8cd6db1876a2ede1aa6be7890a9180110bbc5da002004189b460cfdce8a1d2ab6ea538db2d",
        "2b48d04a53bad2cc31e9a3e9ce743e93cec42f971f4440fc96a86087307c9210ef0dd65486689f835eef73456549ae1f",
        "075d2fb5e18922c6c7779d67a4fefa695c810a1a7671fac1cb38bb0282010045f49169ee4825a250443f24af843c8091",
        "03df500cbe86d51bf6d14549a0ce20aad5a68e47a92cbb9fd0d2583917b9e4797c3ca811dea176cd52f4fb171d01884f",
        "67860789d389ebec12a3ddc1bb1b23692943cd0a9b3382254dd000eb77dae744e872038a22e2cd3032905f596465941a",
        "69c5d40ab562bd678078ceae33a8c9e80cdd29acdc7a74a39a95f972e965c237e841128abce4344dca9fc0b443cc4e9f",
        "a542d872f1b6deab2fca651c77544bbfc3e18390b2b5b096c4b2ada1e9f3066548faeb11cec1107b03c3b5c3e1b85952",
        "bfd0aeef76f65c9a3f138661138efac56a4639f79e18dbfffc6ad9bfa564de0176499d86e8f42e65029c6645ff130102",
        "82010100c51516dcc58b073647bf08d79515100c2bf7b145aa3caa9d1abb076bb90fcb84f177af86d8cbd8fff7a700fc",
        "6101069b055eed2bc70aa0cc176bcc6034f9e1f35dc98dac8573d6a71aa3e16ca0a69037de7db406b949952a615faf07",
        "b91c02cb823928f15ce80a01d20ad34ae6b0de2fc35503083b8ed117f65eda1e9504e35711dda986655fc1ec05e34be7",
        "e45caa2fc558562a0d186461a09c085b13d6df1c3538d277ff2bea978badffaa34141151fbdc230bbb4158f843f34048",
        "53dd09f13a1847b7e423633da981a8106663199b794e0575375a7a1d0ec641375161dd652b9bd64c9244982bda3e5f9a",
        "78375ba031ae79c1c3502b2417962061085b6d3d",
    );

    const RSA_4097: &str = concat!(
        "30820942020100300d06092a864886f70d01010105000482092c308209280201000282020101aa99b3e6ee69e4c0877a",
        "d499e358f9bad61a4d7a42a4a5b9e1d07ac0a9fa65303f580419ec1df512dfa65232f6d5235b8f44a5c92fca3dbc7d71",
        "96f17ed82a747bc3b92ebc602a609caafefbf46956b2d05209ab35282f28cca0e7a016055fdff886efd09946d59272a2",
        "ef943c15eb4d03a702bdeb31a9065689b618299ba7c22584c98612b93cb735a247484867e91d0e7a1e2bb47b1a633f45",
        "49bd3623ffdd9f3222f4334199abe281835cc3535a365acd97ef6aa863ef0180d521f51e851ca3332215901196514b59",
        "60a3e8725775f045bdeea0d7fe3bbcc5ded7563f5ec008ad8c4d44bda1e70cfbfdbc1580fc6d3fe418a315d101d8bc35",
        "6ab656570c2399a3a634a473bfb8dbde6d50ee01cb0d95e0773f5f4211825490b74350c4cf4c11a61b809eb40b2d7266",
        "a3de2a73f4919f951a40ef0e6b660311e7deb682ce089e6c039adcb1532b30889409b8b334444a280e359f7bec43838f",
        "b70d73a93386ade00a19ee0ce9f1e6c55b33beb3d1f3241b7eadd281a7619d063e8072d3bb5c678b5fd0f6b20c928080",
        "8a9934040e4cf479e811a3e038073f274eb1c1d4f09096188531588936e7a2b27a3703768ccab1eb782c757a996aaf81",
        "4298954b606dd9fd28ed502e489cf9dfc3b2c6c35a33d40f07f09718492f59549d9c7ce2b9200759035d292c90725f3c",
        "2975f30e073d6f9b56fe95c7286c6000ccefa05a38e30203010001028202003f093f401c72a14ea1b650bbfc902536aa",
        "747086645a97f2839f9ec3e15a12a1b27a7b00a99733a37a50c54caa948c08f77e9950c53309345504f7dcef7559b0a4",
        "a9232ff8bded0521a152d44025609e43921bc3a4b32f64c3f7f2c200ff024fc2158e523093faf30ce56ea964c7886174",
        "ecb4c7037def0ff4b19caaad5b46cab5688daeb60d911f3159ad56ccfc2dc211659217bb2f8592acc2bc46ad3d5c8d8e",
        "fc8595b80d357be49866a4ca6802a88d7a5bbd10f198f2b432294c3f402743380a523b0572d3d7675ee99cceb8369c42",
        "c8cb6bfb706f2cbc94307d794d1bdf1c6928963256231a551cd73d779ffbacd908076bf1c95490861f0e89aaf069e662",
        "71ec2894bfccd624ac763b627ef84e3e7d27008844419cef53ab5ad856d8a2c046a53b94a2f98cbdb006f68c29538359",
        "0dae722d8681fd791fd6152fb4c13ed71a2a096f124261b4b905641675110c1523090341595c74be56f9c46b9ddb6f25",
        "bb7f265b4677bdb63f44d45c1b13af904a85b1ea4f8fb37edd941851b3d36ecefc89ff7502525dff0a41adc0003e5b22",
        "fa7d0dfe577943b4d39ddafee3d198ccd6dc959a6436483e25d52244bd2a7b194f4e6c2f45dabb2c151443f691dfcc10",
        "c9b7a80a92846c8fc5d53980e12eb2dee997d0623caab0d96b3140659cba42a1316028bd1acda96d5bec72af8e90a672",
        "390a9f32778df8dc5099718b1bf7210282010101c1cc479ceccc2d9489e57091ca84ed320a00eba608a6b241513f1546",
        "c9dcdf278698d212138397f246a22b0ea24d83a7271176cf90649ab81f1da340efcc0db4a8372f4c750afb129ea23546",
        "867e6501b78dda7f0ef1f33e67e1e47715461b8117f0a188cb1e2e0c3da1fa226fcad58a7ae26fd9ea40fde461e58a6f",
        "f9dbaa242454bc8a25b057476351bf7e459cc1f70094e17c23bb61f10fa1a842e2374b7efb23d86828aa3b88fdbe33cd",
        "c09ccd22baafed89202926f9057e31cab74df5387f94dbf08b27f4d74d0cb0bb9a5594b7f168e0a1df58674b52273da8",
        "9c691a3473993e87e1d2cc1dd7785bad96a1e0a7ece3303285f4c3dc222c27963cef176f0282010100f2cc1792ef5ec7",
        "6259ba85e5b70a615e2b3dd3c69d6ece252d99774e6101807004b92eb9e34f5fe351eb792a6309cb3385ea89c05c006e",
        "20f5e54611d5413f5589e68cf10182fcf2a1e68699026172124bfd8ac8957e14fc5d08dcf74c089ab11143fa70ed4cc3",
        "9c8a727f87ece716901a6ab4321f691b9bef123e891374126b458e96b18929459f3f398f5c7250eca7f90872bea6622d",
        "3d4132e3b1aeb059214bdebfb3897de4baa0c6820bf29b97e3ed3ab3e40090bbb2178daef73e2a81ff4dc6ed74d53dc3",
        "246a09d260036f948634961d50c74408de86ce59323047b6d5b40006201c38629e782f669da43015886db0ba31c19b2f",
        "272e095d4859705bcd0282010007288c1f38398ba42889a93ff8bc22d6400881b793bdab6a94b36f5040182ec8ff4061",
        "5f7e4602de0d37b97db3218eadd35658d0b6d89309c91cfca324edd76dff9b593a5b4680766c65e2792bdcc918bce61a",
        "0b199eca233d1e0037d0f3dbae3346561bca37c1bdda2140ccd9809de3654f433e7196f533744765eba04b59aad7952d",
        "a6f93094430396a2788cfd10ad30aa2de87edd1592f38fbc10cc6edad9bb7f778b38d274be1a63b3895bbe6319616539",
        "5f8c4e7b5b4d3613eec8fa09a40b8bbff055169eb3ea7b00390c1cbe902adc636ed012251ab2c5031b32da0d5bb65743",
        "02809a8d3b1059cf03b539004d4bdcd5c088173c22bdbc7c28ccf1752b0282010025ad5a3329063236a6e9f50152c83f",
        "97d769fec5218522644e91341c6b9d4a0b18108c99b8168730c5739f17deca9447e88e1ed644f0a426654230ff6f7272",
        "9b998cb76e66e7a6cd1826a7d872b0207d8a614bfa1888ba44f742fad73d6b50660de1d8a95189ca092ecad9d38405d0",
        "508868ea91a4a230f09fc6db01768d5a965ef2e39ba5474c508c0528a415f14ce83c12fd8b6c526be6c78958202895a1",
        "1f33a0db6ac6f94c5751bfbc4a925966d6ade7a026cf97a628dad2d7c5f255b25aa5fd2ab828a72ef325a9648615c268",
        "eff29520f37a18aaafad87b3fbbfd6411f2491a461b33f64be66b4245e6e2e30093dcc60f87bacd342673878cb5365c6",
        "390282010101a773f8c13885c82e6fe6e581f2c4657936135c7fab9e1737db05ed7ad2fca84ac51f3a18b82b06db7f20",
        "ef0a4d7a8bcca8a1fbc219eba6f76e5c43782be4ad806da4a3fb531176fb1429d6f10379b25e1f3da3e13632b7f5b82f",
        "fd2a9768da5e9b13edea22a51da2f9b0dd11658b72de22715709c23c58c7e28d5ebd0816b2889e0b26413981e623ea6d",
        "62f2da9f31c6df2b8a63076fb63787092526051c7a4df4c8d62140b02cad8ceb63c7f8cadfbe1c2b9e78e99c9516b2d0",
        "ccdc2743d925ee4fc9c6ae31bce03a6506dd15b3fa7d6874ba5380e47eb9bc2319aaba2c09732a8eadec236dd9e6838b",
        "dd415abf49de0fd52487ffdc4ed76aebdc6358ee18de",
    );

    const OFF_BY_ONE_BIT: [(S, &str, u32); 5] = [
        (S::Rsa2048Sha384, RSA_2049, 2049),
        (S::Rsa3072Sha384, RSA_3071, 3071),
        (S::Rsa3072Sha384, RSA_3073, 3073),
        (S::Rsa4096Sha384, RSA_4095, 4095),
        (S::Rsa4096Sha384, RSA_4097, 4097),
    ];

    #[test]
    fn from_pkcs8_refuses_an_rsa_key_one_bit_off_its_size() {
        for (a, h, bits) in OFF_BY_ONE_BIT {
            let k = sig::RsaKeyPair::from_pkcs8(&der(h)).unwrap();
            assert_eq!(
                sig::RsaParameters::public_modulus_len(k.public_key().as_ref()),
                Ok(bits)
            );
            assert_eq!(
                KeyPair::from_pkcs8(a, &der(h)).err(),
                Some(CryptoError::PrivateKey),
                "{bits}"
            );
        }
    }

    #[test]
    fn verify_refuses_an_rsa_key_one_bit_off_its_size() {
        for (a, h, bits) in OFF_BY_ONE_BIT {
            let k = sig::RsaKeyPair::from_pkcs8(&der(h)).unwrap();
            let mut signature = vec![0u8; k.public_modulus_len()];
            k.sign(
                &sig::RSA_PKCS1_SHA384,
                &SystemRandom::new(),
                b"m",
                &mut signature,
            )
            .unwrap();
            let public = k.public_key().as_ref();
            assert_eq!(
                sig::UnparsedPublicKey::new(&sig::RSA_PKCS1_2048_8192_SHA384, public)
                    .verify(b"m", &signature),
                Ok(()),
                "{bits}"
            );
            assert_eq!(
                verify(a, public, b"m", &signature),
                Err(CryptoError::Verify),
                "{bits}"
            );
        }
    }

    #[test]
    fn debug_never_prints_key_material() {
        let k = KeyPair::generate(S::Ed25519).unwrap();
        assert_eq!(format!("{k:?}"), "KeyPair(ed25519, ..)");
    }
}
