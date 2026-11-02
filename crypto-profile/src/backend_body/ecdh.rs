//! Elliptic-curve Diffie-Hellman key agreement under a profile: one-pass Diffie-Hellman (SP
//! 800-56A Rev. 3 §6.2.2.2) in both roles, each agreement completing into `kdf` in the same call,
//! so the shared secret never leaves the crate. A NIST-curve public key is an uncompressed SEC 1
//! point (65, 97 or 133 bytes); an X25519 public key is 32 bytes (RFC 7748).
use crate::kdf::{self, DerivedKey, Spec};
use crate::{Admitted, CryptoError};
use aws_lc_rs::agreement as ag;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use crypto_profile::{Algorithm, KdfAlgorithm, KeyAgreementAlgorithm};
use std::fmt;
use zeroize::Zeroizing;

struct Curve {
    agreement: &'static ag::Algorithm,
    public_len: usize,
    spki_header: &'static [u8],
    sec1: bool,
}

const P256_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const P384_SPKI: &[u8] = &[
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];
const P521_SPKI: &[u8] = &[
    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
    0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00,
];
const X25519_SPKI: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

fn curve(k: KeyAgreementAlgorithm) -> Result<Curve, CryptoError> {
    let (agreement, public_len, spki_header, sec1) = match k {
        KeyAgreementAlgorithm::EcdhP256 => (&ag::ECDH_P256, 65, P256_SPKI, true),
        KeyAgreementAlgorithm::EcdhP384 => (&ag::ECDH_P384, 97, P384_SPKI, true),
        KeyAgreementAlgorithm::EcdhP521 => (&ag::ECDH_P521, 133, P521_SPKI, true),
        KeyAgreementAlgorithm::X25519 => (&ag::X25519, 32, X25519_SPKI, false),
        _ => return Err(CryptoError::Unavailable(Algorithm::KeyAgreement(k))),
    };
    Ok(Curve {
        agreement,
        public_len,
        spki_header,
        sec1,
    })
}

const UNCOMPRESSED: u8 = 0x04;

// Compressed, hybrid and SPKI encodings never reach the module, so both module lines see the same
// inputs (4.x alone decodes hybrid points and explicit-parameter SPKIs).
fn parse_peer(k: KeyAgreementAlgorithm, peer: &[u8]) -> Result<ag::ParsedPublicKey, CryptoError> {
    let refused = CryptoError::KeyAgreementPeerKey { algorithm: k };
    let c = curve(k)?;
    if peer.len() != c.public_len || (c.sec1 && peer.first() != Some(&UNCOMPRESSED)) {
        return Err(refused);
    }
    ag::ParsedPublicKey::try_from(ag::UnparsedPublicKey::new(c.agreement, peer))
        .map_err(|_| refused)
}

/// The point a SubjectPublicKeyInfo carries, for a caller that takes keys in that form: `der` must
/// be the canonical named-curve SPKI header for `k`'s curve followed by a point that passes the
/// same checks as a peer key. The module is never asked to parse the SPKI, because it accepts one
/// followed by trailing bytes.
pub(crate) fn spki_point(k: KeyAgreementAlgorithm, der: &[u8]) -> Result<&[u8], CryptoError> {
    let point = der
        .strip_prefix(curve(k)?.spki_header)
        .ok_or(CryptoError::KeyAgreementPeerKey { algorithm: k })?;
    parse_peer(k, point)?;
    Ok(point)
}

// The module accepts a key followed by trailing bytes; this requires one DER SEQUENCE, with a
// minimal definite length, that ends where the input does.
fn is_one_sequence(der: &[u8]) -> bool {
    let (header, len) = match der {
        [0x30, n @ 0..=0x7f, ..] => (2, usize::from(*n)),
        [0x30, 0x81, n @ 0x80..=0xff, ..] => (3, usize::from(*n)),
        [0x30, 0x82, hi @ 0x01..=0xff, lo, ..] => (4, usize::from(u16::from_be_bytes([*hi, *lo]))),
        _ => return false,
    };
    header + len == der.len()
}

/// RFC 9180 §7.1 Table 2: the DHKEM `kem_id` of a curve with its HKDF.
fn dhkem_kem_id(k: KeyAgreementAlgorithm, d: KdfAlgorithm) -> Result<u16, CryptoError> {
    match (k, d) {
        (KeyAgreementAlgorithm::EcdhP256, KdfAlgorithm::HkdfSha256) => Ok(0x0010),
        (KeyAgreementAlgorithm::EcdhP384, KdfAlgorithm::HkdfSha384) => Ok(0x0011),
        (KeyAgreementAlgorithm::EcdhP521, KdfAlgorithm::HkdfSha512) => Ok(0x0012),
        (KeyAgreementAlgorithm::X25519, KdfAlgorithm::HkdfSha256) => Ok(0x0020),
        _ => Err(CryptoError::KdfSpecMismatch { algorithm: d }),
    }
}

struct Prepared {
    peer: ag::ParsedPublicKey,
    dhkem: Option<(KdfAlgorithm, u16)>,
}

fn prepare(
    a: &Admitted,
    k: KeyAgreementAlgorithm,
    peer: &[u8],
    spec: &Spec<'_>,
    len: usize,
) -> Result<Prepared, CryptoError> {
    let algorithm = kdf::matched(spec)?;
    let dhkem = match spec {
        Spec::Dhkem { .. } => Some((algorithm, dhkem_kem_id(k, algorithm)?)),
        Spec::Hkdf { .. } | Spec::OneStep { .. } => None,
    };
    kdf::admitted(a, spec, len)?;
    Ok(Prepared {
        peer: parse_peer(k, peer)?,
        dhkem,
    })
}

fn derive(
    z: &[u8],
    spec: &Spec<'_>,
    dhkem: Option<(KdfAlgorithm, u16)>,
    enc: &[u8],
    pk_rm: &[u8],
    len: usize,
) -> Result<DerivedKey, CryptoError> {
    match dhkem {
        Some((algorithm, kem_id)) => kdf::dhkem(algorithm, kem_id, z, enc, pk_rm, len),
        None => kdf::compute(z, spec, len),
    }
}

fn public_point(k: KeyAgreementAlgorithm, key: &ag::PrivateKey) -> Result<Vec<u8>, CryptoError> {
    let public = key
        .compute_public_key()
        .map_err(|_| CryptoError::KeyAgreementPrivateKey { algorithm: k })?;
    Ok(public.as_ref().to_vec())
}

/// An ephemeral key, generated in the module for one agreement and never exported. `agree`
/// consumes it (SP 800-56A Rev. 3 §5.6.3.3).
pub struct EphemeralKey {
    admitted: Admitted,
    algorithm: KeyAgreementAlgorithm,
    key: ag::EphemeralPrivateKey,
    public: Vec<u8>,
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralKey({}, ..)", self.algorithm)
    }
}

impl EphemeralKey {
    /// A fresh key on `algorithm`'s curve. Refuses a curve `a`'s profile does not admit, or its
    /// module line lacks (`Admitted::admit_key_agreement`).
    pub fn generate(a: &Admitted, algorithm: KeyAgreementAlgorithm) -> Result<Self, CryptoError> {
        a.admit_key_agreement(algorithm)?;
        let c = curve(algorithm)?;
        let failed = |_| CryptoError::KeyGeneration(Algorithm::KeyAgreement(algorithm));
        let key =
            ag::EphemeralPrivateKey::generate(c.agreement, &SystemRandom::new()).map_err(failed)?;
        let public = key.compute_public_key().map_err(failed)?.as_ref().to_vec();
        Ok(Self {
            admitted: a.clone(),
            algorithm,
            key,
            public,
        })
    }

    /// The key's curve.
    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }

    /// The public key to send the peer: an uncompressed SEC 1 point, or 32 bytes for X25519.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Agrees with the peer's static public key and derives `len` bytes from the shared secret as
    /// `spec` says, under the profile the key was generated under, which admitted its curve. With
    /// `kdf::Spec::Dhkem` this is RFC 9180 §4.1 `Encap`'s shared secret, `enc` being this key's
    /// public key. Refuses, in this order: a `spec` whose algorithm is not of its kind, or a DHKEM
    /// HKDF RFC 9180 Table 2 does not pair with the curve (`CryptoError::KdfSpecMismatch`); a KDF
    /// the profile does not admit; an empty `info` or `fixed_info` unless `kdf_info_may_be_empty`;
    /// an output length outside the KDF's bounds, or other than `Nsecret` for DHKEM; a peer key
    /// that is not an uncompressed point (or 32 bytes for X25519) of the key's length; and a peer
    /// key the module's validation refuses, or an X25519 agreement whose shared secret is all
    /// zeros (`CryptoError::KeyAgreementPeerKey`).
    pub fn agree(
        self,
        peer_static: &[u8],
        spec: &Spec<'_>,
        len: usize,
    ) -> Result<DerivedKey, CryptoError> {
        let prepared = prepare(&self.admitted, self.algorithm, peer_static, spec, len)?;
        let refused = CryptoError::KeyAgreementPeerKey {
            algorithm: self.algorithm,
        };
        let public = self.public;
        ag::agree_ephemeral(self.key, prepared.peer, refused, |z| {
            derive(z, spec, prepared.dhkem, &public, peer_static, len)
        })
    }
}

/// A static key, imported from the owner's PKI or HSM tooling; `ecdh` neither generates nor
/// exports one (`sealbox::PrivateKey` keeps its own P-384 generation and export for the sealed
/// box). Its private key is cleansed by the module when the key is dropped.
pub struct StaticKey {
    admitted: Admitted,
    algorithm: KeyAgreementAlgorithm,
    key: ag::PrivateKey,
    public: Vec<u8>,
}

impl fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StaticKey({}, ..)", self.algorithm)
    }
}

impl StaticKey {
    /// Imports an unencrypted PKCS#8 private key (an RFC 5915 `ECPrivateKey` is also accepted) on
    /// `algorithm`'s curve. Refuses a curve `a`'s profile does not admit, then a key that is
    /// malformed, followed by other bytes, on another curve, or fails the module's checks
    /// (`CryptoError::KeyAgreementPrivateKey`). An X25519 key is imported with
    /// [`StaticKey::from_scalar`].
    pub fn from_pkcs8_der(
        a: &Admitted,
        algorithm: KeyAgreementAlgorithm,
        der: &[u8],
    ) -> Result<Self, CryptoError> {
        a.admit_key_agreement(algorithm)?;
        let c = curve(algorithm)?;
        let refused = CryptoError::KeyAgreementPrivateKey { algorithm };
        if !is_one_sequence(der) {
            return Err(refused);
        }
        let key = ag::PrivateKey::from_private_key_der(c.agreement, der).map_err(|_| refused)?;
        Self::new(a, algorithm, key)
    }

    /// Imports a raw private key: a big-endian scalar of exactly the field length (32, 48 or 66
    /// bytes) for a NIST curve, or the 32-byte RFC 7748 private key for X25519. Refuses a curve
    /// `a`'s profile does not admit, then a key of another length, or a scalar that is zero or not
    /// below the curve order (`CryptoError::KeyAgreementPrivateKey`).
    pub fn from_scalar(
        a: &Admitted,
        algorithm: KeyAgreementAlgorithm,
        d: &[u8],
    ) -> Result<Self, CryptoError> {
        a.admit_key_agreement(algorithm)?;
        let c = curve(algorithm)?;
        let key = ag::PrivateKey::from_private_key(c.agreement, d)
            .map_err(|_| CryptoError::KeyAgreementPrivateKey { algorithm })?;
        Self::new(a, algorithm, key)
    }

    pub(crate) fn generate(
        a: &Admitted,
        algorithm: KeyAgreementAlgorithm,
    ) -> Result<Self, CryptoError> {
        a.admit_key_agreement(algorithm)?;
        let c = curve(algorithm)?;
        let key = ag::PrivateKey::generate(c.agreement)
            .map_err(|_| CryptoError::KeyGeneration(Algorithm::KeyAgreement(algorithm)))?;
        Self::new(a, algorithm, key)
    }

    fn new(
        a: &Admitted,
        algorithm: KeyAgreementAlgorithm,
        key: ag::PrivateKey,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            admitted: a.clone(),
            algorithm,
            public: public_point(algorithm, &key)?,
            key,
        })
    }

    /// The key's curve.
    pub fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }

    /// The public key: an uncompressed SEC 1 point, or 32 bytes for X25519.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Agrees with a peer's ephemeral public key and derives `len` bytes from the shared secret
    /// as `spec` says, under the profile the key was imported under. With `kdf::Spec::Dhkem` this
    /// is RFC 9180 §4.1 `Decap`'s shared secret, `enc` being the peer's key. Refuses as
    /// [`EphemeralKey::agree`] does.
    pub fn agree(
        &self,
        peer_ephemeral: &[u8],
        spec: &Spec<'_>,
        len: usize,
    ) -> Result<DerivedKey, CryptoError> {
        let prepared = prepare(&self.admitted, self.algorithm, peer_ephemeral, spec, len)?;
        let refused = CryptoError::KeyAgreementPeerKey {
            algorithm: self.algorithm,
        };
        ag::agree(&self.key, prepared.peer, refused, |z| {
            derive(z, spec, prepared.dhkem, peer_ephemeral, &self.public, len)
        })
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let der: Pkcs8V1Der<'static> = self.key.as_der().map_err(|_| CryptoError::Primitive)?;
        Ok(Zeroizing::new(der.as_ref().to_vec()))
    }

    pub(crate) fn to_spki_der(&self) -> Result<Vec<u8>, CryptoError> {
        let spki: PublicKeyX509Der<'static> = self
            .key
            .compute_public_key()
            .and_then(|p| p.as_der())
            .map_err(|_| CryptoError::Primitive)?;
        Ok(spki.as_ref().to_vec())
    }

    /// The raw shared secret with `peer`, for tests that check it against published vectors.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn shared_secret(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let parsed = parse_peer(self.algorithm, peer)?;
        let refused = CryptoError::KeyAgreementPeerKey {
            algorithm: self.algorithm,
        };
        ag::agree(&self.key, parsed, refused, |z| {
            Ok(Zeroizing::new(z.to_vec()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Profile, admit};
    use crypto_profile::conformance::__hex;
    use crypto_profile::conformance::vectors::rfc9180::CASES;

    #[test]
    fn the_dhkem_kem_ids_are_rfc_9180_table_2s() {
        use KeyAgreementAlgorithm as E;
        let paired = [
            (E::EcdhP256, KdfAlgorithm::HkdfSha256, 0x0010),
            (E::EcdhP384, KdfAlgorithm::HkdfSha384, 0x0011),
            (E::EcdhP521, KdfAlgorithm::HkdfSha512, 0x0012),
            (E::X25519, KdfAlgorithm::HkdfSha256, 0x0020),
        ];
        for &k in KeyAgreementAlgorithm::ALL {
            for &d in KdfAlgorithm::ALL {
                let want = paired
                    .iter()
                    .find(|(pk, pd, _)| (*pk, *pd) == (k, d))
                    .map_or(Err(CryptoError::KdfSpecMismatch { algorithm: d }), |p| {
                        Ok(p.2)
                    });
                assert_eq!(dhkem_kem_id(k, d), want, "{k:?} {d:?}");
            }
        }
    }

    #[test]
    fn the_sender_side_derives_rfc_9180s_shared_secret() {
        let a = admit(Profile::Unrestricted, Options::default());
        for c in CASES {
            let (k, d) = match c.kem_id {
                0x0010 => (KeyAgreementAlgorithm::EcdhP256, KdfAlgorithm::HkdfSha256),
                0x0012 => (KeyAgreementAlgorithm::EcdhP521, KdfAlgorithm::HkdfSha512),
                0x0020 => (KeyAgreementAlgorithm::X25519, KdfAlgorithm::HkdfSha256),
                other => panic!("kem_id {other:#06x}: not in RFC 9180 Table 2"),
            };
            let sk_em =
                StaticKey::from_scalar(&a, k, &__hex::decode(c.sk_em_hex).unwrap()).unwrap();
            let enc = __hex::decode(c.enc_hex).unwrap();
            let pk_rm = __hex::decode(c.pk_rm_hex).unwrap();
            assert_eq!(sk_em.public_key(), enc, "{}", c.section);
            let dh = sk_em.shared_secret(&pk_rm).unwrap();
            let n = d.hash().output_len();
            let spec = Spec::Dhkem { algorithm: d };
            let got = derive(&dh, &spec, Some((d, c.kem_id)), &enc, &pk_rm, n).unwrap();
            assert_eq!(
                got.as_bytes(),
                __hex::decode(c.shared_secret_hex).unwrap(),
                "{}",
                c.section
            );
        }
    }

    #[test]
    fn a_dhkem_hkdf_the_profile_lacks_is_refused_after_the_pairing() {
        let a = admit(Profile::Fips1403, Options::default())
            .without(Algorithm::Kdf(KdfAlgorithm::HkdfSha384));
        let k = KeyAgreementAlgorithm::EcdhP384;
        let key = StaticKey::from_scalar(&a, k, &[1; 48]).unwrap();
        let dhkem = |algorithm| Spec::Dhkem { algorithm };
        assert_eq!(
            key.agree(&[], &dhkem(KdfAlgorithm::HkdfSha256), 0).err(),
            Some(CryptoError::KdfSpecMismatch {
                algorithm: KdfAlgorithm::HkdfSha256
            })
        );
        assert_eq!(
            key.agree(&[], &dhkem(KdfAlgorithm::HkdfSha384), 0).err(),
            Some(CryptoError::NotInProfile {
                profile: Profile::Fips1403,
                algorithm: Algorithm::Kdf(KdfAlgorithm::HkdfSha384),
            })
        );
    }

    #[test]
    fn an_spki_yields_its_point_and_nothing_else_does() {
        let a = admit(Profile::Fips1403, Options::default());
        let k = KeyAgreementAlgorithm::EcdhP384;
        let key = StaticKey::generate(&a, k).unwrap();
        let spki = key.to_spki_der().unwrap();
        assert_eq!(spki_point(k, &spki), Ok(key.public_key()));
        let refused = Err(CryptoError::KeyAgreementPeerKey { algorithm: k });
        assert_eq!(spki_point(k, key.public_key()), refused);
        let mut hybrid = spki.clone();
        let at = spki.len() - key.public_key().len();
        hybrid[at] = 0x06 | (spki[spki.len() - 1] & 1);
        assert_eq!(spki_point(k, &hybrid), refused);
        assert_eq!(
            spki_point(KeyAgreementAlgorithm::EcdhP256, &spki),
            Err(CryptoError::KeyAgreementPeerKey {
                algorithm: KeyAgreementAlgorithm::EcdhP256
            })
        );
    }

    #[test]
    fn only_one_minimally_encoded_sequence_spanning_the_input_is_whole() {
        let with = |head: &[u8], n: usize| [head, &vec![0; n][..]].concat();
        for whole in [
            with(&[0x30, 0x03], 3),
            with(&[0x30, 0x81, 0x80], 0x80),
            with(&[0x30, 0x82, 0x01, 0x01], 0x101),
        ] {
            assert!(is_one_sequence(&whole), "{:02x?}", &whole[..4]);
        }
        for bad in [
            Vec::new(),
            vec![0x30],
            with(&[0x30, 0x03], 2),
            with(&[0x30, 0x03], 4),
            with(&[0x31, 0x03], 3),
            with(&[0x30, 0x80], 2),
            with(&[0x30, 0x81, 0x7f], 0x7f),
            with(&[0x30, 0x81, 0x80], 0x81),
            with(&[0x30, 0x82, 0x00, 0xff], 0xff),
            with(&[0x30, 0x82, 0x01, 0x01], 0x100),
            with(&[0x30, 0x83, 0x00, 0x01, 0x00], 0x100),
        ] {
            assert!(!is_one_sequence(&bad), "{bad:02x?}");
        }
    }

    #[test]
    fn a_pkcs8_key_followed_by_other_bytes_is_refused_and_an_rfc_5915_key_is_not() {
        use aws_lc_rs::encoding::EcPrivateKeyRfc5915Der;
        let a = admit(Profile::Unrestricted, Options::default());
        for k in [
            KeyAgreementAlgorithm::EcdhP256,
            KeyAgreementAlgorithm::EcdhP384,
            KeyAgreementAlgorithm::EcdhP521,
        ] {
            let key = StaticKey::generate(&a, k).unwrap();
            let der = key.to_pkcs8_der().unwrap();
            let imported = StaticKey::from_pkcs8_der(&a, k, &der).unwrap();
            assert_eq!(imported.public_key(), key.public_key(), "{k:?}");
            let other = StaticKey::generate(&a, k).unwrap().to_pkcs8_der().unwrap();
            for bad in [[&der[..], &[0]].concat(), [&der[..], &other[..]].concat()] {
                assert_eq!(
                    StaticKey::from_pkcs8_der(&a, k, &bad).map(|_| ()),
                    Err(CryptoError::KeyAgreementPrivateKey { algorithm: k }),
                    "{k:?}"
                );
            }
            let sec1: EcPrivateKeyRfc5915Der<'static> = key.key.as_der().unwrap();
            let imported = StaticKey::from_pkcs8_der(&a, k, sec1.as_ref()).unwrap();
            assert_eq!(imported.public_key(), key.public_key(), "{k:?}");
        }
    }

    #[test]
    fn a_compressed_spki_padded_to_the_named_curve_length_is_refused() {
        let a = admit(Profile::Unrestricted, Options::default());
        let k = KeyAgreementAlgorithm::EcdhP256;
        let key = StaticKey::generate(&a, k).unwrap();
        let point = key.public_key();
        let mut der =
            __hex::decode("3039301306072a8648ce3d020106082a8648ce3d030107032200").unwrap();
        der.push(0x02 | (point[64] & 1));
        der.extend_from_slice(&point[1..33]);
        der.extend_from_slice(&[0xa5; 32]);
        assert_eq!(der.len(), 91);
        assert_eq!(
            spki_point(k, &der),
            Err(CryptoError::KeyAgreementPeerKey { algorithm: k })
        );
    }

    #[test]
    fn every_curves_named_spki_yields_its_point_and_no_longer_input_does() {
        let a = admit(Profile::Unrestricted, Options::default());
        for (k, extra) in [
            (KeyAgreementAlgorithm::EcdhP256, 65),
            (KeyAgreementAlgorithm::EcdhP384, 97),
            (KeyAgreementAlgorithm::EcdhP521, 133),
            (KeyAgreementAlgorithm::X25519, 1),
        ] {
            let key = StaticKey::generate(&a, k).unwrap();
            let mut der = key.to_spki_der().unwrap();
            let c = curve(k).unwrap();
            assert_eq!(der.len(), c.spki_header.len() + c.public_len, "{k:?}");
            assert!(der.starts_with(c.spki_header), "{k:?}");
            assert_eq!(spki_point(k, &der), Ok(key.public_key()), "{k:?}");
            let other = StaticKey::generate(&a, k).unwrap();
            der.extend_from_slice(&other.public_key()[other.public_key().len() - extra..]);
            assert_eq!(
                spki_point(k, &der),
                Err(CryptoError::KeyAgreementPeerKey { algorithm: k }),
                "{k:?}"
            );
        }
    }
}
