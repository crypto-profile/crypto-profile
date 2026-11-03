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

// RFC 5480 §2.2: the only peer-key form is the uncompressed point.
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
/// be the canonical named-curve header for `k`'s curve (RFC 5280 §4.1, RFC 5480 §2) followed by a
/// point that passes the same checks as a peer key.
pub(crate) fn spki_point(k: KeyAgreementAlgorithm, der: &[u8]) -> Result<&[u8], CryptoError> {
    let point = der
        .strip_prefix(curve(k)?.spki_header)
        .ok_or(CryptoError::KeyAgreementPeerKey { algorithm: k })?;
    parse_peer(k, point)?;
    Ok(point)
}

// One DER element with a minimal definite length of at most two bytes: its tag, its value and the
// bytes after it.
fn split_tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, header, len) = match der {
        [t, n @ 0..=0x7f, ..] => (*t, 2, usize::from(*n)),
        [t, 0x81, n @ 0x80..=0xff, ..] => (*t, 3, usize::from(*n)),
        [t, 0x82, hi @ 0x01..=0xff, lo, ..] => (*t, 4, usize::from(u16::from_be_bytes([*hi, *lo]))),
        _ => return None,
    };
    let (value, rest) = der[header..].split_at_checked(len)?;
    Some((tag, value, rest))
}

// RFC 5480 §2.1.1: the AlgorithmIdentifier id-ecPublicKey with its namedCurve.
const P256_ALGORITHM: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
const P384_ALGORITHM: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x22,
];
const P521_ALGORITHM: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x23,
];
const ALGORITHM_HEADER: usize = 11;

struct EcKey {
    algorithm: &'static [u8],
    scalar_len: usize,
    point_len: usize,
}

impl EcKey {
    fn named_curve(&self) -> &'static [u8] {
        &self.algorithm[ALGORITHM_HEADER..]
    }
}

fn ec_key(k: KeyAgreementAlgorithm) -> Option<EcKey> {
    let (algorithm, scalar_len, point_len) = match k {
        KeyAgreementAlgorithm::EcdhP256 => (P256_ALGORITHM, 32, 65),
        KeyAgreementAlgorithm::EcdhP384 => (P384_ALGORITHM, 48, 97),
        KeyAgreementAlgorithm::EcdhP521 => (P521_ALGORITHM, 66, 133),
        _ => return None,
    };
    Some(EcKey {
        algorithm,
        scalar_len,
        point_len,
    })
}

/// The publicKey point a key's ECPrivateKey carries, if any, once the key is an RFC 5958 §2
/// PrivateKeyInfo or an RFC 5915 §3 ECPrivateKey on `k`'s curve, as `from_pkcs8_der` lists.
fn checked(k: KeyAgreementAlgorithm, der: &[u8]) -> Result<Option<&[u8]>, CryptoError> {
    let carried = match (ec_key(k), split_tlv(der)) {
        (Some(e), Some((0x30, body, []))) => match body {
            [0x02, 0x01, 0x00, rest @ ..] => private_key_info(&e, rest),
            _ => ec_private_key(&e, body, true),
        },
        _ => None,
    };
    carried.ok_or(CryptoError::KeyAgreementPrivateKey { algorithm: k })
}

// RFC 5958 §2 after version v1: privateKeyAlgorithm, privateKey and [0] attributes. RFC 5915 §1
// puts an EC public key in ECPrivateKey, so v2 and its [1] publicKey never apply.
fn private_key_info<'a>(e: &EcKey, der: &'a [u8]) -> Option<Option<&'a [u8]>> {
    let rest = der.strip_prefix(e.algorithm)?;
    let Some((0x04, private_key, rest)) = split_tlv(rest) else {
        return None;
    };
    match split_tlv(rest) {
        None if rest.is_empty() => {}
        Some((0xa0, attributes, [])) if are_attributes(attributes) => {}
        _ => return None,
    }
    let Some((0x30, body, [])) = split_tlv(private_key) else {
        return None;
    };
    ec_private_key(e, body, false)
}

// RFC 5958 §2 Attributes, IMPLICIT: Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET },
// a SET OF Attribute whose attrValues is a SET OF ANY.
fn are_attributes(der: &[u8]) -> bool {
    set_of(der, |tag, attribute| {
        let Some((0x06, [_, ..], values)) = split_tlv(attribute) else {
            return false;
        };
        tag == 0x30
            && matches!(split_tlv(values), Some((0x31, set, [])) if set_of(set, |_, _| true))
    })
}

// RFC 5915 §3 (EXPLICIT TAGS). §3 requires parameters; inside a PrivateKeyInfo, §1 a) puts the
// curve in privateKeyAlgorithm.
fn ec_private_key<'a>(e: &EcKey, body: &'a [u8], bare: bool) -> Option<Option<&'a [u8]>> {
    let rest = body.strip_prefix(&[0x02, 0x01, 0x01])?;
    let Some((0x04, scalar, rest)) = split_tlv(rest) else {
        return None;
    };
    let (parameters, rest) = optional(0xa0, rest);
    let (public_key, rest) = optional(0xa1, rest);
    let curve = match parameters {
        Some(named_curve) => named_curve == e.named_curve(),
        None => !bare,
    };
    if scalar.len() != e.scalar_len || !curve || !rest.is_empty() {
        return None;
    }
    match public_key.map(split_tlv) {
        None => Some(None),
        // RFC 5480 §2.2: an uncompressed point, the crate's only peer-key form.
        Some(Some((0x03, [0x00, point @ ..], [])))
            if point.len() == e.point_len && point.first() == Some(&UNCOMPRESSED) =>
        {
            Some(Some(point))
        }
        Some(_) => None,
    }
}

// RFC 5915 §3 for the NIST curves, RFC 7748 §5 for X25519: the private key has the field's length.
fn checked_scalar(k: KeyAgreementAlgorithm, d: &[u8]) -> Result<(), CryptoError> {
    let len = ec_key(k)
        .map(|e| e.scalar_len)
        .or((k == KeyAgreementAlgorithm::X25519).then_some(32));
    if Some(d.len()) == len {
        Ok(())
    } else {
        Err(CryptoError::KeyAgreementPrivateKey { algorithm: k })
    }
}

// X.690 §11.6: `next` does not precede `prev`, compared as octet strings with the shorter padded
// at its end with 0-octets.
fn not_after(prev: &[u8], next: &[u8]) -> bool {
    let padded = |s: &[u8]| {
        (0..prev.len().max(next.len()))
            .map(|i| s.get(i).copied().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    padded(prev) <= padded(next)
}

// The elements of a SET OF in `der`, each passing `element(tag, value)`, in ascending order of their
// encodings (X.690 §11.6).
fn set_of(mut der: &[u8], element: impl Fn(u8, &[u8]) -> bool) -> bool {
    let mut previous: Option<&[u8]> = None;
    for _ in 0..=der.len() {
        if der.is_empty() {
            return true;
        }
        let Some((tag, value, rest)) = split_tlv(der) else {
            return false;
        };
        let whole = &der[..der.len() - rest.len()];
        if !element(tag, value) || !previous.is_none_or(|p| not_after(p, whole)) {
            return false;
        }
        previous = Some(whole);
        der = rest;
    }
    false
}

fn optional(tag: u8, der: &[u8]) -> (Option<&[u8]>, &[u8]) {
    match split_tlv(der) {
        Some((t, value, rest)) if t == tag => (Some(value), rest),
        _ => (None, der),
    }
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
    /// Imports a P-256, P-384 or P-521 private key, DER-encoded, in one of two forms:
    ///
    /// - an RFC 5958 §2 `PrivateKeyInfo`, version v1: privateKeyAlgorithm `id-ecPublicKey` with
    ///   `algorithm`'s namedCurve (RFC 5480 §2.1.1), privateKey an RFC 5915 `ECPrivateKey`, then
    ///   optional `[0]` attributes;
    /// - an RFC 5915 §3 `ECPrivateKey` with its parameters.
    ///
    /// The `ECPrivateKey` is version 1, a privateKey of exactly 32, 48 or 66 bytes, then optional
    /// parameters naming `algorithm`'s curve and an optional publicKey holding the key's own
    /// uncompressed point (RFC 5915 §3, RFC 5480 §2.2). Refuses a curve `a`'s profile does not
    /// admit, then anything else, a field or version these sections do not define, BER, `id-ecDH`
    /// and `id-ecMQV`, other bytes after the key, and a key the module refuses
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
        let carried = checked(algorithm, der)?;
        let key = ag::PrivateKey::from_private_key_der(c.agreement, der).map_err(|_| refused)?;
        let key = Self::new(a, algorithm, key)?;
        key.matches_carried(carried)?;
        Ok(key)
    }

    // RFC 5915 §3: publicKey is a convenience; one that is not this key's marks a corrupt key.
    fn matches_carried(&self, carried: Option<&[u8]>) -> Result<(), CryptoError> {
        match carried {
            Some(point) if point != self.public => Err(CryptoError::KeyAgreementPrivateKey {
                algorithm: self.algorithm,
            }),
            _ => Ok(()),
        }
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
        checked_scalar(algorithm, d)?;
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
        let is_one_sequence = |der: &[u8]| matches!(split_tlv(der), Some((0x30, _, [])));
        for (whole, header) in [
            (with(&[0x30, 0x03], 3), 2),
            (with(&[0x30, 0x81, 0x80], 0x80), 3),
            (with(&[0x30, 0x82, 0x01, 0x01], 0x101), 4),
        ] {
            let empty: &[u8] = &[];
            assert_eq!(
                split_tlv(&whole),
                Some((0x30, &whole[header..], empty)),
                "{:02x?}",
                &whole[..4]
            );
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

    fn fields(der: &[u8]) -> Vec<Vec<u8>> {
        let (_, mut rest, _) = split_tlv(der).unwrap();
        let mut out = Vec::new();
        while !rest.is_empty() && out.len() < 8 {
            let (tag, value, next) = split_tlv(rest).unwrap();
            out.push(tlv(tag, value));
            rest = next;
        }
        out
    }

    fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &fields.concat())
    }

    const EC_CURVES: [KeyAgreementAlgorithm; 3] = [
        KeyAgreementAlgorithm::EcdhP256,
        KeyAgreementAlgorithm::EcdhP384,
        KeyAgreementAlgorithm::EcdhP521,
    ];
    const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const ID_EC_DH: &[u8] = &[0x2b, 0x81, 0x04, 0x01, 0x0c];
    const ID_EC_MQV: &[u8] = &[0x2b, 0x81, 0x04, 0x01, 0x0d];

    fn named_curve(k: KeyAgreementAlgorithm) -> Vec<u8> {
        use KeyAgreementAlgorithm as E;
        let oid: &[u8] = match k {
            E::EcdhP256 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            E::EcdhP384 => &[0x2b, 0x81, 0x04, 0x00, 0x22],
            E::EcdhP521 => &[0x2b, 0x81, 0x04, 0x00, 0x23],
            other => panic!("{other:?} has no RFC 5480 namedCurve"),
        };
        tlv(0x06, oid)
    }

    fn another(k: KeyAgreementAlgorithm) -> KeyAgreementAlgorithm {
        let at = EC_CURVES.iter().position(|&c| c == k).unwrap();
        EC_CURVES[(at + 1) % EC_CURVES.len()]
    }

    fn bits(unused: u8, point: &[u8]) -> Vec<u8> {
        tlv(0x03, &[&[unused][..], point].concat())
    }

    fn attribute(oid: &[u8], values: &[u8]) -> Vec<u8> {
        sequence(&[tlv(0x06, oid), tlv(0x31, values)])
    }

    fn local_key_id() -> Vec<u8> {
        attribute(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15],
            &tlv(0x04, &[1, 2, 3, 4]),
        )
    }

    fn friendly_name() -> Vec<u8> {
        attribute(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14],
            &tlv(0x1e, &[0x00, 0x6b]),
        )
    }

    // One curve's key, taken apart into RFC 5915 and RFC 5958 fields to rebuild variants from.
    struct Parts {
        k: KeyAgreementAlgorithm,
        key: StaticKey,
        scalar: Vec<u8>,
    }

    impl Parts {
        fn of(key: StaticKey) -> Self {
            let info = fields(&key.to_pkcs8_der().unwrap());
            let ec_key = fields(split_tlv(&info[2]).unwrap().1);
            let scalar = split_tlv(&ec_key[1]).unwrap().1.to_vec();
            Self {
                k: key.algorithm(),
                key,
                scalar,
            }
        }

        fn version(&self) -> Vec<u8> {
            vec![0x02, 0x01, 0x01]
        }

        fn scalar(&self) -> Vec<u8> {
            tlv(0x04, &self.scalar)
        }

        fn parameters(&self) -> Vec<u8> {
            tlv(0xa0, &named_curve(self.k))
        }

        fn public(&self) -> Vec<u8> {
            tlv(0xa1, &bits(0, self.key.public_key()))
        }

        fn ec_key(&self) -> Vec<Vec<u8>> {
            vec![
                self.version(),
                self.scalar(),
                self.parameters(),
                self.public(),
            ]
        }

        fn algorithm(&self) -> Vec<u8> {
            sequence(&[tlv(0x06, ID_EC_PUBLIC_KEY), named_curve(self.k)])
        }

        fn info_fields(&self, ec_key: &[Vec<u8>]) -> Vec<Vec<u8>> {
            vec![
                vec![0x02, 0x01, 0x00],
                self.algorithm(),
                tlv(0x04, &sequence(ec_key)),
            ]
        }

        fn info(&self, ec_key: &[Vec<u8>], after: &[Vec<u8>]) -> Vec<u8> {
            sequence(&[&self.info_fields(ec_key)[..], after].concat())
        }

        fn info_with(&self, at: usize, field: Vec<u8>) -> Vec<u8> {
            let mut f = self.info_fields(&self.ec_key());
            f[at] = field;
            sequence(&f)
        }
    }

    fn assert_taken(a: &Admitted, k: KeyAgreementAlgorithm, der: &[u8], public: &[u8]) {
        let carried = checked(k, der).unwrap_or_else(|e| panic!("{k:?} {e:?} {der:02x?}"));
        assert!(carried.is_none_or(|p| p == public), "{k:?} {der:02x?}");
        let imported = StaticKey::from_pkcs8_der(a, k, der).unwrap();
        assert_eq!(imported.public_key(), public, "{k:?} {der:02x?}");
    }

    fn assert_refused(a: &Admitted, k: KeyAgreementAlgorithm, why: &str, der: &[u8]) {
        assert!(
            checked(k, der).is_err(),
            "validator: {k:?} {why} {der:02x?}"
        );
        assert_eq!(
            StaticKey::from_pkcs8_der(a, k, der).map(|_| ()),
            Err(CryptoError::KeyAgreementPrivateKey { algorithm: k }),
            "import: {k:?} {why} {der:02x?}"
        );
    }

    #[test]
    fn emitted_keys_and_every_rfc_form_are_taken() {
        use aws_lc_rs::encoding::EcPrivateKeyRfc5915Der;
        let a = admit(Profile::Unrestricted, Options::default());
        for k in EC_CURVES {
            let p = Parts::of(StaticKey::generate(&a, k).unwrap());
            let public = p.key.public_key();
            let emitted = p.key.to_pkcs8_der().unwrap();
            assert_eq!(checked(k, &emitted), Ok(Some(public)), "{k:?}");
            assert_taken(&a, k, &emitted, public);
            let sec1: EcPrivateKeyRfc5915Der<'static> = p.key.key.as_der().unwrap();
            assert_eq!(checked(k, sec1.as_ref()), Ok(Some(public)), "{k:?}");
            assert_taken(&a, k, sec1.as_ref(), public);
            let [v, d, params, q] = <[Vec<u8>; 4]>::try_from(p.ec_key()).unwrap();
            for (inner, carried) in [
                (vec![v.clone(), d.clone()], None),
                (vec![v.clone(), d.clone(), params.clone()], None),
                (vec![v.clone(), d.clone(), q.clone()], Some(public)),
                (p.ec_key(), Some(public)),
            ] {
                let der = p.info(&inner, &[]);
                assert_eq!(checked(k, &der), Ok(carried), "{k:?} {der:02x?}");
                assert_taken(&a, k, &der, public);
            }
            for bare in [
                sequence(&[v.clone(), d.clone(), params.clone()]),
                sequence(&p.ec_key()),
            ] {
                assert_taken(&a, k, &bare, public);
            }
            for attributes in [
                Vec::new(),
                local_key_id(),
                [friendly_name(), local_key_id()].concat(),
            ] {
                assert_taken(
                    &a,
                    k,
                    &p.info(&p.ec_key(), &[tlv(0xa0, &attributes)]),
                    public,
                );
            }
            let mut d = vec![0x11; p.scalar.len()];
            d[0] = 0;
            let led = StaticKey::from_scalar(&a, k, &d).unwrap();
            assert_taken(&a, k, &led.to_pkcs8_der().unwrap(), led.public_key());
        }
    }

    #[test]
    fn the_sealbox_golden_keys_are_well_formed() {
        use crypto_profile::conformance::vectors::sealbox;
        let a = admit(Profile::Unrestricted, Options::default());
        let k = KeyAgreementAlgorithm::EcdhP384;
        for hex in [
            sealbox::PRIVATE_KEY_PKCS8_HEX,
            sealbox::release_0_9_0::PRIVATE_KEY_PKCS8_HEX,
        ] {
            let der = __hex::decode(hex).unwrap();
            let key = StaticKey::from_pkcs8_der(&a, k, &der).unwrap();
            assert_eq!(checked(k, &der), Ok(Some(key.public_key())));
        }
    }

    #[test]
    fn a_private_key_info_is_rfc_5958_v1_with_rfc_5480s_algorithm_and_nothing_else() {
        let a = admit(Profile::Unrestricted, Options::default());
        let null = || vec![0x05, 0x00];
        for k in EC_CURVES {
            let p = Parts::of(StaticKey::generate(&a, k).unwrap());
            let point = [&[0][..], p.key.public_key()].concat();
            let ec = p.ec_key();
            let v2 = |after: &[Vec<u8>]| {
                let mut f = p.info_fields(&ec);
                f[0] = vec![0x02, 0x01, 0x01];
                sequence(&[&f[..], after].concat())
            };
            let algorithm = |fields: &[Vec<u8>]| p.info_with(1, sequence(fields));
            let ec_pk = || tlv(0x06, ID_EC_PUBLIC_KEY);
            let attributes = |content: &[u8]| p.info(&ec, &[tlv(0xa0, content)]);
            for (why, der) in [
                ("v1 with a [1]", p.info(&ec, &[tlv(0x81, &point)])),
                (
                    "v1 with a constructed [1]",
                    p.info(&ec, &[tlv(0xa1, &bits(0, p.key.public_key()))]),
                ),
                (
                    "v1 with [0] then [1]",
                    p.info(&ec, &[tlv(0xa0, &[]), tlv(0x81, &point)]),
                ),
                ("v2 without a [1]", v2(&[])),
                ("v2 with a [1]", v2(&[tlv(0x81, &point)])),
                (
                    "v2 with [0] and [1]",
                    v2(&[tlv(0xa0, &[]), tlv(0x81, &point)]),
                ),
                ("version 2", p.info_with(0, vec![0x02, 0x01, 0x02])),
                (
                    "version 0 in two bytes",
                    p.info_with(0, vec![0x02, 0x02, 0x00, 0x00]),
                ),
                ("id-ecDH", algorithm(&[tlv(0x06, ID_EC_DH), named_curve(k)])),
                (
                    "id-ecMQV",
                    algorithm(&[tlv(0x06, ID_EC_MQV), named_curve(k)]),
                ),
                (
                    "another curve",
                    algorithm(&[ec_pk(), named_curve(another(k))]),
                ),
                ("no parameters", algorithm(&[ec_pk()])),
                ("NULL parameters", algorithm(&[ec_pk(), null()])),
                (
                    "parameters then NULL",
                    algorithm(&[ec_pk(), named_curve(k), null()]),
                ),
                (
                    "privateKey not an OCTET STRING",
                    p.info_with(2, sequence(&ec)),
                ),
                (
                    "bytes after ECPrivateKey",
                    p.info_with(2, tlv(0x04, &[sequence(&ec), null()].concat())),
                ),
                (
                    "NULL inside ECPrivateKey",
                    p.info(&[&ec[..], &[null()]].concat(), &[]),
                ),
                ("trailing byte", [p.info(&ec, &[]), vec![0]].concat()),
                ("NULL after privateKey", p.info(&ec, &[null()])),
                (
                    "truncated field after privateKey",
                    p.info(&ec, &[vec![0x05]]),
                ),
                ("[0] then NULL", p.info(&ec, &[tlv(0xa0, &[]), null()])),
                ("two [0]", p.info(&ec, &[tlv(0xa0, &[]), tlv(0xa0, &[])])),
                ("unknown [2]", p.info(&ec, &[tlv(0xa2, &null())])),
                (
                    "attributes as an explicit SET",
                    p.info(&ec, &[tlv(0x31, &local_key_id())]),
                ),
                ("attribute not a SEQUENCE", attributes(&null())),
                (
                    "attribute without an OID",
                    attributes(&sequence(&[tlv(0x31, &[])])),
                ),
                (
                    "attribute with an empty OID",
                    attributes(&sequence(&[tlv(0x06, &[]), tlv(0x31, &[])])),
                ),
                (
                    "attribute without values",
                    attributes(&sequence(&[tlv(0x06, ID_EC_DH)])),
                ),
                (
                    "attribute values not a SET",
                    attributes(&sequence(&[tlv(0x06, ID_EC_DH), tlv(0x30, &[])])),
                ),
                (
                    "attribute with a field after its values",
                    attributes(&sequence(&[tlv(0x06, ID_EC_DH), tlv(0x31, &[]), null()])),
                ),
                (
                    "attribute then NULL",
                    attributes(&[local_key_id(), null()].concat()),
                ),
                (
                    "truncated attribute",
                    attributes(&local_key_id()[..local_key_id().len() - 1]),
                ),
            ] {
                assert_refused(&a, k, why, &der);
            }
        }
    }

    #[test]
    fn an_ec_private_key_holds_rfc_5915s_fields_in_order_and_nothing_else() {
        let a = admit(Profile::Unrestricted, Options::default());
        let null = || vec![0x05, 0x00];
        for k in EC_CURVES {
            let p = Parts::of(StaticKey::generate(&a, k).unwrap());
            let [v, d, params, q] = <[Vec<u8>; 4]>::try_from(p.ec_key()).unwrap();
            let point = p.key.public_key();
            let curve_oid = named_curve(k);
            let mut hybrid = point.to_vec();
            hybrid[0] = 0x06 | (point[point.len() - 1] & 1);
            let mut compressed = vec![0x02 | (point[point.len() - 1] & 1)];
            compressed.extend_from_slice(&point[1..point.len().div_ceil(2)]);
            let mut led = vec![0x11; p.scalar.len()];
            led[0] = 0;
            let stripped = tlv(0x04, &led[1..]);
            let public =
                |inner: Vec<u8>| vec![v.clone(), d.clone(), params.clone(), tlv(0xa1, &inner)];
            for (why, inner) in [
                (
                    "version 0",
                    vec![vec![0x02, 0x01, 0x00], d.clone(), params.clone(), q.clone()],
                ),
                (
                    "version 2",
                    vec![vec![0x02, 0x01, 0x02], d.clone(), params.clone(), q.clone()],
                ),
                (
                    "scalar one byte short",
                    vec![v.clone(), tlv(0x04, &p.scalar[1..]), params.clone()],
                ),
                (
                    "scalar one byte long",
                    vec![
                        v.clone(),
                        tlv(0x04, &[&[0][..], &p.scalar].concat()),
                        params.clone(),
                    ],
                ),
                (
                    "leading zero stripped",
                    vec![v.clone(), stripped, params.clone()],
                ),
                (
                    "scalar not an OCTET STRING",
                    vec![v.clone(), tlv(0x02, &p.scalar), params.clone()],
                ),
                (
                    "[0] another curve",
                    vec![
                        v.clone(),
                        d.clone(),
                        tlv(0xa0, &named_curve(another(k))),
                        q.clone(),
                    ],
                ),
                (
                    "[0] implicit",
                    vec![v.clone(), d.clone(), tlv(0x80, &curve_oid[2..]), q.clone()],
                ),
                (
                    "[0] empty",
                    vec![v.clone(), d.clone(), tlv(0xa0, &[]), q.clone()],
                ),
                (
                    "[0] curve then NULL",
                    vec![
                        v.clone(),
                        d.clone(),
                        tlv(0xa0, &[curve_oid.clone(), null()].concat()),
                        q.clone(),
                    ],
                ),
                (
                    "[0] NULL",
                    vec![v.clone(), d.clone(), tlv(0xa0, &null()), q.clone()],
                ),
                ("[1] compressed", public(bits(0, &compressed))),
                ("[1] hybrid", public(bits(0, &hybrid))),
                ("[1] unused bits", public(bits(1, point))),
                (
                    "[1] one byte short",
                    public(bits(0, &point[..point.len() - 1])),
                ),
                (
                    "[1] one byte long",
                    public(bits(0, &[point, &[0]].concat())),
                ),
                ("[1] empty BIT STRING", public(tlv(0x03, &[]))),
                ("[1] OCTET STRING", public(tlv(0x04, point))),
                (
                    "[1] BIT STRING then NULL",
                    public([bits(0, point), null()].concat()),
                ),
                (
                    "[1] implicit",
                    vec![
                        v.clone(),
                        d.clone(),
                        params.clone(),
                        tlv(0x81, &[&[0][..], point].concat()),
                    ],
                ),
                (
                    "[1] before [0]",
                    vec![v.clone(), d.clone(), q.clone(), params.clone()],
                ),
                (
                    "privateKey before version",
                    vec![d.clone(), v.clone(), params.clone(), q.clone()],
                ),
                (
                    "[0] before privateKey",
                    vec![v.clone(), params.clone(), d.clone(), q.clone()],
                ),
                (
                    "two versions",
                    vec![v.clone(), v.clone(), d.clone(), params.clone(), q.clone()],
                ),
                (
                    "two privateKeys",
                    vec![v.clone(), d.clone(), d.clone(), params.clone(), q.clone()],
                ),
                (
                    "two [0]",
                    vec![
                        v.clone(),
                        d.clone(),
                        params.clone(),
                        params.clone(),
                        q.clone(),
                    ],
                ),
                (
                    "two [1]",
                    vec![v.clone(), d.clone(), params.clone(), q.clone(), q.clone()],
                ),
                (
                    "unknown [2]",
                    vec![
                        v.clone(),
                        d.clone(),
                        params.clone(),
                        q.clone(),
                        tlv(0xa2, &null()),
                    ],
                ),
                (
                    "NULL at the end",
                    vec![v.clone(), d.clone(), params.clone(), q.clone(), null()],
                ),
                ("no privateKey", vec![v.clone(), params.clone(), q.clone()]),
            ] {
                assert_refused(&a, k, why, &p.info(&inner, &[]));
                assert_refused(&a, k, why, &sequence(&inner));
            }
            for (why, bare) in [
                ("bare without parameters", sequence(&[v.clone(), d.clone()])),
                (
                    "bare without parameters, with [1]",
                    sequence(&[v.clone(), d.clone(), q.clone()]),
                ),
                ("bare then NULL", [sequence(&p.ec_key()), null()].concat()),
            ] {
                assert_refused(&a, k, why, &bare);
            }
        }
    }

    #[test]
    fn a_carried_public_key_is_the_keys_own() {
        let a = admit(Profile::Unrestricted, Options::default());
        for k in EC_CURVES {
            let p = Parts::of(StaticKey::generate(&a, k).unwrap());
            let other = StaticKey::generate(&a, k).unwrap();
            let refused = Err(CryptoError::KeyAgreementPrivateKey { algorithm: k });
            assert_eq!(p.key.matches_carried(None), Ok(()), "{k:?}");
            assert_eq!(
                p.key.matches_carried(Some(p.key.public_key())),
                Ok(()),
                "{k:?}"
            );
            assert_eq!(
                p.key.matches_carried(Some(other.public_key())),
                refused,
                "{k:?}"
            );
            let mut inner = p.ec_key();
            inner[3] = tlv(0xa1, &bits(0, other.public_key()));
            for der in [p.info(&inner, &[]), sequence(&inner)] {
                assert_eq!(checked(k, &der), Ok(Some(other.public_key())), "{k:?}");
                assert_eq!(
                    StaticKey::from_pkcs8_der(&a, k, &der).map(|_| ()),
                    refused,
                    "{k:?} {der:02x?}"
                );
            }
        }
    }

    #[test]
    fn no_x25519_key_is_imported_from_der() {
        let a = admit(Profile::Unrestricted, Options::default());
        let k = KeyAgreementAlgorithm::X25519;
        let der = [
            &__hex::decode("302e020100300506032b656e04220420").unwrap()[..],
            &[0x11; 32],
        ]
        .concat();
        assert!(checked(k, &der).is_err());
        assert_eq!(
            StaticKey::from_pkcs8_der(&a, k, &der).map(|_| ()),
            Err(CryptoError::KeyAgreementPrivateKey { algorithm: k })
        );
    }

    #[test]
    fn a_raw_private_key_has_exactly_its_curves_length() {
        let a = admit(Profile::Unrestricted, Options::default());
        for (k, n) in [
            (KeyAgreementAlgorithm::EcdhP256, 32),
            (KeyAgreementAlgorithm::EcdhP384, 48),
            (KeyAgreementAlgorithm::EcdhP521, 66),
            (KeyAgreementAlgorithm::X25519, 32),
        ] {
            let refused = Err(CryptoError::KeyAgreementPrivateKey { algorithm: k });
            assert_eq!(checked_scalar(k, &vec![0x11; n]), Ok(()), "{k:?}");
            for m in [0, 1, n - 1, n + 1, 2 * n] {
                assert_eq!(checked_scalar(k, &vec![0x11; m]), refused, "{k:?} {m}");
                if k != KeyAgreementAlgorithm::X25519 {
                    let end_to_end = StaticKey::from_scalar(&a, k, &vec![0x11; m]);
                    assert_eq!(end_to_end.map(|_| ()), refused, "{k:?} {m}");
                }
            }
        }
    }

    #[test]
    fn set_of_elements_are_compared_as_octet_strings_padded_with_zeros() {
        assert!(not_after(&[1, 2], &[1, 3]));
        assert!(not_after(&[1, 2], &[1, 2]));
        assert!(not_after(&[1, 2], &[1, 2, 1]));
        assert!(not_after(&[1, 2], &[1, 2, 0]));
        assert!(not_after(&[1, 2, 0], &[1, 2]));
        assert!(!not_after(&[1, 3], &[1, 2]));
        assert!(!not_after(&[1, 2, 1], &[1, 2]));
        assert!(!not_after(&[1, 3], &[1, 2, 9]));
        assert!(!not_after(&[2], &[1, 9, 9]));
        assert!(not_after(&[1, 9, 9], &[2]));
    }

    fn attr(last: u8, values: &[u8]) -> Vec<u8> {
        attribute(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, last],
            values,
        )
    }

    #[test]
    fn the_set_ofs_of_a_private_key_info_are_in_ascending_der_order() {
        let a = admit(Profile::Unrestricted, Options::default());
        let octets = |b: &[u8]| tlv(0x04, b);
        for k in EC_CURVES {
            let p = Parts::of(StaticKey::generate(&a, k).unwrap());
            let info = |content: &[u8]| p.info(&p.ec_key(), &[tlv(0xa0, content)]);
            let (x, y, z) = (attr(0x14, &[]), attr(0x15, &[]), attr(0x16, &[]));
            let ordered: [(&str, Vec<u8>); 5] = [
                ("two attributes", [x.clone(), y.clone()].concat()),
                (
                    "three attributes",
                    [x.clone(), y.clone(), z.clone()].concat(),
                ),
                ("equal attributes", [x.clone(), x.clone()].concat()),
                (
                    "values by content",
                    attr(0x14, &[octets(&[1]), octets(&[2])].concat()),
                ),
                (
                    "values by length, then tag",
                    attr(
                        0x14,
                        &[
                            tlv(0x02, &[5]),
                            octets(&[0xff]),
                            octets(&[0, 0]),
                            tlv(0x0c, &[0, 0]),
                        ]
                        .concat(),
                    ),
                ),
            ];
            for (_, content) in &ordered {
                assert_taken(&a, k, &info(content), p.key.public_key());
            }
            let unordered: [(&str, Vec<u8>); 6] = [
                ("two attributes", [y.clone(), x.clone()].concat()),
                (
                    "the last two of three",
                    [x.clone(), z.clone(), y.clone()].concat(),
                ),
                (
                    "the first two of three",
                    [y.clone(), x.clone(), z.clone()].concat(),
                ),
                (
                    "two values",
                    attr(0x14, &[octets(&[2]), octets(&[1])].concat()),
                ),
                (
                    "two values by length",
                    attr(0x14, &[octets(&[0, 0]), octets(&[0xff])].concat()),
                ),
                (
                    "the last two values of three",
                    attr(0x14, &[octets(&[1]), octets(&[3]), octets(&[2])].concat()),
                ),
            ];
            for (why, content) in &unordered {
                assert_refused(&a, k, why, &info(content));
            }
        }
    }

    #[test]
    fn no_short_or_truncated_private_key_is_imported() {
        let a = admit(Profile::Unrestricted, Options::default());
        let k = KeyAgreementAlgorithm::EcdhP384;
        let refused = Err(CryptoError::KeyAgreementPrivateKey { algorithm: k });
        let mut short = vec![Vec::new()];
        for b0 in 0..=u8::MAX {
            short.push(vec![b0]);
            for b1 in 0..=u8::MAX {
                short.push(vec![b0, b1]);
                short.push(vec![0x30, b0, b1]);
            }
        }
        for der in &short {
            assert_eq!(
                StaticKey::from_pkcs8_der(&a, k, der).map(|_| ()),
                refused,
                "{der:02x?}"
            );
        }
        let key = StaticKey::generate(&a, k).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap();
        for n in 0..pkcs8.len() {
            assert_eq!(
                StaticKey::from_pkcs8_der(&a, k, &pkcs8[..n]).map(|_| ()),
                refused,
                "{n}"
            );
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
