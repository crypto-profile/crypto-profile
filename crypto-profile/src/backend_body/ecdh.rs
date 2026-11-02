//! Elliptic-curve Diffie-Hellman key agreement under a profile: one-pass Diffie-Hellman (SP
//! 800-56A Rev. 3 §6.2.2.2) in both roles, each agreement completing into `kdf` in the same call,
//! so the shared secret never leaves the crate. A NIST-curve public key is an uncompressed SEC 1
//! point (65, 97 or 133 bytes); an X25519 public key is 32 bytes (RFC 7748).
use crate::kdf::{self, DerivedKey, Spec};
use crate::{Admitted, CryptoError};
use aws_lc_rs::agreement as ag;
use aws_lc_rs::rand::SystemRandom;
use crypto_profile::{Algorithm, KeyAgreementAlgorithm};
use std::fmt;
use zeroize::Zeroizing;

struct Curve {
    agreement: &'static ag::Algorithm,
    public_len: usize,
    sec1: bool,
}

fn curve(k: KeyAgreementAlgorithm) -> Result<Curve, CryptoError> {
    let (agreement, public_len, sec1) = match k {
        KeyAgreementAlgorithm::EcdhP256 => (&ag::ECDH_P256, 65, true),
        KeyAgreementAlgorithm::EcdhP384 => (&ag::ECDH_P384, 97, true),
        KeyAgreementAlgorithm::EcdhP521 => (&ag::ECDH_P521, 133, true),
        KeyAgreementAlgorithm::X25519 => (&ag::X25519, 32, false),
        _ => return Err(CryptoError::Unavailable(Algorithm::KeyAgreement(k))),
    };
    Ok(Curve {
        agreement,
        public_len,
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

fn prepare(
    a: &Admitted,
    k: KeyAgreementAlgorithm,
    peer: &[u8],
    spec: &Spec<'_>,
    len: usize,
) -> Result<ag::ParsedPublicKey, CryptoError> {
    kdf::matched(spec)?;
    kdf::admitted(a, spec, len)?;
    parse_peer(k, peer)
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
    /// `spec` says, under the profile the key was generated under, which admitted its curve.
    /// Refuses, in this order: a `spec` whose algorithm is not of its kind
    /// (`CryptoError::KdfSpecMismatch`); a KDF the profile does not admit; an empty `info` or `fixed_info` unless
    /// `kdf_info_may_be_empty`; an output length outside the KDF's bounds; a peer key that is not
    /// an uncompressed point (or 32 bytes for X25519) of the key's length; and a peer key the
    /// module's validation refuses, or an X25519 agreement whose shared secret is all zeros
    /// (`CryptoError::KeyAgreementPeerKey`).
    pub fn agree(
        self,
        peer_static: &[u8],
        spec: &Spec<'_>,
        len: usize,
    ) -> Result<DerivedKey, CryptoError> {
        let peer = prepare(&self.admitted, self.algorithm, peer_static, spec, len)?;
        let refused = CryptoError::KeyAgreementPeerKey {
            algorithm: self.algorithm,
        };
        ag::agree_ephemeral(self.key, peer, refused, |z| kdf::compute(z, spec, len))
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
    /// malformed, on another curve, or fails the module's checks
    /// (`CryptoError::KeyAgreementPrivateKey`). An X25519 key is imported with
    /// [`StaticKey::from_scalar`].
    pub fn from_pkcs8_der(
        a: &Admitted,
        algorithm: KeyAgreementAlgorithm,
        der: &[u8],
    ) -> Result<Self, CryptoError> {
        a.admit_key_agreement(algorithm)?;
        let c = curve(algorithm)?;
        let key = ag::PrivateKey::from_private_key_der(c.agreement, der)
            .map_err(|_| CryptoError::KeyAgreementPrivateKey { algorithm })?;
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
    /// as `spec` says, under the profile the key was imported under. Refuses as
    /// [`EphemeralKey::agree`] does.
    pub fn agree(
        &self,
        peer_ephemeral: &[u8],
        spec: &Spec<'_>,
        len: usize,
    ) -> Result<DerivedKey, CryptoError> {
        let peer = prepare(&self.admitted, self.algorithm, peer_ephemeral, spec, len)?;
        let refused = CryptoError::KeyAgreementPeerKey {
            algorithm: self.algorithm,
        };
        ag::agree(&self.key, peer, refused, |z| kdf::compute(z, spec, len))
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
