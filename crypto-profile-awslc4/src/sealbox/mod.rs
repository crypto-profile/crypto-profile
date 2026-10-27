//! A sealed box: an ephemeral P-384 ECDH to the recipient's static key, HKDF-SHA384
//! keyed by a caller-chosen domain, and AES-256-GCM over the plaintext with the
//! caller's AAD. Wire format: version, ephemeral point, nonce, ciphertext, tag.
mod keys;

pub use crypto_profile::sealbox_wire::{
    EPHEMERAL_KEY_LEN, HEADER_LEN, NONCE_LEN, TAG_LEN, VERSION,
};
pub use keys::{PEM_LEN, PrivateKey, PublicKey, SPKI_LEN};

use crate::aead::{Aes256GcmKey, KEY_LEN};
use crate::fips::assert_fips_module;
use aws_lc_rs::aead::AES_256_GCM;
use aws_lc_rs::agreement::{
    ECDH_P384, EphemeralPrivateKey, ParsedPublicKey, UnparsedPublicKey, agree, agree_ephemeral,
};
use aws_lc_rs::hkdf::{HKDF_SHA384, Salt};
use aws_lc_rs::rand::SystemRandom;
use crypto_profile::CryptoError;
use crypto_profile::sealbox_wire::{parse_blob, sealed_len};
use std::fmt;
use zeroize::Zeroizing;

const KDF_SUITE: &[u8] = b" p384 hkdf-sha384 aes-256-gcm";

/// The wire bytes of one sealed box.
pub struct SealedBlob(Vec<u8>);

impl SealedBlob {
    /// The blob's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the blob, returning its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SealedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedBlob(<{} bytes>)", self.0.len())
    }
}

fn kdf_labels(domain: &[u8]) -> (&[u8], Vec<u8>) {
    let mut info = Vec::with_capacity(domain.len() + KDF_SUITE.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(KDF_SUITE);
    (domain, info)
}

fn derive_key(
    shared: &[u8],
    domain: &[u8],
    ephemeral: &[u8],
    recipient: &PublicKey,
) -> Result<Aes256GcmKey, CryptoError> {
    let (salt, info_prefix) = kdf_labels(domain);
    let prk = Salt::new(HKDF_SHA384, salt).extract(shared);
    let info = [&info_prefix[..], ephemeral, recipient.spki_der()];
    let okm = prk.expand(&info, &AES_256_GCM);
    let okm = okm.map_err(|_| CryptoError::Primitive)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    let filled = okm.fill(&mut key[..]);
    filled.map_err(|_| CryptoError::Primitive)?;
    Aes256GcmKey::new(&key)
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::SealPlaintext);
    }
    Ok(())
}

/// Seals a non-empty `plaintext` to `recipient` under `domain`, authenticating `aad`.
pub fn seal(
    recipient: &PublicKey,
    domain: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBlob, CryptoError> {
    assert_fips_module().and_then(|()| check_plaintext(plaintext))?;
    let generated = EphemeralPrivateKey::generate(&ECDH_P384, &SystemRandom::new());
    let ephemeral = generated.map_err(|_| CryptoError::Primitive)?;
    let computed = ephemeral.compute_public_key();
    let point = computed.map_err(|_| CryptoError::Primitive)?;
    let as_array = <&[u8; EPHEMERAL_KEY_LEN]>::try_from(point.as_ref());
    let point_bytes = as_array.map_err(|_| CryptoError::Primitive)?;
    let peer = UnparsedPublicKey::new(&ECDH_P384, recipient.spki_der());
    let derive = |shared: &[u8]| derive_key(shared, domain, point_bytes, recipient);
    let agreed = agree_ephemeral(ephemeral, peer, CryptoError::Primitive, derive);
    let sealer = agreed?;
    let mut out = Zeroizing::new(Vec::with_capacity(sealed_len(plaintext.len())));
    out.push(VERSION);
    out.extend_from_slice(point_bytes);
    out.extend_from_slice(&[0u8; NONCE_LEN]);
    out.extend_from_slice(plaintext);
    let (head, body) = out.split_at_mut(HEADER_LEN);
    let (nonce, tag) = sealer.seal_in_place(aad, body)?;
    head[1 + EPHEMERAL_KEY_LEN..].copy_from_slice(&nonce);
    out.extend_from_slice(&tag);
    Ok(SealedBlob(std::mem::take(&mut *out)))
}

/// Opens a blob sealed to `recipient` under `domain` and `aad`.
pub fn open(
    recipient: &PrivateKey,
    domain: &[u8],
    aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let parts = assert_fips_module().and_then(|()| parse_blob(blob))?;
    let peer = ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, parts.ephemeral));
    let ephemeral = peer.map_err(|_| CryptoError::SealEphemeralKey)?;
    let derive =
        |shared: &[u8]| derive_key(shared, domain, parts.ephemeral, recipient.public_key());
    let agreed = agree(
        recipient.agreement_key(),
        ephemeral,
        CryptoError::SealEphemeralKey,
        derive,
    );
    let opener = agreed?;
    let mut buf = Zeroizing::new(Vec::with_capacity(parts.sealed.len()));
    buf.extend_from_slice(parts.sealed);
    let opened = opener.open_in_place(&parts.nonce, aad, &mut buf[..]);
    let plaintext_len = opened.map_err(|_| CryptoError::SealOpen)?.len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::conformance::__hex;
    use crypto_profile::conformance::vectors::sealbox as kat;
    use crypto_profile::sealbox_wire::MIN_BLOB_LEN;

    const DOMAIN: &[u8] = kat::DOMAIN;
    const KAT_PLAINTEXT: &[u8] = kat::PLAINTEXT;
    const KAT_NONCE: [u8; NONCE_LEN] = kat::NONCE;
    const TOKEN: &[u8] = b"hvs.CAESIJ-wrapping-token-sentinel-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";

    fn kat_aad() -> Vec<u8> {
        kat::aad()
    }

    fn unhex(s: &str) -> Vec<u8> {
        __hex::decode(s).unwrap()
    }

    fn kat_recipient() -> PrivateKey {
        PrivateKey::from_pkcs8_der(&unhex(kat::PRIVATE_KEY_PKCS8_HEX)).unwrap()
    }

    fn kat_ephemeral() -> Vec<u8> {
        unhex(kat::BLOB_HEX)[1..1 + EPHEMERAL_KEY_LEN].to_vec()
    }

    fn seal_with(key: &Aes256GcmKey) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut buf = KAT_PLAINTEXT.to_vec();
        let (nonce, tag) = key.seal_in_place(&kat_aad(), &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        (nonce, buf)
    }

    fn open_with(key: &Aes256GcmKey, nonce: [u8; NONCE_LEN], sealed: &[u8]) -> Option<Vec<u8>> {
        let mut buf = sealed.to_vec();
        let n = key.open_in_place(&nonce, &kat_aad(), &mut buf).ok()?.len();
        buf.truncate(n);
        Some(buf)
    }

    fn agreed_key(private: &PrivateKey, ephemeral: &[u8], recipient: &PublicKey) -> Aes256GcmKey {
        let peer =
            ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, ephemeral)).unwrap();
        agree(
            private.agreement_key(),
            peer,
            CryptoError::Primitive,
            |shared: &[u8]| derive_key(shared, DOMAIN, ephemeral, recipient),
        )
        .unwrap()
    }

    #[test]
    fn the_kdf_labels_for_a_domain_reproduce_the_v1_constants() {
        let (salt, info_prefix) = kdf_labels(kat::DOMAIN);
        assert_eq!(salt, kat::DOMAIN);
        let mut expected = kat::DOMAIN.to_vec();
        expected.extend_from_slice(b" p384 hkdf-sha384 aes-256-gcm");
        assert_eq!(info_prefix, expected);
    }

    #[test]
    fn a_blob_sealed_under_one_domain_does_not_open_under_another() {
        let key = PrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), b"domain-a", b"aad", b"secret").unwrap();
        assert!(matches!(
            open(&key, b"domain-b", b"aad", blob.as_bytes()),
            Err(CryptoError::SealOpen)
        ));
    }

    #[test]
    fn an_empty_plaintext_is_refused_so_every_sealed_blob_can_open() {
        let key = PrivateKey::generate().unwrap();
        assert!(matches!(
            seal(key.public_key(), b"d", b"", b""),
            Err(CryptoError::SealPlaintext)
        ));
    }

    #[test]
    fn a_sealed_blob_is_built_at_exact_capacity_and_opens_to_itself() {
        let key = PrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), DOMAIN, b"aad", TOKEN).unwrap();
        assert_eq!(blob.as_bytes().len(), sealed_len(TOKEN.len()));
        assert_eq!(blob.0.capacity(), blob.0.len());
        assert_eq!(blob.as_bytes()[0], VERSION);
        let opened = open(&key, DOMAIN, b"aad", blob.as_bytes()).unwrap();
        assert!(opened.as_slice() == TOKEN);
        assert_eq!(opened.capacity(), blob.as_bytes().len() - HEADER_LEN);
        assert_eq!(
            format!("{blob:?}"),
            format!("SealedBlob(<{} bytes>)", blob.as_bytes().len())
        );
        let copy = blob.as_bytes().to_vec();
        assert_eq!(blob.into_bytes(), copy);
    }

    #[test]
    fn opens_the_v1_known_answer_blob() {
        let opened = open(&kat_recipient(), DOMAIN, &kat_aad(), &unhex(kat::BLOB_HEX)).unwrap();
        assert!(opened.as_slice() == KAT_PLAINTEXT);
    }

    #[test]
    fn the_derived_key_matches_a_known_answer_for_a_fixed_shared_secret() {
        let recipient = kat_recipient();
        let key = derive_key(
            &[0x33; 48],
            DOMAIN,
            &kat_ephemeral(),
            recipient.public_key(),
        )
        .unwrap();
        assert_eq!(
            open_with(&key, KAT_NONCE, &unhex(kat::FIXED_SHARED_CT_HEX)).as_deref(),
            Some(KAT_PLAINTEXT)
        );
    }

    #[test]
    fn a_different_shared_secret_with_the_same_public_inputs_derives_a_different_key() {
        let recipient = kat_recipient();
        let ephemeral = kat_ephemeral();
        let derive =
            |shared: &[u8]| derive_key(shared, DOMAIN, &ephemeral, recipient.public_key()).unwrap();
        let (nonce, ct) = seal_with(&derive(&[0x33; 48]));
        assert_eq!(
            open_with(&derive(&[0x33; 48]), nonce, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
        for other in [[0x34u8; 48], [0u8; 48]] {
            assert_eq!(open_with(&derive(&other), nonce, &ct), None);
        }
    }

    #[test]
    fn a_key_agreed_by_another_recipient_private_key_does_not_open() {
        let recipient = PrivateKey::generate().unwrap();
        let intruder = PrivateKey::generate().unwrap();
        let ephemeral = PrivateKey::generate().unwrap();
        let point = ephemeral.agreement_key().compute_public_key().unwrap();
        let right = agreed_key(&recipient, point.as_ref(), recipient.public_key());
        let wrong = agreed_key(&intruder, point.as_ref(), recipient.public_key());
        let (nonce, ct) = seal_with(&right);
        assert_eq!(
            open_with(&right, nonce, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
        assert_eq!(open_with(&wrong, nonce, &ct), None);
    }

    #[test]
    fn each_tampered_field_is_refused_with_its_own_error() {
        let key = PrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), DOMAIN, b"aad", TOKEN).unwrap();
        let b = blob.as_bytes();
        let refused = |bytes: &[u8]| match open(&key, DOMAIN, b"aad", bytes) {
            Ok(_) => panic!("a tampered blob opened"),
            Err(e) => e,
        };
        let mut v2 = b.to_vec();
        v2[0] = 2;
        assert!(matches!(refused(&v2), CryptoError::SealVersion));
        let mut off_curve = b.to_vec();
        off_curve[2..1 + EPHEMERAL_KEY_LEN].fill(0);
        assert!(matches!(refused(&off_curve), CryptoError::SealEphemeralKey));
        for i in [1 + EPHEMERAL_KEY_LEN, HEADER_LEN, b.len() - 1] {
            let mut t = b.to_vec();
            t[i] ^= 1;
            assert!(matches!(refused(&t), CryptoError::SealOpen), "{i}");
        }
        assert!(matches!(
            refused(&b[..MIN_BLOB_LEN - 1]),
            CryptoError::SealBlob
        ));
        assert!(matches!(
            open(&key, DOMAIN, b"aaD", b),
            Err(CryptoError::SealOpen)
        ));
    }
}
