//! A sealed box: an ephemeral P-384 ECDH to the recipient's static key, HKDF-SHA384
//! keyed by a caller-chosen domain, and AES-256-GCM over the plaintext with the
//! caller's AAD. Wire format: version, ephemeral point, nonce, ciphertext, tag. Every operation
//! refuses unless the profile admits ECDH on P-384 and HKDF-SHA384.
mod keys;

pub use crypto_profile::sealbox_wire::{
    EPHEMERAL_KEY_LEN, HEADER_LEN, NONCE_LEN, TAG_LEN, VERSION,
};
pub use keys::{PEM_LEN, PrivateKey, PublicKey, SPKI_LEN};

use crate::aead::{Aes256GcmKey, KEY_LEN};
use crate::ecdh::EphemeralKey;
use crate::fips::assert_fips_module;
use crate::kdf::Spec;
use crate::{Admitted, CryptoError};
use crypto_profile::sealbox_wire::{parse_blob, sealed_len};
use crypto_profile::{KdfAlgorithm, KeyAgreementAlgorithm};
use std::fmt;
use zeroize::Zeroizing;

const KDF_SUITE: &[u8] = b" p384 hkdf-sha384 aes-256-gcm";
const AGREEMENT: KeyAgreementAlgorithm = KeyAgreementAlgorithm::EcdhP384;
const KDF: KdfAlgorithm = KdfAlgorithm::HkdfSha384;

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

fn admit(a: &Admitted) -> Result<(), CryptoError> {
    a.admit_key_agreement(AGREEMENT)?;
    a.admit_kdf(KDF)
}

fn kdf_info(domain: &[u8], ephemeral: &[u8], recipient: &PublicKey) -> Vec<u8> {
    let spki = recipient.spki_der();
    let mut info =
        Vec::with_capacity(domain.len() + KDF_SUITE.len() + ephemeral.len() + spki.len());
    info.extend_from_slice(domain);
    info.extend_from_slice(KDF_SUITE);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(spki);
    info
}

fn kdf_spec<'a>(domain: &'a [u8], info: &'a [u8]) -> Spec<'a> {
    Spec::Hkdf {
        algorithm: KDF,
        salt: Some(domain),
        info,
    }
}

fn aead_key(okm: &[u8]) -> Result<Aes256GcmKey, CryptoError> {
    let key: &[u8; KEY_LEN] = okm.try_into().map_err(|_| CryptoError::Primitive)?;
    Aes256GcmKey::new(key)
}

fn check_domain(domain: &[u8]) -> Result<(), CryptoError> {
    if domain.is_empty() {
        return Err(CryptoError::SealDomainEmpty);
    }
    Ok(())
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::SealPlaintext);
    }
    Ok(())
}

/// Seals a non-empty `plaintext` to `recipient` under a non-empty `domain`, authenticating `aad`.
/// Refuses, in this order: outside FIPS mode (`CryptoError::NotFips`); a profile that does not
/// admit ECDH on P-384 and HKDF-SHA384 (`CryptoError::NotInProfile`); an empty `domain`
/// (`CryptoError::SealDomainEmpty`); an empty `plaintext`.
pub fn seal(
    a: &Admitted,
    recipient: &PublicKey,
    domain: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBlob, CryptoError> {
    assert_fips_module()
        .and_then(|()| admit(a))
        .and_then(|()| check_domain(domain))
        .and_then(|()| check_plaintext(plaintext))?;
    let ephemeral = EphemeralKey::generate(a, AGREEMENT)?;
    let point = <[u8; EPHEMERAL_KEY_LEN]>::try_from(ephemeral.public_key())
        .map_err(|_| CryptoError::Primitive)?;
    let info = kdf_info(domain, &point, recipient);
    let okm = ephemeral.agree(recipient.point(), &kdf_spec(domain, &info), KEY_LEN)?;
    let sealer = aead_key(okm.as_bytes())?;
    let mut out = Zeroizing::new(Vec::with_capacity(sealed_len(plaintext.len())));
    out.push(VERSION);
    out.extend_from_slice(&point);
    out.extend_from_slice(&[0u8; NONCE_LEN]);
    out.extend_from_slice(plaintext);
    let (head, body) = out.split_at_mut(HEADER_LEN);
    let (nonce, tag) = sealer.seal_in_place(aad, body)?;
    head[1 + EPHEMERAL_KEY_LEN..].copy_from_slice(&nonce);
    out.extend_from_slice(&tag);
    Ok(SealedBlob(std::mem::take(&mut *out)))
}

/// Opens a blob sealed to `recipient` under `domain` and `aad`. Refuses outside FIPS mode, then a
/// profile that does not admit ECDH on P-384 and HKDF-SHA384, then an empty `domain`
/// (`CryptoError::SealDomainEmpty`), before reading the blob.
pub fn open(
    a: &Admitted,
    recipient: &PrivateKey,
    domain: &[u8],
    aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let parts = assert_fips_module()
        .and_then(|()| admit(a))
        .and_then(|()| check_domain(domain))
        .and_then(|()| parse_blob(blob))?;
    let info = kdf_info(domain, parts.ephemeral, recipient.recipient());
    let okm = recipient
        .agreement_key()
        .agree(parts.ephemeral, &kdf_spec(domain, &info), KEY_LEN)
        .map_err(|e| match e {
            CryptoError::KeyAgreementPeerKey { .. } => CryptoError::SealEphemeralKey,
            other => other,
        })?;
    let opener = aead_key(okm.as_bytes())?;
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
    use crate::ecdh::StaticKey;
    use crate::{Options, Profile};
    use crypto_profile::conformance::__hex;
    use crypto_profile::conformance::vectors::sealbox as kat;
    use crypto_profile::sealbox_wire::MIN_BLOB_LEN;

    const DOMAIN: &[u8] = kat::DOMAIN;
    const KAT_PLAINTEXT: &[u8] = kat::PLAINTEXT;
    const KAT_NONCE: [u8; NONCE_LEN] = kat::NONCE;
    const TOKEN: &[u8] = b"sealbox-plaintext-sentinel-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-01234";

    fn fips() -> Admitted {
        crate::admit(Profile::Fips1403, Options::default())
    }

    fn kat_aad() -> Vec<u8> {
        kat::aad()
    }

    fn unhex(s: &str) -> Vec<u8> {
        __hex::decode(s).unwrap()
    }

    fn kat_recipient() -> PrivateKey {
        PrivateKey::from_pkcs8_der(&fips(), &unhex(kat::PRIVATE_KEY_PKCS8_HEX)).unwrap()
    }

    fn kat_ephemeral() -> Vec<u8> {
        unhex(kat::BLOB_HEX)[1..1 + EPHEMERAL_KEY_LEN].to_vec()
    }

    fn derive_key(shared: &[u8], ephemeral: &[u8], recipient: &PublicKey) -> Aes256GcmKey {
        let info = kdf_info(DOMAIN, ephemeral, recipient);
        let okm = crate::kdf::derive(&fips(), shared, &kdf_spec(DOMAIN, &info), KEY_LEN).unwrap();
        aead_key(okm.as_bytes()).unwrap()
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
        let info = kdf_info(DOMAIN, ephemeral, recipient);
        let okm = private
            .agreement_key()
            .agree(ephemeral, &kdf_spec(DOMAIN, &info), KEY_LEN)
            .unwrap();
        aead_key(okm.as_bytes()).unwrap()
    }

    #[test]
    fn the_kdf_inputs_for_a_domain_reproduce_the_v1_layout() {
        let recipient = kat_recipient();
        let ephemeral = kat_ephemeral();
        let info = kdf_info(kat::DOMAIN, &ephemeral, recipient.recipient());
        let mut expected = kat::DOMAIN.to_vec();
        expected.extend_from_slice(b" p384 hkdf-sha384 aes-256-gcm");
        expected.extend_from_slice(&ephemeral);
        expected.extend_from_slice(recipient.recipient().spki_der());
        assert_eq!(info, expected);
        assert_eq!(info.capacity(), info.len());
        assert_eq!(
            kdf_spec(kat::DOMAIN, &info),
            Spec::Hkdf {
                algorithm: KdfAlgorithm::HkdfSha384,
                salt: Some(kat::DOMAIN),
                info: &info,
            }
        );
    }

    #[test]
    fn only_a_32_byte_okm_makes_an_aead_key() {
        assert!(aead_key(&[7; KEY_LEN]).is_ok());
        for len in [KEY_LEN - 1, KEY_LEN + 1] {
            assert!(matches!(
                aead_key(&vec![7; len]),
                Err(CryptoError::Primitive)
            ));
        }
    }

    #[test]
    fn a_blob_sealed_under_one_domain_does_not_open_under_another() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let blob = seal(&fips(), key.recipient(), b"domain-a", b"aad", b"secret").unwrap();
        assert!(matches!(
            open(&fips(), &key, b"domain-b", b"aad", blob.as_bytes()),
            Err(CryptoError::SealOpen)
        ));
    }

    #[test]
    fn an_empty_domain_is_refused_by_seal_and_by_open() {
        let key = PrivateKey::generate(&fips()).unwrap();
        assert!(matches!(
            seal(&fips(), key.recipient(), b"", b"aad", b"secret"),
            Err(CryptoError::SealDomainEmpty)
        ));
        let blob = seal(&fips(), key.recipient(), DOMAIN, b"aad", b"secret").unwrap();
        assert!(matches!(
            open(&fips(), &key, b"", b"aad", blob.as_bytes()),
            Err(CryptoError::SealDomainEmpty)
        ));
        assert!(matches!(
            open(&fips(), &key, b"", b"aad", b""),
            Err(CryptoError::SealDomainEmpty)
        ));
    }

    #[test]
    fn a_profile_without_p384_ecdh_and_hkdf_sha384_is_refused_before_any_input_rule() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let blob = seal(&fips(), key.recipient(), DOMAIN, b"aad", b"secret").unwrap();
        for p in [Profile::Bsi, Profile::Cnsa2] {
            let a = crate::admit(p, Options::default());
            let refused = CryptoError::NotInProfile {
                profile: p,
                algorithm: crate::Algorithm::KeyAgreement(AGREEMENT),
            };
            assert_eq!(
                seal(&a, key.recipient(), b"", b"aad", b"").err(),
                Some(refused)
            );
            assert_eq!(open(&a, &key, b"", b"aad", b"").err(), Some(refused));
            assert_eq!(
                open(&a, &key, DOMAIN, b"aad", blob.as_bytes()).err(),
                Some(refused)
            );
        }
        let no_kdf = fips().without(crate::Algorithm::Kdf(KDF));
        let refused = CryptoError::NotInProfile {
            profile: Profile::Fips1403,
            algorithm: crate::Algorithm::Kdf(KDF),
        };
        assert_eq!(
            seal(&no_kdf, key.recipient(), b"", b"", b"").err(),
            Some(refused)
        );
        assert_eq!(open(&no_kdf, &key, b"", b"", b"").err(), Some(refused));
        for p in [
            Profile::Unrestricted,
            Profile::Preferred,
            Profile::Cnsa1,
            Profile::Fips1403,
            Profile::Fips1402,
        ] {
            let a = crate::admit(p, Options::default());
            let blob = seal(&a, key.recipient(), DOMAIN, b"aad", TOKEN).unwrap();
            assert_eq!(
                open(&a, &key, DOMAIN, b"aad", blob.as_bytes())
                    .unwrap()
                    .as_slice(),
                TOKEN,
                "{p}"
            );
        }
    }

    #[test]
    fn an_empty_plaintext_is_refused_so_every_sealed_blob_can_open() {
        let key = PrivateKey::generate(&fips()).unwrap();
        assert!(matches!(
            seal(&fips(), key.recipient(), b"d", b"", b""),
            Err(CryptoError::SealPlaintext)
        ));
    }

    #[test]
    fn a_sealed_blob_is_built_at_exact_capacity_and_opens_to_itself() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let blob = seal(&fips(), key.recipient(), DOMAIN, b"aad", TOKEN).unwrap();
        assert_eq!(blob.as_bytes().len(), sealed_len(TOKEN.len()));
        assert_eq!(blob.0.capacity(), blob.0.len());
        assert_eq!(blob.as_bytes()[0], VERSION);
        let opened = open(&fips(), &key, DOMAIN, b"aad", blob.as_bytes()).unwrap();
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
        let opened = open(
            &fips(),
            &kat_recipient(),
            DOMAIN,
            &kat_aad(),
            &unhex(kat::BLOB_HEX),
        )
        .unwrap();
        assert!(opened.as_slice() == KAT_PLAINTEXT);
    }

    #[test]
    fn the_derived_key_matches_a_known_answer_for_a_fixed_shared_secret() {
        let recipient = kat_recipient();
        let key = derive_key(&[0x33; 48], &kat_ephemeral(), recipient.recipient());
        assert_eq!(
            open_with(&key, KAT_NONCE, &unhex(kat::FIXED_SHARED_CT_HEX)).as_deref(),
            Some(KAT_PLAINTEXT)
        );
    }

    #[test]
    fn a_different_shared_secret_with_the_same_public_inputs_derives_a_different_key() {
        let recipient = kat_recipient();
        let ephemeral = kat_ephemeral();
        let derive = |shared: &[u8]| derive_key(shared, &ephemeral, recipient.recipient());
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
        let recipient = PrivateKey::generate(&fips()).unwrap();
        let intruder = PrivateKey::generate(&fips()).unwrap();
        let ephemeral = StaticKey::generate(&fips(), AGREEMENT).unwrap();
        let point = ephemeral.public_key();
        let right = agreed_key(&recipient, point, recipient.recipient());
        let wrong = agreed_key(&intruder, point, recipient.recipient());
        let (nonce, ct) = seal_with(&right);
        assert_eq!(
            open_with(&right, nonce, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
        assert_eq!(open_with(&wrong, nonce, &ct), None);
    }

    #[test]
    fn each_tampered_field_is_refused_with_its_own_error() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let blob = seal(&fips(), key.recipient(), DOMAIN, b"aad", TOKEN).unwrap();
        let b = blob.as_bytes();
        let refused = |bytes: &[u8]| match open(&fips(), &key, DOMAIN, b"aad", bytes) {
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
            open(&fips(), &key, DOMAIN, b"aaD", b),
            Err(CryptoError::SealOpen)
        ));
    }
}
