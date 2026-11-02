use super::{AGREEMENT, EPHEMERAL_KEY_LEN, admit};
use crate::Admitted;
use crate::ecdh::{StaticKey, spki_point};
use crate::fips::assert_fips_module;
use crypto_profile::CryptoError;
use std::fmt;
use zeroize::Zeroizing;

/// The DER length of a P-384 SubjectPublicKeyInfo.
pub const SPKI_LEN: usize = 120;
/// The length of a canonical P-384 public-key PEM with LF line endings.
pub const PEM_LEN: usize = 215;
const PEM_TAG: &str = "PUBLIC KEY";

/// A sealed-box recipient's P-384 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    spki: [u8; SPKI_LEN],
}

impl PublicKey {
    /// Parses a P-384 SubjectPublicKeyInfo holding an uncompressed point, refusing any other key or
    /// encoding.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let spki: [u8; SPKI_LEN] = der.try_into().map_err(|_| CryptoError::SealPublicKey)?;
        spki_point(AGREEMENT, &spki).map_err(|_| CryptoError::SealPublicKey)?;
        Ok(Self { spki })
    }

    /// Parses exactly one canonical `PUBLIC KEY` PEM block holding a P-384 key.
    pub fn from_pem(text: &str) -> Result<Self, CryptoError> {
        check_length(text)?;
        let block = pem::parse(text).map_err(|_| CryptoError::SealPublicKey)?;
        check_tag(block.tag())?;
        let key = Self::from_spki_der(block.contents())?;
        check_canonical(text, key.spki_der())?;
        Ok(key)
    }

    /// The canonical PEM encoding of the key.
    pub fn to_pem(&self) -> String {
        encode_pem(&self.spki)
    }

    /// The key's SubjectPublicKeyInfo DER.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// The uncompressed point: the last bytes of a P-384 SubjectPublicKeyInfo, its
    /// `subjectPublicKey` BIT STRING contents.
    pub(super) fn point(&self) -> &[u8] {
        &self.spki[SPKI_LEN - EPHEMERAL_KEY_LEN..]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(P-384)")
    }
}

/// A sealed-box recipient's P-384 private key, held once, as an `ecdh::StaticKey`.
pub struct PrivateKey {
    key: StaticKey,
    recipient: PublicKey,
}

impl PrivateKey {
    /// Generates a fresh key in the FIPS module. Refuses outside FIPS mode, and under a profile
    /// that does not admit ECDH on P-384 and HKDF-SHA384.
    pub fn generate(a: &Admitted) -> Result<Self, CryptoError> {
        assert_fips_module().and_then(|()| admit(a))?;
        Self::from_key(StaticKey::generate(a, AGREEMENT)?)
    }

    /// Imports a P-384 PKCS#8 private key. Refuses outside FIPS mode, under a profile that does
    /// not admit ECDH on P-384 and HKDF-SHA384, and a key that is malformed, is not P-384, or is
    /// followed by other bytes (`CryptoError::SealPrivateKey`).
    pub fn from_pkcs8_der(a: &Admitted, der: &[u8]) -> Result<Self, CryptoError> {
        assert_fips_module().and_then(|()| admit(a))?;
        let key = StaticKey::from_pkcs8_der(a, AGREEMENT, der)
            .map_err(|_| CryptoError::SealPrivateKey)?;
        Self::from_key(key)
    }

    fn from_key(key: StaticKey) -> Result<Self, CryptoError> {
        let recipient = PublicKey::from_spki_der(&key.to_spki_der()?)?;
        Ok(Self { key, recipient })
    }

    /// The key's PKCS#8 encoding, encoded by the module on each call into a buffer the caller
    /// owns and that is wiped on drop.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.key.to_pkcs8_der()
    }

    /// The raw public key: the uncompressed P-384 point.
    pub fn public_key(&self) -> &[u8] {
        self.key.public_key()
    }

    /// The public key to seal to.
    pub fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub(super) fn agreement_key(&self) -> &StaticKey {
        &self.key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

fn encode_pem(spki: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(PEM_TAG, spki.to_vec()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

fn check_length(text: &str) -> Result<(), CryptoError> {
    if text.len() != PEM_LEN {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

fn check_tag(tag: &str) -> Result<(), CryptoError> {
    if tag != PEM_TAG {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

fn check_canonical(text: &str, spki: &[u8]) -> Result<(), CryptoError> {
    if encode_pem(spki) != text {
        return Err(CryptoError::SealPublicKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Options, Profile, admit};
    use aws_lc_rs::agreement::{ECDH_P256, PrivateKey as AgreementKey};
    use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};

    fn p256_pkcs8() -> Vec<u8> {
        let key = AgreementKey::generate(&ECDH_P256).unwrap();
        let der: Pkcs8V1Der<'static> = key.as_der().unwrap();
        der.as_ref().to_vec()
    }

    fn fips() -> Admitted {
        admit(Profile::Fips1403, Options::default())
    }

    #[test]
    fn a_generated_key_has_a_120_byte_p384_spki_and_a_redacted_debug() {
        let key = PrivateKey::generate(&fips()).unwrap();
        assert_eq!(key.recipient().spki_der().len(), SPKI_LEN);
        assert_eq!(format!("{key:?}"), "PrivateKey(<redacted>)");
        assert_eq!(format!("{:?}", key.recipient()), "PublicKey(P-384)");
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = PrivateKey::generate(&fips()).unwrap();
        let b = PrivateKey::generate(&fips()).unwrap();
        assert_ne!(a.recipient(), b.recipient());
    }

    #[test]
    fn pkcs8_round_trips_into_the_same_key_and_encoding_and_does_not_grow() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        assert_eq!(der.len(), der.capacity());
        let back = PrivateKey::from_pkcs8_der(&fips(), &der).unwrap();
        assert_eq!(back.recipient(), key.recipient());
        assert_eq!(back.to_pkcs8_der().unwrap(), der);
    }

    #[test]
    fn the_raw_public_key_is_the_spkis_point() {
        let key = PrivateKey::generate(&fips()).unwrap();
        assert_eq!(key.public_key().len(), EPHEMERAL_KEY_LEN);
        assert_eq!(key.public_key()[0], 0x04);
        assert_eq!(key.recipient().point(), key.public_key());
        assert!(key.recipient().spki_der().ends_with(key.public_key()));
    }

    #[test]
    fn keys_refuse_a_profile_without_p384_ecdh_or_hkdf_sha384() {
        let der = PrivateKey::generate(&fips())
            .unwrap()
            .to_pkcs8_der()
            .unwrap();
        for p in [Profile::Bsi, Profile::Cnsa2] {
            let a = admit(p, Options::default());
            let refused = Err(CryptoError::NotInProfile {
                profile: p,
                algorithm: crate::Algorithm::KeyAgreement(AGREEMENT),
            });
            assert_eq!(PrivateKey::generate(&a).map(|_| ()), refused, "{p}");
            assert_eq!(
                PrivateKey::from_pkcs8_der(&a, &der).map(|_| ()),
                refused,
                "{p}"
            );
        }
        for p in [
            Profile::Preferred,
            Profile::Cnsa1,
            Profile::Fips1402,
            Profile::Unrestricted,
        ] {
            let a = admit(p, Options::default());
            assert!(PrivateKey::generate(&a).is_ok(), "{p}");
            assert!(PrivateKey::from_pkcs8_der(&a, &der).is_ok(), "{p}");
        }
    }

    #[test]
    fn a_hybrid_or_compressed_point_spki_is_refused() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let spki = key.recipient().spki_der();
        let at = SPKI_LEN - EPHEMERAL_KEY_LEN;
        let mut hybrid = spki.to_vec();
        hybrid[at] = 0x06 | (spki[SPKI_LEN - 1] & 1);
        let mut compressed = crypto_profile::conformance::__hex::decode(
            "3046301006072a8648ce3d020106052b81040022033200",
        )
        .unwrap();
        compressed.push(0x02 | (spki[SPKI_LEN - 1] & 1));
        compressed.extend_from_slice(&spki[at + 1..at + 49]);
        compressed.resize(SPKI_LEN, 0xa5);
        for bad in [hybrid, compressed] {
            assert_eq!(bad.len(), SPKI_LEN);
            assert!(
                matches!(
                    PublicKey::from_spki_der(&bad),
                    Err(CryptoError::SealPublicKey)
                ),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn a_p256_or_garbage_private_key_is_refused() {
        for der in [p256_pkcs8(), b"not a key".to_vec()] {
            assert!(matches!(
                PrivateKey::from_pkcs8_der(&fips(), &der),
                Err(CryptoError::SealPrivateKey)
            ));
        }
    }

    #[test]
    fn a_pkcs8_key_followed_by_other_bytes_is_refused() {
        let der = PrivateKey::generate(&fips())
            .unwrap()
            .to_pkcs8_der()
            .unwrap();
        let padded = [&der[..], &[0]].concat();
        assert!(matches!(
            PrivateKey::from_pkcs8_der(&fips(), &padded),
            Err(CryptoError::SealPrivateKey)
        ));
    }

    #[test]
    fn a_pkcs8_key_with_a_field_after_the_private_key_is_refused() {
        let der = PrivateKey::generate(&fips())
            .unwrap()
            .to_pkcs8_der()
            .unwrap();
        assert_eq!(&der[..3], &[0x30, 0x81, 0xb6]);
        let with_null = [&[0x30, 0x81, 0xb8][..], &der[3..], &[0x05, 0x00]].concat();
        assert!(matches!(
            PrivateKey::from_pkcs8_der(&fips(), &with_null),
            Err(CryptoError::SealPrivateKey)
        ));
    }

    #[test]
    fn the_public_pem_is_canonical_and_round_trips() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let text = key.recipient().to_pem();
        assert_eq!(text.len(), PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!text.contains('\r'));
        assert_eq!(&PublicKey::from_pem(&text).unwrap(), key.recipient());
        assert_eq!(
            &PublicKey::from_spki_der(key.recipient().spki_der()).unwrap(),
            key.recipient()
        );
    }

    const P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwb+kKvUQ/6NXarrQo1llFsZkKq3p\nuwMJSL1oX7GpbcalqGg9o0UfaXuMQoO4n+cJ7zqWEHgkmImfZBUhkoVpHQ==\n-----END PUBLIC KEY-----\n";

    #[test]
    fn a_non_canonical_foreign_or_malformed_public_key_is_refused() {
        let key = PrivateKey::generate(&fips()).unwrap();
        let canonical = key.recipient().to_pem();
        let other = PrivateKey::generate(&fips()).unwrap().recipient().to_pem();
        let spki = key.recipient().spki_der();
        let mut reflowed = canonical.replacen('\n', "", 2);
        reflowed.insert(26, '\n');
        reflowed.push('\n');
        assert_eq!(reflowed.len(), PEM_LEN);
        for bad in [
            canonical.replace('\n', "\r\n"),
            format!("{canonical}trailing"),
            format!("{canonical}{other}"),
            canonical.replace("PUBLIC KEY", "PRIVATE KEY"),
            canonical.replace("PUBLIC KEY", "PUBLIC KEZ"),
            P256_PUBLIC_PEM.to_string(),
            reflowed,
            encode_pem(&[0u8; SPKI_LEN]),
            "x".repeat(PEM_LEN),
            String::new(),
        ] {
            assert!(
                matches!(PublicKey::from_pem(&bad), Err(CryptoError::SealPublicKey)),
                "{bad:?}"
            );
        }
        for bad in [&spki[..SPKI_LEN - 1], &[0u8; SPKI_LEN][..]] {
            assert!(matches!(
                PublicKey::from_spki_der(bad),
                Err(CryptoError::SealPublicKey)
            ));
        }
    }

    const SPKI: [u8; SPKI_LEN] = [7u8; SPKI_LEN];

    #[test]
    fn the_encoding_is_215_bytes_of_lf_pem() {
        let text = encode_pem(&SPKI);
        assert_eq!(text.len(), PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn the_pem_length_must_be_exact() {
        assert!(check_length(&"x".repeat(PEM_LEN)).is_ok());
        for n in [0, PEM_LEN - 1, PEM_LEN + 1] {
            assert!(
                matches!(
                    check_length(&"x".repeat(n)),
                    Err(CryptoError::SealPublicKey)
                ),
                "{n}"
            );
        }
    }

    #[test]
    fn only_the_public_key_tag_is_accepted() {
        assert!(check_tag("PUBLIC KEY").is_ok());
        for tag in ["PUBLIC KEZ", "PRIVATE KEY", "EC PUBLIC KEY", ""] {
            assert!(
                matches!(check_tag(tag), Err(CryptoError::SealPublicKey)),
                "{tag:?}"
            );
        }
    }

    #[test]
    fn only_the_byte_exact_re_encoding_is_canonical() {
        let text = encode_pem(&SPKI);
        assert!(check_canonical(&text, &SPKI).is_ok());
        let mut other = SPKI;
        other[0] = 8;
        assert!(matches!(
            check_canonical(&text, &other),
            Err(CryptoError::SealPublicKey)
        ));
        assert!(matches!(
            check_canonical(&text.replace('\n', "\r\n"), &SPKI),
            Err(CryptoError::SealPublicKey)
        ));
    }
}
