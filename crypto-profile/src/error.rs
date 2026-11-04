//! The crate's refusals.
use crate::algorithm::{
    AeadAlgorithm, Algorithm, KdfAlgorithm, KeyAgreementAlgorithm, SignatureAlgorithm, TlsVersion,
};
use crate::capability::Approval;
use crate::peer_certificate::PeerCertificateViolation;
use crate::profile::{Options, Profile};
use std::fmt;

/// A family of algorithms in a TLS policy or a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Family {
    /// Protocol versions.
    Version,
    /// Cipher suites.
    CipherSuite,
    /// Key-exchange groups.
    KxGroup,
    /// Signature schemes.
    SignatureScheme,
    /// Key algorithms, for TLS certificate keys.
    KeyAlgorithm,
    /// Message authentication codes, outside TLS.
    Mac,
    /// Key-derivation functions, outside TLS.
    Kdf,
    /// Key agreement, outside TLS.
    KeyAgreement,
    /// Authenticated encryption, outside TLS.
    Aead,
    /// Hashing, outside TLS.
    Hash,
    /// Signatures, outside TLS.
    Signature,
}

/// Why a certificate signing request could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CsrError {
    /// A subject alternative name or distinguished-name value is not valid for its type.
    InvalidName,
    /// The request parameters were refused.
    InvalidParams,
    /// Signing the request failed.
    Signing,
}

/// Bounded identity of a peer verifier, independent of certificates and trust anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerVerifierIdentity {
    /// An owned verifier or completion policy.
    Owned {
        /// The certificate rule, absent for default-off policies.
        rule: Option<crate::PeerCertificateRuleId>,
        /// Canonical handshake-scheme mask, with bit positions from scheme preference order.
        handshake_schemes: u64,
    },
    /// A verifier whose policy identity cannot be established.
    Opaque,
}

/// Why a TLS configuration step was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsError {
    /// The provider refused the policy's protocol versions.
    ProtocolVersions,
    /// The private key was refused.
    PrivateKey,
    /// A process-default provider is already installed.
    DefaultProviderInstalled,
    /// The certificate chain is empty, or its end-entity certificate does not carry the key.
    KeyMismatch,
    /// A rule-bearing policy requires a completion builder that installs its owned verifier.
    StrictBuilderRequired {
        /// The applicable strict completion entry point in `tls`.
        entry_point: &'static str,
    },
    /// The completion policy and verifier have incompatible identities.
    IncompatiblePeerVerifier {
        /// The completion policy's identity.
        expected: PeerVerifierIdentity,
        /// The supplied verifier's identity.
        actual: PeerVerifierIdentity,
    },
    /// A peer certificate failed its profile's certificate rule.
    PeerCertificate {
        /// The governing profile.
        profile: Profile,
        /// The bounded refusal descriptor.
        violation: PeerCertificateViolation,
    },
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersions => f.write_str("the provider refused the protocol versions"),
            Self::PrivateKey => f.write_str("the private key was refused"),
            Self::DefaultProviderInstalled => {
                f.write_str("a process-default provider is already installed")
            }
            Self::KeyMismatch => {
                f.write_str("the certificate chain is empty or does not carry the key")
            }
            Self::IncompatiblePeerVerifier { expected, actual } => {
                write!(
                    f,
                    "the peer verifier {actual:?} is incompatible with {expected:?}"
                )
            }
            Self::StrictBuilderRequired { entry_point } => {
                write!(f, "the peer certificate rule requires tls::{entry_point}")
            }
            Self::PeerCertificate { profile, violation } => {
                write!(f, "the {profile} peer certificate was refused: {violation}")
            }
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PeerCertificate { violation, .. } => Some(violation),
            Self::IncompatiblePeerVerifier { .. }
            | Self::StrictBuilderRequired { .. }
            | Self::ProtocolVersions
            | Self::PrivateKey
            | Self::DefaultProviderInstalled
            | Self::KeyMismatch => None,
        }
    }
}

/// A refusal from one of the crate's operations. It never carries key or plaintext material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The algorithm is not available on this backend's module.
    Unavailable(Algorithm),
    /// A TLS policy names nothing in this family.
    PolicyEmpty(Family),
    /// A TLS policy names this algorithm more than once.
    PolicyDuplicate(Algorithm),
    /// A provider does not carry exactly a policy's algorithms.
    PolicyDrift,
    /// A TLS policy lists a version but names nothing in this family usable with it.
    PolicyVersionUnusable {
        /// The listed version.
        version: TlsVersion,
        /// The family with nothing usable at that version.
        family: Family,
    },
    /// The process is not running the AWS-LC FIPS module, or a provider is not FIPS.
    NotFips,
    /// Key generation failed.
    KeyGeneration(Algorithm),
    /// A signature did not verify.
    Verify,
    /// Signing failed.
    Sign,
    /// A certificate signing request could not be produced.
    Csr(CsrError),
    /// A TLS configuration step was refused.
    Tls(TlsError),
    /// The random generator failed.
    Random,
    /// The AEAD key was refused.
    AeadKey,
    /// AEAD sealing failed.
    AeadSeal,
    /// The AEAD ciphertext did not authenticate.
    AeadOpen,
    /// A sealed-box plaintext is empty.
    SealPlaintext,
    /// A sealed-box domain is empty. The domain is the HKDF salt, and the module does not mark an
    /// HKDF call with an empty salt approved.
    SealDomainEmpty,
    /// A sealed blob is shorter than a header, one byte and a tag.
    SealBlob,
    /// A sealed blob carries an unknown version.
    SealVersion,
    /// A sealed blob's ephemeral key is not an uncompressed P-384 point.
    SealEphemeralKey,
    /// A sealing public key is not a canonical P-384 SubjectPublicKeyInfo.
    SealPublicKey,
    /// A sealing private key is not a P-384 PKCS#8 key.
    SealPrivateKey,
    /// A sealed blob does not open under this key, domain and AAD.
    SealOpen,
    /// A cryptographic primitive failed.
    Primitive,
    /// A profile, narrowed by its options, names nothing in a family.
    #[non_exhaustive]
    EmptyProfile {
        /// The profile.
        profile: Profile,
        /// The options it was narrowed by.
        options: Options,
        /// The family left empty.
        category: Family,
    },
    /// A signature private key that cannot be imported: its PKCS#8 structure is not the one its
    /// RFCs define for the algorithm, or the module refuses it.
    SignaturePrivateKey {
        /// The signature algorithm.
        algorithm: SignatureAlgorithm,
    },
    /// A public key that is not the raw key of the signature algorithm's shape, such as a
    /// SubjectPublicKeyInfo or a compressed point.
    SignaturePublicKey {
        /// The signature algorithm.
        algorithm: SignatureAlgorithm,
    },
    /// A signature algorithm that is not a TLS certificate key algorithm, refused where a TLS key
    /// or a certificate request is made: an RSA-PSS variant.
    NotTlsKey {
        /// The refused algorithm.
        algorithm: SignatureAlgorithm,
    },
    /// A key algorithm the profile does not admit.
    KeyNotInProfile {
        /// The profile.
        profile: Profile,
        /// The refused key algorithm.
        algorithm: SignatureAlgorithm,
    },
    /// An algorithm the running module does not approve.
    NotApproved {
        /// The first algorithm found not approved.
        algorithm: Algorithm,
        /// Its approval.
        approval: Approval,
    },
    /// An algorithm, outside TLS, the profile does not admit.
    NotInProfile {
        /// The profile.
        profile: Profile,
        /// The refused algorithm.
        algorithm: Algorithm,
    },
    /// An HMAC key whose length is outside the profile's range.
    MacKeyLength {
        /// The profile.
        profile: Profile,
        /// The key's length in bytes.
        bytes: usize,
        /// The shortest key the profile admits, in bits.
        min_bits: usize,
        /// The longest key the module admits, in bits.
        max_bits: usize,
    },
    /// A MAC did not verify.
    MacVerify,
    /// A KDF output length outside 1 to the KDF's `max_output_len()`.
    KdfOutputLength {
        /// The KDF.
        algorithm: KdfAlgorithm,
        /// The requested length in bytes.
        bytes: usize,
        /// The longest output the KDF gives, in bytes.
        max_bytes: usize,
    },
    /// An empty KDF secret.
    KdfSecretEmpty,
    /// An empty KDF `info` under a profile that refuses one.
    KdfInfoEmpty {
        /// The profile.
        profile: Profile,
    },
    /// A profile that admits an empty KDF `info`, which the module does not approve; refused by
    /// `assert_admitted_approved` when the caller names `Family::Kdf` and the profile admits any
    /// KDF.
    KdfInfoMayBeEmpty {
        /// The profile.
        profile: Profile,
    },
    /// A KDF specification whose variant does not match its algorithm.
    KdfSpecMismatch {
        /// The algorithm the specification carries.
        algorithm: KdfAlgorithm,
    },
    /// A peer public key that is malformed for the curve, or that the module's validation refused.
    KeyAgreementPeerKey {
        /// The key-agreement algorithm.
        algorithm: KeyAgreementAlgorithm,
    },
    /// A static key-agreement private key that cannot be imported.
    KeyAgreementPrivateKey {
        /// The key-agreement algorithm.
        algorithm: KeyAgreementAlgorithm,
    },
    /// An AEAD key whose length is not the algorithm's `key_len()`.
    AeadKeyLength {
        /// The AEAD algorithm.
        algorithm: AeadAlgorithm,
        /// The key's length in bytes.
        bytes: usize,
    },
    /// A plaintext longer than the AEAD algorithm's `max_plaintext_len()`.
    AeadPlaintextLength {
        /// The AEAD algorithm.
        algorithm: AeadAlgorithm,
        /// The plaintext's length in bytes.
        bytes: usize,
    },
    /// An AEAD key that has sealed 2^32 times (SP 800-38D §8.3); a new key is needed.
    AeadLimit {
        /// The AEAD algorithm.
        algorithm: AeadAlgorithm,
    },
    /// A family `assert_admitted_approved` does not check: a TLS family, which
    /// `assert_module_approves` checks, or one this backend does not walk.
    FamilyNotAdmitted(Family),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Unavailable(a) => {
                write!(f, "{a:?} is not available on this backend's module")
            }
            CryptoError::PolicyEmpty(fam) => write!(f, "the TLS policy names no {fam:?}"),
            CryptoError::PolicyDuplicate(a) => write!(f, "the TLS policy names {a:?} twice"),
            CryptoError::PolicyVersionUnusable { version, family } => write!(
                f,
                "the TLS policy lists {version:?} but names no {family:?} usable with it"
            ),
            CryptoError::PolicyDrift => {
                f.write_str("the provider does not carry exactly the policy's algorithms")
            }
            CryptoError::NotFips => {
                f.write_str("the AWS-LC FIPS module is not active, or the provider is not FIPS")
            }
            CryptoError::KeyGeneration(a) => write!(f, "key generation for {a:?} failed"),
            CryptoError::Verify => f.write_str("the signature does not verify"),
            CryptoError::Sign => f.write_str("signing failed"),
            CryptoError::Csr(e) => write!(f, "the certificate signing request failed: {e:?}"),
            CryptoError::Tls(e) => write!(f, "the TLS configuration was refused: {e:?}"),
            CryptoError::Random => f.write_str("the random generator failed"),
            CryptoError::AeadKey => f.write_str("the AEAD key was refused"),
            CryptoError::AeadSeal => f.write_str("AEAD sealing failed"),
            CryptoError::AeadOpen => f.write_str("the AEAD ciphertext does not authenticate"),
            CryptoError::SealPlaintext => f.write_str("the sealed plaintext is empty"),
            CryptoError::SealDomainEmpty => f.write_str("the sealed-box domain is empty"),
            CryptoError::SealBlob => f.write_str("the sealed blob is too short"),
            CryptoError::SealVersion => f.write_str("the sealed blob has an unknown version"),
            CryptoError::SealEphemeralKey => {
                f.write_str("the sealed blob's ephemeral key is not an uncompressed P-384 point")
            }
            CryptoError::SealPublicKey => {
                f.write_str("the sealing public key is not a canonical P-384 SubjectPublicKeyInfo")
            }
            CryptoError::SealPrivateKey => {
                f.write_str("the sealing private key is not a P-384 PKCS#8 key")
            }
            CryptoError::SealOpen => {
                f.write_str("the sealed blob does not open under this key, domain and AAD")
            }
            CryptoError::Primitive => f.write_str("a cryptographic primitive failed"),
            CryptoError::EmptyProfile {
                profile,
                options,
                category,
            } => {
                write!(
                    f,
                    "the {profile} profile, with {options}, names no {category:?}"
                )
            }
            CryptoError::SignaturePrivateKey { algorithm } => {
                write!(f, "the {algorithm} private key was refused")
            }
            CryptoError::SignaturePublicKey { algorithm } => {
                write!(f, "the public key is not a raw {algorithm} public key")
            }
            CryptoError::NotTlsKey { algorithm } => {
                write!(f, "{algorithm} is not a TLS certificate key algorithm")
            }
            CryptoError::KeyNotInProfile { profile, algorithm } => {
                write!(f, "the {profile} profile does not admit {algorithm} keys")
            }
            CryptoError::NotApproved {
                algorithm,
                approval,
            } => {
                write!(
                    f,
                    "{algorithm:?} is not approved by the running module: {approval:?}"
                )
            }
            CryptoError::NotInProfile { profile, algorithm } => {
                write!(f, "the {profile} profile does not admit {algorithm:?}")
            }
            CryptoError::MacKeyLength {
                profile,
                bytes,
                min_bits,
                max_bits,
            } => write!(
                f,
                "an HMAC key of {bytes} bytes is outside the {profile} profile's {min_bits}-{max_bits} bit range"
            ),
            CryptoError::MacVerify => f.write_str("the MAC did not verify"),
            CryptoError::KdfOutputLength {
                algorithm,
                bytes,
                max_bytes,
            } => write!(
                f,
                "a KDF output of {bytes} bytes ({algorithm:?}) is outside 1-{max_bytes} bytes"
            ),
            CryptoError::KdfSecretEmpty => f.write_str("the KDF secret is empty"),
            CryptoError::KdfInfoEmpty { profile } => {
                write!(f, "the {profile} profile refuses an empty KDF info")
            }
            CryptoError::KdfInfoMayBeEmpty { profile } => write!(
                f,
                "the {profile} profile admits an empty KDF info, which the module does not approve"
            ),
            CryptoError::KdfSpecMismatch { algorithm } => {
                write!(f, "{algorithm:?} does not match its KDF specification")
            }
            CryptoError::KeyAgreementPeerKey { algorithm } => {
                write!(f, "the peer public key is not a valid {algorithm} key")
            }
            CryptoError::KeyAgreementPrivateKey { algorithm } => {
                write!(f, "the {algorithm} private key was refused")
            }
            CryptoError::AeadKeyLength { algorithm, bytes } => write!(
                f,
                "the {algorithm} key must be {} bytes, not {bytes}",
                algorithm.key_len()
            ),
            CryptoError::AeadPlaintextLength { algorithm, bytes } => write!(
                f,
                "a plaintext of {bytes} bytes exceeds {algorithm}'s maximum of {} bytes",
                algorithm.max_plaintext_len()
            ),
            CryptoError::AeadLimit { algorithm } => {
                write!(
                    f,
                    "the {algorithm} key has sealed 2^32 times; use a new key"
                )
            }
            CryptoError::FamilyNotAdmitted(family) => write!(
                f,
                "assert_admitted_approved does not check the {family:?} family; assert_module_approves checks the TLS families"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{
        AeadAlgorithm, Algorithm, KdfAlgorithm, KeyAgreementAlgorithm, KxGroup, MacAlgorithm,
        SignatureAlgorithm, TlsSignatureScheme,
    };
    use crate::capability::Approval;
    use crate::profile::{Options, Profile};

    #[test]
    fn display_texts_are_pinned() {
        assert_eq!(
            CryptoError::Random.to_string(),
            "the random generator failed"
        );
        assert_eq!(
            CryptoError::NotFips.to_string(),
            "the AWS-LC FIPS module is not active, or the provider is not FIPS"
        );
        assert_eq!(
            CryptoError::Unavailable(Algorithm::Signature(SignatureAlgorithm::MlDsa87)).to_string(),
            "Signature(MlDsa87) is not available on this backend's module"
        );
        assert_eq!(
            CryptoError::PolicyEmpty(Family::KxGroup).to_string(),
            "the TLS policy names no KxGroup"
        );
        assert_eq!(
            [
                Family::Mac,
                Family::Kdf,
                Family::KeyAgreement,
                Family::Aead,
                Family::Hash,
                Family::Signature
            ]
            .map(|f| format!("{f:?}")),
            ["Mac", "Kdf", "KeyAgreement", "Aead", "Hash", "Signature"]
        );
        assert_eq!(
            CryptoError::PolicyVersionUnusable {
                version: TlsVersion::Tls12,
                family: Family::KxGroup
            }
            .to_string(),
            "the TLS policy lists Tls12 but names no KxGroup usable with it"
        );
        assert_eq!(
            CryptoError::PolicyDuplicate(Algorithm::Scheme(TlsSignatureScheme::Ed25519))
                .to_string(),
            "the TLS policy names Scheme(Ed25519) twice"
        );
        assert_eq!(
            CryptoError::Csr(CsrError::InvalidName).to_string(),
            "the certificate signing request failed: InvalidName"
        );
        assert_eq!(
            CryptoError::Tls(TlsError::PrivateKey).to_string(),
            "the TLS configuration was refused: PrivateKey"
        );
    }

    #[test]
    fn profile_display_texts_are_pinned() {
        let pq = Options {
            pq_key_exchange_required: true,
            peer_certificates_match_profile: false,
            cnsa1_unclassified_nss: false,
        };
        let table: [(CryptoError, &str); 21] = [
            (
                CryptoError::EmptyProfile {
                    profile: Profile::Cnsa1,
                    options: pq,
                    category: Family::KxGroup,
                },
                "the cnsa1 profile, with post-quantum key exchange required, names no KxGroup",
            ),
            (
                CryptoError::EmptyProfile {
                    profile: Profile::Cnsa2,
                    options: Options::default(),
                    category: Family::KeyAlgorithm,
                },
                "the cnsa2 profile, with no options, names no KeyAlgorithm",
            ),
            (
                CryptoError::KeyNotInProfile {
                    profile: Profile::Bsi,
                    algorithm: SignatureAlgorithm::Rsa3072Sha384,
                },
                "the bsi profile does not admit rsa3072-sha384 keys",
            ),
            (
                CryptoError::SignaturePrivateKey {
                    algorithm: SignatureAlgorithm::Ed25519,
                },
                "the ed25519 private key was refused",
            ),
            (
                CryptoError::SignaturePublicKey {
                    algorithm: SignatureAlgorithm::MlDsa87,
                },
                "the public key is not a raw ml-dsa-87 public key",
            ),
            (
                CryptoError::NotTlsKey {
                    algorithm: SignatureAlgorithm::Rsa3072Sha384Pss,
                },
                "rsa3072-sha384-pss is not a TLS certificate key algorithm",
            ),
            (
                CryptoError::NotApproved {
                    algorithm: Algorithm::Kx(KxGroup::X25519),
                    approval: Approval::Unverified,
                },
                "Kx(X25519) is not approved by the running module: Unverified",
            ),
            (
                CryptoError::NotApproved {
                    algorithm: Algorithm::Signature(SignatureAlgorithm::MlDsa87),
                    approval: Approval::AlgorithmTested { cavp: "A7855 (x)" },
                },
                "Signature(MlDsa87) is not approved by the running module: AlgorithmTested { cavp: \"A7855 (x)\" }",
            ),
            (
                CryptoError::NotInProfile {
                    profile: Profile::Cnsa2,
                    algorithm: Algorithm::Mac(MacAlgorithm::HmacSha256),
                },
                "the cnsa2 profile does not admit Mac(HmacSha256)",
            ),
            (
                CryptoError::MacKeyLength {
                    profile: Profile::Bsi,
                    bytes: 15,
                    min_bits: 128,
                    max_bits: 524_288,
                },
                "an HMAC key of 15 bytes is outside the bsi profile's 128-524288 bit range",
            ),
            (CryptoError::MacVerify, "the MAC did not verify"),
            (
                CryptoError::KdfOutputLength {
                    algorithm: KdfAlgorithm::HkdfSha256,
                    bytes: 8161,
                    max_bytes: 8160,
                },
                "a KDF output of 8161 bytes (HkdfSha256) is outside 1-8160 bytes",
            ),
            (CryptoError::KdfSecretEmpty, "the KDF secret is empty"),
            (
                CryptoError::KdfInfoEmpty {
                    profile: Profile::Fips1403,
                },
                "the fips1403 profile refuses an empty KDF info",
            ),
            (
                CryptoError::KdfInfoMayBeEmpty {
                    profile: Profile::Unrestricted,
                },
                "the unrestricted profile admits an empty KDF info, which the module does not approve",
            ),
            (
                CryptoError::KdfSpecMismatch {
                    algorithm: KdfAlgorithm::OneStepSha256,
                },
                "OneStepSha256 does not match its KDF specification",
            ),
            (
                CryptoError::KeyAgreementPeerKey {
                    algorithm: KeyAgreementAlgorithm::EcdhP384,
                },
                "the peer public key is not a valid ecdh-p384 key",
            ),
            (
                CryptoError::KeyAgreementPrivateKey {
                    algorithm: KeyAgreementAlgorithm::X25519,
                },
                "the x25519 private key was refused",
            ),
            (
                CryptoError::AeadKeyLength {
                    algorithm: AeadAlgorithm::Aes128Gcm,
                    bytes: 32,
                },
                "the aes-128-gcm key must be 16 bytes, not 32",
            ),
            (
                CryptoError::AeadLimit {
                    algorithm: AeadAlgorithm::Aes256Gcm,
                },
                "the aes-256-gcm key has sealed 2^32 times; use a new key",
            ),
            (
                CryptoError::FamilyNotAdmitted(Family::CipherSuite),
                "assert_admitted_approved does not check the CipherSuite family; assert_module_approves checks the TLS families",
            ),
        ];
        for (e, text) in table {
            assert_eq!(e.to_string(), text);
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn the_aead_plaintext_length_text_is_pinned() {
        assert_eq!(
            CryptoError::AeadPlaintextLength {
                algorithm: AeadAlgorithm::Chacha20Poly1305,
                bytes: 274_877_906_880,
            }
            .to_string(),
            "a plaintext of 274877906880 bytes exceeds chacha20-poly1305's maximum of 274877906879 bytes"
        );
    }

    #[test]
    fn every_other_display_text_is_pinned() {
        let table: [(CryptoError, &str); 16] = [
            (
                CryptoError::PolicyDrift,
                "the provider does not carry exactly the policy's algorithms",
            ),
            (
                CryptoError::KeyGeneration(Algorithm::Signature(SignatureAlgorithm::Ed25519)),
                "key generation for Signature(Ed25519) failed",
            ),
            (CryptoError::Verify, "the signature does not verify"),
            (CryptoError::Sign, "signing failed"),
            (CryptoError::AeadKey, "the AEAD key was refused"),
            (CryptoError::AeadSeal, "AEAD sealing failed"),
            (
                CryptoError::AeadOpen,
                "the AEAD ciphertext does not authenticate",
            ),
            (CryptoError::SealPlaintext, "the sealed plaintext is empty"),
            (
                CryptoError::SealDomainEmpty,
                "the sealed-box domain is empty",
            ),
            (CryptoError::SealBlob, "the sealed blob is too short"),
            (
                CryptoError::SealVersion,
                "the sealed blob has an unknown version",
            ),
            (
                CryptoError::SealEphemeralKey,
                "the sealed blob's ephemeral key is not an uncompressed P-384 point",
            ),
            (
                CryptoError::SealPublicKey,
                "the sealing public key is not a canonical P-384 SubjectPublicKeyInfo",
            ),
            (
                CryptoError::SealPrivateKey,
                "the sealing private key is not a P-384 PKCS#8 key",
            ),
            (
                CryptoError::SealOpen,
                "the sealed blob does not open under this key, domain and AAD",
            ),
            (CryptoError::Primitive, "a cryptographic primitive failed"),
        ];
        for (e, text) in table {
            assert_eq!(e.to_string(), text);
        }
    }
}
