//! The crate's refusals.
use crate::algorithm::{Algorithm, SignatureAlgorithm};
use crate::capability::Approval;
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
    /// Key algorithms.
    KeyAlgorithm,
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
    /// The process is not running the AWS-LC FIPS module, or a provider is not FIPS.
    NotFips,
    /// Key generation failed.
    KeyGeneration(Algorithm),
    /// A private key was refused.
    PrivateKey,
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
    EmptyProfile {
        /// The profile.
        profile: Profile,
        /// The options it was narrowed by.
        options: Options,
        /// The family left empty.
        category: Family,
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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Unavailable(a) => {
                write!(f, "{a:?} is not available on this backend's module")
            }
            CryptoError::PolicyEmpty(fam) => write!(f, "the TLS policy names no {fam:?}"),
            CryptoError::PolicyDuplicate(a) => write!(f, "the TLS policy names {a:?} twice"),
            CryptoError::PolicyDrift => {
                f.write_str("the provider does not carry exactly the policy's algorithms")
            }
            CryptoError::NotFips => {
                f.write_str("the AWS-LC FIPS module is not active, or the provider is not FIPS")
            }
            CryptoError::KeyGeneration(a) => write!(f, "key generation for {a:?} failed"),
            CryptoError::PrivateKey => f.write_str("the private key was refused"),
            CryptoError::Verify => f.write_str("the signature does not verify"),
            CryptoError::Sign => f.write_str("signing failed"),
            CryptoError::Csr(e) => write!(f, "the certificate signing request failed: {e:?}"),
            CryptoError::Tls(e) => write!(f, "the TLS configuration was refused: {e:?}"),
            CryptoError::Random => f.write_str("the random generator failed"),
            CryptoError::AeadKey => f.write_str("the AEAD key was refused"),
            CryptoError::AeadSeal => f.write_str("AEAD sealing failed"),
            CryptoError::AeadOpen => f.write_str("the AEAD ciphertext does not authenticate"),
            CryptoError::SealPlaintext => f.write_str("the sealed plaintext is empty"),
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
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{Algorithm, KxGroup, SignatureAlgorithm, TlsSignatureScheme};
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
        };
        let table: [(CryptoError, &str); 5] = [
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
        ];
        for (e, text) in table {
            assert_eq!(e.to_string(), text);
        }
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
            (CryptoError::PrivateKey, "the private key was refused"),
            (CryptoError::Verify, "the signature does not verify"),
            (CryptoError::Sign, "signing failed"),
            (CryptoError::AeadKey, "the AEAD key was refused"),
            (CryptoError::AeadSeal, "AEAD sealing failed"),
            (
                CryptoError::AeadOpen,
                "the AEAD ciphertext does not authenticate",
            ),
            (CryptoError::SealPlaintext, "the sealed plaintext is empty"),
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
