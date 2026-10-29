//! Immutable certificate rules, independent of handshake signature schemes.
use crate::{HashAlgorithm, Profile};

/// A finite certificate-policy identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerCertificateRuleId {
    /// The unrestricted profile rule.
    Unrestricted,
    /// The preferred profile rule.
    Preferred,
    /// The cnsa2 profile rule.
    Cnsa2,
    /// The cnsa1 profile rule.
    Cnsa1,
    /// The bsi profile rule.
    Bsi,
    /// The fips1403 profile rule.
    Fips1403,
    /// The fips1402 profile rule.
    Fips1402,
}

/// A supported named elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

/// A standardized pure ML-DSA parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

/// The published RSA modulus-size condition, separate from implementation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSizeRule {
    /// A minimum modulus bit length.
    Minimum(u16),
    /// An exact finite list of modulus bit lengths.
    Exact(&'static [u16]),
}

/// The key families and parameters admitted for a certificate role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerKeyRule {
    /// Admitted EC curves.
    pub ec_curves: &'static [PeerCurve],
    /// RSA modulus-size condition, if RSA is admitted.
    pub rsa: Option<RsaSizeRule>,
    /// Whether RSA modulus bit lengths must also be even.
    pub rsa_even_bits: bool,
    /// Whether Ed25519 is admitted.
    pub ed25519: bool,
    /// Admitted pure ML-DSA parameter sets.
    pub ml_dsa: &'static [MlDsaParameterSet],
}

/// A bounded public-key descriptor, carrying no key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKey {
    /// An EC key on the named curve.
    Ec(PeerCurve),
    /// An RSA key's actual modulus bit length.
    Rsa(u16),
    /// An Ed25519 key.
    Ed25519,
    /// A pure ML-DSA key.
    MlDsa(MlDsaParameterSet),
    /// An unsupported algorithm or parameter OID; input bytes are omitted.
    Unknown,
}

/// A certificate signature algorithm, independent of CertificateVerify schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateSignature {
    /// ECDSA with issuer curve and digest.
    Ecdsa(PeerCurve, HashAlgorithm),
    /// RSA-PSS with matching digest/MGF1 and digest-length salt.
    RsaPss(HashAlgorithm),
    /// RSA PKCS#1 v1.5 with this digest.
    RsaPkcs1(HashAlgorithm),
    /// Ed25519.
    Ed25519,
    /// Pure ML-DSA.
    MlDsa(MlDsaParameterSet),
    /// An unsupported algorithm or parameter OID; input bytes are omitted.
    Unknown,
}

/// Why a peer certificate failed the profile rule. Descriptors never carry DER or key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCertificateViolation {
    /// The leaf public key is outside the rule.
    LeafKey(PeerKey),
    /// A selected-path certificate signature is outside the rule.
    ChainSignature(CertificateSignature),
    /// An issuer key, including an anchor signing its child, is outside the rule.
    IssuerKey(PeerKey),
    /// Certificate key or algorithm parameters cannot be decoded.
    Malformed,
}

impl std::fmt::Display for PeerCertificateViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafKey(key) => write!(f, "leaf key {key:?}"),
            Self::ChainSignature(signature) => write!(f, "chain signature {signature:?}"),
            Self::IssuerKey(key) => write!(f, "issuer key {key:?}"),
            Self::Malformed => f.write_str("malformed certificate key or algorithm parameters"),
        }
    }
}

impl std::error::Error for PeerCertificateViolation {}

/// Immutable cited certificate-policy data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCertificateRule {
    /// Canonical cache identity.
    pub id: PeerCertificateRuleId,
    /// Leaf key constraints.
    pub leaf_keys: PeerKeyRule,
    /// Issuing key constraints, including the trust anchor.
    pub issuer_keys: PeerKeyRule,
    /// Admitted path signature algorithms.
    pub signatures: &'static [CertificateSignature],
    /// Public source editions and locations for these constraints.
    pub citations: &'static [&'static str],
}

use CertificateSignature::*;
use HashAlgorithm::{Sha256, Sha384, Sha512};
use MlDsaParameterSet::{MlDsa65, MlDsa87};
use PeerCurve::{P256, P384, P521};
static UNRESTRICTED: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Unrestricted,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: false,
        ed25519: true,
        ml_dsa: &[MlDsa87],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: false,
        ed25519: true,
        ml_dsa: &[MlDsa87],
    },
    signatures: &[
        Ecdsa(P256, Sha256),
        Ecdsa(P256, Sha384),
        Ecdsa(P256, Sha512),
        Ecdsa(P384, Sha256),
        Ecdsa(P384, Sha384),
        Ecdsa(P384, Sha512),
        Ecdsa(P521, Sha256),
        Ecdsa(P521, Sha384),
        Ecdsa(P521, Sha512),
        RsaPss(Sha256),
        RsaPss(Sha384),
        RsaPss(Sha512),
        RsaPkcs1(Sha256),
        RsaPkcs1(Sha384),
        RsaPkcs1(Sha512),
        Ed25519,
        MlDsa(MlDsa87),
    ],
    citations: &["Crate recommendation: docs/profiles.md sections 3 and 5"],
};
static PREFERRED: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Preferred,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(3072)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[MlDsa65, MlDsa87],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(3072)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    signatures: &[
        Ecdsa(P256, Sha256),
        Ecdsa(P256, Sha384),
        Ecdsa(P256, Sha512),
        Ecdsa(P384, Sha256),
        Ecdsa(P384, Sha384),
        Ecdsa(P384, Sha512),
        Ecdsa(P521, Sha256),
        Ecdsa(P521, Sha384),
        Ecdsa(P521, Sha512),
        RsaPss(Sha256),
        RsaPss(Sha384),
        RsaPss(Sha512),
        RsaPkcs1(Sha256),
        RsaPkcs1(Sha384),
        RsaPkcs1(Sha512),
    ],
    citations: &[
        "ASD ISM September 2026, ISM-1763 p. 8, ISM-1991 p. 9, ISM-1765 p. 10, ISM-1374 p. 20",
    ],
};
static CNSA2: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Cnsa2,
    leaf_keys: PeerKeyRule {
        ec_curves: &[],
        rsa: None,
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[MlDsa87],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[],
        rsa: None,
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[MlDsa87],
    },
    signatures: &[MlDsa(MlDsa87)],
    citations: &["CNSSP 15 December 2024, Annex B paragraph 1, pp. B-1 to B-2"],
};
static CNSA1: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Cnsa1,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P384],
        rsa: Some(RsaSizeRule::Exact(&[3072, 4096])),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P384],
        rsa: Some(RsaSizeRule::Exact(&[3072, 4096])),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    signatures: &[Ecdsa(P384, Sha384), RsaPss(Sha384), RsaPkcs1(Sha384)],
    citations: &["RFC 8603 section 4.1; RFC 9151 sections 5.2, 5.4, 6.3, 7.2"],
};
static BSI: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Bsi,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(3000)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(3000)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    signatures: &[
        Ecdsa(P256, Sha256),
        Ecdsa(P384, Sha384),
        Ecdsa(P521, Sha512),
        RsaPss(Sha256),
        RsaPss(Sha384),
        RsaPss(Sha512),
    ],
    citations: &["BSI TR-02102-2 version 2026-01, sections 3.4.3 and 3.6, Tables 12 and 14"],
};
static FIPS1403: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Fips1403,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: true,
        ed25519: true,
        ml_dsa: &[MlDsa87],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: true,
        ed25519: true,
        ml_dsa: &[MlDsa87],
    },
    signatures: &[
        Ecdsa(P256, Sha256),
        Ecdsa(P256, Sha384),
        Ecdsa(P256, Sha512),
        Ecdsa(P384, Sha256),
        Ecdsa(P384, Sha384),
        Ecdsa(P384, Sha512),
        Ecdsa(P521, Sha256),
        Ecdsa(P521, Sha384),
        Ecdsa(P521, Sha512),
        RsaPss(Sha256),
        RsaPss(Sha384),
        RsaPss(Sha512),
        RsaPkcs1(Sha256),
        RsaPkcs1(Sha384),
        RsaPkcs1(Sha512),
        Ed25519,
        MlDsa(MlDsa87),
    ],
    citations: &[
        "NIST SP 800-52r2 section 3.3.3; FIPS 186-5 sections 5.1, 5.4, 6.4, 7; CMVP approved algorithm lists",
    ],
};
static FIPS1402: PeerCertificateRule = PeerCertificateRule {
    id: PeerCertificateRuleId::Fips1402,
    leaf_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    issuer_keys: PeerKeyRule {
        ec_curves: &[P256, P384, P521],
        rsa: Some(RsaSizeRule::Minimum(2048)),
        rsa_even_bits: false,
        ed25519: false,
        ml_dsa: &[],
    },
    signatures: &[
        Ecdsa(P256, Sha256),
        Ecdsa(P256, Sha384),
        Ecdsa(P256, Sha512),
        Ecdsa(P384, Sha256),
        Ecdsa(P384, Sha384),
        Ecdsa(P384, Sha512),
        Ecdsa(P521, Sha256),
        Ecdsa(P521, Sha384),
        Ecdsa(P521, Sha512),
        RsaPss(Sha256),
        RsaPss(Sha384),
        RsaPss(Sha512),
        RsaPkcs1(Sha256),
        RsaPkcs1(Sha384),
        RsaPkcs1(Sha512),
    ],
    citations: &[
        "NIST SP 800-52r2 section 3.3.3; SP 800-131A r2 Table 2; FIPS 140-2 IG A.14 pp. 221-222; FIPS 186-4 sections 5.5 and 6.4",
    ],
};

/// The canonical, immutable certificate rule for a profile.
pub fn peer_certificate_rule(profile: Profile) -> &'static PeerCertificateRule {
    match profile {
        Profile::Unrestricted => &UNRESTRICTED,
        Profile::Preferred => &PREFERRED,
        Profile::Cnsa2 => &CNSA2,
        Profile::Cnsa1 => &CNSA1,
        Profile::Bsi => &BSI,
        Profile::Fips1403 => &FIPS1403,
        Profile::Fips1402 => &FIPS1402,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_certificate_typed_causes_are_bounded() {
        use crate::TlsError;
        use std::error::Error;
        let rows = [
            (
                PeerCertificateViolation::LeafKey(PeerKey::Rsa(8192)),
                "leaf key Rsa(8192)",
            ),
            (
                PeerCertificateViolation::ChainSignature(CertificateSignature::Unknown),
                "chain signature Unknown",
            ),
            (
                PeerCertificateViolation::IssuerKey(PeerKey::Unknown),
                "issuer key Unknown",
            ),
            (
                PeerCertificateViolation::Malformed,
                "malformed certificate key or algorithm parameters",
            ),
        ];
        for (violation, text) in rows {
            assert_eq!(violation.to_string(), text);
            assert_eq!(violation.source().map(|e| e.to_string()), None);
            let cause = TlsError::PeerCertificate {
                profile: Profile::Cnsa1,
                violation,
            };
            assert_eq!(
                cause,
                TlsError::PeerCertificate {
                    profile: Profile::Cnsa1,
                    violation
                }
            );
            assert_eq!(
                cause.to_string(),
                format!("the cnsa1 peer certificate was refused: {text}")
            );
            let error: &(dyn Error + 'static) = &cause;
            assert_eq!(error.downcast_ref::<TlsError>(), Some(&cause));
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<PeerCertificateViolation>(),
                Some(&violation)
            );
        }
        for (error, text) in [
            (
                TlsError::ProtocolVersions,
                "the provider refused the protocol versions",
            ),
            (TlsError::PrivateKey, "the private key was refused"),
            (
                TlsError::DefaultProviderInstalled,
                "a process-default provider is already installed",
            ),
            (
                TlsError::KeyMismatch,
                "the certificate chain is empty or does not carry the key",
            ),
        ] {
            assert_eq!(error.to_string(), text);
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn peer_certificate_literal_matrix() {
        use CertificateSignature::*;
        use HashAlgorithm::{Sha256, Sha384, Sha512};
        use MlDsaParameterSet::{MlDsa65, MlDsa87};
        use PeerCurve::{P256, P384, P521};
        let classical = &[
            Ecdsa(P256, Sha256),
            Ecdsa(P256, Sha384),
            Ecdsa(P256, Sha512),
            Ecdsa(P384, Sha256),
            Ecdsa(P384, Sha384),
            Ecdsa(P384, Sha512),
            Ecdsa(P521, Sha256),
            Ecdsa(P521, Sha384),
            Ecdsa(P521, Sha512),
            RsaPss(Sha256),
            RsaPss(Sha384),
            RsaPss(Sha512),
            RsaPkcs1(Sha256),
            RsaPkcs1(Sha384),
            RsaPkcs1(Sha512),
        ];
        let expanded = &[
            Ecdsa(P256, Sha256),
            Ecdsa(P256, Sha384),
            Ecdsa(P256, Sha512),
            Ecdsa(P384, Sha256),
            Ecdsa(P384, Sha384),
            Ecdsa(P384, Sha512),
            Ecdsa(P521, Sha256),
            Ecdsa(P521, Sha384),
            Ecdsa(P521, Sha512),
            RsaPss(Sha256),
            RsaPss(Sha384),
            RsaPss(Sha512),
            RsaPkcs1(Sha256),
            RsaPkcs1(Sha384),
            RsaPkcs1(Sha512),
            Ed25519,
            MlDsa(MlDsa87),
        ];
        let rows: [(
            Profile,
            PeerCertificateRuleId,
            PeerKeyRule,
            PeerKeyRule,
            &[CertificateSignature],
        ); 7] = [
            (
                Profile::Unrestricted,
                PeerCertificateRuleId::Unrestricted,
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: false,
                    ed25519: true,
                    ml_dsa: &[MlDsa87],
                },
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: false,
                    ed25519: true,
                    ml_dsa: &[MlDsa87],
                },
                expanded,
            ),
            (
                Profile::Preferred,
                PeerCertificateRuleId::Preferred,
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(3072)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[MlDsa65, MlDsa87],
                },
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(3072)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                classical,
            ),
            (
                Profile::Cnsa2,
                PeerCertificateRuleId::Cnsa2,
                PeerKeyRule {
                    ec_curves: &[],
                    rsa: None,
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[MlDsa87],
                },
                PeerKeyRule {
                    ec_curves: &[],
                    rsa: None,
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[MlDsa87],
                },
                &[MlDsa(MlDsa87)],
            ),
            (
                Profile::Cnsa1,
                PeerCertificateRuleId::Cnsa1,
                PeerKeyRule {
                    ec_curves: &[P384],
                    rsa: Some(RsaSizeRule::Exact(&[3072, 4096])),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                PeerKeyRule {
                    ec_curves: &[P384],
                    rsa: Some(RsaSizeRule::Exact(&[3072, 4096])),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                &[Ecdsa(P384, Sha384), RsaPss(Sha384), RsaPkcs1(Sha384)],
            ),
            (
                Profile::Bsi,
                PeerCertificateRuleId::Bsi,
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(3000)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(3000)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                &[
                    Ecdsa(P256, Sha256),
                    Ecdsa(P384, Sha384),
                    Ecdsa(P521, Sha512),
                    RsaPss(Sha256),
                    RsaPss(Sha384),
                    RsaPss(Sha512),
                ],
            ),
            (
                Profile::Fips1403,
                PeerCertificateRuleId::Fips1403,
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: true,
                    ed25519: true,
                    ml_dsa: &[MlDsa87],
                },
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: true,
                    ed25519: true,
                    ml_dsa: &[MlDsa87],
                },
                expanded,
            ),
            (
                Profile::Fips1402,
                PeerCertificateRuleId::Fips1402,
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                PeerKeyRule {
                    ec_curves: &[P256, P384, P521],
                    rsa: Some(RsaSizeRule::Minimum(2048)),
                    rsa_even_bits: false,
                    ed25519: false,
                    ml_dsa: &[],
                },
                classical,
            ),
        ];
        for (profile, id, leaf, issuer, signatures) in rows {
            let rule = peer_certificate_rule(profile);
            assert_eq!(rule.id, id);
            assert_eq!(rule.leaf_keys, leaf);
            assert_eq!(rule.issuer_keys, issuer);
            assert_eq!(rule.signatures, signatures);
            assert!(!rule.citations.is_empty());
        }
    }
}
