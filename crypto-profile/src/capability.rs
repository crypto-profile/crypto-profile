//! What each AWS-LC FIPS module can do and what its security policy says about each algorithm,
//! with the policy citation for every sourced cell.
use crate::algorithm::*;
use crate::error::CryptoError;

/// An AWS-LC FIPS module line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ModuleLine {
    /// AWS-LC FIPS 3.x (aws-lc-rs 1.17).
    AwsLcFips3,
    /// AWS-LC FIPS 4.x (aws-lc-rs 1.18).
    AwsLcFips4,
}

/// How the FIPS module is linked; each linkage is a separate module, with its own certificate or
/// submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Linkage {
    /// Linked into the binary.
    Static,
    /// Loaded as a shared library.
    Dynamic,
}

/// An AWS-LC FIPS module: a line and a linkage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Module {
    /// The module line.
    pub line: ModuleLine,
    /// The linkage.
    pub linkage: Linkage,
}

/// A certificate's CMVP status as recorded when this crate version was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertStatus {
    /// On the CMVP validated list.
    Validated,
    /// Submitted and in CMVP review.
    InProcess,
    /// Moved to the CMVP historical list.
    Historical,
}

/// The certificate a module carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate {
    /// The module's name, with the release for a 3.x line.
    pub module_name: &'static str,
    /// The certificate number, absent while in review.
    pub number: Option<u32>,
    /// The status when this crate version was released; the CMVP list is authoritative.
    pub status: CertStatus,
    /// The security policy URL, absent while none is published.
    pub policy: Option<&'static str>,
}

/// A module's validation status for one algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// Listed as approved; `source` cites the table.
    Approved {
        /// The security-policy citation.
        source: &'static str,
    },
    /// Not approved; `source` cites where the policy says so or omits it.
    NotApproved {
        /// The security-policy citation.
        source: &'static str,
    },
    /// No source settles it. Treated as not approved everywhere.
    Unverified,
}

impl Approval {
    /// Whether the cell is approved. `Unverified` is not.
    pub const fn is_approved(self) -> bool {
        matches!(self, Approval::Approved { .. })
    }
}

/// One cell of the capability table. A cipher suite cell speaks only to the suite's algorithms;
/// whether its protocol version is approved is the `Protocol` cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The backend for this module implements the algorithm.
    pub available: bool,
    /// The module's validation status for it.
    pub approval: Approval,
}

const POLICY_5314: &str = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5314.pdf";
const POLICY_5298: &str = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5298.pdf";

/// The certificate for a module.
pub const fn certificate(m: Module) -> Certificate {
    match (m.line, m.linkage) {
        (ModuleLine::AwsLcFips3, Linkage::Static) => Certificate {
            module_name: "AWS-LC 3 Cryptographic Module (static), AWS-LC FIPS 3.1.0",
            number: Some(5314),
            status: CertStatus::Validated,
            policy: Some(POLICY_5314),
        },
        (ModuleLine::AwsLcFips3, Linkage::Dynamic) => Certificate {
            module_name: "AWS-LC 3 Cryptographic Module (dynamic), AWS-LC FIPS 3.1.0",
            number: Some(5298),
            status: CertStatus::Validated,
            policy: Some(POLICY_5298),
        },
        (ModuleLine::AwsLcFips4, Linkage::Static) => Certificate {
            module_name: "AWS-LC 4 Cryptographic Module (static)",
            number: None,
            status: CertStatus::InProcess,
            policy: None,
        },
        (ModuleLine::AwsLcFips4, Linkage::Dynamic) => Certificate {
            module_name: "AWS-LC 4 Cryptographic Module (dynamic)",
            number: None,
            status: CertStatus::InProcess,
            policy: None,
        },
    }
}

const fn table5(l: Linkage) -> &'static str {
    match l {
        Linkage::Static => {
            "AWS-LC FIPS 3.1.0 Security Policy, cert #5314 (static), Table 5, pp. 8-11"
        }
        Linkage::Dynamic => {
            "AWS-LC FIPS 3.1.0 Security Policy, cert #5298 (dynamic), Table 5, pp. 8-11"
        }
    }
}

const fn absent(l: Linkage) -> &'static str {
    match l {
        Linkage::Static => {
            "AWS-LC FIPS 3.1.0 Security Policy, cert #5314 (static): not listed in Tables 5-8"
        }
        Linkage::Dynamic => {
            "AWS-LC FIPS 3.1.0 Security Policy, cert #5298 (dynamic): not listed in Tables 5-8"
        }
    }
}

const fn three_x(l: Linkage, a: Algorithm) -> Capability {
    let yes = Approval::Approved { source: table5(l) };
    let no = Approval::NotApproved { source: absent(l) };
    let (available, approval) = match a {
        Algorithm::Signature(s) => match s {
            SignatureAlgorithm::MlDsa87 => (false, no),
            SignatureAlgorithm::EcdsaP256Sha256
            | SignatureAlgorithm::EcdsaP384Sha384
            | SignatureAlgorithm::EcdsaP521Sha384
            | SignatureAlgorithm::EcdsaP521Sha512
            | SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::Rsa2048Sha384
            | SignatureAlgorithm::Rsa3072Sha384
            | SignatureAlgorithm::Rsa4096Sha384 => (true, yes),
        },
        Algorithm::Scheme(s) => match s {
            TlsSignatureScheme::MlDsa87 => (false, no),
            TlsSignatureScheme::EcdsaNistp256Sha256
            | TlsSignatureScheme::EcdsaNistp384Sha384
            | TlsSignatureScheme::EcdsaNistp521Sha512
            | TlsSignatureScheme::Ed25519
            | TlsSignatureScheme::RsaPssSha256
            | TlsSignatureScheme::RsaPssSha384
            | TlsSignatureScheme::RsaPssSha512
            | TlsSignatureScheme::RsaPkcs1Sha256
            | TlsSignatureScheme::RsaPkcs1Sha384
            | TlsSignatureScheme::RsaPkcs1Sha512 => (true, yes),
        },
        Algorithm::Kx(k) => match k {
            KxGroup::MlKem1024 | KxGroup::Secp384r1 | KxGroup::Secp256r1 => (true, yes),
            KxGroup::X25519 => (true, no),
            KxGroup::X25519MlKem768 | KxGroup::Secp256r1MlKem768 => (true, Approval::Unverified),
        },
        Algorithm::Cipher(c) => match c {
            CipherSuite::Tls13Aes256GcmSha384
            | CipherSuite::Tls13Aes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaAes128GcmSha256
            | CipherSuite::Tls12EcdheRsaAes256GcmSha384
            | CipherSuite::Tls12EcdheRsaAes128GcmSha256 => (true, yes),
            CipherSuite::Tls13Chacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => (true, no),
        },
        Algorithm::Hash(h) => match h {
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => (true, yes),
        },
        Algorithm::Protocol(v) => match v {
            TlsVersion::Tls12 => (true, yes),
            TlsVersion::Tls13 => (true, Approval::Unverified),
        },
    };
    Capability {
        available,
        approval,
    }
}

const fn four_x(a: Algorithm) -> Capability {
    let unsourced = Capability {
        available: true,
        approval: Approval::Unverified,
    };
    match a {
        Algorithm::Signature(s) => match s {
            SignatureAlgorithm::MlDsa87
            | SignatureAlgorithm::EcdsaP256Sha256
            | SignatureAlgorithm::EcdsaP384Sha384
            | SignatureAlgorithm::EcdsaP521Sha384
            | SignatureAlgorithm::EcdsaP521Sha512
            | SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::Rsa2048Sha384
            | SignatureAlgorithm::Rsa3072Sha384
            | SignatureAlgorithm::Rsa4096Sha384 => unsourced,
        },
        Algorithm::Scheme(t) => match t {
            TlsSignatureScheme::EcdsaNistp256Sha256
            | TlsSignatureScheme::EcdsaNistp384Sha384
            | TlsSignatureScheme::EcdsaNistp521Sha512
            | TlsSignatureScheme::Ed25519
            | TlsSignatureScheme::RsaPssSha256
            | TlsSignatureScheme::RsaPssSha384
            | TlsSignatureScheme::RsaPssSha512
            | TlsSignatureScheme::RsaPkcs1Sha256
            | TlsSignatureScheme::RsaPkcs1Sha384
            | TlsSignatureScheme::RsaPkcs1Sha512
            | TlsSignatureScheme::MlDsa87 => unsourced,
        },
        Algorithm::Kx(k) => match k {
            KxGroup::MlKem1024
            | KxGroup::X25519MlKem768
            | KxGroup::Secp256r1MlKem768
            | KxGroup::Secp384r1
            | KxGroup::Secp256r1
            | KxGroup::X25519 => unsourced,
        },
        Algorithm::Cipher(c) => match c {
            CipherSuite::Tls13Aes256GcmSha384
            | CipherSuite::Tls13Aes128GcmSha256
            | CipherSuite::Tls13Chacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheEcdsaAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaAes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheRsaAes256GcmSha384
            | CipherSuite::Tls12EcdheRsaAes128GcmSha256
            | CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => unsourced,
        },
        Algorithm::Hash(h) => match h {
            HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => unsourced,
        },
        Algorithm::Protocol(v) => match v {
            TlsVersion::Tls12 | TlsVersion::Tls13 => unsourced,
        },
    }
}

/// What the backend for `m` can do for `a`, and what that module's security policy says about it.
pub const fn capability(m: Module, a: Algorithm) -> Capability {
    match m.line {
        ModuleLine::AwsLcFips3 => three_x(m.linkage, a),
        ModuleLine::AwsLcFips4 => four_x(a),
    }
}

/// Refuses an algorithm the module's backend does not implement.
pub fn ensure_available(m: Module, a: Algorithm) -> Result<(), CryptoError> {
    if capability(m, a).available {
        Ok(())
    } else {
        Err(CryptoError::Unavailable(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const M3S: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Static,
    };
    const M3D: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Dynamic,
    };
    const M4S: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Static,
    };
    const M4D: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Dynamic,
    };

    fn modules() -> [Module; 4] {
        [M3S, M3D, M4S, M4D]
    }

    #[test]
    fn certificates_name_their_module() {
        let c = certificate(M3S);
        assert_eq!((c.number, c.status), (Some(5314), CertStatus::Validated));
        assert!(c.policy.unwrap().ends_with("140sp5314.pdf"));
        let c = certificate(M3D);
        assert_eq!((c.number, c.status), (Some(5298), CertStatus::Validated));
        assert!(c.policy.unwrap().ends_with("140sp5298.pdf"));
        for m in [M4S, M4D] {
            let c = certificate(m);
            assert_eq!(
                (c.number, c.status, c.policy),
                (None, CertStatus::InProcess, None)
            );
        }
    }

    #[test]
    fn every_sourced_cell_cites_its_own_certificate() {
        for m in modules() {
            for a in Algorithm::all() {
                match capability(m, a).approval {
                    Approval::Approved { source } | Approval::NotApproved { source } => {
                        assert!(!source.is_empty(), "{m:?} {a:?}");
                        let want = match m.linkage {
                            Linkage::Static => "#5314",
                            Linkage::Dynamic => "#5298",
                        };
                        assert!(source.contains(want), "{m:?} {a:?} cites {source}");
                    }
                    Approval::Unverified => {}
                }
            }
        }
    }

    #[test]
    fn four_x_is_available_and_unverified_everywhere() {
        for m in [M4S, M4D] {
            for a in Algorithm::all() {
                assert_eq!(
                    capability(m, a),
                    Capability {
                        available: true,
                        approval: Approval::Unverified
                    },
                    "{a:?}"
                );
            }
        }
    }

    #[test]
    fn three_x_lacks_ml_dsa_only() {
        for m in [M3S, M3D] {
            for a in Algorithm::all() {
                let ml_dsa = matches!(
                    a,
                    Algorithm::Signature(SignatureAlgorithm::MlDsa87)
                        | Algorithm::Scheme(TlsSignatureScheme::MlDsa87)
                );
                assert_eq!(capability(m, a).available, !ml_dsa, "{m:?} {a:?}");
            }
        }
    }

    #[test]
    fn three_x_approval_matches_table_5() {
        use Algorithm as A;
        let approved = |a| capability(M3S, a).approval.is_approved();
        assert!(approved(A::Signature(SignatureAlgorithm::Ed25519)));
        assert!(approved(A::Signature(SignatureAlgorithm::Rsa2048Sha384)));
        assert!(approved(A::Signature(SignatureAlgorithm::EcdsaP521Sha384)));
        assert!(approved(A::Kx(KxGroup::MlKem1024)));
        assert!(approved(A::Kx(KxGroup::Secp384r1)));
        assert!(approved(A::Cipher(CipherSuite::Tls13Aes128GcmSha256)));
        assert!(approved(A::Hash(HashAlgorithm::Sha512)));
        assert!(approved(A::Protocol(TlsVersion::Tls12)));
        for a in [
            A::Signature(SignatureAlgorithm::MlDsa87),
            A::Scheme(TlsSignatureScheme::MlDsa87),
            A::Kx(KxGroup::X25519),
            A::Cipher(CipherSuite::Tls13Chacha20Poly1305Sha256),
            A::Cipher(CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256),
        ] {
            assert!(
                matches!(capability(M3S, a).approval, Approval::NotApproved { .. }),
                "{a:?}"
            );
        }
        for a in [
            A::Kx(KxGroup::X25519MlKem768),
            A::Kx(KxGroup::Secp256r1MlKem768),
            A::Protocol(TlsVersion::Tls13),
        ] {
            assert_eq!(capability(M3S, a).approval, Approval::Unverified, "{a:?}");
        }
    }

    #[test]
    fn unverified_is_never_approved() {
        assert!(!Approval::Unverified.is_approved());
        assert!(!Approval::NotApproved { source: "x" }.is_approved());
        assert!(Approval::Approved { source: "x" }.is_approved());
    }

    #[test]
    fn ensure_available_refuses_ml_dsa_on_3x() {
        let a = Algorithm::Signature(SignatureAlgorithm::MlDsa87);
        assert_eq!(ensure_available(M3S, a), Err(CryptoError::Unavailable(a)));
        assert_eq!(ensure_available(M4S, a), Ok(()));
    }

    #[test]
    fn three_x_table_is_pinned_cell_by_cell() {
        use Algorithm as A;
        use SignatureAlgorithm as S;
        use TlsSignatureScheme as T;
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum K {
            Approved,
            NotApproved,
            Unverified,
        }
        use K::{Approved as Y, NotApproved as N, Unverified as U};
        let expected: [(Algorithm, bool, K); 40] = [
            (A::Signature(S::MlDsa87), false, N),
            (A::Signature(S::EcdsaP256Sha256), true, Y),
            (A::Signature(S::EcdsaP384Sha384), true, Y),
            (A::Signature(S::EcdsaP521Sha384), true, Y),
            (A::Signature(S::EcdsaP521Sha512), true, Y),
            (A::Signature(S::Ed25519), true, Y),
            (A::Signature(S::Rsa2048Sha384), true, Y),
            (A::Signature(S::Rsa3072Sha384), true, Y),
            (A::Signature(S::Rsa4096Sha384), true, Y),
            (A::Scheme(T::EcdsaNistp256Sha256), true, Y),
            (A::Scheme(T::EcdsaNistp384Sha384), true, Y),
            (A::Scheme(T::EcdsaNistp521Sha512), true, Y),
            (A::Scheme(T::Ed25519), true, Y),
            (A::Scheme(T::RsaPssSha256), true, Y),
            (A::Scheme(T::RsaPssSha384), true, Y),
            (A::Scheme(T::RsaPssSha512), true, Y),
            (A::Scheme(T::RsaPkcs1Sha256), true, Y),
            (A::Scheme(T::RsaPkcs1Sha384), true, Y),
            (A::Scheme(T::RsaPkcs1Sha512), true, Y),
            (A::Scheme(T::MlDsa87), false, N),
            (A::Kx(KxGroup::MlKem1024), true, Y),
            (A::Kx(KxGroup::X25519MlKem768), true, U),
            (A::Kx(KxGroup::Secp256r1MlKem768), true, U),
            (A::Kx(KxGroup::Secp384r1), true, Y),
            (A::Kx(KxGroup::Secp256r1), true, Y),
            (A::Kx(KxGroup::X25519), true, N),
            (A::Cipher(CipherSuite::Tls13Aes256GcmSha384), true, Y),
            (A::Cipher(CipherSuite::Tls13Aes128GcmSha256), true, Y),
            (A::Cipher(CipherSuite::Tls13Chacha20Poly1305Sha256), true, N),
            (
                A::Cipher(CipherSuite::Tls12EcdheEcdsaAes256GcmSha384),
                true,
                Y,
            ),
            (
                A::Cipher(CipherSuite::Tls12EcdheEcdsaAes128GcmSha256),
                true,
                Y,
            ),
            (
                A::Cipher(CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256),
                true,
                N,
            ),
            (
                A::Cipher(CipherSuite::Tls12EcdheRsaAes256GcmSha384),
                true,
                Y,
            ),
            (
                A::Cipher(CipherSuite::Tls12EcdheRsaAes128GcmSha256),
                true,
                Y,
            ),
            (
                A::Cipher(CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256),
                true,
                N,
            ),
            (A::Hash(HashAlgorithm::Sha256), true, Y),
            (A::Hash(HashAlgorithm::Sha384), true, Y),
            (A::Hash(HashAlgorithm::Sha512), true, Y),
            (A::Protocol(TlsVersion::Tls12), true, Y),
            (A::Protocol(TlsVersion::Tls13), true, U),
        ];
        assert_eq!(expected.len(), Algorithm::all().len());
        for m in [M3S, M3D] {
            for (a, available, kind) in &expected {
                let c = capability(m, *a);
                let got = match c.approval {
                    Approval::Approved { .. } => K::Approved,
                    Approval::NotApproved { .. } => K::NotApproved,
                    Approval::Unverified => K::Unverified,
                };
                assert_eq!((c.available, got), (*available, *kind), "{m:?} {a:?}");
            }
        }
    }
}
