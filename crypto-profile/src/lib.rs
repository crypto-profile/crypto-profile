//! Algorithm types, the per-module capability model, the named profiles and the conformance suite
//! shared by every `crypto-profile` backend. This crate performs no cryptography.
#![deny(missing_docs)]

pub mod algorithm;
mod error;
pub mod peer_certificate;
pub use peer_certificate::{
    CertificateSignature, MlDsaParameterSet, PeerCertificateRule, PeerCertificateRuleId,
    PeerCertificateViolation, PeerCurve, PeerKey, PeerKeyRule, RsaSizeRule, peer_certificate_rule,
};

pub use algorithm::{
    Algorithm, CipherSuite, HashAlgorithm, KxGroup, ParseAlgorithmError, SignatureAlgorithm,
    TlsSignatureScheme, TlsVersion,
};
pub use error::{CryptoError, CsrError, Family, PeerVerifierIdentity, TlsError};

pub mod capability;
pub use capability::{
    Approval, Capability, CertStatus, Certificate, Linkage, Module, ModuleLine, capability,
    certificate, ensure_available,
};
pub mod profile;
pub use profile::{GoverningText, Options, ParseProfileError, Profile, ProfileSpec};
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod sealbox_wire;
#[doc(hidden)]
pub mod __test_data {
    pub const RSA8192_PKCS8: &[u8] = include_bytes!("../testdata/rsa8192.pkcs8.der");
}
include!(concat!(env!("OUT_DIR"), "/provider.rs"));
include!(concat!(env!("OUT_DIR"), "/backend_body.rs"));
