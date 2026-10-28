//! Algorithm types, the per-module capability model and the conformance suite shared by every
//! `crypto-profile` backend. This crate performs no cryptography.
#![deny(missing_docs)]

pub mod algorithm;
mod error;

pub use algorithm::{
    Algorithm, CipherSuite, HashAlgorithm, KxGroup, ParseAlgorithmError, SignatureAlgorithm,
    TlsSignatureScheme, TlsVersion,
};
pub use error::{CryptoError, CsrError, Family, TlsError};

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
