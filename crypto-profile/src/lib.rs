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
    Algorithm, CipherSuite, HashAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm, KxGroup,
    MacAlgorithm, ParseAlgorithmError, SignatureAlgorithm, TlsSignatureScheme, TlsVersion,
};
pub use error::{CryptoError, CsrError, Family, PeerVerifierIdentity, TlsError};

pub mod capability;
pub use capability::{
    Approval, Capability, CertStatus, Certificate, Linkage, Module, ModuleLine, capability,
    certificate, ensure_available,
};
pub mod profile;
pub use profile::{
    AdmittedSelection, GoverningText, MAC_KEY_MAX_BITS, Options, ParseProfileError, Profile,
    ProfileSpec, kdf_info_may_be_empty, mac_key_floor_bits, select_admitted,
};
#[cfg(feature = "conformance")]
pub mod conformance;
pub mod sealbox_wire;
#[doc(hidden)]
pub mod __test_data {
    pub const RSA8192_PKCS8: &[u8] = include_bytes!("../testdata/rsa8192.pkcs8.der");
}
/// `Options`, `ProfileSpec`, `Selection` and `AdmittedSelection` are `#[non_exhaustive]`
/// (decision 0012), so a new field is not a breaking change. Outside this crate `Options` is built
/// from its default:
///
/// ```
/// use crypto_profile::Options;
/// let mut o = Options::default();
/// o.pq_key_exchange_required = true;
/// assert_eq!(o.to_string(), "post-quantum key exchange required");
/// ```
///
/// ```compile_fail,E0639
/// use crypto_profile::Options;
/// let mut o = Options { ..Options::default() };
/// o.pq_key_exchange_required = true;
/// assert_eq!(o.to_string(), "post-quantum key exchange required");
/// ```
#[allow(dead_code)]
mod options_are_built_from_their_default {}
include!(concat!(env!("OUT_DIR"), "/provider.rs"));
include!(concat!(env!("OUT_DIR"), "/backend_body.rs"));
