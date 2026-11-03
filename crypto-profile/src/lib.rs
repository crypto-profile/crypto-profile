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
    AeadAlgorithm, Algorithm, CipherSuite, HashAlgorithm, KdfAlgorithm, KeyAgreementAlgorithm,
    KxGroup, MacAlgorithm, ParseAlgorithmError, SignatureAlgorithm, TlsSignatureScheme, TlsVersion,
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
/// The algorithm enums, `Algorithm` and `Profile` are `#[non_exhaustive]` (decision 0012), so a
/// new variant is not a breaking change. A `match` outside this crate needs a `_` arm:
///
/// ```
/// use crypto_profile::{Algorithm, MacAlgorithm};
/// fn outside_tls(a: Algorithm) -> Option<bool> {
///     match a {
///         Algorithm::Signature(_) | Algorithm::Scheme(_) | Algorithm::Kx(_) => Some(false),
///         Algorithm::Cipher(_) | Algorithm::Protocol(_) => Some(false),
///         Algorithm::Mac(_) | Algorithm::Kdf(_) | Algorithm::KeyAgreement(_) => Some(true),
///         Algorithm::Aead(_) | Algorithm::Hash(_) => Some(true),
///         _ => None,
///     }
/// }
/// assert_eq!(outside_tls(Algorithm::Mac(MacAlgorithm::HmacSha256)), Some(true));
/// ```
///
/// ```compile_fail,E0004
/// use crypto_profile::{Algorithm, MacAlgorithm};
/// fn outside_tls(a: Algorithm) -> Option<bool> {
///     match a {
///         Algorithm::Signature(_) | Algorithm::Scheme(_) | Algorithm::Kx(_) => Some(false),
///         Algorithm::Cipher(_) | Algorithm::Protocol(_) => Some(false),
///         Algorithm::Mac(_) | Algorithm::Kdf(_) | Algorithm::KeyAgreement(_) => Some(true),
///         Algorithm::Aead(_) | Algorithm::Hash(_) => Some(true),
///     }
/// }
/// assert_eq!(outside_tls(Algorithm::Mac(MacAlgorithm::HmacSha256)), Some(true));
/// ```
///
/// ```
/// use crypto_profile::Profile;
/// fn government(p: Profile) -> Option<bool> {
///     match p {
///         Profile::Unrestricted | Profile::Preferred => Some(false),
///         Profile::Cnsa2 | Profile::Cnsa1 | Profile::Bsi => Some(true),
///         Profile::Fips1403 | Profile::Fips1402 => Some(true),
///         _ => None,
///     }
/// }
/// assert_eq!(government(Profile::Bsi), Some(true));
/// ```
///
/// ```compile_fail,E0004
/// use crypto_profile::Profile;
/// fn government(p: Profile) -> Option<bool> {
///     match p {
///         Profile::Unrestricted | Profile::Preferred => Some(false),
///         Profile::Cnsa2 | Profile::Cnsa1 | Profile::Bsi => Some(true),
///         Profile::Fips1403 | Profile::Fips1402 => Some(true),
///     }
/// }
/// assert_eq!(government(Profile::Bsi), Some(true));
/// ```
///
/// ```
/// use crypto_profile::HashAlgorithm;
/// fn sha3(h: HashAlgorithm) -> Option<bool> {
///     match h {
///         HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => Some(false),
///         HashAlgorithm::Sha3_256 | HashAlgorithm::Sha3_384 | HashAlgorithm::Sha3_512 => Some(true),
///         _ => None,
///     }
/// }
/// assert_eq!(sha3(HashAlgorithm::Sha3_384), Some(true));
/// ```
///
/// ```compile_fail,E0004
/// use crypto_profile::HashAlgorithm;
/// fn sha3(h: HashAlgorithm) -> Option<bool> {
///     match h {
///         HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => Some(false),
///         HashAlgorithm::Sha3_256 | HashAlgorithm::Sha3_384 | HashAlgorithm::Sha3_512 => Some(true),
///     }
/// }
/// assert_eq!(sha3(HashAlgorithm::Sha3_384), Some(true));
/// ```
#[allow(dead_code)]
mod matches_outside_the_crate_need_a_wildcard {}
/// Every `ALL` is a `&'static [T]` (decision 0012), so a new variant changes its length, not its
/// type:
///
/// ```
/// use crypto_profile::{HashAlgorithm, Profile};
/// let all: &'static [Profile] = Profile::ALL;
/// assert!(all.contains(&Profile::Cnsa2));
/// let mut lens = Vec::new();
/// for &h in HashAlgorithm::ALL {
///     lens.push(h.output_len());
/// }
/// assert_eq!(lens, [32, 48, 64, 32, 48, 64]);
/// ```
#[allow(dead_code)]
mod every_all_is_a_slice {}
include!(concat!(env!("OUT_DIR"), "/provider.rs"));
include!(concat!(env!("OUT_DIR"), "/backend_body.rs"));
