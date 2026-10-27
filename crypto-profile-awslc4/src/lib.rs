//! The crypto-profile backend on the AWS-LC FIPS 4.x module (aws-lc-rs 1.18, `fips`).
//! `rustls` is re-exported because its types are this crate's API; `aws-lc-rs` is not.
#![deny(missing_docs)]

pub use crypto_profile::*;
#[cfg(feature = "test-support")]
pub use rcgen;
pub use rustls;

pub mod aead;
pub mod csr;
pub mod digest;
pub mod fips;
pub mod random;
pub mod sealbox;
pub mod signature;

/// The certified module this build links.
pub const MODULE: Module = Module {
    line: ModuleLine::AwsLcFips4,
    linkage: if cfg!(crypto_profile_static) {
        Linkage::Static
    } else {
        Linkage::Dynamic
    },
};

pub(crate) fn ensure(alg: Algorithm) -> Result<(), CryptoError> {
    ensure_available(MODULE, alg)
}
