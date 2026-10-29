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
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;

#[cfg(not(crypto_profile_provider_direct))]
crypto_profile::provider!(crate::provider_arms);
#[cfg(crypto_profile_provider_direct)]
#[path = "../../crypto-profile/src/provider/mod.rs"]
mod provider;
mod provider_arms;

#[cfg(not(crypto_profile_provider_direct))]
crypto_profile::backend_body!();
#[cfg(crypto_profile_provider_direct)]
#[path = "../../crypto-profile/src/backend_body/mod.rs"]
mod backend_body;

mod profiles;
pub use profiles::{Resolved, assert_module_approves, resolve};

/// The AWS-LC FIPS module (line and linkage) this build links. Its certificate status is
/// [`fips::certificate()`]; for 4.x the module is in CMVP review.
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
