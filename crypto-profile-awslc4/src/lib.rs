//! The crypto-profile backend on the AWS-LC FIPS 4.x module (aws-lc-rs 1.18, `fips`).
//! `rustls` is re-exported because its types are this crate's API; `aws-lc-rs` is not.
#![deny(missing_docs)]

pub use crypto_profile::*;
#[cfg(feature = "test-support")]
pub use rcgen;
pub use rustls;

#[cfg(not(crypto_profile_provider_direct))]
crypto_profile::provider!(crate::provider_arms);
#[cfg(crypto_profile_provider_direct)]
#[path = "../../crypto-profile/src/provider/mod.rs"]
mod provider;
mod provider_arms;

#[cfg(not(crypto_profile_provider_direct))]
crypto_profile::backend_body!(crate::backend_arms);
#[cfg(crypto_profile_provider_direct)]
#[path = "../../crypto-profile/src/backend_body/mod.rs"]
mod backend_body;

mod backend_arms;
#[cfg(any(test, feature = "test-support"))]
pub use backend_body::test_support;
pub use backend_body::{Resolved, assert_module_approves, resolve};
pub use backend_body::{aead, csr, digest, fips, random, sealbox, signature, tls};

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

/// Returns the exact runtime-linked AWS-LC release, independently of its certificate release.
///
/// This initializes the linked library and also reflects its version with dynamic linkage.
pub fn awslc_version() -> &'static str {
    aws_lc_rs::awslc_version()
}

pub(crate) fn ensure(alg: Algorithm) -> Result<(), CryptoError> {
    ensure_available(MODULE, alg)
}

#[cfg(test)]
mod shared_body_tests {
    #[test]
    fn shared_exports_and_facade_agree() {
        let key =
            crate::backend_body::signature::KeyPair::generate(crate::SignatureAlgorithm::MlDsa87)
                .unwrap();
        assert_eq!(
            crate::backend_arms::MlDsa::public_key(key.pkcs8_der()).unwrap(),
            key.public_key()
        );
        assert_eq!(
            crate::backend_arms::MlDsa::rcgen_alg().unwrap(),
            rcgen::PublicKeyData::algorithm(&key)
        );
    }
}
