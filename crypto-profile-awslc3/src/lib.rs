//! The crypto-profile backend on the AWS-LC FIPS 3.x module (aws-lc-rs 1.17, `fips`).
//! `rustls` is re-exported because its types are this crate's API; `aws-lc-rs` is not.
#![deny(missing_docs)]

pub use crypto_profile::*;
#[cfg(feature = "test-support")]
pub use rcgen;
pub use rustls;

crypto_profile::provider!(crate::provider_arms);
mod provider_arms;

crypto_profile::backend_body!(crate::backend_arms);
mod backend_arms;
#[cfg(any(test, feature = "test-support"))]
pub use backend_body::test_support;
pub use backend_body::{
    Admitted, Resolved, admit, assert_admitted_approved, assert_module_approves, resolve,
};
pub use backend_body::{aead, csr, digest, fips, hmac, random, sealbox, signature, tls};

/// The AWS-LC FIPS module (line and linkage) this build links. Its certificate status is
/// [`fips::certificate()`]; for 3.x the certified release is 3.1.0.
pub const MODULE: Module = Module {
    line: ModuleLine::AwsLcFips3,
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
mod tests {
    use super::*;

    #[test]
    fn ensure_refuses_unavailable_keys_and_schemes() {
        for algorithm in [
            Algorithm::Signature(SignatureAlgorithm::MlDsa87),
            Algorithm::Scheme(TlsSignatureScheme::MlDsa87),
        ] {
            assert_eq!(ensure(algorithm), Err(CryptoError::Unavailable(algorithm)));
        }
        assert_eq!(
            ensure(Algorithm::Signature(SignatureAlgorithm::EcdsaP384Sha384)),
            Ok(())
        );
    }
}
