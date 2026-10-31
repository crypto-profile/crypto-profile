//! Shared backend body source index.
mod backend {
    pub(crate) use crate::backend_arms::*;
}
pub mod aead;
pub mod csr;
pub mod digest;
pub mod fips;
pub mod hmac;
pub mod peer_certificates;
mod profiles;
pub mod random;
pub mod sealbox;
pub mod signature;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub use profiles::{Admitted, admit, assert_admitted_approved};
pub use profiles::{Resolved, assert_module_approves, resolve};
