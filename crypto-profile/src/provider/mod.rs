//! The provider's source, compiled as a module by a backend built with `--cfg crypto_profile_provider_direct` (decision 0005).
pub(crate) mod assembly;
pub(crate) mod hash;
pub(crate) mod kx;
pub(crate) mod tls12;
pub(crate) mod tls13;
