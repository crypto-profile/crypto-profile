use rustls::SignatureScheme;
use rustls::pki_types::{PrivatePkcs8KeyDer, SignatureVerificationAlgorithm};
use rustls::sign::SigningKey;
use std::sync::Arc;

pub(crate) static PQDSA_ALL: &[&dyn SignatureVerificationAlgorithm] = &[];
pub(crate) static PQDSA_MAPPING: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] = &[];
pub(crate) fn load_pqdsa(_: &PrivatePkcs8KeyDer<'_>) -> Option<Arc<dyn SigningKey>> {
    None
}
