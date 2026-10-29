#![allow(missing_docs)]
use crypto_profile_awslc4::rustls;
use crypto_profile_awslc4::tls::{Policy, assert_provider_matches, install_default};
use crypto_profile_awslc4::{
    CipherSuite, CryptoError, KxGroup, TlsError, TlsSignatureScheme, TlsVersion,
};

#[test]
fn installs_once_then_refuses() {
    let p = Policy {
        peer_certificate_rule: None,
        versions: vec![TlsVersion::Tls13],
        cipher_suites: vec![CipherSuite::Tls13Aes256GcmSha384],
        kx_groups: vec![KxGroup::Secp384r1],
        signature_schemes: vec![TlsSignatureScheme::EcdsaNistp384Sha384],
    };
    assert_eq!(install_default(&p), Ok(()));
    let installed = rustls::crypto::CryptoProvider::get_default().unwrap();
    assert_eq!(assert_provider_matches(installed, &p), Ok(()));
    assert_eq!(
        install_default(&p),
        Err(CryptoError::Tls(TlsError::DefaultProviderInstalled))
    );
}
