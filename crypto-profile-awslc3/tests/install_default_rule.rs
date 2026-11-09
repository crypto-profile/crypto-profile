#![allow(missing_docs)]
use crypto_profile_awslc3::rustls;
use crypto_profile_awslc3::test_support::{drive_typed, pki};
use crypto_profile_awslc3::tls::{
    install_default, server_builder, server_cert_verifier_builder, strict_client_builder,
};
use crypto_profile_awslc3::{
    CryptoError, Options, PeerCertificateViolation, PeerKey, Profile, SignatureAlgorithm as S,
    TlsError, resolve,
};
use rustls::pki_types::PrivateKeyDer;
use std::sync::Arc;

fn rule_refusal(e: &rustls::Error) -> Option<TlsError> {
    let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        cause,
    ))) = e
    else {
        return None;
    };
    cause.downcast_ref::<TlsError>().copied()
}

#[test]
fn a_default_installed_from_a_rule_policy_refuses_what_the_rule_refuses() {
    let mut options = Options::default();
    options.peer_certificates_match_profile = true;
    let strict = resolve(Profile::Preferred, options).unwrap();
    let lax = resolve(Profile::Preferred, Options::default()).unwrap();
    // WebPKI accepts this chain; the `preferred` rule refuses an RSA leaf under 3072 bits.
    let p = pki(S::EcdsaP384Sha384, S::Rsa2048Sha384).unwrap();
    let key = PrivateKeyDer::Pkcs8(p.key.to_pkcs8_der().unwrap().to_vec().into());
    let server = server_builder(&lax.tls)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(p.chain.clone(), key)
        .unwrap();
    let roots = Arc::new(p.roots);
    let refused = Some(TlsError::PeerCertificate {
        profile: Profile::Preferred,
        violation: PeerCertificateViolation::LeafKey(PeerKey::Rsa(2048)),
    });

    let verifier = server_cert_verifier_builder(roots.clone(), &strict.tls)
        .unwrap()
        .build()
        .unwrap();
    let client = strict_client_builder(&strict.tls, verifier)
        .unwrap()
        .with_no_client_auth();
    let (_, e) = drive_typed(client, server.clone()).unwrap_err();
    assert_eq!(rule_refusal(&e), refused);

    match install_default(&strict.tls) {
        Err(CryptoError::Tls(TlsError::StrictBuilderRequired { .. })) => {}
        Ok(()) => {
            #[expect(clippy::disallowed_methods)]
            let client = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let (_, e) = drive_typed(client, server).expect_err(
                "a configuration built from the default accepted a leaf the rule refuses",
            );
            assert_eq!(rule_refusal(&e), refused);
        }
        Err(e) => panic!("install_default: {e:?}"),
    }
}
