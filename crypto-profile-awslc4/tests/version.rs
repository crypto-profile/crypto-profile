//! Exact linked release and independent certificate provenance.

use crypto_profile_awslc4::{Linkage, Module, ModuleLine, awslc_version, certificate};

#[test]
fn reports_the_linked_release() {
    assert_eq!(awslc_version(), aws_lc_rs::awslc_version());
    assert_eq!(awslc_version(), "4.2.0");
}

#[test]
fn certificate_release_is_independent_of_the_linked_release() {
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        let certificate = certificate(Module {
            line: ModuleLine::AwsLcFips3,
            linkage,
        });
        assert!(certificate.module_name.contains("3.1.0"));
        assert!(!certificate.module_name.contains(awslc_version()));
    }
}
