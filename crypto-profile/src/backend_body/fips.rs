//! The FIPS checks: the module's own mode, and a TLS configuration's FIPS status.
use crate::CryptoError;

/// The pure decision behind [`assert_fips_module`].
pub fn fips_result(active: bool) -> Result<(), CryptoError> {
    if active {
        Ok(())
    } else {
        Err(CryptoError::NotFips)
    }
}

/// Refuses unless the loaded AWS-LC module reports FIPS mode.
pub fn assert_fips_module() -> Result<(), CryptoError> {
    fips_result(aws_lc_rs::try_fips_mode().is_ok())
}

/// Refuses a client configuration that rustls does not report as FIPS. A configuration that
/// admits X25519 or ChaCha20, or TLS 1.2 without Extended Master Secret, is not FIPS.
pub fn assert_fips_client_config(c: &rustls::ClientConfig) -> Result<(), CryptoError> {
    fips_result(c.fips())
}

/// Refuses a server configuration that rustls does not report as FIPS.
pub fn assert_fips_server_config(c: &rustls::ServerConfig) -> Result<(), CryptoError> {
    fips_result(c.fips())
}

/// The pure decision behind [`self_test`]: refuses before `runner` runs.
pub(crate) fn self_test_given(
    runner: Option<fn() -> Result<(), ()>>,
    fips_mode: impl FnOnce() -> bool,
) -> Result<(), CryptoError> {
    let Some(run) = runner else {
        return Err(CryptoError::SelfTestUnavailable);
    };
    if !fips_mode() {
        return Err(CryptoError::NotFips);
    }
    run().map_err(|()| CryptoError::SelfTest)
}

/// Re-runs the module's known-answer self-tests (CASTs) on demand.
///
/// Refuses with `CryptoError::SelfTestUnavailable` where the backend does not expose them (the
/// 3.x line), whether or not the module is in FIPS mode; otherwise with `CryptoError::NotFips`
/// unless it is. `Ok` means every CAST re-ran and passed in a FIPS-mode module. The module's
/// integrity test is not re-run.
///
/// By default a known-answer mismatch aborts the process before this returns.
/// `CryptoError::SelfTest` is a failure the module reported instead, such as an operation that
/// failed during a test, though some operation failures abort as well: treat the module as
/// failed. Call this at start-up or from an
/// operator action, never on a request path.
pub fn self_test() -> Result<(), CryptoError> {
    self_test_given(super::backend::self_test_runner(), || {
        aws_lc_rs::try_fips_mode().is_ok()
    })
}

/// The certificate of the module this build links.
pub fn certificate() -> crypto_profile::Certificate {
    crypto_profile::certificate(crate::MODULE)
}

/// The pure decision behind [`approval`]: an approval is void unless the module is in FIPS mode.
pub fn approval_given(fips_mode: bool, a: crypto_profile::Approval) -> crypto_profile::Approval {
    if fips_mode {
        a
    } else {
        crypto_profile::Approval::Unverified
    }
}

/// This build's module approval for `alg`, void (`Unverified`) unless the module reports FIPS
/// mode now. This is the capability cell, as its source states it: the module's security policy,
/// or, with none published, one CAVP certificate (decision 0004), which never approves.
/// [`assert_fips_client_config`] is the provider's FIPS-mode classification, which mirrors
/// rustls's and can differ (for example, the hybrid key-exchange groups classify as FIPS while
/// their approval here is `Unverified`).
pub fn approval(alg: crypto_profile::Algorithm) -> crypto_profile::Approval {
    approval_given(
        aws_lc_rs::try_fips_mode().is_ok(),
        crypto_profile::capability(crate::MODULE, alg).approval,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decision_has_both_branches() {
        assert_eq!(fips_result(true), Ok(()));
        assert_eq!(fips_result(false), Err(CryptoError::NotFips));
    }

    static RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn passes() -> Result<(), ()> {
        RAN.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn fails() -> Result<(), ()> {
        Err(())
    }

    fn never() -> Result<(), ()> {
        unreachable!("the self-test ran before its checks passed")
    }

    #[test]
    fn the_self_test_decision_refuses_before_it_runs() {
        assert_eq!(
            self_test_given(None, || unreachable!(
                "the FIPS mode was read for an unavailable test"
            )),
            Err(CryptoError::SelfTestUnavailable)
        );
        assert_eq!(
            self_test_given(Some(never), || false),
            Err(CryptoError::NotFips)
        );
        assert_eq!(
            self_test_given(Some(fails), || true),
            Err(CryptoError::SelfTest)
        );
        RAN.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(self_test_given(Some(passes), || true), Ok(()));
        assert!(RAN.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn the_self_test_matches_its_line() {
        match crate::MODULE.line {
            crypto_profile::ModuleLine::AwsLcFips4 => assert_eq!(self_test(), Ok(())),
            crypto_profile::ModuleLine::AwsLcFips3 => {
                assert_eq!(self_test(), Err(CryptoError::SelfTestUnavailable))
            }
            other => panic!("{other:?}: no expected self-test outcome"),
        }
    }

    #[test]
    fn the_fips_module_is_active_on_this_build() {
        assert_eq!(assert_fips_module(), Ok(()));
    }

    #[test]
    fn an_approval_is_void_outside_fips_mode() {
        let a = crypto_profile::Approval::Approved { source: "x" };
        assert_eq!(approval_given(true, a), a);
        assert_eq!(
            approval_given(false, a),
            crypto_profile::Approval::Unverified
        );
    }

    #[test]
    fn approval_on_this_build_is_the_capability_cell() {
        let a = crypto_profile::Algorithm::Hash(crypto_profile::HashAlgorithm::Sha256);
        assert_eq!(
            approval(a),
            crypto_profile::capability(crate::MODULE, a).approval
        );
    }

    #[test]
    fn the_module_certificate_matches_its_line() {
        if crate::MODULE.line == crypto_profile::ModuleLine::AwsLcFips3 {
            assert_eq!(certificate().status, crypto_profile::CertStatus::Validated);
            assert_eq!(
                certificate().number,
                Some(
                    if crate::MODULE.linkage == crypto_profile::Linkage::Static {
                        5314
                    } else {
                        5298
                    }
                )
            );
            assert!(certificate().module_name.contains("3.1.0"));
        } else {
            assert_eq!(crate::MODULE.line, crypto_profile::ModuleLine::AwsLcFips4);
            assert_eq!(certificate().status, crypto_profile::CertStatus::InProcess);
        }
    }
}
