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
/// [`assert_fips_client_config`] is rustls's FIPS-mode classification, which can differ (for
/// example, rustls treats the hybrid key-exchange groups as FIPS while their approval here is
/// `Unverified`).
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
    fn the_module_is_4x_and_its_certificate_is_in_review() {
        assert_eq!(crate::MODULE.line, crypto_profile::ModuleLine::AwsLcFips4);
        assert_eq!(certificate().status, crypto_profile::CertStatus::InProcess);
    }
}
