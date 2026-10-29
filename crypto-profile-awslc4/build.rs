//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg, and the
//! module's library name, as `CRYPTO_PROFILE_FIPS_LIBRARY`.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_provider_direct)");
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_static)");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC");
    if let Ok(target) = std::env::var("TARGET") {
        println!(
            "cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC_{}",
            target.replace('-', "_")
        );
    }
    let dep = |suffix: &str| {
        std::env::vars()
            .find(|(k, _)| k.starts_with("DEP_AWS_LC_RS_") && k.ends_with(suffix))
            .map(|(_, v)| v)
    };
    let kind = dep("_SYS_LINK_KIND");
    match kind.as_deref() {
        Some("static") => println!("cargo:rustc-cfg=crypto_profile_static"),
        Some("dylib") => {}
        other => panic!(
            "crypto-profile-awslc4: aws-lc-rs did not report how the FIPS module is linked ({other:?}); refusing to guess"
        ),
    }
    let libs: Vec<String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("DEP_AWS_LC_RS_") && k.ends_with("_SYS_LIBCRYPTO"))
        .map(|(_, v)| v)
        .collect();
    const WANT: &str = "aws_lc_fips_0_14_2_crypto";
    if let Err(e) = bundled(&libs, WANT) {
        panic!("crypto-profile-awslc4: {e}");
    }
    println!("cargo::rustc-env=CRYPTO_PROFILE_FIPS_LIBRARY={WANT}");
}

fn bundled(libs: &[String], want: &str) -> Result<(), String> {
    match libs {
        [lib] if lib == want => Ok(()),
        other => Err(format!(
            "the linked FIPS module is not the bundled aws-lc-fips-sys source build: expected {want}, aws-lc-rs reported {other:?}; unset AWS_LC_FIPS_SYS_NO_PREFIX, and on a host with a system AWS-LC set AWS_LC_FIPS_SYS_USE_SYSTEM=0"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::bundled;

    const WANT: &str = "aws_lc_fips_0_14_2_crypto";

    #[test]
    fn the_bundled_name_is_accepted() {
        assert_eq!(bundled(&[WANT.to_string()], WANT), Ok(()));
    }

    #[test]
    fn a_bare_name_is_refused() {
        let Err(e) = bundled(&["crypto".to_string()], WANT) else {
            panic!("a bare name was accepted");
        };
        assert!(e.contains("\"crypto\"") && e.contains(WANT), "{e}");
        assert!(
            e.contains("AWS_LC_FIPS_SYS_USE_SYSTEM=0") && e.contains("AWS_LC_FIPS_SYS_NO_PREFIX"),
            "{e}"
        );
    }

    #[test]
    fn missing_or_ambiguous_metadata_is_refused() {
        assert!(bundled(&[], WANT).is_err());
        assert!(bundled(&[WANT.to_string(), WANT.to_string()], WANT).is_err());
    }

    #[test]
    fn another_version_is_refused() {
        assert!(bundled(&["aws_lc_fips_0_14_3_crypto".to_string()], WANT).is_err());
    }
}
