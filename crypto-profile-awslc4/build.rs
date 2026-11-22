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
        aws_lc_rs_metadata(std::env::vars_os(), suffix)
            .into_iter()
            .next()
    };
    let kind = dep("_SYS_LINK_KIND");
    match kind.as_deref() {
        Some("static") => println!("cargo:rustc-cfg=crypto_profile_static"),
        Some("dylib") => {}
        other => panic!(
            "crypto-profile-awslc4: aws-lc-rs did not report how the FIPS module is linked ({other:?}); refusing to guess"
        ),
    }
    let libs = aws_lc_rs_metadata(std::env::vars_os(), "_SYS_LIBCRYPTO");
    const WANT: &str = "aws_lc_fips_0_14_4_crypto";
    if let Err(e) = bundled(&libs, WANT) {
        panic!("crypto-profile-awslc4: {e}");
    }
    // Cargo passes a `links` crate's metadata only to its direct dependents.
    let direct = std::env::var("DEP_AWS_LC_FIPS_0_14_4_LIBCRYPTO").ok();
    if let Err(e) = pinned(direct.as_deref(), WANT) {
        panic!("crypto-profile-awslc4: {e}");
    }
    println!("cargo::rustc-env=CRYPTO_PROFILE_FIPS_LIBRARY={WANT}");
}

fn pinned(direct: Option<&str>, want: &str) -> Result<(), String> {
    match direct {
        Some(lib) if lib == want => Ok(()),
        other => Err(format!(
            "aws-lc-fips-sys must be a direct dependency pinned to the release whose library is {want}; its link metadata reported {other:?} (#54, decision 0017)"
        )),
    }
}

fn aws_lc_rs_metadata(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    suffix: &str,
) -> Vec<String> {
    vars.filter_map(|(k, v)| {
        let k = k.to_str()?;
        (k.starts_with("DEP_AWS_LC_RS_") && k.ends_with(suffix))
            .then(|| v.to_string_lossy().into_owned())
    })
    .collect()
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
    use super::{aws_lc_rs_metadata, bundled, pinned};

    const WANT: &str = "aws_lc_fips_0_14_4_crypto";

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
        assert!(bundled(&["aws_lc_fips_0_14_5_crypto".to_string()], WANT).is_err());
    }

    #[test]
    fn the_direct_pin_is_accepted() {
        assert_eq!(pinned(Some(WANT), WANT), Ok(()));
    }

    #[test]
    fn a_missing_direct_pin_is_refused() {
        let Err(e) = pinned(None, WANT) else {
            panic!("a build without the direct aws-lc-fips-sys dependency was accepted");
        };
        assert!(e.contains("direct dependency") && e.contains(WANT), "{e}");
    }

    #[test]
    fn another_pinned_version_is_refused() {
        assert!(pinned(Some("aws_lc_fips_0_14_2_crypto"), WANT).is_err());
        assert!(pinned(Some("aws_lc_fips_0_14_5_crypto"), WANT).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_variables_are_skipped_or_fail_closed() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let vars = vec![
            (OsString::from_vec(vec![0xff]), OsString::from("x")),
            (OsString::from("UNRELATED"), OsString::from_vec(vec![0xff])),
            (
                OsString::from("DEP_AWS_LC_RS_0_0_0_SYS_LIBCRYPTO"),
                OsString::from_vec([WANT.as_bytes(), &[0xff]].concat()),
            ),
        ];
        let libs = aws_lc_rs_metadata(vars.into_iter(), "_SYS_LIBCRYPTO");
        assert_eq!(libs.len(), 1);
        assert!(bundled(&libs, WANT).is_err());
    }
}
