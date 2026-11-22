//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg, and the
//! module's library name, as `CRYPTO_PROFILE_FIPS_LIBRARY`.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_static)");
    let libs = aws_lc_rs_metadata(std::env::vars_os(), "_SYS_LIBCRYPTO");
    let lib = "aws_lc_fips_0_13_17_crypto";
    if let Err(e) = bundled(&libs, lib) {
        panic!("crypto-profile-awslc3: {e}");
    }
    // Cargo passes a `links` crate's metadata only to its direct dependents.
    let direct = std::env::var("DEP_AWS_LC_FIPS_0_13_17_LIBCRYPTO").ok();
    if let Err(e) = pinned(direct.as_deref(), lib) {
        panic!("crypto-profile-awslc3: {e}");
    }
    let required = |name| std::env::var(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let target = required("TARGET").to_lowercase().replace('-', "_");
    // Both lookups mirror aws-lc-fips-sys 0.13.17 builder/main.rs:183-204,253-300; the defaults
    // are :793 (NO_PREFIX) and :809 (STATIC).
    let no_prefix = format!("AWS_LC_FIPS_SYS_NO_PREFIX_{target}");
    println!("cargo:rerun-if-env-changed={no_prefix}");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_NO_PREFIX");
    if let Err(e) = prefixed(
        std::env::var(&no_prefix).ok().as_deref(),
        std::env::var("AWS_LC_FIPS_SYS_NO_PREFIX").ok().as_deref(),
    ) {
        panic!("crypto-profile-awslc3: {e}");
    }
    let scoped = format!("AWS_LC_FIPS_SYS_STATIC_{target}");
    println!("cargo:rerun-if-env-changed={scoped}");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC");
    let value = std::env::var(&scoped)
        .or_else(|_| std::env::var("AWS_LC_FIPS_SYS_STATIC"))
        .ok();
    let explicit = value.as_deref().and_then(parse_bool);
    let os = required("CARGO_CFG_TARGET_OS");
    let arch = required("CARGO_CFG_TARGET_ARCH");
    if explicit.unwrap_or(
        (os == "linux" || os.ends_with("bsd")) && (arch == "x86_64" || arch == "aarch64"),
    ) {
        println!("cargo:rustc-cfg=crypto_profile_static");
    }
    println!("cargo::rustc-env=CRYPTO_PROFILE_FIPS_LIBRARY={lib}");
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
            "the linked FIPS module is not the bundled aws-lc-fips-sys source build: expected {want}, aws-lc-rs reported {other:?}; on a host with a system AWS-LC set AWS_LC_FIPS_SYS_USE_SYSTEM=0"
        )),
    }
}

fn pinned(direct: Option<&str>, want: &str) -> Result<(), String> {
    match direct {
        Some(lib) if lib == want => Ok(()),
        other => Err(format!(
            "aws-lc-fips-sys must be a direct dependency pinned to the release whose library is {want}; its link metadata reported {other:?} (#54, decision 0017)"
        )),
    }
}

fn prefixed(scoped: Option<&str>, plain: Option<&str>) -> Result<(), String> {
    match scoped.or(plain).and_then(parse_bool) {
        Some(true) => Err(
            "the bundled module was built without its symbol prefix, so its names can collide with another libcrypto in the process, and 0.13.17 still reports the prefixed name; unset AWS_LC_FIPS_SYS_NO_PREFIX (#83)".to_string(),
        ),
        Some(false) | None => Ok(()),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    let value = value.to_lowercase();
    if value.starts_with('0')
        || value.starts_with('n')
        || value.starts_with("off")
        || value.starts_with('f')
    {
        Some(false)
    } else if value.starts_with(|c: char| c.is_ascii_digit())
        || value.starts_with('y')
        || value.starts_with("on")
        || value.starts_with('t')
    {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{aws_lc_rs_metadata, bundled, pinned, prefixed};

    const WANT: &str = "aws_lc_fips_0_13_17_crypto";

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
        assert!(e.contains("AWS_LC_FIPS_SYS_USE_SYSTEM=0"), "{e}");
    }

    #[test]
    fn missing_or_ambiguous_metadata_is_refused() {
        assert!(bundled(&[], WANT).is_err());
        assert!(bundled(&[WANT.to_string(), WANT.to_string()], WANT).is_err());
    }

    #[test]
    fn another_version_is_refused() {
        assert!(bundled(&["aws_lc_fips_0_13_18_crypto".to_string()], WANT).is_err());
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
        assert!(pinned(Some("aws_lc_fips_0_13_18_crypto"), WANT).is_err());
    }

    #[test]
    fn an_unprefixed_build_is_refused() {
        for v in ["1", "true", "yes", "on", "TRUE"] {
            let Err(e) = prefixed(Some(v), None) else {
                panic!("{v}: an unprefixed build was accepted");
            };
            assert!(e.contains("AWS_LC_FIPS_SYS_NO_PREFIX"), "{e}");
            assert!(prefixed(None, Some(v)).is_err(), "{v}");
        }
    }

    #[test]
    fn a_prefixed_build_is_accepted() {
        assert_eq!(prefixed(None, None), Ok(()));
        for v in ["0", "false", "no", "off", "", "maybe"] {
            assert_eq!(prefixed(Some(v), None), Ok(()), "{v}");
            assert_eq!(prefixed(None, Some(v)), Ok(()), "{v}");
        }
    }

    #[test]
    fn the_target_scoped_variable_wins() {
        assert_eq!(prefixed(Some("0"), Some("1")), Ok(()));
        assert!(prefixed(Some("1"), Some("0")).is_err());
        assert_eq!(prefixed(Some("maybe"), Some("1")), Ok(()));
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
