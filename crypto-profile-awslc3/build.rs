//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg, and the
//! module's library name, as `CRYPTO_PROFILE_FIPS_LIBRARY`.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_static)");
    let libs: Vec<String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("DEP_AWS_LC_RS_") && k.ends_with("_SYS_LIBCRYPTO"))
        .map(|(_, v)| v)
        .collect();
    let lib = "aws_lc_fips_0_13_17_crypto";
    if let Err(e) = bundled(&libs, lib) {
        panic!("crypto-profile-awslc3: {e}");
    }
    let required = |name| std::env::var(name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let target = required("TARGET").to_lowercase().replace('-', "_");
    let scoped = format!("AWS_LC_FIPS_SYS_STATIC_{target}");
    println!("cargo:rerun-if-env-changed={scoped}");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC");
    let value = std::env::var(&scoped)
        .or_else(|_| std::env::var("AWS_LC_FIPS_SYS_STATIC"))
        .ok();
    // aws-lc-fips-sys 0.13.17 builder/main.rs:192-204,253-300,809 defines precedence,
    // boolean parsing and the FIPS platform default; refuse other versions above.
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

fn bundled(libs: &[String], want: &str) -> Result<(), String> {
    match libs {
        [lib] if lib == want => Ok(()),
        other => Err(format!(
            "the linked FIPS module is not the bundled aws-lc-fips-sys source build: expected {want}, aws-lc-rs reported {other:?}; unset AWS_LC_FIPS_SYS_NO_PREFIX, and on a host with a system AWS-LC set AWS_LC_FIPS_SYS_USE_SYSTEM=0"
        )),
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
    use super::bundled;

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
        assert!(bundled(&["aws_lc_fips_0_13_18_crypto".to_string()], WANT).is_err());
    }
}
