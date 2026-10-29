//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg, and the
//! module's library name, as `CRYPTO_PROFILE_FIPS_LIBRARY`.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_static)");
    let dep = |suffix: &str| {
        let values: Vec<_> = std::env::vars()
            .filter(|(k, _)| k.starts_with("DEP_AWS_LC_RS_") && k.ends_with(suffix))
            .collect();
        assert_eq!(
            values.len(),
            1,
            "missing or ambiguous dependency metadata: {suffix}"
        );
        values[0].1.clone()
    };
    let lib = dep("_SYS_LIBCRYPTO");
    assert_eq!(
        lib, "aws_lc_fips_0_13_17_crypto",
        "unsupported sys metadata; linkage rule requires exactly aws-lc-fips-sys 0.13.17"
    );
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
