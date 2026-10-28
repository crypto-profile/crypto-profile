//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg, and the
//! module's library name, as `CRYPTO_PROFILE_FIPS_LIBRARY`.
fn main() {
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
    match dep("_SYS_LIBCRYPTO") {
        Some(name) => println!("cargo::rustc-env=CRYPTO_PROFILE_FIPS_LIBRARY={name}"),
        None => panic!(
            "crypto-profile-awslc4: aws-lc-rs did not report the FIPS module's library name; refusing to guess"
        ),
    }
}
