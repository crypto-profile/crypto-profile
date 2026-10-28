//! Reports how aws-lc-rs linked the FIPS module, as the `crypto_profile_static` cfg.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crypto_profile_static)");
    println!("cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC");
    if let Ok(target) = std::env::var("TARGET") {
        println!(
            "cargo:rerun-if-env-changed=AWS_LC_FIPS_SYS_STATIC_{}",
            target.replace('-', "_")
        );
    }
    let kind = std::env::vars()
        .find(|(k, _)| k.starts_with("DEP_AWS_LC_RS_") && k.ends_with("_SYS_LINK_KIND"))
        .map(|(_, v)| v);
    match kind.as_deref() {
        Some("static") => println!("cargo:rustc-cfg=crypto_profile_static"),
        Some("dylib") => {}
        other => panic!(
            "crypto-profile-awslc4: aws-lc-rs did not report how the FIPS module is linked ({other:?}); refusing to guess"
        ),
    }
}
