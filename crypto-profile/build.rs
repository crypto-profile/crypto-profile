//! Emits the `provider!` macro from the provider's source files (decision 0005).
fn main() {
    println!("cargo::rerun-if-changed=src/provider");
    let root = std::fs::read_to_string("src/provider/mod.rs")
        .unwrap_or_else(|e| panic!("crypto-profile: cannot read src/provider/mod.rs: {e}"));
    let names: Vec<&str> = root
        .lines()
        .filter_map(|l| l.strip_prefix("pub(crate) mod ")?.strip_suffix(';'))
        .collect();
    let mut on_disk: Vec<String> = std::fs::read_dir("src/provider")
        .unwrap_or_else(|e| panic!("crypto-profile: cannot list src/provider: {e}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("crypto-profile: cannot list src/provider: {e}"))
                .file_name()
        })
        .filter_map(|n| n.to_str()?.strip_suffix(".rs").map(str::to_string))
        .filter(|n| n != "mod")
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    listed.sort();
    if listed != on_disk {
        panic!(
            "crypto-profile: src/provider/mod.rs lists {listed:?} but the directory holds {on_disk:?}"
        );
    }
    let mut modules = String::new();
    for name in &names {
        let path = format!("src/provider/{name}.rs");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("crypto-profile: cannot read {path}: {e}"));
        modules.push_str(&format!("pub(crate) mod {name} {{\n{source}\n}}\n"));
    }
    let out = std::env::var("OUT_DIR").unwrap_or_else(|e| panic!("crypto-profile: OUT_DIR: {e}"));
    let text = format!(
        "/// Emits this crate's rustls `CryptoProvider` as the module `provider` of the invoking\n\
         /// backend, which depends on `aws-lc-rs`, `rustls`, `zeroize` and `crypto-profile` under\n\
         /// those names (decision 0005).\n\
         #[doc(hidden)]\n\
         #[macro_export]\n\
         macro_rules! provider {{\n    () => {{\n        mod provider {{\n{modules}        }}\n    }};\n}}\n"
    );
    std::fs::write(std::path::Path::new(&out).join("provider.rs"), text)
        .unwrap_or_else(|e| panic!("crypto-profile: cannot write the provider macro: {e}"));
}
