//! Emits the `provider!` macro from the provider's source files (decision 0005).
fn main() {
    println!("cargo::rerun-if-changed=src/provider");
    let root = std::fs::read_to_string("src/provider/mod.rs")
        .unwrap_or_else(|e| panic!("crypto-profile: cannot read src/provider/mod.rs: {e}"));
    let is_ident = |s: &str| {
        s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let backend = "mod backend {\n    pub(crate) use crate::provider_arms::*;\n}\n";
    let root = match root.split_once(backend) {
        Some((before, after)) => format!("{before}{after}"),
        None => panic!("crypto-profile: src/provider/mod.rs must hold {backend:?}"),
    };
    let mut names: Vec<&str> = Vec::new();
    let mut seen_purpose = false;
    for line in root.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with("//!") && !seen_purpose {
            seen_purpose = true;
            continue;
        }
        match line
            .strip_prefix("pub(crate) mod ")
            .and_then(|l| l.strip_suffix(';'))
        {
            Some(name) if is_ident(name) => names.push(name),
            _ => panic!(
                "crypto-profile: src/provider/mod.rs may hold only blank lines, one `//!` line, the `backend` module and `pub(crate) mod <name>;` lines, not {line:?}"
            ),
        }
    }
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
         /// `arms` names the backend module holding the backend-only items (decision 0005).\n\
         #[doc(hidden)]\n\
         #[macro_export]\n\
         #[expect(clippy::crate_in_macro_def)]\n\
         macro_rules! provider {{\n    ($($arms:ident)::+) => {{\n        mod provider {{\n            mod backend {{\n                pub(crate) use $($arms)::+::*;\n            }}\n{modules}        }}\n    }};\n}}\n"
    );
    std::fs::write(std::path::Path::new(&out).join("provider.rs"), text)
        .unwrap_or_else(|e| panic!("crypto-profile: cannot write the provider macro: {e}"));
}
