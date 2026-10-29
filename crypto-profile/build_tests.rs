use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "source-emission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn write(&self, path: &str, text: &str) {
        std::fs::write(self.0.join(path), text).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn identifiers_reject_keywords_and_non_identifiers() {
    for name in ["_", "crate", "gen", "a-b", "1foo", "", "é"] {
        assert!(!is_ident(name), "{name}");
    }
    for name in ["_module", "a1", "signature"] {
        assert!(is_ident(name), "{name}");
    }
}

#[test]
fn body_index_enforces_visibility_purpose_and_cfg_pairing() {
    let fixture = Fixture::new();
    for index in [
        "pub(crate) mod signature;\n",
        "pub mod profiles;\n",
        "mod signature;\n",
        "pub mod test_support;\n",
        "#[cfg(any(test, feature = \"test-support\"))]\n",
        "#[cfg(any(test, feature = \"test-support\"))]\npub mod signature;\n",
        "//! First\n//! Second\n",
        "\u{00a0}\n",
        "mod backend {\n    pub(crate) use crate::backend_arms::*;\n}\n//! Late\n",
        "//!mod backend {\n    pub(crate) use crate::backend_arms::*;\n}\n",
    ] {
        fixture.write("mod.rs", index);
        assert!(
            std::panic::catch_unwind(|| modules(&fixture.0, true)).is_err(),
            "{index}"
        );
    }
}

#[test]
fn nested_emission_and_direct_resolution_agree() {
    let fixture = Fixture::new();
    fixture.write("mod.rs", "//! Body.\nmod backend {\n    pub(crate) use crate::backend_arms::*;\n}\npub mod sealbox;\nmod profiles;\n#[cfg(any(test, feature = \"test-support\"))]\npub mod test_support;\n");
    std::fs::create_dir(fixture.0.join("sealbox")).unwrap();
    fixture.write("sealbox.rs", "//! Ordinary production source.\nmod keys;\npub const VALUE: u8 = keys::VALUE + super::backend::VALUE;\n");
    fixture.write(
        "sealbox/keys.rs",
        "//! Nested source.\npub const VALUE: u8 = 3;\n",
    );
    fixture.write("profiles.rs", "");
    fixture.write("test_support.rs", "#[cfg(not(feature = \"test-support\"))]\ncompile_error!(\"test support must be conditional\");\npub const VALUE: u8 = 9;\n");
    let emitted = Fixture::new();
    let output = &emitted.0;
    emit(&fixture.0, "backend_body", true, &output);
    let generated = read(&output.join("backend_body.rs"));
    assert!(generated.contains("mod keys {\n//! Nested source."));
    assert!(!generated.lines().any(|line| line == "mod keys;"));
    for (mode, declaration) in [
        (
            "macro",
            format!(
                "include!({:?}); backend_body!(crate::backend_arms);",
                output.join("backend_body.rs")
            ),
        ),
        (
            "direct",
            format!("#[path = {:?}] mod backend_body;", fixture.0.join("mod.rs")),
        ),
    ] {
        for enabled in [false, true] {
            let source = output.join(format!("{mode}-{enabled}.rs"));
            std::fs::write(&source, format!("mod backend_arms {{ pub const VALUE: u8 = 4; }}\n{declaration}\nfn main() {{ assert_eq!(backend_body::sealbox::VALUE, 7); #[cfg(feature = \"test-support\")] assert_eq!(backend_body::test_support::VALUE, 9); }}")).unwrap();
            let binary = output.join(format!("{mode}-{enabled}"));
            let mut compiler = std::process::Command::new("rustc");
            if enabled {
                compiler.args(["--cfg", "feature=\"test-support\""]);
            }
            assert!(
                compiler
                    .args(["--edition", "2024"])
                    .arg(&source)
                    .arg("-o")
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                std::process::Command::new(binary)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}

#[test]
fn provider_bridge_name_cannot_be_redeclared() {
    let fixture = Fixture::new();
    fixture.write(
        "mod.rs",
        "mod backend {\n    pub(crate) use crate::provider_arms::*;\n}\npub(crate) mod backend;\n",
    );
    fixture.write("backend.rs", "");
    let error = std::panic::catch_unwind(|| modules(&fixture.0, false)).unwrap_err();
    assert!(
        error
            .downcast_ref::<String>()
            .unwrap()
            .contains("duplicate module: backend")
    );
}

#[test]
fn cfg_cannot_cross_the_backend_bridge() {
    let fixture = Fixture::new();
    fixture.write("mod.rs", "#[cfg(any(test, feature = \"test-support\"))]\nmod backend {\n    pub(crate) use crate::backend_arms::*;\n}\npub mod test_support;\n");
    fixture.write("test_support.rs", "");
    assert!(std::panic::catch_unwind(|| modules(&fixture.0, true)).is_err());
}

#[test]
fn child_declaration_text_in_strings_is_refused() {
    let fixture = Fixture::new();
    fixture.write("mod.rs", "pub mod sealbox;\n");
    std::fs::create_dir(fixture.0.join("sealbox")).unwrap();
    fixture.write("sealbox/keys.rs", "");
    for source in [
        "//mod keys;\nmod keys;\n",
        "/*\nmod keys;\n*/\n",
        "const TEXT: &str = r#\"mod keys;\"#;\nmod keys;\n",
        "const TEXT: &str = r#\"\nmod keys;\n\"#;\n",
        "const TEXT: &str = \"\nmod keys;\n\";\n",
        "\u{00a0}\nmod keys;\n",
    ] {
        fixture.write("sealbox.rs", source);
        assert!(
            std::panic::catch_unwind(|| modules(&fixture.0, true)).is_err(),
            "{source}"
        );
    }
}
