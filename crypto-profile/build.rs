//! Emits backend source macros from validated source indices (decision 0005).
use std::collections::BTreeSet;
use std::path::Path;

fn fail(path: &Path, message: &str) -> ! {
    panic!("crypto-profile: {}: {message}", path.display())
}

fn is_ident(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && ![
            "_", "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else",
            "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match",
            "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct",
            "super", "trait", "true", "type", "unsafe", "use", "where", "while", "abstract",
            "become", "box", "do", "final", "gen", "macro", "override", "priv", "try", "typeof",
            "unsized", "virtual", "yield",
        ]
        .contains(&name)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(path, &format!("cannot read: {e}")))
}

fn is_ascii_blank(line: &str) -> bool {
    line.trim_matches([' ', '\t']).is_empty()
}

fn check_directory(dir: &Path, expected: &BTreeSet<String>, index: &Path) {
    let actual: BTreeSet<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| fail(dir, &format!("cannot list: {e}")))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| fail(dir, &format!("cannot list: {e}")))
                .file_name()
                .into_string()
                .unwrap_or_else(|name| fail(dir, &format!("invalid filename: {name:?}")))
        })
        .collect();
    if &actual != expected {
        fail(
            index,
            &format!(
                "directory mismatch at {}: listed {expected:?}, found {actual:?}",
                dir.display()
            ),
        );
    }
}

fn has_exact_child(source: &str) -> bool {
    const DECLARATION: &str = "mod keys;";
    if source
        .lines()
        .any(|line| line.chars().any(|c| !c.is_ascii() && c.is_whitespace()))
    {
        return false;
    }
    if source.matches(DECLARATION).count() != 1 {
        return false;
    }
    let bytes = source.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if !source.is_char_boundary(offset) {
            offset += 1;
            continue;
        }
        let rest = &source[offset..];
        if rest.starts_with(DECLARATION) {
            return (offset == 0 || bytes[offset - 1] == b'\n')
                && matches!(bytes.get(offset + DECLARATION.len()), None | Some(b'\n'));
        }
        if rest.starts_with("//") {
            offset += rest.find('\n').unwrap_or(rest.len());
        } else if rest.starts_with("/*") {
            let mut depth = 1;
            offset += 2;
            while offset < bytes.len() && depth > 0 {
                if bytes[offset..].starts_with(b"/*") {
                    depth += 1;
                    offset += 2;
                } else if bytes[offset..].starts_with(b"*/") {
                    depth -= 1;
                    offset += 2;
                } else {
                    offset += 1;
                }
            }
        } else if bytes[offset] == b'r' {
            let hashes = bytes[offset + 1..]
                .iter()
                .take_while(|&&b| b == b'#')
                .count();
            if bytes.get(offset + 1 + hashes) == Some(&b'"') {
                offset += 2 + hashes;
                let closing = format!("\"{}", "#".repeat(hashes));
                offset += source[offset..]
                    .find(&closing)
                    .map_or(bytes.len() - offset, |end| end + closing.len());
            } else {
                offset += 1;
            }
        } else if bytes[offset] == b'"' {
            offset += 1;
            while offset < bytes.len() {
                let byte = bytes[offset];
                offset += 1;
                if byte == b'\\' {
                    offset = (offset + 1).min(bytes.len());
                } else if byte == b'"' {
                    break;
                }
            }
        } else if bytes[offset] == b'\'' && bytes.get(offset + 2) == Some(&b'\'') {
            offset += 3;
        } else if bytes[offset..].starts_with(b"'\\") {
            offset += 2;
            while offset < bytes.len() && bytes[offset] != b'\'' {
                offset += 1;
            }
            offset = (offset + 1).min(bytes.len());
        } else {
            offset += 1;
        }
    }
    false
}

fn modules(dir: &Path, body: bool) -> (String, bool) {
    let index = dir.join("mod.rs");
    let root = read(&index);
    let bridge = if body {
        "mod backend {\n    pub(crate) use crate::backend_arms::*;\n}\n"
    } else {
        "mod backend {\n    pub(crate) use crate::provider_arms::*;\n}\n"
    };
    let mut profile_exports = false;
    let mut has_bridge = false;
    let mut names = BTreeSet::new();
    let mut declarations = Vec::new();
    let mut first = true;
    let mut test_support = false;
    let mut lines = root.lines();
    while let Some(line) = lines.next() {
        if test_support && line != "pub mod test_support;" {
            fail(&index, "invalid index line: unpaired test_support cfg");
        }
        if is_ascii_blank(line) {
            continue;
        }
        if first && line.starts_with("//!") {
            first = false;
            continue;
        }
        first = false;
        if body
            && !test_support
            && !profile_exports
            && line == "pub use profiles::{Resolved, assert_module_approves, resolve};"
        {
            profile_exports = true;
            continue;
        }
        if line == "mod backend {" && !has_bridge {
            for expected in bridge.lines().skip(1) {
                if lines.next() != Some(expected) {
                    fail(&index, "invalid index line: expected exact backend bridge");
                }
            }
            has_bridge = true;
            continue;
        }
        if body && line == "#[cfg(any(test, feature = \"test-support\"))]" && !test_support {
            test_support = true;
            continue;
        }
        let (visibility, name) = if body {
            if line == "mod profiles;" && !test_support {
                ("", "profiles")
            } else if let Some(name) = line
                .strip_prefix("pub mod ")
                .and_then(|s| s.strip_suffix(';'))
            {
                if ![
                    "signature",
                    "peer_certificates",
                    "csr",
                    "aead",
                    "digest",
                    "random",
                    "fips",
                    "tls",
                    "sealbox",
                    "test_support",
                ]
                .contains(&name)
                    || (name == "test_support") != test_support
                {
                    fail(&index, &format!("invalid index line: {line:?}"));
                }
                ("pub ", name)
            } else {
                fail(&index, &format!("invalid index line: {line:?}"));
            }
        } else if let Some(name) = line
            .strip_prefix("pub(crate) mod ")
            .and_then(|s| s.strip_suffix(';'))
        {
            ("pub(crate) ", name)
        } else {
            fail(&index, &format!("invalid index line: {line:?}"));
        };
        if !is_ident(name) {
            fail(&index, &format!("invalid identifier: {name:?}"));
        }
        if name == "backend" || !names.insert(name.to_string()) {
            fail(&index, &format!("duplicate module: {name}"));
        }
        declarations.push((name, visibility, test_support));
        test_support = false;
    }
    if test_support {
        fail(&index, "invalid index line: unpaired test_support cfg");
    }
    if !body && !has_bridge {
        fail(&index, "missing exact backend bridge");
    }
    let mut expected = BTreeSet::from(["mod.rs".to_string()]);
    expected.extend(names.iter().map(|name| format!("{name}.rs")));
    if body && names.contains("sealbox") {
        expected.insert("sealbox".to_string());
    }
    check_directory(dir, &expected, &index);
    let mut output = String::new();
    for (name, visibility, conditional) in declarations {
        let path = dir.join(format!("{name}.rs"));
        let mut source = read(&path);
        if body && name == "sealbox" {
            let child = dir.join("sealbox");
            check_directory(&child, &BTreeSet::from(["keys.rs".to_string()]), &path);
            if !has_exact_child(&source) {
                fail(&path, "expected exactly one `mod keys;` child declaration");
            }
            let keys = read(&child.join("keys.rs"));
            source = source
                .lines()
                .map(|line| {
                    if line == "mod keys;" {
                        format!("mod keys {{\n{keys}\n}}\n")
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect();
        }
        if conditional {
            output.push_str("#[cfg(any(test, feature = \"test-support\"))]\n");
        }
        output.push_str(&format!("{visibility}mod {name} {{\n{source}\n}}\n"));
    }
    if profile_exports {
        if !names.contains("profiles") {
            fail(&index, "profile exports require profiles module");
        }
        output.push_str("pub use profiles::{Resolved, assert_module_approves, resolve};\n");
    }
    (output, has_bridge)
}

fn emit(dir: &Path, name: &str, body: bool, out: &Path) {
    println!("cargo::rerun-if-changed={}", dir.display());
    let (modules, bridge) = modules(dir, body);
    let (argument, import) = if bridge {
        (
            "$($arms:ident)::+",
            "mod backend { pub(crate) use $($arms)::+::*; }",
        )
    } else {
        ("", "")
    };
    let lint = if body && modules.is_empty() && !bridge {
        ""
    } else {
        "#[expect(clippy::crate_in_macro_def)]\n"
    };
    let text = format!(
        "/// Emits backend source against the invoking backend's dependencies (decision 0005).\n\
         #[doc(hidden)]\n\
         #[macro_export]\n\
         {lint}\
         macro_rules! {name} {{\n    ({argument}) => {{\n        mod {name} {{\n{import}\n{modules}\n        }}\n    }};\n}}\n"
    );
    std::fs::write(out.join(format!("{name}.rs")), text)
        .unwrap_or_else(|e| fail(out, &format!("cannot write {name} macro: {e}")));
}

fn main() {
    let out = std::env::var("OUT_DIR").unwrap_or_else(|e| panic!("crypto-profile: OUT_DIR: {e}"));
    let out = Path::new(&out);
    emit(Path::new("src/provider"), "provider", false, out);
    emit(Path::new("src/backend_body"), "backend_body", true, out);
}

#[cfg(test)]
#[path = "build_tests.rs"]
mod tests;
