#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR="$work/target"
copy() {
  rm -rf "$work/src"
  mkdir -p "$work/src"
  (cd "$root" && git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' path; do if [ -f "$path" ]; then cp --parents "$path" "$work/src"; fi; done)
}
check() { (cd "$work/src" && cargo check -p crypto-profile --locked 2>&1); }
copy
out="$(check)" || { printf '%s\n' "$out"; echo "the unmodified copy does not build"; exit 1; }
expect_refusal() {
  local name="$1" want="$2"
  if out="$(check)"; then
    echo "$name: the build succeeded"; exit 1
  fi
  grep -qF "$want" <<<"$out" || { printf '%s\n' "$out"; echo "$name: the build failed for another reason"; exit 1; }
  echo "$name: refused"
}
for tree in backend_body provider; do
  mod="$work/src/crypto-profile/src/$tree/mod.rs"
  for case in inner outer item unicode-whitespace duplicate missing file directory; do
    copy
    case "$case" in
      inner) printf '#![allow(dead_code)]\n' >>"$mod"; want="invalid index line" ;;
      outer) printf '#[allow(dead_code)]\n' >>"$mod"; want="invalid index line" ;;
      item) printf 'fn arbitrary() {}\n' >>"$mod"; want="invalid index line" ;;
      unicode-whitespace) printf '\302\240\n' >>"$mod"; want="invalid index line" ;;
      duplicate)
        if [ "$tree" = provider ]; then decl='pub(crate) mod assembly;'; else
          decl='pub mod signature;'
        fi
        printf '%s\n%s\n' "$decl" "$decl" >>"$mod"; want="duplicate module" ;;
      missing)
        if [ "$tree" = provider ]; then printf 'pub(crate) mod missing;\n' >>"$mod"; else rm "$work/src/crypto-profile/src/$tree/signature.rs"; fi
        want="directory mismatch" ;;
      file) printf '\n' >"$work/src/crypto-profile/src/$tree/unlisted.rs"; want="directory mismatch" ;;
      directory) mkdir "$work/src/crypto-profile/src/$tree/unlisted"; want="directory mismatch" ;;
    esac
    expect_refusal "$tree: $case" "src/$tree/mod.rs: $want"
  done
done
for case in missing duplicate unlisted directory; do
  copy
  body="$work/src/crypto-profile/src/backend_body"
  case "$case" in
    missing) rm "$body/sealbox/keys.rs"; want="directory mismatch" ;;
    duplicate) printf 'mod keys;\n' >>"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    unlisted) touch "$body/sealbox/unlisted.rs"; want="directory mismatch" ;;
    directory) mkdir "$body/sealbox/unlisted"; want="directory mismatch" ;;
  esac
  expect_refusal "populated sealbox child: $case" "src/backend_body/sealbox.rs: $want"
done
copy
body="$work/src/crypto-profile/src/backend_body"
rm -rf "$body"
mkdir -p "$body"
cat >"$body/mod.rs" <<'INDEX'
//! Shared backend body.
mod backend {
    pub(crate) use crate::backend_arms::*;
}
pub mod sealbox;
mod profiles;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
INDEX
cp "$body/mod.rs" "$work/body-index"
cat >"$body/mod.rs" <<'INDEX'
#[cfg(any(test, feature = "test-support"))]
mod backend {
    pub(crate) use crate::backend_arms::*;
}
pub mod test_support;
INDEX
printf '\n' >"$body/test_support.rs"
expect_refusal "body cfg crossing bridge" "src/backend_body/mod.rs: invalid index line: unpaired test_support cfg"
cp "$work/body-index" "$body/mod.rs"
mkdir "$body/sealbox"
printf 'mod keys;\n' >"$body/sealbox.rs"
printf '\n' >"$body/sealbox/keys.rs"
printf '\n' >"$body/profiles.rs"
printf '\n' >"$body/test_support.rs"
out="$(check)" || { printf '%s\n' "$out"; echo "the populated body index does not build"; exit 1; }
echo "populated body index: accepted"
cp -R "$body" "$work/body-baseline"
for case in missing duplicate unlisted directory string raw-string multiline-string unicode-whitespace; do
  rm -rf "$body"
  cp -R "$work/body-baseline" "$body"
  case "$case" in
    missing) rm "$body/sealbox/keys.rs"; want="directory mismatch" ;;
    duplicate) printf 'mod keys;\n' >>"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    string) printf 'const TEXT: &str = "mod keys;";\nmod keys;\n' >"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    raw-string) printf 'const TEXT: &str = r#"\nmod keys;\n"#;\n' >"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    multiline-string) printf 'const TEXT: &str = "\nmod keys;\n";\n' >"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    unicode-whitespace) printf '\302\240\nmod keys;\n' >"$body/sealbox.rs"; want='expected exactly one `mod keys;`' ;;
    unlisted) touch "$body/sealbox/unlisted.rs"; want="directory mismatch" ;;
    directory) mkdir "$body/sealbox/unlisted"; want="directory mismatch" ;;
  esac
  expect_refusal "sealbox child: $case" "src/backend_body/sealbox.rs: $want"
done
