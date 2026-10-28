#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR="$work/target"
copy() {
  rm -rf "$work/src"
  mkdir -p "$work/src"
  (cd "$root" && git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$work/src")
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
mod="$work/src/crypto-profile/src/provider/mod.rs"
copy
sed -i.bak '1a\
#![allow(dead_code)]' "$mod" && rm -f "$mod.bak"
expect_refusal "an inner attribute in mod.rs" "src/provider/mod.rs may hold only blank lines"
copy
printf 'pub(crate) mod missing;\n' >>"$mod"
expect_refusal "a listed module with no file" "src/provider/mod.rs lists"
copy
printf '\n' >"$work/src/crypto-profile/src/provider/unlisted.rs"
expect_refusal "a provider file mod.rs does not list" "src/provider/mod.rs lists"
