#!/usr/bin/env bash
set -euo pipefail
root="$PWD"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
CARGO_NET_OFFLINE=false cargo fetch --manifest-path "$root/Cargo.toml" --locked
CARGO_NET_OFFLINE=false cargo fetch --manifest-path "$root/crypto-profile-awslc3/Cargo.toml" --locked
mkdir -p "$work/src"
printf 'fn main() {}\n' > "$work/src/main.rs"
manifest() {
  cat > "$work/Cargo.toml" <<EOF
[package]
name = "backend-links-control"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
EOF
  for backend in "$@"; do
    printf '%s = { path = "%s/%s" }\n' "$backend" "$root" "$backend" >> "$work/Cargo.toml"
  done
}
for backend in crypto-profile-awslc4 crypto-profile-awslc3; do
  cargo metadata --manifest-path "$root/$backend/Cargo.toml" --offline --locked \
    --no-deps --format-version 1 | python3 -c '
import json, sys
packages = [p for p in json.load(sys.stdin)["packages"] if p["name"] == sys.argv[1]]
assert len(packages) == 1 and packages[0]["links"] == "crypto-profile-backend", packages
' "$backend"
  manifest "$backend"
  if [[ "$backend" == crypto-profile-awslc4 ]]; then
    cp "$root/Cargo.lock" "$work/Cargo.lock"
  else
    cp "$root/$backend/Cargo.lock" "$work/Cargo.lock"
  fi
  cargo check --manifest-path "$work/Cargo.toml" --offline
  rm -f "$work/Cargo.lock"
done
manifest crypto-profile-awslc4 crypto-profile-awslc3
if cargo metadata --manifest-path "$work/Cargo.toml" --offline --format-version 1 > "$work/error" 2>&1; then
  echo 'both backend graphs unexpectedly resolved'; exit 1
fi
if ! { grep -q 'crypto-profile-backend' "$work/error" && grep -q 'links' "$work/error"; }; then
  grep -q 'failed to select a version for `aws-lc-rs`' "$work/error"
  grep -q '=1.17.4' "$work/error"
  grep -q '=1.18.2' "$work/error"
  grep -q 'all possible versions conflict' "$work/error"
fi
cat "$work/error"
