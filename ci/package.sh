#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
out="${1:?usage: ci/package.sh <outdir>}"
mkdir -p "$out"
target="$(mktemp -d "${TMPDIR:-/tmp}/crypto-profile-package.XXXXXXXX")"
trap 'rm -rf -- "$target"' EXIT
CARGO_TARGET_DIR="$target" cargo package --manifest-path "$root/Cargo.toml" --workspace --all-features --locked
CARGO_TARGET_DIR="$target" cargo package --manifest-path "$root/crypto-profile-awslc3/Cargo.toml" --all-features --locked \
  --config "patch.crates-io.crypto-profile.path=\"$root/crypto-profile\""
cp "$target"/package/*.crate "$out"/
ls -l "$out"
