#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/tmp}/module-guard-negative.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
if AWS_LC_FIPS_SYS_NO_PREFIX=1 CARGO_TARGET_DIR="$work/target" \
    cargo build --manifest-path "$root/Cargo.toml" -p crypto-profile-awslc4 --locked > "$work/build.log" 2>&1; then
  echo "FAIL crypto-profile-awslc4 built with an unprefixed module name" >&2
  exit 1
fi
if ! grep -q 'crypto-profile-awslc4: the linked FIPS module is not the bundled' "$work/build.log"; then
  echo "FAIL crypto-profile-awslc4 failed for another reason:" >&2
  tail -20 "$work/build.log" >&2
  exit 1
fi
echo "PASS crypto-profile-awslc4 refuses an unprefixed module name"
