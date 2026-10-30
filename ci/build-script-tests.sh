#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-${RUNNER_TEMP:-/tmp}}/crypto-profile-build-tests.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
rustc --test --edition 2024 "$root/crypto-profile/build.rs" -o "$scratch/build-tests"
"$scratch/build-tests"
for backend in crypto-profile-awslc4 crypto-profile-awslc3; do
  rustc --test --edition 2024 "$root/$backend/build.rs" -o "$scratch/$backend-build-tests"
  "$scratch/$backend-build-tests"
done
