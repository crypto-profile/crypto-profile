#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-${RUNNER_TEMP:-/tmp}}/crypto-profile-build-tests.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
rustc --test --edition 2024 "$root/crypto-profile/build.rs" -o "$scratch/build-tests"
"$scratch/build-tests"
