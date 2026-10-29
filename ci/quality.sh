#!/usr/bin/env bash
set -euo pipefail
kind="${1:?expected coverage or mutants}"
backend="${2:?expected backend package}"
case "$kind" in coverage|mutants) ;; *) echo "unknown quality gate: $kind" >&2; exit 1 ;; esac
case "$backend" in crypto-profile-awslc4|crypto-profile-awslc3) ;; *) echo "unknown backend: $backend" >&2; exit 1 ;; esac
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/opt/rust/tmp}/crypto-profile-quality.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work"
export CARGO_TARGET_DIR="$work/target"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
if [ "$backend" = crypto-profile-awslc4 ]; then
  export RUSTFLAGS='--cfg crypto_profile_provider_direct'
fi
if [ "$kind" = coverage ]; then
  cd "$root"
  if [ "$backend" = crypto-profile-awslc4 ]; then
    cargo llvm-cov --workspace --all-features --locked --fail-under-lines 95 --ignore-filename-regex '(test_support|conformance)'
  else
    cargo llvm-cov --manifest-path crypto-profile-awslc3/Cargo.toml --all-features --locked --fail-under-lines 95 --ignore-filename-regex '(test_support|conformance)'
  fi
else
  mkdir "$work/src"
  (cd "$root" && git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' path; do if [ -f "$path" ]; then cp --parents "$path" "$work/src"; fi; done)
  cd "$work/src"
  if [ "$backend" = crypto-profile-awslc3 ]; then cd crypto-profile-awslc3; fi
  args=(--workspace --no-shuffle --in-place --output "$work/mutants")
  if [ -n "${3:-}" ]; then args+=(--shard "$3"); fi
  cargo mutants "${args[@]}"
fi
