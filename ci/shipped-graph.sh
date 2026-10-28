#!/usr/bin/env bash
set -euo pipefail
tree() { cargo tree -p crypto-profile-awslc4 --locked --color never --target all $features "$@"; }
err="$(mktemp)"
trap 'rm -f "$err"' EXIT
for features in "" "--all-features"; do
  rustls="$(tree --edges normal,features --invert rustls)"
  webpki="$(tree --edges normal,features --invert rustls-webpki)"
  grep -q '^rustls v0\.23\.46' <<<"$rustls" || { echo "rustls v0.23.46 is not in the shipped graph; this check is written for that pin and read nothing"; exit 1; }
  grep -q '^rustls-webpki v0\.103\.16' <<<"$webpki" || { echo "rustls-webpki v0.103.16 is not in the shipped graph; this check is written for that pin and read nothing"; exit 1; }
  if grep -E 'rustls feature "(aws_lc_rs|aws-lc-rs|custom-provider|fips|ring|prefer-post-quantum)"' <<<"$rustls"; then
    echo "a stock rustls provider, or custom-provider, reaches the shipped graph ($features)"; exit 1
  fi
  if grep -E 'rustls-webpki feature "(aws-lc-rs|aws-lc-rs-fips|aws-lc-rs-unstable|ring)"' <<<"$webpki"; then
    echo "rustls-webpki's own verifiers reach the shipped graph ($features)"; exit 1
  fi
  if ring="$(tree --edges normal --invert ring 2>"$err")"; then
    if grep -v -e '^warning: nothing to print\.$' -e '^$' -e '^To find dependencies that require specific target platforms, try to use option `--target all` first, and then narrow your search scope accordingly\.$' "$err"; then
      echo "the ring probe wrote an unexpected diagnostic"; exit 1
    fi
  else
    grep -q 'did not match any packages' "$err" || { cat "$err"; echo "the ring probe failed"; exit 1; }
    ring=""
  fi
  if [ -n "$ring" ]; then
    printf '%s\n' "$ring"; echo "ring reaches the shipped graph ($features)"; exit 1
  fi
done
cargo clippy -p crypto-profile-awslc4 --lib --all-features --locked -- -D warnings
