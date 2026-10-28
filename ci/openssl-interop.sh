#!/usr/bin/env bash
set -euo pipefail
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
if [ -z "${CRYPTO_PROFILE_OPENSSL:-}" ]; then
  prefix="${OPENSSL_PREFIX:-$PWD/target/openssl-$OPENSSL_VERSION}"
  if [ ! -x "$prefix/bin/openssl" ]; then
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    curl -fsSL -o "$work/openssl.tar.gz" "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
    if command -v sha256sum >/dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
    echo "$OPENSSL_SHA256  $work/openssl.tar.gz" | $sum -c -
    tar -xzf "$work/openssl.tar.gz" -C "$work"
    (cd "$work/openssl-$OPENSSL_VERSION" && ./Configure --prefix="$prefix" --libdir=lib no-shared no-docs no-tests && make -j"$(getconf _NPROCESSORS_ONLN)" && make install_sw)
  fi
  export CRYPTO_PROFILE_OPENSSL="$prefix/bin/openssl"
fi
out="$(cargo test -p crypto-profile-awslc4 --all-features --locked --test openssl_interop -- --ignored --test-threads=1 2>&1)" || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
grep -qE '^test result: ok\. 2 passed; 0 failed; 0 ignored' <<<"$out" || { echo "the interop tests did not both run"; exit 1; }
