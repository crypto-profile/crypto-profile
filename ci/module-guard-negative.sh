#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/tmp}/module-guard-negative.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^AWS_LC_FIPS_SYS_NO_PREFIX_' || true)
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
if AWS_LC_FIPS_SYS_NO_PREFIX=1 CARGO_TARGET_DIR="$work/target3" \
    cargo build --manifest-path "$root/crypto-profile-awslc3/Cargo.toml" --locked > "$work/build3.log" 2>&1; then
  echo "FAIL crypto-profile-awslc3 built with an unprefixed module" >&2
  exit 1
fi
if ! grep -q 'crypto-profile-awslc3: the bundled module was built without its symbol prefix' "$work/build3.log"; then
  echo "FAIL crypto-profile-awslc3 failed for another reason:" >&2
  tail -20 "$work/build3.log" >&2
  exit 1
fi
echo "PASS crypto-profile-awslc3 refuses an unprefixed module"
tree="$work/tree"
mkdir -p "$tree"
while IFS= read -r -d '' f; do
  [ -e "$root/$f" ] && (cd "$root" && cp --parents -- "$f" "$tree")
done < <(git -C "$root" ls-files -z --cached --others --exclude-standard)
sed -i '/^aws-lc-fips-sys = /d' "$tree/crypto-profile-awslc4/Cargo.toml"
if grep -q '^aws-lc-fips-sys = ' "$tree/crypto-profile-awslc4/Cargo.toml"; then
  echo "FAIL could not remove the aws-lc-fips-sys pin from the copy" >&2
  exit 1
fi
if CARGO_TARGET_DIR="$work/target" \
    cargo build --manifest-path "$tree/Cargo.toml" -p crypto-profile-awslc4 --offline > "$work/unpinned.log" 2>&1; then
  echo "FAIL crypto-profile-awslc4 built without its direct aws-lc-fips-sys pin" >&2
  exit 1
fi
if ! grep -q 'crypto-profile-awslc4: aws-lc-fips-sys must be a direct dependency' "$work/unpinned.log"; then
  echo "FAIL crypto-profile-awslc4 without its pin failed for another reason:" >&2
  tail -20 "$work/unpinned.log" >&2
  exit 1
fi
echo "PASS crypto-profile-awslc4 refuses a build without its direct aws-lc-fips-sys pin"
