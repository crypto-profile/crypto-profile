#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
out="${RUNNER_TEMP:?}/published"
mkdir -p "$out"
version="$(cargo metadata --manifest-path "$root/Cargo.toml" --offline --no-deps --format-version 1 \
  | PYTHONOPTIMIZE= python3 -I -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="crypto-profile"))')"
index_line() {
  local name="$1" body code
  body="$(mktemp)"
  code="$(curl -sS --proto '=https' --max-time 60 --retry 3 -o "$body" -w '%{http_code}' "https://index.crates.io/${name:0:2}/${name:2:2}/$name")" || { rm -f "$body"; echo "index lookup for $name failed" >&2; return 1; }
  case "$code" in
    200) grep -F "\"vers\":\"$version\"" "$body" || true ;;
    404) ;;
    *) echo "index lookup for $name returned HTTP $code" >&2; rm -f "$body"; return 1 ;;
  esac
  rm -f "$body"
}
publish() {
  local name="$1" line; shift
  line="$(index_line "$name")" || exit 1
  if [[ -n "$line" ]]; then
    echo "SKIP $name $version is already on crates.io"
  else
    cargo publish --locked --no-verify "$@"
  fi
}
fetch() {
  local name="$1" line want got local_sum; shift
  line="$(index_line "$name")"
  [[ -n "$line" ]] || { echo "$name $version is not in the index" >&2; return 1; }
  want="$(PYTHONOPTIMIZE= python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["cksum"])' "$line")"
  curl -fsS --proto '=https' --max-time 60 --retry 3 -o "$out/$name-$version.crate" "https://static.crates.io/crates/$name/$name-$version.crate"
  got="$(sha256sum "$out/$name-$version.crate" | cut -d' ' -f1)"
  [[ "$got" == "$want" ]] || { echo "$name $version: sha256 $got does not match index cksum $want" >&2; return 1; }
  CARGO_TARGET_DIR="$RUNNER_TEMP/repack" cargo package --locked --no-verify "$@"
  local_sum="$(sha256sum "$RUNNER_TEMP/repack/package/$name-$version.crate" | cut -d' ' -f1)"
  [[ "$got" == "$local_sum" ]] || { echo "$name $version: crates.io sha256 $got does not match this commit's package $local_sum" >&2; return 1; }
  echo "OK $name $version $got"
}
publish crypto-profile -p crypto-profile --manifest-path "$root/Cargo.toml"
publish crypto-profile-awslc4 -p crypto-profile-awslc4 --manifest-path "$root/Cargo.toml"
publish crypto-profile-awslc3 --manifest-path "$root/crypto-profile-awslc3/Cargo.toml"
fetch crypto-profile -p crypto-profile --manifest-path "$root/Cargo.toml"
fetch crypto-profile-awslc4 -p crypto-profile-awslc4 --manifest-path "$root/Cargo.toml"
fetch crypto-profile-awslc3 --manifest-path "$root/crypto-profile-awslc3/Cargo.toml"
