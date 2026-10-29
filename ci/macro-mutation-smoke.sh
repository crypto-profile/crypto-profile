#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${TMPDIR:-/opt/rust/tmp}/crypto-profile-macro-smoke.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export TMPDIR="$work"
export CARGO_TARGET_DIR="$work/target"
mkdir "$work/src"
(cd "$root" && git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' path; do if [ -f "$path" ]; then cp --parents "$path" "$work/src"; fi; done)
cd "$work/src"
build() { cargo test -p crypto-profile-awslc4 --all-features --locked --no-run >"$work/build.log" 2>&1 || { cat "$work/build.log"; exit 1; }; }
check() { cargo test -p crypto-profile-awslc4 --all-features --locked >"$work/test.log" 2>&1; }
build
check || { cat "$work/test.log"; exit 1; }
for tree in provider backend_body; do
  case "$tree" in
    provider)
      file=crypto-profile/src/provider/hash.rs
      original='ctx.update(bytes);'
      replacement='ctx.update(&bytes[..0]);'
      assertion=sha2_of_abc_and_the_streaming_paths_agree
      ;;
    backend_body)
      file=crypto-profile/src/backend_body/signature.rs
      original='self.public.clone()'
      replacement='Vec::new()'
      assertion=every_algorithm_generates_signs_and_verifies
      ;;
  esac
  cp "$file" "$work/original"
  python3 - "$file" "$original" "$replacement" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
source = path.read_text()
assert source.count(sys.argv[2]) == 1
path.write_text(source.replace(sys.argv[2], sys.argv[3]))
PY
  build
  if check; then echo "$tree mutation survived"; exit 1; fi
  grep -q "test .*${assertion} .*FAILED" "$work/test.log" || { cat "$work/test.log"; echo "$tree failed for another reason"; exit 1; }
  grep -q 'assertion .*failed' "$work/test.log" || { cat "$work/test.log"; exit 1; }
  cp "$work/original" "$file"
  echo "$tree mutation: compiled and caught by $assertion"
done
build
check || { cat "$work/test.log"; exit 1; }
echo 'restored macro baseline: passed'
