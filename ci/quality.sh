#!/usr/bin/env bash
set -euo pipefail
kind="${1:?expected coverage, mutants or mutants-diff}"
backend="${2:?expected backend package}"
case "$kind" in coverage|mutants|mutants-diff) ;; *) echo "unknown quality gate: $kind" >&2; exit 1 ;; esac
case "$backend" in crypto-profile-awslc4|crypto-profile-awslc3) ;; *) echo "unknown backend: $backend" >&2; exit 1 ;; esac
root="$(git rev-parse --show-toplevel)"
if [ "$kind" = mutants-diff ]; then
  base="${3:?expected base revision}"
  git -C "$root" rev-parse --verify --quiet "$base^{commit}" >/dev/null || { echo "unknown base revision: $base" >&2; exit 1; }
  if [ -n "$(git -C "$root" status --porcelain)" ]; then
    echo "mutants-diff runs on a clean tree: commit or stash first" >&2
    exit 1
  fi
fi
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
  if [ "$kind" = mutants-diff ]; then
    if [ "$backend" = crypto-profile-awslc4 ]; then
      # Direct mode names the shared body through this path; without it cargo-mutants skips the body files.
      git -C "$root" diff --no-color --no-ext-diff --no-textconv --src-prefix=a/ --dst-prefix=b/ "$base"...HEAD -- '*.rs' \
        | sed -E '/^(diff --git |--- |\+\+\+ )/ s#([ab])/crypto-profile/src/(backend_body|provider)/#\1/crypto-profile-awslc4/src/../../crypto-profile/src/\2/#g' \
        > "$work/branch.diff"
    else
      git -C "$root" diff --no-color --no-ext-diff --no-textconv --src-prefix=a/ --dst-prefix=b/ --relative=crypto-profile-awslc3 "$base"...HEAD -- '*.rs' > "$work/branch.diff"
    fi
    if [ ! -s "$work/branch.diff" ]; then
      echo "no Rust source changed for $backend since $base"
      exit 0
    fi
  fi
  cd "$work/src"
  if [ "$backend" = crypto-profile-awslc3 ]; then cd crypto-profile-awslc3; fi
  if [ "$kind" = mutants-diff ]; then
    cargo mutants --list-files --workspace > "$work/mutated.files"
    if [ ! -s "$work/mutated.files" ]; then
      echo "cargo-mutants listed no files to mutate for $backend" >&2
      exit 1
    fi
    sed -nE 's#^\+\+\+ b/(.*)$#\1#p' "$work/branch.diff" > "$work/changed.files"
    if [ ! -s "$work/changed.files" ]; then
      echo "cannot read file names from the diff for $backend" >&2
      exit 1
    fi
    declare -A canonical=()
    while IFS= read -r known; do
      norm="$(realpath -m --relative-to=. -- "$known")" && [ -n "$norm" ] || { echo "cannot normalise $known with realpath -m" >&2; exit 1; }
      canonical["$norm"]=1
    done < "$work/mutated.files"
    overlap=0
    while IFS= read -r changed; do
      if grep -Fxq -- "$changed" "$work/mutated.files"; then overlap=1; continue; fi
      # a changed path that names a mutated file by another spelling means the diff rewrite drifted
      norm="$(realpath -m --relative-to=. -- "$changed")" && [ -n "$norm" ] || { echo "cannot normalise $changed with realpath -m" >&2; exit 1; }
      if [ -n "${canonical[$norm]:-}" ]; then
        echo "the diff's paths do not match cargo-mutants' file names for $backend; the path mapping is broken" >&2
        exit 1
      fi
    done < "$work/changed.files"
    if [ "$overlap" = 0 ]; then
      echo "no mutated source changed for $backend since $base"
      exit 0
    fi
    listed="$(cargo mutants --list --workspace --in-diff "$work/branch.diff")"
    if [ -z "$listed" ]; then
      echo "the changed lines in $(paste -sd' ' "$work/changed.files") hold no mutant"
      exit 0
    fi
    printf '%s\n' "$listed"
    cargo mutants --workspace --no-shuffle --in-place --in-diff "$work/branch.diff" --output "$work/mutants"
    exit 0
  fi
  args=(--workspace --no-shuffle --in-place --output "$work/mutants")
  if [ -n "${3:-}" ]; then args+=(--shard "$3"); fi
  cargo mutants "${args[@]}"
fi
