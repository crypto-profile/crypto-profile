#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
tag="${GITHUB_REF_NAME:?}"
version="${tag#v}"
notes="${RUNNER_TEMP:?}/release-notes.md"
crates=("$RUNNER_TEMP/published/"*"-$version.crate")
[[ ${#crates[@]} -eq 3 && -f "${crates[0]}" ]] || { echo "expected 3 published crates for $version, found ${#crates[@]}" >&2; exit 1; }
PYTHONOPTIMIZE= python3 -I -c '
import re, sys
root, version, out = sys.argv[1:]
text = open(f"{root}/CHANGELOG.md").read()
m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
if not m or not m.group(1).strip():
    sys.exit(f"CHANGELOG.md has no ## [{version}] section")
head = ("**This crate is not a validated module.** The validation status that matters is that of the AWS-LC FIPS "
        f"module; see the [README](https://github.com/crypto-profile/crypto-profile/blob/v{version}/README.md#what-it-is-not).\n\n")
open(out, "w").write(head + m.group(1).strip() + "\n")
' "$root" "$version" "$notes"
if gh release view "$tag" > /dev/null 2>&1; then
  echo "SKIP release $tag exists; uploading its crates"
  gh release upload "$tag" "${crates[@]}" --clobber
else
  gh release create "$tag" "${crates[@]}" --verify-tag --title "crypto-profile $version" --notes-file "$notes"
fi
