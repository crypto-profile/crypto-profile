#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
tag="${GITHUB_REF_NAME:?}"
version="${tag#v}"
repo="${GITHUB_SERVER_URL:-https://github.com}/${GH_REPO:?}"
notes="${RUNNER_TEMP:?}/release-notes.md"
crates=()
for name in crypto-profile crypto-profile-awslc4 crypto-profile-awslc3; do
  crate="$RUNNER_TEMP/published/$name-$version.crate"
  [[ -f "$crate" ]] || { echo "$crate was not published" >&2; exit 1; }
  crates+=("$crate")
done
PYTHONOPTIMIZE= python3 -I -c '
import re, sys
root, version, repo, out = sys.argv[1:]
text = open(f"{root}/CHANGELOG.md", encoding="utf-8").read()
m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
if not m or not m.group(1).strip():
    sys.exit(f"CHANGELOG.md has no ## [{version}] section")
blob = f"{repo}/blob/v{version}/"
body = re.sub(r"\]\((?![a-z][a-z0-9+.-]*:|#|/)", "](" + blob, m.group(1).strip())
head = ("**These crates are not a validated module, and not FIPS-certified.** The validation status that matters "
        f"is that of the AWS-LC FIPS module; see the [README]({blob}README.md#what-it-is-not).\n\n")
open(out, "w", encoding="utf-8").write(head + body + "\n")
' "$root" "$version" "$repo" "$notes"
flags=(--latest)
[[ "$version" == *-* ]] && flags=(--prerelease --latest=false)
if ! draft="$(gh release view "$tag" --json isDraft --jq .isDraft)"; then
  gh release create "$tag" "${crates[@]}" --verify-tag --title "crypto-profile $version" --notes-file "$notes" "${flags[@]}"
elif [[ "$draft" == true ]]; then
  gh release upload "$tag" "${crates[@]}" --clobber
  gh release edit "$tag" --draft=false --notes-file "$notes" "${flags[@]}"
else
  echo "SKIP release $tag is already published"
fi
