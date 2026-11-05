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
flags=(--prerelease=false --latest)
[[ "$version" == *-* ]] && flags=(--prerelease --latest=false)
title="crypto-profile $version"
assets_match() {
  local got="${RUNNER_TEMP:?}/release-assets" crate
  rm -rf "$got"
  gh release download "$tag" --dir "$got"
  [[ "$(ls "$got" | sort)" == "$(printf '%s\n' "${crates[@]##*/}" | sort)" ]] || return 1
  for crate in "${crates[@]}"; do cmp -s "$crate" "$got/${crate##*/}" || return 1; done
}
if ! draft="$(gh release view "$tag" --json isDraft --jq .isDraft 2> "$RUNNER_TEMP/release-view.err")"; then
  grep -qx 'release not found' "$RUNNER_TEMP/release-view.err" || { cat "$RUNNER_TEMP/release-view.err" >&2; exit 1; }
  gh release create "$tag" "${crates[@]}" --verify-tag --title "$title" --notes-file "$notes" "${flags[@]}"
elif [[ "$draft" == true ]]; then
  gh release upload "$tag" "${crates[@]}" --clobber
  gh release view "$tag" --json assets --jq '.assets[].name' | while read -r asset; do
    [[ " ${crates[*]##*/} " == *" $asset "* ]] || gh release delete-asset "$tag" "$asset" --yes
  done
  assets_match || { echo "draft $tag does not carry exactly the published crates" >&2; exit 1; }
  gh release edit "$tag" --draft=false --title "$title" --notes-file "$notes" "${flags[@]}"
else
  assets_match || { echo "release $tag is published without exactly the published crates; immutable releases cannot be corrected" >&2; exit 1; }
  echo "SKIP release $tag is already published"
fi
