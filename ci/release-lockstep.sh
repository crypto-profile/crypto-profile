#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
meta() { cargo metadata --manifest-path "$1" --offline --no-deps --format-version 1; }
{ meta "$root/Cargo.toml"; echo; meta "$root/crypto-profile-awslc3/Cargo.toml"; } | PYTHONOPTIMIZE= python3 -I -c '
import json, os, re, sys
def check(ok, msg):
    if not ok:
        sys.exit(f"FAIL release-lockstep: {msg}")
docs = [json.loads(line) for line in sys.stdin if line.strip()]
pkgs = {p["name"]: p for d in docs for p in d["packages"]}
names = ["crypto-profile", "crypto-profile-awslc4", "crypto-profile-awslc3"]
missing = [n for n in names if n not in pkgs]
check(not missing, f"missing packages: {missing}")
versions = {n: pkgs[n]["version"] for n in names}
check(len(set(versions.values())) == 1, f"versions differ: {versions}")
version = versions["crypto-profile"]
for n in names[1:]:
    reqs = [d["req"] for d in pkgs[n]["dependencies"] if d["name"] == "crypto-profile"]
    check(reqs and all(r == f"={version}" for r in reqs), f"{n} requires crypto-profile {reqs}, not ={version}")
changelog = open(os.path.join(sys.argv[1], "CHANGELOG.md")).read()
check(re.search(rf"^## \[{re.escape(version)}\]", changelog, re.M), f"CHANGELOG.md has no ## [{version}] heading")
if os.environ.get("GITHUB_REF_TYPE") == "tag":
    tag = os.environ.get("GITHUB_REF_NAME", "")
    check(tag == f"v{version}", f"tag {tag} does not match version {version}")
print(f"PASS release-lockstep {version}")
' "$root"
