# 0017: Exact pins, advisories and the 3.x backend's retirement

Date: 2026-11-05. Status: accepted.

## Context

Each backend's manifest pins `aws-lc-rs`, `rustls`, `rustls-webpki` and `rcgen` exactly (`=`). Published crates consume these backends, and no decision records why the pins are exact, what that costs a consumer, or when the 3.x backend stops receiving releases (#28).

Three facts shape the answer:

1. **Cargo cannot move an exact requirement.** `cargo update` keeps a dependency at `=x.y.z`, and a second requirement on the same crate, in the same semver-compatible range, that excludes the pinned version fails to resolve. So a fix released by one of the four crates does not reach a consumer through their own lockfile.
2. **The module crate is not pinned.** aws-lc-rs requires `aws-lc-fips-sys` with a caret requirement (`aws-lc-rs-1.19.0/Cargo.toml:106-107`, `0.14.2`; `aws-lc-rs-1.17.4/Cargo.toml:106-107`, `0.13.17`). The aws-lc-rs pin fixes the `aws-lc-fips-sys` series, and with it the module line, but a consumer's own resolution picks the release within that series. Only this repository's lockfiles fix it, and a library's lockfile does not reach its consumers. A later series may or may not stay on the module line; the pin move that takes it says which.
3. **The 3.x line has an upstream ceiling.** aws-lc-rs 1.18 and later require `aws-lc-fips-sys` 0.14, the 4.x line (`aws-lc-rs-1.18.0/Cargo.toml:106-107`), and rcgen 0.14.10 requires aws-lc-rs 1.18 (`rcgen-0.14.10/Cargo.toml:112-113`). A fix released only above that ceiling cannot reach the 3.x backend without leaving its module line.

## Decision

1. **The four are pinned exactly.** A caret requirement on any of them would let a consumer's resolution move it to a release whose API, descriptors or module line the backend was not built against:
   - `aws-lc-rs` fixes the `aws-lc-fips-sys` series, so the module line, and on 3.x keeps resolution off the 4.x line;
   - `rustls` fixes the policy and provider API, which the backend re-exports ([decision 0002](0002-rustls-reexport.md));
   - `rustls-webpki` is called directly by the backend's peer-certificate checks, and rustls requires it by caret, so the pin fixes the version both use;
   - `rcgen` fixes descriptor availability and its aws-lc-rs requirement, which on 3.x is the ceiling above.

   Other dependencies, `aws-lc-fips-sys` among them, resolve by caret in a consumer's graph. A pin moves only through a reviewed pull request, which keeps the pin comments and updates every document that names the version.
2. **A fix in a pinned crate reaches consumers only through a crypto-profile release.** The three crates release together, so a fix in any of the four is a release of all three. There is no supported path to take one ahead of a release.
3. **An advisory with a fix on the backend's module line gets a release.** A published advisory is one from RustSec, GitHub or the upstream project's own security bulletin. When one affects a pinned crate, and a release of that crate the backend can take without leaving its module line fixes it, the pin moves to that release and the three crates are released from the latest release line. That is a patch release, unless the fix needs a change to crypto-profile's API; then it is a minor release, and before 1.0 the earlier minor line gets no backport. An advisory in `aws-lc-fips-sys` fixed within its series reaches consumers through their own `cargo update`; this repository updates its lockfiles so the fix is tested, and needs no release for it. One fixed only in a later series is an aws-lc-rs pin move, under this item or the next.
4. **An advisory without one does not stop releases (maintainer, 2026-11-05).** When no fix exists, or the only fix leaves a backend's module line, that backend keeps its pin and keeps being released. Each of its releases names the advisory in the CHANGELOG under Known issues, with its identifier and the backend that cannot take the fix; review enforces that, not a gate. `deny.toml` ignores the advisory by identifier, with that reason, in the same pull request that moves every backend that can take the fix, or at once if none can; both roots read the one `deny.toml`, so an earlier ignore would hide the advisory on a backend that can still take the fix. Whether to carry the advisory or move to the other backend is the consumer's decision. This is risk management, not risk avoidance: for the 3.x backend, the alternative is no backend on a module line that holds CMVP certificates.
5. **The 3.x backend is retired only after the 4.x line is validated (maintainer, 2026-11-05).** `crypto-profile-awslc3` keeps receiving releases until both 4.x modules, static and dynamic, are on the CMVP validated modules list. A consumer of either linkage then has a 4.x module line that holds CMVP certificates to move to; if one certificate is issued first, 3.x keeps being released for the other. After that it stops when either holds:
   - aws-lc-rs or AWS-LC announces the end of support for aws-lc-rs 1.17 or the AWS-LC FIPS 3.x branch; an advisory upstream does not fix on the line is §4's case, not this one;
   - no consumer of it is known to remain.

   crates.io lists the published crates that depend on a backend, not the applications that do, so "no consumer known" means none on crates.io and none who has said so in an issue. The last 3.x release says it is the last, in the CHANGELOG and the README. Published versions stay published; whether to keep using them is the consumer's decision.

## Consequences

- A consumer upgrades a pinned crate by upgrading crypto-profile.
- An advisory the 3.x line cannot fix stays named in every 3.x release's CHANGELOG until the line retires or upstream fixes it within the line.
- The 3.x backend's lifetime depends on the CMVP's schedule for the 4.x modules, which this project does not control.
- A pin update that leaves a document naming the old version is a defect in that update.
