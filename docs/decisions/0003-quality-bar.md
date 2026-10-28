# 0003: One quality bar, with per-mutant exceptions

- **Status:** Accepted, 2026-10-28

## Context

Every line of this crate either selects cryptography or reports on it, and a defect in either is a security defect. Tiered coverage targets invite argument about which tier code belongs in; file-level exclusions hide whatever is in the file. Mutation testing shows whether a test would notice the code being wrong, which line coverage alone does not.

Some mutants cannot be killed by an honest test. The clearest is `fips::assert_fips_module()`, whose only input is the loaded module's own `FIPS_mode()`. On a FIPS build that is always true, so replacing the function body with `Ok(())` changes nothing a test can observe. Making it false would need a separately built non-FIPS AWS-LC installed under the FIPS library's soname, which needs C tooling outside the crate.

## Decision

1. **One bar for all shipped code:** at least 95% line coverage, measured with `cargo llvm-cov`, and 0 missed mutants from `cargo mutants` across the workspace.
2. **Test infrastructure is not shipped code.** `crypto-profile-awslc4/src/test_support.rs` and the conformance scaffolding under `crypto-profile/src/conformance/` are excluded from both measures. Nothing else is excluded by file.
3. **An exception names one mutant.** It is one `exclude_re` entry in `.cargo/mutants.toml` that matches exactly that mutant, with its reason and what covers the risk instead. It is used only when no honest test can kill the mutant: an equivalent mutant, or one whose only input is a fixed property of the build. A file-level exclusion is refused in review.
4. **The `assert_fips_module` pattern.** The decision is the pure function `fips::fips_result(bool)`, tested in both directions. The wrapper `assert_fips_module()` only passes it `aws_lc_rs::try_fips_mode().is_ok()`. The wrapper's `Ok(())` mutant is an exception on both linkages, with the reason above. (Ruling, 2026-10-28: a test that swaps in a non-FIPS dynamic library needs C tooling outside the crate, so it is not in round 1.)
5. **While the repository is private,** CI runs formatting, clippy, cargo-deny, the MSRV check, the Linux x86_64 tests on both linkages and the DCO check. Coverage, mutation testing, and the macOS and arm64 tests run in CI once the repository is public; until then they run locally before every pull request.

## Consequences

- Each exception is visible, specific and reviewable, and a new mutant in the same function is not covered by an old exception.
- Contributors write pure decision functions and thin wrappers where a wrapper's input is fixed by the build, so the decision itself is fully tested.
- The `assert_fips_module` wrapper is untested in the negative direction. Its risk is bounded by its size (one call into aws-lc-rs) and by `fips_result`'s tests; the sealed box and any application that calls it depend on that.
- Running the expensive gates locally while the repository is private puts the burden on the contributor, and the pull request template asks them to confirm it.
