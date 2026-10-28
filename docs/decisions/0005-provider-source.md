# 0005: The provider is plain source, wrapped into a macro by core's build script

- **Status:** Accepted, 2026-10-29

## Context

The crate's rustls `CryptoProvider` lives in a core macro, so each backend expands it against its own aws-lc-rs and rustls while core depends on neither. Measured on rustc and clippy 1.99.1, cargo-mutants 27.1.0 and cargo-llvm-cov 0.8.7:

- cargo-mutants does not mutate inside a `macro_rules!` body, and does not mutate `if` conditions, so a hand-written macro would pass "0 missed mutants" vacuously;
- clippy does not lint code expanded from another crate's macro, and dead code there goes unreported;
- llvm-cov attributes a foreign macro's whole expansion to its invocation line;
- `include!` of a relative path inside a macro resolves against the invoking crate, not core;
- a backend module reached through a `#[cfg]`'d `#[path]` attribute is linted, measured and mutated like any other file, and a mutant written into it reaches the macro build through the build script's `rerun-if-changed`.

## Decision

1. **The provider is plain Rust source under `crypto-profile/src/provider/`.** Core's `build.rs` takes the module list from `mod.rs`'s `pub(crate) mod X;` lines, panics if that list differs from the directory's `.rs` files, and wraps the listed files, verbatim, into the `#[doc(hidden)] #[macro_export]` `provider!` in `OUT_DIR`, which core `include!`s.
2. **A backend expands `provider!` and also carries the direct-mode module:** `#[cfg(crypto_profile_provider_direct)] #[path = "../../crypto-profile/src/provider/mod.rs"] mod provider;`. Clippy, coverage and cargo-mutants' file discovery use that mode. CI runs clippy in both modes and coverage in direct mode, with cargo-mutants 27.1.0 and cargo-llvm-cov 0.8.7 pinned.
3. **The macro takes no argument yet (`provider!()`).** Backend-only items arrive with the signing keys, which amend this item.
4. **A component whose `fips()` is the module's FIPS mode has an equivalent `-> true` mutant,** because every test process runs in FIPS mode. Each is excepted by one exact `exclude_re` (decision 0003); the `-> false` mutant stays live and is killed.
5. **Body-file rules.** A body file is any `crypto-profile/src/provider/*.rs` other than `mod.rs`. It:
   - contains no `$`, no `macro_rules!` and no inner attribute other than a leading `//!`;
   - names, in non-test code, only `std::`, `aws_lc_rs::`, `rustls::`, `crypto_profile::`, `zeroize::`, `super::<sibling>::` and `super::backend::`, the paths that resolve the same in a backend module and inside the macro expansion;
   - names `crate::` (the backend) only inside its `#[cfg(test)] mod tests`, and only once the generated macro carries `#[expect(clippy::crate_in_macro_def)]`; until then a test reaches a sibling's helpers through `super::super::<sibling>::tests::`;
   - reads a fixture under `crypto-profile/src/provider/testdata/` only as `include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../crypto-profile/src/provider/testdata/<file>"))`;
   - declares items `pub(crate)` or private, and every `pub(crate)` item outside its tests has a shipped consumer;
   - puts each call to a `clippy.toml`-disallowed method under `#[expect(clippy::disallowed_methods)]` on the function that makes it, test or not;
   - keeps its unit tests at the bottom as `#[cfg(test)] mod tests` (`pub(crate) mod tests` when a sibling's tests use its helpers).

## Consequences

- `mod.rs` is the one module list: both modes compile exactly the files it names, and a file in the directory that it does not name fails the build.
- A backend that glob re-exports core (`pub use crypto_profile::*`, as `crypto-profile-awslc4` does) makes the hidden `provider!` reachable from the backend's root too. It stays `#[doc(hidden)]` there and is not part of either crate's API.
- A second backend carries the same `#[path]` module, but only one backend may carry it for cargo-mutants, or each body mutant is tested twice.
