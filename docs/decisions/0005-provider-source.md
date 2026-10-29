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

1. **The provider is plain Rust source under `crypto-profile/src/provider/`.** Core's `build.rs` takes the module list from `mod.rs`'s `pub(crate) mod X;` lines. It panics if `mod.rs` lacks the direct-mode `backend` module (item 3) or holds any other line than a blank line, one `//!` line or `pub(crate) mod <identifier>;`, or if the list differs from the directory's `.rs` files. Otherwise it wraps the listed files, verbatim, into the `#[doc(hidden)] #[macro_export]` `provider!` in `OUT_DIR`, which core `include!`s.
2. **Every backend expands `provider!`; only `crypto-profile-awslc4` also carries the direct-mode module:** `#[cfg(crypto_profile_provider_direct)] #[path = "../../crypto-profile/src/provider/mod.rs"] mod provider;`. Clippy, coverage and cargo-mutants' file discovery use that mode, so each provider file is seen once, through that backend. Any other backend instantiates `provider!` only, and its own code, its `provider_arms` module included, is ordinary code, linted and tested normally. CI runs clippy in both modes and coverage in direct mode, with cargo-mutants 27.1.0 and cargo-llvm-cov 0.8.7 pinned.
3. **The backend-only arms are an ordinary backend module named by the macro argument (`provider!(crate::provider_arms)`), glob-imported as `backend` inside the expansion.** `ident` matches the `crate` keyword, so a body module reaches the arms as `super::backend::<item>`; in direct mode `mod.rs` declares the same `backend` module, which the build script requires and leaves out of the macro.
4. **A component whose `fips()` is the module's FIPS mode has an equivalent `-> true` mutant,** because every test process runs in FIPS mode. Each is excepted by one exact `exclude_re` (decision 0003); the `-> false` mutant stays live and is killed.
5. **Body-file rules.** A body file is any `crypto-profile/src/provider/*.rs` other than `mod.rs`. It:
   - contains no `$`, no `macro_rules!` and no inner attribute other than a leading `//!`;
   - names, in non-test code, only `std::`, `aws_lc_rs::`, `rustls::`, `crypto_profile::`, `zeroize::`, `super::<sibling>::` and `super::backend::`, the paths that resolve the same in a backend module and inside the macro expansion;
   - names `crate::` (the backend) only inside its `#[cfg(test)] mod tests`, and only once the generated macro carries `#[expect(clippy::crate_in_macro_def)]`; until then a test reaches a sibling's helpers through `super::super::<sibling>::tests::`;
   - embeds a test fixture in its test as a `const`, with the fixture's provenance on the const's doc line, and reads no file across the package boundary;
   - declares items `pub(crate)` or private, and every `pub(crate)` item outside its tests has a shipped consumer;
   - puts each call to a `clippy.toml`-disallowed method under `#[expect(clippy::disallowed_methods)]` on the function that makes it, test or not;
   - keeps its unit tests at the bottom as `#[cfg(test)] mod tests` (`pub(crate) mod tests` when a sibling's tests use its helpers).

## Consequences

- `mod.rs` is the one module list and carries nothing else but the direct-mode `backend` module, which the macro emits for itself: no attribute, inner or outer, and no other item, so nothing else in it applies to one mode only. Both modes compile exactly the files it names, and a file in the directory that it does not name fails the build.
- A body file that names `crate::` requires the macro's `#[expect(clippy::crate_in_macro_def)]`.
- A backend that glob re-exports core (`pub use crypto_profile::*`, as `crypto-profile-awslc4` does) makes the hidden `provider!` reachable from the backend's root too. It stays `#[doc(hidden)]` there and is not part of either crate's API.
- A second backend does not carry the `#[path]` module: only `crypto-profile-awslc4` does, or each body mutant would be tested twice. A second backend instantiates `provider!` only.

## Shared backend body

A separate hidden `backend_body!` macro uses the same source-list validator and emitter as
`provider!`. Its index is `crypto-profile/src/backend_body/mod.rs`. The ten backend
modules and nested sealbox keys live in this tree; the backend shell
re-exports their API unchanged. A single `MlDsa` arm supplies generation, public-key
extraction, signing, verifier and fallible descriptor lookup, plus optional test fixtures.
A key stores its descriptor after key validation so the rcgen getter stays infallible.

The body index permits blanks, at most one leading purpose doc line, public declarations
for `signature`, `csr`, `aead`, `digest`, `random`, `fips`, `tls`, and `sealbox`, private
`mod profiles;`, and exactly `#[cfg(any(test, feature = "test-support"))]` paired with
`pub mod test_support;`. The exact `pub use profiles::{Resolved, assert_module_approves, resolve};`
exports the private profile module’s API in both modes. When present, its private
`backend` module imports exactly
`crate::backend_arms::*`; macro emission replaces that bridge with its argument import.
Both indices reject duplicate or invalid names, arbitrary attributes and items, missing
files, and unlisted files or directories. The complete source trees trigger regeneration.

The nested body file `sealbox.rs` contains exactly one `mod keys;`. The emitter validates
`sealbox/` contains only `keys.rs` and inlines that child at its declaration. Other
production contents of `sealbox.rs` are ordinary Rust, outside the index grammar.
Direct compilation uses ordinary Rust child resolution and the same source files.

The shared backend body permits public module children and public API items. Its paths
also permit `pem::`, `rcgen::`, and backend-root references including `crate::signature`,
`crate::tls`, `crate::MODULE`, and `crate::ensure`. Backends re-export the public body
modules and `profiles::{Resolved, resolve, assert_module_approves}` at their root when
those modules move. These paths therefore resolve identically in both compilation modes.
Core includes only the emitted macro definition and acquires no cryptographic dependency.
The 4.x shell selects the direct body with the existing `crypto_profile_provider_direct`
cfg; other backends use only macro emission.

Every backend shell must expose `pub fn awslc_version() -> &'static str`, delegating
to `aws_lc_rs::awslc_version()` to report the runtime-linked release. This is also a
mandatory item for the 3.x shell. The linked release is independent of the certified
release recorded by `certificate(MODULE)`; the 3.x certificate names 3.1.0 while
the pinned 3.x build links 3.6.0.
