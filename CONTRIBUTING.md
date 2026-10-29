# Contributing to crypto-profile

These rules apply to every contributor, human or AI-assisted. [`docs/usage.md`](docs/usage.md) describes what the crate does and claims; read it before changing either.

## 1. Setup

- **Rust 1.99.1 or later.** `rust-toolchain.toml` pins 1.99.1 with `rustfmt`, `clippy` and `llvm-tools`, and every manifest sets `rust-version = "1.99.1"`.
- **The FIPS build tools:** a C and C++ compiler, CMake, Go, Perl, and clang (libclang). [`docs/usage.md`](docs/usage.md) section 4 gives the sources.
- **Both linkages.** On Linux x86_64 and aarch64 the default build links the FIPS module statically. Build and test the dynamic linkage too:

  ```sh
  cargo test --workspace --all-features
  AWS_LC_FIPS_SYS_STATIC=0 cargo test --workspace --all-features
  ```

  The two builds produce different artifacts, so a separate `CARGO_TARGET_DIR` for each avoids rebuilding AWS-LC every time you switch. On macOS only the dynamic linkage is supported.

## 2. The gates

Run these gates for both workspaces. The root lockfile covers core and 4.x; 3.x has its own lockfile. Use `--locked` so a gate cannot silently change either resolution. Clear target-qualified `AWS_LC_FIPS_SYS_STATIC_<target>` variables before selecting a linkage. Use separate target directories for static and dynamic builds.

```sh
cargo fmt --all --check
cargo fmt --manifest-path crypto-profile-awslc3/Cargo.toml --all --check
rustfmt --check --edition 2024 crypto-profile/src/provider/mod.rs
rustfmt --check --edition 2024 crypto-profile/src/backend_body/mod.rs
for backend in crypto-profile-awslc4 crypto-profile-awslc3; do
  for static in 1 0; do
    AWS_LC_FIPS_SYS_STATIC="$static" cargo test --manifest-path "$backend/Cargo.toml" --all-features --locked
    AWS_LC_FIPS_SYS_STATIC="$static" cargo clippy --manifest-path "$backend/Cargo.toml" --all-targets --all-features --locked -- -D warnings
    AWS_LC_FIPS_SYS_STATIC="$static" ci/shipped-graph.sh "$backend"
    AWS_LC_FIPS_SYS_STATIC="$static" ci/openssl-interop.sh "$backend"
  done
done
cargo test -p crypto-profile --all-features --locked
cargo clippy -p crypto-profile --all-targets --all-features --locked -- -D warnings
RUSTFLAGS='--cfg crypto_profile_provider_direct' cargo test --manifest-path crypto-profile-awslc4/Cargo.toml --all-features --locked
RUSTFLAGS='--cfg crypto_profile_provider_direct' cargo clippy --manifest-path crypto-profile-awslc4/Cargo.toml --all-targets --all-features --locked -- -D warnings
ci/provider-build-negative.sh
ci/backend-links-negative.sh
ci/macro-mutation-smoke.sh
cargo deny --locked check
(cd crypto-profile-awslc3 && cargo deny --config ../deny.toml --locked check)
cargo +1.99.1 check --workspace --all-features --locked
cargo +1.99.1 check --manifest-path crypto-profile-awslc3/Cargo.toml --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
cargo doc --manifest-path crypto-profile-awslc3/Cargo.toml --all-features --no-deps --locked
```

Interop requires OpenSSL 3.5 or later; set `CRYPTO_PROFILE_OPENSSL` to an existing executable for an offline run. Each backend and linkage must report two passed interop tests. Do not count skipped tests as evidence.

For coverage and mutation, use cargo-llvm-cov 0.8.7 and cargo-mutants 27.1.0. Use a unique scratch directory with enough space for `TMPDIR` and isolated targets. Inspect mutant discovery and results, and clean the scratch directory on exit. The direct cfg covers shared source through 4.x; do not set it on 3.x.

```sh
RUSTFLAGS='--cfg crypto_profile_provider_direct' cargo llvm-cov --workspace --all-features --locked --fail-under-lines 95 --ignore-filename-regex '(test_support|conformance)'
RUSTFLAGS='--cfg crypto_profile_provider_direct' cargo mutants --workspace --no-shuffle
cargo llvm-cov --manifest-path crypto-profile-awslc3/Cargo.toml --all-features --locked --fail-under-lines 95 --ignore-filename-regex '(test_support|conformance)'
ci/quality.sh mutants crypto-profile-awslc3
```

Per-change mutation checks can use `cargo mutants --in-diff <diff>`; the final gate runs both full workspaces. Source emission validates both module indices and the nested sealbox child. Inspect the shared files directly with the 4.x direct cfg; run the macro smoke check to verify regeneration and test sensitivity.

`--all-features` matters: the conformance suite needs the backend's `test-support` feature and is skipped without it.

`clippy.toml` refuses rustls's stock-provider entry points (`disallowed-methods`). Code that has to call one, as `crypto-profile/src/backend_body/tls.rs` does to build a provider from a policy, carries `#[expect(clippy::disallowed_methods)]` on that function and nowhere wider. The stock-provider entries carry `allow-invalid`, because the library builds without rustls's provider and they resolve only where the dev-dependency brings it in; `crypto-profile-awslc4/tests/differential.rs` calls them under `#[expect]`. The provider's source is linted only in the direct build ("Lints, provider source"); inside the macro expansion clippy sees nothing ([decision 0005](docs/decisions/0005-provider-source.md)).

## 3. The quality bar

One bar for all shipped code ([decision 0003](docs/decisions/0003-quality-bar.md)):

- at least **95% line coverage**;
- **0 missed mutants** from `cargo mutants`.

Use cargo-mutants 27.1.0 and cargo-llvm-cov 0.8.7, the versions CI pins.

The test infrastructure (`crypto-profile/src/backend_body/test_support.rs` and the conformance scaffolding under `crypto-profile/src/conformance/`) is not shipped behaviour and is excluded from both. Nothing else is excluded by file.

**A mutant exception** is the last resort, for a mutant no honest test can kill: an equivalent mutant, or one whose only input is a fixed property of the build. It is one `exclude_re` entry in `.cargo/mutants.toml` that matches exactly that mutant, with a comment above it giving the reason and what covers the risk instead. For example:

```toml
# The decision is fips_result, tested both ways; the wrapper's only input is the loaded module's FIPS_mode(), which a FIPS build cannot make false.
"^crypto-profile/src/backend_body/fips\\.rs:[0-9]+:[0-9]+: replace assert_fips_module -> Result<\\(\\), CryptoError> with Ok\\(\\(\\)\\)$",
```

A file-level exclusion, or a pattern that matches more than one mutant, is refused in review.

## 4. The test oracles stay independent

A test that checks a mapping against the mapping itself proves nothing. The suite keeps its expected values apart from the code under test:

- **Registry codepoints.** Core carries literal IANA values: `iana()` for every cipher suite, key-exchange group, signature scheme and TLS version (`crypto-profile/src/algorithm.rs`, pinned by `iana_codepoints_are_the_registry_values`). Every backend mapping is tested against them (`every_mapping_carries_its_registry_codepoint` in `crypto-profile/src/backend_body/tls.rs`). The handshake helper reads the negotiated suite, group and scheme as wire codepoints and maps them back through `iana()`, never through the mapping under test (`crypto-profile/src/backend_body/test_support.rs`).
- **CSR signatures.** On 4.x a backend test hook selects rustls-webpki verifiers from a literal per-algorithm table. On 3.x the hook selects this crate's provider verifiers: the independent upstream verifier feature requires a newer dependency that crosses the selected module line. The 3.x signature check therefore shares verification implementation with the provider. Both backends compare the CSR signature OID with core's literal `signature_oid()` and verify signatures over the encoded request (`every_algorithm_signs_a_request_for_its_own_key` in `crypto-profile/src/backend_body/csr.rs`).
- **Provider behaviour.** `tests/differential.rs` drives every group, suite and scheme both the provider and rustls's reference provider implement, in both directions, against literal codepoints; compares the verification tables and `fips()` classification; checks that each TLS 1.3 suite's QUIC algorithm derives the same packet and header protection as rustls's for the same secret; and checks that every certificate-chain verifier accepts the same valid signature as rustls-webpki's and refuses the same flipped one.
- **Known answers** come from published vector sets, byte for byte as retrieved, with their provenance and digests in `crypto-profile/src/conformance/vectors/SOURCES.md`.

When you add a value, take it from the registry or the standard, not from the code you are testing.

## 5. Adding an algorithm

1. **Add the enum variant** in `crypto-profile/src/algorithm.rs`. Adding a variant is a minor-version bump while the crate is 0.x. The algorithm enums are exhaustive by design ([decision 0001](docs/decisions/0001-founding.md)), and every `match` on them lists every variant with no `_` arm. So the compiler refuses to build until the variant has an arm in each of them: its `ordinal()`, `iana()` or `signature_oid()`, every `capability()` cell (step 4), and every backend mapping (step 5). It forces nothing else.
2. **Add it to its family's `ALL` array,** at the position its `ordinal()` gives. The compiler does not check `ALL`. The test `<family>_all_lists_every_variant_in_ordinal_order` checks that `ALL` holds the ordinals `0..N` in order, so a variant left out of `ALL` fails it unless its ordinal is the last one, `N`. Review catches that case: give the new variant its ordinal and its place in `ALL` together. Everything that walks `ALL` skips a variant missing from it: the capability walk, the registry-literal tests and the CSR oracle table.
3. **Add its literal identifiers** to core: `iana()` from the IANA TLS registries, or `signature_oid()` from the RFC that assigns the OID, and extend the literal tables in the tests that pin them.
4. **Give it a `capability()` cell for every `Module`** in `crypto-profile/src/capability.rs`. Each cell states:
   - *available*: whether that module's backend implements it;
   - *approval*: `Approved` or `NotApproved`, with a `source` naming the certificate and the security-policy table (and the page, for an approval); for a module with CAVP certificates and no published security policy, `AlgorithmTested`, with a `cavp` naming one CAVP certificate (one processor variant, the lowest-numbered where several qualify) that shows every operation the cell needs, with the parameters it names ([decision 0004](docs/decisions/0004-algorithm-tested.md)); or `Unverified` when no published source settles it.

   A cell you cannot source is `Unverified`. Never mark a cell `Approved` on the strength of another module's policy, a CAVP certificate alone, a vendor statement or an algorithm's general reputation.
5. **Map it in every backend** (the rustls item, the aws-lc-rs algorithm, the rcgen algorithm, as applies).
6. **Add conformance coverage.** The capability walk (`conformance_capability_honesty`) picks it up through `ALL`. The compiler does not force known answers or profiles. Add known answers from a published vector set to `crypto-profile/src/conformance/vectors/`, recorded in `SOURCES.md`, and a row to the oracle table in the CSR test for a signature algorithm.
7. **Decide which profiles admit it.** Add it to each profile constant in `crypto-profile/src/profile.rs` whose governing text admits it, with the citation in the constant's doc comment, and update the golden table in `crypto-profile/src/conformance/golden.rs`. A regime-named profile admits only what its cited edition's tables admit.

## 6. Adding a backend

A backend is a crate named for its module line. It must:

- expose the same module paths and signatures as `crypto-profile-awslc4` (`aead`, `csr`, `digest`, `fips`, `random`, `sealbox`, `signature`, `tls`) and re-export the core crate;
- declare `pub const MODULE: Module`, with the linkage taken from the build, never assumed. If the build cannot report it, the build fails;
- run the shared suite from its own tests:

  ```rust
  crypto_profile::conformance_tests!(your_crate);
  ```

The suite checks the backend against the known answers, walks every capability cell for its `MODULE`, and checks that the test binary's linkage matches `MODULE`. It checks each profile against the golden rows, and checks the exact `excluded` entries for the module line and the `EmptyProfile` refusals. The peers it builds offer only the module's algorithms, so a profile that resolves is still checked in full.

`conformance_tests!` expands to `use your_crate::*;` and names these paths in your crate, so it compiles only if each exists with the shape `crypto-profile-awslc4` gives it (`crypto-profile/src/conformance/mod.rs`, `conformance_tests`):

- the core crate's types re-exported at the crate root (`SignatureAlgorithm`, `TlsVersion`, `CipherSuite`, `KxGroup`, `TlsSignatureScheme`, `Algorithm`, `CryptoError` and the rest), and `MODULE`;
- `test_support::handshake(client: &Policy, server: &Policy, key: SignatureAlgorithm) -> Result<Negotiated, String>`, behind a `test-support` feature that the test target requires (`required-features = ["test-support"]`). It runs a real in-process handshake and reports the version, suite, group and scheme from their wire codepoints, mapped back through the core crate's `iana()`;
- `test_support::FIPS_LIBRARY: &str`, the FIPS module's crypto library name, under the same feature;
- `test_support::{Negotiated, handshake_certified, handshake_with_ca}`, with `Negotiated`'s five public fields (`version`, `suite`, `kx`, `scheme`, and `kind`, the client's `rustls::HandshakeKind`), and the `rcgen` re-export, under the same feature;
- the `rustls` re-export, from which the suite names `rustls::RootCertStore` and `rustls::server::ResolvesServerCertUsingSni` and reads a config's `require_ems`;
- `resolve`, and `Resolved` with its public fields, `admit_key` and `certified_key`, implementing `PartialEq` and `Debug`. `Resolved`'s five-field struct-literal shape (`profile`, `options`, `tls`, `keys`, `excluded`) is part of the contract, because the suite's `open_peer` builds one by literal;
- `tls::Policy`, with the four public list fields, implementing `Clone`, `PartialEq` and `Debug`, `tls::crypto_provider`, `tls::client_builder` and `tls::server_builder`;
- `fips::assert_fips_client_config` and `fips::assert_fips_server_config`;
- `signature::KeyPair::generate`, `KeyPair::sign`, `KeyPair::public_key` and `signature::verify`, with `KeyPair` implementing `rcgen::SigningKey`;
- `digest::digest`;
- `aead::KEY_LEN`, `aead::NONCE_LEN` and `aead::Aes256GcmKey`, with `new` and `open_in_place`;
- `sealbox::PrivateKey::from_pkcs8_der` and `sealbox::open`.

A backend instantiates the provider with `crypto_profile::provider!(crate::provider_arms)`. Only `crypto-profile-awslc4` also carries the direct-mode `#[path]` module (`crypto-profile-awslc4/src/lib.rs`), so clippy, coverage and cargo-mutants see each provider file once, through that backend ([decision 0005](docs/decisions/0005-provider-source.md)); another backend instantiates the macro only, and its own code, `provider_arms` included, is ordinary code, linted, measured and mutated like the rest of the backend. It supplies a `provider_arms` module with three items: `pub(crate) fn load_pqdsa(pkcs8: &rustls::pki_types::PrivatePkcs8KeyDer<'_>) -> Option<std::sync::Arc<dyn rustls::sign::SigningKey>>`, which loads the ML-DSA keys the backend's module signs with (ML-DSA-44, -65 and -87 on 4.x) and returns `None` on a backend that has none; `pub(crate) static PQDSA_ALL: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm]`, the ML-DSA certificate-chain verifiers (ML-DSA-44, -65 and -87 on 4.x); and `pub(crate) static PQDSA_MAPPING: &[(rustls::SignatureScheme, &[&dyn rustls::pki_types::SignatureVerificationAlgorithm])]`, the ML-DSA handshake schemes (ML-DSA-87 on 4.x). A backend without ML-DSA leaves both statics empty. A new provider file is listed in `crypto-profile/src/provider/mod.rs`, which is the only module list ([decision 0005](docs/decisions/0005-provider-source.md)).

The linkage test looks for the shared library `test_support::FIPS_LIBRARY` names: the backend's build script takes it from aws-lc-rs's link metadata (`DEP_AWS_LC_RS_*_SYS_LIBCRYPTO`) and fails the build if it is missing, empty, or contains a path separator or control character. An unprefixed build reports `crypto`, which is accepted.

## 7. Residuals you must not make worse

[`docs/usage.md`](docs/usage.md) section 11 lists them:

- a `PrivateKeyDer` handed to rustls is rustls's to hold;
- each distinct ordered `signature_schemes` list leaks one static verifier table.

Section 9 lists what a policy or profile does not restrict. A change that widens any of these needs its own decision record.

## 8. Hard rules

- **No new cryptographic primitives.** Every primitive is AWS-LC's, through aws-lc-rs. This crate selects, composes and checks; it does not implement.
- **No validation claim beyond the module's certificate.** The crate reports the module a build links and that module's certificate status. Never write, in code, docs, a commit or a pull request, that the crate is validated, certified or FIPS-compliant, or that a deployment's operating system or hardware is covered by a certificate.
- **Secret material is zeroizing from allocation and never grows.** A buffer holding a private key, PKCS#8, plaintext or a derived key is a `zeroize::Zeroizing` buffer from the moment it is allocated, sized once, and never reaches `Debug`, `Display` or an error value.
- **No product or vendor names** in compatibility text. Describe the class of peer, for example "legacy applications that aren't TLS 1.3 capable".
- **Comments only where the code cannot be read without one:** one to three lines giving the mechanism or the invariant. Reasoning and history go in the commit message or a decision record.
- **No `unsafe`.** Every crate sets `unsafe_code = "forbid"` through the workspace lints.
- **No `aws_lc_rs` re-export.** The backend re-exports `rustls`, and `rcgen` only under `test-support`.
- **Typed refusals.** Only `Approved` is approved: `AlgorithmTested`, `NotApproved` and `Unverified` never are. Direct operations on an algorithm a backend lacks are refused with `CryptoError::Unavailable`. **Amended 2026-10-29:** named profile resolution intersects the published set with line availability after Options, reports every line exclusion in `excluded`, and refuses any empty family with `EmptyProfile`. No silent exclusions and no approval filtering; see [decision 0006](docs/decisions/0006-per-line-profile-resolution.md).

## 9. Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line whose name and email match the commit's author, certifying the Developer Certificate of Origin below. `git commit -s` adds it. CI refuses a pull request with any commit that lacks one.

For AI-assisted work, the human who submits the change signs off, and by doing so certifies the DCO for the whole change and takes responsibility for it. An AI tool cannot sign off.

The text, verbatim from <https://developercertificate.org>:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## 10. AI assistance

AI assistance is allowed. It must be disclosed in the pull request template's "AI assistance used" field: say which tools, and what they were used for. A pull request whose AI-generated content is not disclosed is closed.

Disclosure does not lower the bar. The gates, the oracle rules and the hard rules above apply in full.

## 11. Licensing

crypto-profile is licensed under MIT OR Apache-2.0. Contributions are accepted under the same terms (inbound equals outbound): unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

The provider ports code from rustls (MIT) and rustls-webpki (ISC); their notices are in [`crypto-profile/LICENSE-THIRD-PARTY`](crypto-profile/LICENSE-THIRD-PARTY), and each published package carries an identical copy. A file that ports third-party code names its source, version and licence in a header, and its licence text is in each package's `LICENSE-THIRD-PARTY`; the copies stay identical.

## Isolated backend workspaces

The root workspace contains core and the 4.x backend. The 3.x backend is an
excluded workspace with its own lockfile; root `--workspace` commands do not
check it. Run its tests and lints separately:

```sh
cargo test --manifest-path crypto-profile-awslc3/Cargo.toml --all-features --locked
cargo clippy --manifest-path crypto-profile-awslc3/Cargo.toml --all-targets --all-features --locked -- -D warnings
```

Run both backend suites with `AWS_LC_FIPS_SYS_STATIC=1` and `=0`. Both packages
claim `links = "crypto-profile-backend"`. The exact dependency pins refuse a
consumer containing both first; the shared links key guards that graph if the
pins ever become compatible. `ci/backend-links-negative.sh` verifies both links
values, each individual control, and the combined refusal with its actual reason.
Select exactly one backend per application.

The 3.x lockfile pins aws-lc-fips-sys to 0.13.17, preserving the selected module
provenance. Its build script requires the forwarded libcrypto metadata to be exactly
`aws_lc_fips_0_13_17_crypto` because its linkage derivation mirrors that
builder's rules. Missing or different metadata refuses the build, including in
a downstream consumer's dependency graph. Runtime conformance checks the
actual loaded library for each linkage.

Only 4.x supports `crypto_profile_provider_direct`; use it for root coverage
and mutation discovery. Run 3.x coverage and mutation analysis separately,
without that cfg. Its mutation configuration does not cross into the root
workspace or rediscover the emitted shared bodies.

The 4.x manifest pins aws-lc-rs 1.18.2 and rcgen 0.14.10; its lockfile selects aws-lc-fips-sys 0.14.2. The 3.x manifest pins aws-lc-rs 1.17.4 and rcgen 0.14.9. Both pin rustls 0.23.46 and rustls-webpki 0.103.16. Preserve the explanatory pin comments when updating dependencies.
