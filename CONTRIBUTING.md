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

CI runs these on every pull request. While the repository is private, CI runs formatting, clippy, cargo-deny, the MSRV check, the Linux x86_64 tests on both linkages and the DCO check; run coverage, mutation testing, and the macOS and arm64 tests locally before you open a pull request.

| Gate | Command |
|---|---|
| Formatting | `cargo fmt --all --check` |
| Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Supply chain | `cargo deny --locked check` |
| Tests, static | `cargo test --workspace --all-features --locked` |
| Tests, dynamic | `AWS_LC_FIPS_SYS_STATIC=0 cargo test --workspace --all-features --locked` |
| Coverage | `cargo llvm-cov --workspace --all-features --locked --fail-under-lines 95 --ignore-filename-regex '(test_support\|conformance)'` |
| Mutation | `cargo mutants --workspace` |
| Docs | `cargo doc --workspace --all-features --no-deps`, with no warnings |

`--all-features` matters: the conformance suite needs the backend's `test-support` feature and is skipped without it.

`clippy.toml` refuses rustls's stock-provider entry points (`disallowed-methods`). Code that has to call one, as `crypto-profile-awslc4/src/tls.rs` does to build a provider from a policy, carries `#[expect(clippy::disallowed_methods)]` on that function and nowhere wider.

## 3. The quality bar

One bar for all shipped code ([decision 0003](docs/decisions/0003-quality-bar.md)):

- at least **95% line coverage**;
- **0 missed mutants** from `cargo mutants`.

The test infrastructure (`crypto-profile-awslc4/src/test_support.rs` and the conformance scaffolding under `crypto-profile/src/conformance/`) is not shipped behaviour and is excluded from both. Nothing else is excluded by file.

**A mutant exception** is the last resort, for a mutant no honest test can kill: an equivalent mutant, or one whose only input is a fixed property of the build. It is one `exclude_re` entry in `.cargo/mutants.toml` that matches exactly that mutant, with a comment above it giving the reason and what covers the risk instead. For example:

```toml
# The decision is fips_result, tested both ways; the wrapper's only input is the loaded module's FIPS_mode(), which a FIPS build cannot make false.
"^crypto-profile-awslc4/src/fips\\.rs:[0-9]+:[0-9]+: replace assert_fips_module -> Result<\\(\\), CryptoError> with Ok\\(\\(\\)\\)$",
```

A file-level exclusion, or a pattern that matches more than one mutant, is refused in review.

## 4. The test oracles stay independent

A test that checks a mapping against the mapping itself proves nothing. The suite keeps its expected values apart from the code under test:

- **Registry codepoints.** Core carries literal IANA values: `iana()` for every cipher suite, key-exchange group, signature scheme and TLS version (`crypto-profile/src/algorithm.rs`, pinned by `iana_codepoints_are_the_registry_values`). Every backend mapping is tested against them (`every_mapping_carries_its_registry_codepoint` in `crypto-profile-awslc4/src/tls.rs`). The handshake helper reads the negotiated suite, group and scheme as wire codepoints and maps them back through `iana()`, never through the mapping under test (`crypto-profile-awslc4/src/test_support.rs`).
- **CSR signatures.** Every algorithm's CSR signature is verified by rustls-webpki's `aws_lc_rs` verifiers, chosen by a literal per-algorithm table in the test, and the CSR's signature-algorithm OID is compared with core's literal `signature_oid()` (`every_algorithm_signs_a_request_for_its_own_key` in `crypto-profile-awslc4/src/csr.rs`). A wrong hash or OID in the signing path fails it.
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
7. **Decide which profiles admit it.** Add it to each profile constant in `crypto-profile/src/profile.rs` whose governing text admits it, with the citation in the constant's doc comment, and update the golden table in `crypto-profile-awslc4/tests/profiles.rs`. A regime-named profile admits only what its cited edition's tables admit.

## 6. Adding a backend

A backend is a crate named for its module line. It must:

- expose the same module paths and signatures as `crypto-profile-awslc4` (`aead`, `csr`, `digest`, `fips`, `random`, `sealbox`, `signature`, `tls`) and re-export the core crate;
- declare `pub const MODULE: Module`, with the linkage taken from the build, never assumed. If the build cannot report it, the build fails;
- run the shared suite from its own tests:

  ```rust
  crypto_profile::conformance_tests!(your_crate);
  ```

The suite checks the backend against the known answers, walks every capability cell for its `MODULE`, and checks that the test binary's linkage matches `MODULE`.

`conformance_tests!` expands to `use your_crate::*;` and names these paths in your crate, so it compiles only if each exists with the shape `crypto-profile-awslc4` gives it (`crypto-profile/src/conformance/mod.rs`, `conformance_tests`):

- the core crate's types re-exported at the crate root (`SignatureAlgorithm`, `TlsVersion`, `CipherSuite`, `KxGroup`, `TlsSignatureScheme`, `Algorithm`, `CryptoError` and the rest), and `MODULE`;
- `test_support::handshake(client: &Policy, server: &Policy, key: SignatureAlgorithm) -> Result<Negotiated, String>`, behind a `test-support` feature that the test target requires (`required-features = ["test-support"]`). It runs a real in-process handshake and reports the version, suite, group and scheme from their wire codepoints, mapped back through the core crate's `iana()`;
- `tls::Policy`, with the four public list fields, and `tls::crypto_provider`;
- `signature::KeyPair::generate`, `KeyPair::sign`, `KeyPair::public_key` and `signature::verify`;
- `digest::digest`;
- `aead::KEY_LEN`, `aead::NONCE_LEN` and `aead::Aes256GcmKey`, with `new` and `open_in_place`;
- `sealbox::PrivateKey::from_pkcs8_der` and `sealbox::open`.

The linkage test looks for the 4.x shared library by name, `libaws_lc_fips_0_14_2_crypto`; a backend on another aws-lc-fips-sys version needs that name changed in the macro.

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
- **Typed refusals.** Only `Approved` is approved: `AlgorithmTested`, `NotApproved` and `Unverified` never are, and an algorithm a backend lacks is refused with `CryptoError::Unavailable`, never dropped silently.

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
