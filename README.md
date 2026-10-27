# crypto-profile

Named cryptographic profiles for Rust: a policy layer and a [rustls](https://github.com/rustls/rustls) `CryptoProvider` over [aws-lc-rs](https://github.com/aws/aws-lc-rs).

> **Status: pre-release, and the repository is private.** The API will change before 0.1. Nothing is published to crates.io.

## What it is

One reviewed place for an application's cryptographic choices:

- **Profiles.** Named, inspectable algorithm sets an application selects at start-up and that fail closed when the build can't satisfy them. None is built yet; they are round 2 (see below).
- **A rustls provider** whose key-exchange groups, cipher suites and signature schemes follow a `tls::Policy`, and `fips::assert_fips_module`, which an application calls at start-up to refuse to run unless the loaded module reports FIPS mode.
- **The functions applications need beside TLS,** each implemented once:
  - hashing;
  - random bytes;
  - AEAD with module-chosen nonces;
  - a sealed box;
  - signature keys, signing and verification;
  - certificate-request generation.
- **A capability table** that records, for each certified or submitted module and each algorithm, whether the backend implements it and what the module's security policy says about it, citing the policy table for every sourced cell.

## What it is not

- **Not new cryptography.** Every primitive is AWS-LC's, through aws-lc-rs.
- **Not a validated module, and not FIPS-certified.** The validation status that matters is the AWS-LC FIPS module's, which this crate builds on; it does not change it or claim it. See the AWS-LC [FIPS module status](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md).
- Not affiliated with AWS or the rustls project.

## AWS-LC FIPS module lines

Cargo resolves one `aws-lc-rs` 1.x per lockfile, so each module line gets its own backend crate. Your `Cargo.toml` then shows which line you are on.

| Backend | Module line | Status |
|---|---|---|
| `crypto-profile-awslc4` | AWS-LC FIPS 4.x, through aws-lc-rs 1.18 | Built in round 1. |
| `crypto-profile-awslc3` | AWS-LC FIPS 3.x, through aws-lc-rs 1.17 | Planned for round 3. |

The modules' certificate status, as recorded when this file was last updated (read 2026-10-28). The [CMVP lists](https://csrc.nist.gov/projects/cryptographic-module-validation-program) are authoritative.

| Module | Status |
|---|---|
| AWS-LC FIPS 3.1.0 | Validated: certificate [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314) (static) and [#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298) (dynamic). |
| AWS-LC FIPS 4.x | Submitted, in CMVP review; no security policy published yet. Static and dynamic are separate submissions ([AWS-LC `FIPS.md`](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md), "Modules in Process"). |

aws-lc-rs 1.17.4 with its `fips` feature compiles ML-DSA out, so the 3.x backend will refuse ML-DSA with a typed error rather than fall back. See [`docs/usage.md`](docs/usage.md) for linkage, what the crate claims, and its limits.

## Profiles (round 2)

These are planned. Round 1 builds none of them; it builds the algorithm inventory and the capability model they will be defined over.

- `unrestricted`
- `preferred`
- `cnsa2`
- `cnsa1`
- `bsi`
- `fips1403`
- `fips1402`

## Documentation

- [`docs/usage.md`](docs/usage.md): choosing a backend, linkage, what the crate claims, TLS policies, limits and residuals.
- [`docs/decisions/`](docs/decisions/): the decision records.
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and [`CHANGELOG.md`](CHANGELOG.md).

## Licensing

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

AWS-LC, which this crate links, carries its own terms, including the OpenSSL licence for parts of the FIPS module. Anyone distributing binaries is responsible for its notices.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
