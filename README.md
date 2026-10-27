# crypto-profile

Named cryptographic profiles for Rust: a policy layer and a [rustls](https://github.com/rustls/rustls) `CryptoProvider` over [aws-lc-rs](https://github.com/aws/aws-lc-rs).

> **Status: pre-release.** The API is being extracted from [Maknae](https://github.com/darkhonor/maknae)'s `maknae-crypto` crate and will change before 0.1.

## What it is

One reviewed place for an application's cryptographic choices:

- **Profiles.** Named, inspectable algorithm sets an application selects at start-up and that fail closed when the build can't satisfy them:
  - `preferred`
  - `cnsa` (CNSA 2.0)
  - `bsi` (BSI TR-02102)
  - `fips1403`
  - `fips1402`
- **A rustls provider** whose key-exchange groups, cipher suites and signature schemes follow the selected profile, with a start-up assertion that the process is running the FIPS module.
- **The functions applications need beside TLS,** each implemented once:
  - hashing;
  - random bytes;
  - AEAD with crate-chosen nonces;
  - a sealed box;
  - signature-algorithm selection;
  - key and certificate-request generation.

## What it is not

- **Not new cryptography.** Every primitive is AWS-LC's, through aws-lc-rs.
- **Not a validated module, and not FIPS-certified.** The validation status that matters is the AWS-LC FIPS module's, which this crate builds on; it does not change it or claim it. See the AWS-LC [FIPS module status](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md).
- Not affiliated with AWS or the rustls project.

## AWS-LC FIPS module lines

Cargo can resolve only one `aws-lc-rs` 1.x per build, so each module line gets its own backend crate. Your `Cargo.toml` then shows which line you are on.

| Backend | Module line | Status |
|---|---|---|
| `crypto-profile-awslc4` | AWS-LC-FIPS 4.x | Planned first. 4.0 is under CMVP review. |
| `crypto-profile-awslc3` | AWS-LC-FIPS 3.x | Planned for projects that must stay on the validated 3.x line. |

The 3.x FIPS line has no ML-DSA, so `cnsa` refuses to start on it rather than quietly falling back.

## Licensing

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

AWS-LC, which this crate links, carries its own terms, including the OpenSSL licence for parts of the FIPS module. Anyone distributing binaries is responsible for its notices.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
