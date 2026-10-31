# crypto-profile

[![CI](https://github.com/crypto-profile/crypto-profile/actions/workflows/ci.yml/badge.svg)](https://github.com/crypto-profile/crypto-profile/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/crates/msrv/crypto-profile?logo=rust&label=rust)](Cargo.toml)
[![License](https://img.shields.io/crates/l/crypto-profile)](#licensing)

Named cryptographic profiles for Rust: a policy layer and a [rustls](https://github.com/rustls/rustls) `CryptoProvider` over [aws-lc-rs](https://github.com/aws/aws-lc-rs).

## What it is

One reviewed place for an application's cryptographic choices:

- **Profiles.** Named, inspectable algorithm sets an application selects at start-up that report unavailable module-line entries in `Resolved::excluded` and refuse any empty family. See [Profiles](#profiles).
- **A rustls provider** whose key-exchange groups, cipher suites and signature schemes follow a `tls::Policy`, and `fips::assert_fips_module`, which an application calls at start-up to refuse to run unless the loaded module reports FIPS mode.
- **The functions applications need beside TLS,** each implemented once:
  - hashing;
  - random bytes;
  - AEAD with module-chosen nonces;
  - a sealed box;
  - signature keys, signing and verification;
  - certificate-request generation.
- **A capability table** that records, for each certified or submitted module and each algorithm, whether the backend implements it and what the published evidence says about it: the module's security policy, cited by table for every sourced cell, or, for a module with no published security policy, one CAVP certificate, which is never an approval ([decision 0004](docs/decisions/0004-algorithm-tested.md)).

## What it is not

- **Not new cryptography.** Every primitive is AWS-LC's, through aws-lc-rs.
- **Not a validated module, and not FIPS-certified.** The validation status that matters is the AWS-LC FIPS module's, which this crate builds on; it does not change it or claim it. See the AWS-LC [FIPS module status](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md).
- Not affiliated with AWS or the rustls project.

## AWS-LC FIPS module lines

Cargo resolves one `aws-lc-rs` 1.x per lockfile, so each module line gets its own backend crate. Your `Cargo.toml` then shows which line you are on.

| Backend | Module line | Status |
|---|---|---|
| `crypto-profile-awslc4` | AWS-LC FIPS 4.x, through aws-lc-rs 1.18 | Built from AWS-LC 4.2.0; 4.x is in CMVP review. |
| `crypto-profile-awslc3` | AWS-LC FIPS 3.x, through aws-lc-rs 1.17 | Built from AWS-LC 3.6.0; the 3.1.0 release carries the certificates below. |

Select exactly one backend per build. Both declare `links = "crypto-profile-backend"`. Today their exact aws-lc-rs pins refuse a combined graph first; the shared links key also refuses it if those pins become compatible. Each backend exposes `awslc_version()` for the exact runtime-linked release, separately from `certificate(MODULE)`.

AWS-LC 3.6.0 is a later revision of the AWS-LC FIPS 3.x line whose 3.1.0 release has the certificates below.

The modules' certificate status, as recorded when this file was last updated (read 2026-10-28). The [CMVP lists](https://csrc.nist.gov/projects/cryptographic-module-validation-program) are authoritative.

| Module | Status |
|---|---|
| AWS-LC FIPS 3.1.0 | Validated: certificate [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314) (static) and [#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298) (dynamic). |
| AWS-LC FIPS 4.x | Submitted, in CMVP review; no security policy published yet. Static and dynamic are separate submissions ([AWS-LC `FIPS.md`](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md), "Modules in Process"). |

aws-lc-rs 1.17.4 with its `fips` feature compiles ML-DSA out, so the 3.x backend refuses ML-DSA with a typed error rather than fall back. See [`docs/usage.md`](docs/usage.md) for linkage, what the crate claims, and its limits.

## Profiles

A profile is an algorithm set, not a validation claim.

- `unrestricted`: every algorithm in the inventory. Not a government profile.
- `preferred`: the crate's recommendation, as [`docs/profiles.md`](docs/profiles.md) defines it. Not a government profile.
- `cnsa2`: CNSSP 15 (December 2024) Annex B, on TLS 1.3 as the crate maps it.
- `cnsa1`: CNSSP 15 (20 October 2016) Annex B in RFC 9151's TLS profile; a transition profile for CNSA 1.0 counterparts, with its gaps named in [`docs/profiles.md`](docs/profiles.md).
- `bsi`: BSI TR-02102-2 and TR-02102-1, version 2026-01.
- `fips1403`: what FIPS 140-3 approves under the published texts.
- `fips1402`: what FIPS 140-2 approved, for peers whose boundary is 140-2.

Resolution intersects the published profile set with module-line availability after Options, preserving preference order and reporting every line exclusion. This changes neither the governing text nor the module approval claim. See [per-line resolution](docs/decisions/0006-per-line-profile-resolution.md).

The option "post-quantum key exchange required" (`Options { pq_key_exchange_required: true, ..Options::default() }`) keeps only ML-KEM and hybrid key exchange on any profile, and so TLS 1.3 only. Whether the running module is validated for a resolved profile is a separate call, `assert_module_approves`, which fails closed.

## Documentation

- [`docs/usage.md`](docs/usage.md): choosing a backend, linkage, what the crate claims, TLS policies, limits and residuals.
- [`docs/profiles.md`](docs/profiles.md): the profiles, their governing texts and contents, the post-quantum option, module approval, named residuals and the after-2030 table.
- [`docs/sources.md`](docs/sources.md): every document the profiles, citations and capability cells depend on, with edition, issuer link and SHA-256.
- [`docs/decisions/`](docs/decisions/): the decision records.
- [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and [`CHANGELOG.md`](CHANGELOG.md).

## Licensing

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

AWS-LC, which this crate links, carries its own terms, including the OpenSSL licence for parts of the FIPS module. Anyone distributing binaries is responsible for its notices.

The provider ports code from rustls (MIT) and rustls-webpki (ISC); their notices are in [`crypto-profile/LICENSE-THIRD-PARTY`](crypto-profile/LICENSE-THIRD-PARTY), and each published package carries an identical copy.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
