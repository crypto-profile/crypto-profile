# Using crypto-profile

This guide covers round 1: the core crate `crypto-profile` and the backend `crypto-profile-awslc4`. The named profiles are round 2 and are not described here.

Citations of the form `crate-x.y.z/path:line` refer to that crate's published source at that version. Paths without a version refer to this repository.

## 1. Choosing a backend

There is one backend crate per AWS-LC FIPS module line:

| Backend | aws-lc-rs | Module line |
|---|---|---|
| `crypto-profile-awslc4` | 1.18.2 (`fips`), which builds aws-lc-fips-sys 0.14.2 | AWS-LC FIPS 4.x |
| `crypto-profile-awslc3` (round 3) | 1.17.x (`fips`), which builds aws-lc-fips-sys 0.13.x | AWS-LC FIPS 3.x |

Cargo resolves one aws-lc-rs 1.x per lockfile, so a single crate cannot offer both lines, even behind separate features. Each backend therefore pins its own aws-lc-rs, and an application depends on exactly one. Its `Cargo.toml` then shows which module line it builds.

Every backend exposes the same module paths (`aead`, `csr`, `digest`, `fips`, `random`, `sealbox`, `signature`, `tls`), re-exports the core crate, and declares `pub const MODULE: Module`. Writing `use crypto_profile_awslc4 as crypto;` keeps a later change of module line to one line of `Cargo.toml`.

ML-DSA is available only on the 4.x backend: aws-lc-rs 1.17.4 compiles its `pqdsa` module out under `fips` (`aws-lc-rs-1.17.4/src/lib.rs:283-284`), while 1.18.2 exposes `signature::ML_DSA_87_SIGNING` unconditionally (`aws-lc-rs-1.18.2/src/signature.rs:1177`). The capability table marks ML-DSA unavailable on 3.x, so the 3.x backend will refuse it with `CryptoError::Unavailable` (`crypto-profile/src/capability.rs`, `three_x` and `ensure_available`).

## 2. Static or dynamic linkage

**Selecting it.** aws-lc-fips-sys reads the environment variable `AWS_LC_FIPS_SYS_STATIC`, or the target-scoped `AWS_LC_FIPS_SYS_STATIC_<target_triple_with_underscores>`, which it checks first (`aws-lc-fips-sys-0.14.2/builder/main.rs:183-204,883`). The value is read case-insensitively: one beginning `0`, `n`, `off` or `f` means dynamic; one beginning with any other digit, or with `y`, `on` or `t`, means static (`builder/main.rs:266-286`). There is no Cargo feature for it.

**The default when it is unset** (`aws-lc-fips-sys-0.14.2/builder/main.rs:288-306`):
- static on Linux and the BSDs, on x86_64 and aarch64;
- dynamic everywhere else, macOS included.

AWS-LC supports static FIPS builds only on Linux ("Static FIPS builds are only supported on Linux platforms", AWS-LC `crypto/fipsmodule/FIPS.md:50-54`, at commit `add9bcbc`), and the aws-lc-fips-sys README calls a shared `libcrypto` "the required form for FIPS on macOS and Windows" (`aws-lc-fips-sys-0.14.2/README.md:170`).

**Each linkage is a separate module, with its own certificate or submission.**

| Module | Static | Dynamic |
|---|---|---|
| AWS-LC FIPS 3.1.0 | certificate #5314 | certificate #5298 |
| AWS-LC FIPS 4.x | separate submission, in CMVP review | separate submission, in CMVP review |

Sources: the CMVP certificate pages for [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314) and [#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298); AWS-LC `crypto/fipsmodule/FIPS.md:13-14` (3.1) and `:56-60` (4.0, "Modules in Process").

**How the crate knows.** aws-lc-fips-sys 0.14.2 reports `link_kind` (`static` or `dylib`) as build metadata (`aws-lc-fips-sys-0.14.2/README.md:11-24`), and aws-lc-rs re-exports it under its own `links` key (`aws-lc-rs-1.18.2/build.rs:53-124`). The backend's build script (`crypto-profile-awslc4/build.rs`) reads the variable matching `DEP_AWS_LC_RS_*_SYS_LINK_KIND`, found by prefix because the name embeds the aws-lc-rs version. If the variable is absent or holds anything other than `static` or `dylib`, the build fails; the crate never guesses a linkage.

On Linux, a dynamic build loads `libaws_lc_fips_0_14_2_crypto.so`. The conformance test `conformance_linkage_matches_the_binary` (`crypto-profile/src/conformance/mod.rs`) checks `/proc/self/maps` for that library against `MODULE.linkage`. On macOS the test looks for `libaws_lc_fips_0_14_2_crypto.dylib` in `otool -L`; that name has not yet been observed on a macOS build.

**Reading it at run time.**
- `crypto_profile_awslc4::MODULE` is the `Module { line, linkage }` this build links (`crypto-profile-awslc4/src/lib.rs`).
- `crypto_profile_awslc4::fips::certificate()` returns that module's `Certificate`: its name, its number (absent while in review), its status as recorded when this crate version was released, and its security-policy URL (absent while none is published) (`crypto-profile/src/capability.rs`, `certificate`).

**The non-FIPS `aws-lc-sys`.** rustls's `fips` feature enables its `aws_lc_rs` feature, which turns on `aws-lc-rs/aws-lc-sys` (`rustls-0.23.46/Cargo.toml`, `[features]`). rcgen's `aws_lc_rs` feature does the same. So `aws-lc-sys` 0.46.0 is in the lockfile and is compiled. With `fips` on, aws-lc-rs binds the FIPS library instead (`extern crate aws_lc_fips_sys as aws_lc`, `aws-lc-rs-1.18.2/src/lib.rs:245-248`), None of the round 1 test binaries, static or dynamic, contains a symbol from the non-FIPS library. Each library's symbols carry a version prefix, so the check is repeatable: `nm <test binary> | grep -c aws_lc_0_46_0_` gives 0, and `grep -c aws_lc_fips_0_14_2_` gives about 2,280.

## 3. What the crate claims, and what it doesn't

The crate claims two things:
- which module a build links, as `MODULE`;
- that module's certificate status as of the crate version's release, as `certificate()`, with the security-policy citation behind every capability cell.

The [CMVP validated and Modules In Process lists](https://csrc.nist.gov/projects/cryptographic-module-validation-program) are authoritative. A status recorded in a released crate does not move when the CMVP list does.

The crate never claims:
- that it is validated or certified itself;
- that a deployment's operating system or processor is a tested operational environment. Both 3.x certificates list Amazon Linux 2023 only, on Graviton4 and Xeon Platinum 8375C, each with and without PAA (#5314 and #5298 security policies, Table 3, p. 7). Whether a deployment falls inside a certificate's operational environments is the deployer's determination.

**The 4.x module** is submitted, in CMVP review, with no security policy published (AWS-LC `FIPS.md:56-60`; the CMVP [Modules In Process list](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list), read 2026-10-28). With no policy to cite, every 4.x approval cell is `Approval::Unverified`, and `certificate()` reports `CertStatus::InProcess` with no number (`crypto-profile/src/capability.rs`, `four_x` and `certificate`). `Unverified` is never treated as approved (`Approval::is_approved`).

## 4. Build prerequisites

The FIPS build compiles AWS-LC from source, so the build host needs:
- a C and C++ compiler toolchain (`aws-lc-rs-1.18.2/README.md:22`);
- CMake and Go, which FIPS builds require (`aws-lc-rs-1.18.2/README.md:29`);
- Perl, a hard dependency of the AWS-LC FIPS build (`aws-lc-fips-sys-0.14.2/README.md:218-221`);
- clang (libclang), when the target platform needs bindings generated with bindgen (`aws-lc-rs-1.18.2/README.md:29,94`).

AWS-LC's [`BUILDING.md`](https://github.com/aws/aws-lc/blob/main/BUILDING.md) is the full reference.

## 5. Using rustls

Use the re-exported crate: `crypto_profile_awslc4::rustls`. Don't declare `rustls` as a dependency of your own.

- The backend builds rustls 0.23.46 with `default-features = false` and the features `fips`, `std` and `tls12` (`crypto-profile-awslc4/Cargo.toml`). A direct dependency with rustls's defaults adds `aws_lc_rs`, `logging`, `prefer-post-quantum`, `std` and `tls12` (`rustls-0.23.46/Cargo.toml`, `[features] default`), and Cargo unifies those onto the one rustls in your build.
- Avoiding a direct dependency does not fix rustls's features. Cargo unifies features across the whole dependency graph, so any other crate that depends on rustls adds its own; an async TLS adapter with its default features, for example, adds `aws_lc_rs`, `logging` and `tls12` (`tokio-rustls-0.26.6/Cargo.toml`, `[features] default`). `cargo tree -e features -i rustls` shows what your build enables. Only the rustls version is fixed, by the backend's `=0.23.46` pin.
- Build configurations through `tls::client_builder`, `tls::server_builder`, `tls::install_default` and the two verifier builders, which all take a `Policy`. rustls's own `ClientConfig::builder()` and `ServerConfig::builder()` use the process-default provider, and when none is installed they install rustls's stock aws-lc-rs provider from its crate features (`rustls-0.23.46/src/crypto/mod.rs:243-286`). That provider carries rustls's defaults, not your policy.

**Residual: provider internals are reachable.** `rustls::crypto::CryptoProvider` has public fields: the cipher suites, the key-exchange groups, the signature verification algorithms, the random source and the key provider. Code holding a provider can call the primitives behind them directly. This repository's `clippy.toml` refuses the entry points it lists (`disallowed-methods`), such as key-exchange `start`, the HPKE functions, `SecureRandom::fill` and `KeyProvider::load_private_key`, in the crate's own code; it does not list every primitive reachable this way, but that lint does not reach your crate. Round 3 replaces the built-in provider with one this project owns.

## 6. TLS policies

`tls::Policy` (`crypto-profile-awslc4/src/tls.rs`) lists what a TLS configuration may use, each list in preference order:

| Field | Meaning |
|---|---|
| `versions` | protocol versions |
| `cipher_suites` | cipher suites; a suite whose version is not in `versions` is not offered |
| `kx_groups` | key-exchange groups |
| `signature_schemes` | the handshake signature schemes this side accepts from its peer |

`tls::crypto_provider(&Policy)` builds a provider carrying exactly the policy's suites, groups and schemes, in the policy's order. It refuses:
- an empty `versions`, `kx_groups` or `signature_schemes` list, or a cipher-suite list left empty once suites of unlisted versions are dropped, with `CryptoError::PolicyEmpty(family)`;
- an algorithm the backend's module does not have, with `CryptoError::Unavailable(alg)`.

`tls::assert_provider_matches(&provider, &policy)` refuses a provider whose suites, groups or schemes differ from the policy's, or are in a different order, with `CryptoError::PolicyDrift`.

**What `signature_schemes` restricts:** the schemes this side's verifier accepts for the peer's handshake signature. The provider and both verifier builders carry the same list. **What it does not restrict** is in section 9.

## 7. Compatibility limits

These follow from rustls; they apply to any configuration this crate builds.

- **Legacy applications that aren't TLS 1.3 capable** can connect over TLS 1.2 only with ECDHE key exchange and an AEAD cipher suite. rustls's TLS 1.2 suites are ECDHE with ECDSA or RSA authentication and AES-GCM or ChaCha20-Poly1305, and no others (`rustls-0.23.46/src/crypto/aws_lc_rs/mod.rs:145-155`).
- There are no CBC suites, no RSA key transport and no finite-field DHE. A peer that needs one of these cannot connect.
- **A FIPS provider refuses a TLS 1.2 peer without Extended Master Secret.** rustls sets `require_ems` from the provider's FIPS status (`rustls-0.23.46/src/client/builder.rs:166`, `src/server/builder.rs:104`) and enforces it in the TLS 1.2 handshake (`src/client/tls12.rs:110`, `src/server/tls12.rs:82`). The 3.x security policies list the TLS KDF "using non-extended master secret" as Non-Approved, Not Allowed (#5314 Table 8, p. 12). The test `tls12_fips_config_requires_ems` (`crypto-profile-awslc4/src/tls.rs`) pins this.

## 8. Two different FIPS questions

The backend answers two questions that are easy to confuse.

**rustls's FIPS-mode classification.** `fips::assert_fips_client_config` and `fips::assert_fips_server_config` (`crypto-profile-awslc4/src/fips.rs`) refuse a configuration for which rustls's `fips()` is false. That holds when the module reports FIPS mode and rustls classifies every cipher suite, key-exchange group and signature verification algorithm, the random source and the key provider as FIPS (`rustls-0.23.46/src/crypto/mod.rs:294-307`), with Extended Master Secret required where TLS 1.2 is enabled (`src/client/client_conn.rs:396-409`, `src/server/server_conn.rs:553-563`).
- A policy with X25519 or ChaCha20-Poly1305 fails it: rustls marks both as not FIPS (`rustls-0.23.46/src/crypto/ring/kx.rs:81-93`; `src/crypto/aws_lc_rs/tls13.rs:116-118`, `tls12.rs:240-242`).
- A policy with the hybrid groups X25519MLKEM768 or SECP256R1MLKEM768 passes it. rustls classifies a hybrid by whichever component comes first, following SP 800-56C Rev. 2 (`rustls-0.23.46/src/crypto/aws_lc_rs/pq/hybrid.rs:71-90`).

**The crate's validation claim.** `fips::approval(alg)` returns the capability cell's `Approval` for this build's module, as the module's security policy states it. It is void (`Unverified`) unless the module reports FIPS mode at the time of the call (`crypto-profile-awslc4/src/fips.rs`, `approval` and `approval_given`).
- On 3.x, the hybrid groups are `Unverified`, because neither 3.x security policy mentions hybrid key establishment, and so is TLS 1.3, because the policies' TLS KDF row lists v1.0/1.1 and v1.2 only (`crypto-profile/src/capability.rs`, `three_x`).
- On 4.x, everything is `Unverified`, because no 4.x security policy is published.

**Passing the first is not the second.** A configuration that rustls classifies as FIPS can include algorithms whose approval this crate cannot source. Use `assert_fips_*` to refuse X25519, ChaCha20 and non-EMS TLS 1.2; use `approval` for what the module's security policy says.

`fips::assert_fips_module()` is a third, narrower check: it refuses unless the loaded AWS-LC module reports FIPS mode. The sealed box calls it on every seal and open. On a dynamic build it is the application's own check that the library the loader found is in FIPS mode. A shared library is found at run time, and if the FIPS library's directory is not on the loader's path, a different `libcrypto` may be loaded (`aws-lc-fips-sys-0.14.2/README.md:170-176`). aws-lc-fips-sys also links a start-up check that aborts the process if the runtime library is not in FIPS mode, to catch shared-library shadowing (`README.md:163-166`).

## 9. What a policy does not restrict in round 1

- **Certificate-chain signature algorithms.** The verifiers keep rustls's full list of algorithms for signatures on certificates (`WebPkiSupportedAlgorithms::all`); a `Policy` narrows only the handshake-signature mapping (`crypto-profile-awslc4/src/tls.rs`, `verification_algorithms`).
- **The scheme a local signing key chooses.** rustls picks the scheme this side signs with from the peer's offer and the key's type; `signature_schemes` does not narrow it.
- **The algorithm of a key passed to `tls::load_private_key`.** The key is loaded through rustls's key provider and is not checked against any policy (`crypto-profile-awslc4/src/tls.rs`, `load_private_key`).

## 10. Which module a build is

The 4.x backend compiles aws-lc-fips-sys 0.14.2, which bundles AWS-LC 4.2.0 source (`AWSLC_VERSION_NUMBER_STRING "4.2.0"`, `aws-lc-fips-sys-0.14.2/aws-lc/include/openssl/base.h:125`). The module in CMVP review is AWS-LC-FIPS v4.0 (AWS-LC `FIPS.md:56-60`). Whether this build is the submitted module is unverified, and the crate does not claim it.

The same caution applies to round 3: aws-lc-fips-sys 0.13.17 bundles AWS-LC 3.6.0 source (`aws-lc-fips-sys-0.13.17/aws-lc/include/openssl/base.h:125`), while the 3.x certificates validate the source tag AWS-LC-FIPS-3.1.0 (#5314 security policy, §11.1, p. 72). Whether a 0.13.17 build is the certified 3.1.0 module is unverified, and the 3.x backend will not claim it.

## 11. Secret-handling residuals

The crate holds secret material in zeroizing buffers that are sized at allocation and never grow. Two places fall outside that, and a contributor must not widen them:

- **Key generation.** `signature::KeyPair::generate` generates through rcgen, so the new key sits inside rcgen's key pair, outside a zeroizing buffer, until that key pair drops at the end of `generate`. Its PKCS#8 encoding is copied into a zeroizing buffer first (`crypto-profile-awslc4/src/signature.rs`, `KeyPair::generate`).
- **Keys handed to rustls.** A `PrivateKeyDer` passed to `tls::load_private_key`, or to a rustls configuration, is rustls's to hold and drop.

Two further residuals hold no secret material:

- **Per-policy verifier tables.** Each distinct ordered `signature_schemes` list leaks one static verification-algorithm table, cached for the life of the process (`crypto-profile-awslc4/src/tls.rs`, `verification_algorithms`). This is bounded by the number of distinct lists an application builds.
- **RSA public exponents.** `signature::verify` checks an RSA public key's length against the size its algorithm names, and those lengths assume the exponent 65537, which is what `KeyPair::generate` produces. A key whose exponent encodes to a different length is refused with `CryptoError::Verify`, so that case fails closed. An exponent with the same encoded length, such as 65539, passes the length check and is left to aws-lc. Exponents other than 65537 are unsupported, and no test exercises one (`crypto-profile-awslc4/src/signature.rs`, `verify` and `matches_spki`).

## 12. Known-answer coverage

The conformance suite (`crypto-profile/src/conformance/`, run by every backend) checks the backend against these vectors. Their provenance and SHA-256 digests are in `crypto-profile/src/conformance/vectors/SOURCES.md`.

| Area | Vectors |
|---|---|
| ECDSA verification | Wycheproof P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 |
| Ed25519 verification | Wycheproof, and RFC 8032 §7.1 tests 1 to 3 |
| RSA PKCS#1 v1.5 SHA-384 verification | Wycheproof at 2048, 3072 and 4096 bits |
| ML-DSA-87 verification | Wycheproof, the cases with an empty context only; the backend verifies under the empty context |
| AES-256-GCM | Wycheproof, 256-bit keys with 96-bit nonces and 128-bit tags, opening only |
| SHA-256, SHA-384, SHA-512 | NIST CAVP byte-oriented short messages |
| Sealed box | a version-1 known-answer blob from an independent implementation, which must open unchanged |

Gaps, and what covers them instead:
- **ECDSA P-521/SHA-384** has no Wycheproof file. Its signatures are checked by the CSR test, which verifies every algorithm's CSR signature with rustls-webpki (`crypto-profile-awslc4/src/csr.rs`, `every_algorithm_signs_a_request_for_its_own_key`).
- **RSA-PSS** is verified through TLS handshakes over the three PSS schemes, not through Wycheproof. `signature::verify` checks PKCS#1 v1.5, the scheme this crate's RSA keys sign CSRs with.
- **AES-GCM sealing** has no known answers, because sealing never takes a caller's nonce: the module chooses it (`crypto-profile-awslc4/src/aead.rs`). Round trips and refusals cover sealing.
