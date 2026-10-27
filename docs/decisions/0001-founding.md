# 0001: Founding scope, structure and claim discipline

- **Status:** Accepted, 2026-10-28
- **Provenance:** the code came from `darkhonor/maknae@b8416f6`, `crates/maknae-crypto`.

## Context

Applications that build on the AWS-LC FIPS module through aws-lc-rs, with rustls for TLS, each re-implement the same choices: which algorithms to allow, how to build a rustls provider from them, how to check that the process is running the FIPS module, and how to describe all of that to a reviewer. Each copy drifts, and each makes its own claims about validation.

Three facts shape any shared implementation:

1. **One aws-lc-rs 1.x per lockfile.** Cargo resolves a single aws-lc-rs 1.x per build, so one crate cannot carry both the 3.x module line (aws-lc-rs 1.17) and the 4.x line (aws-lc-rs 1.18), even behind separate features.
2. **Each linkage is a separate module.** The AWS-LC FIPS 3.1.0 module carries certificate #5314 for its static build and #5298 for its dynamic build, each with its own security policy. The 4.x module is in CMVP review as separate static and dynamic submissions (AWS-LC `crypto/fipsmodule/FIPS.md:13-14,56-60`).
3. **The two lines differ in what they can do.** aws-lc-rs 1.17.4 compiles ML-DSA out under `fips` (`aws-lc-rs-1.17.4/src/lib.rs:283-284`); 1.18.2 does not (`aws-lc-rs-1.18.2/src/signature.rs:1177`).

## Decision

1. **Scope.** crypto-profile is one reviewed implementation of the cryptography an application needs, over the AWS-LC FIPS module through aws-lc-rs, with rustls for TLS. It adds no primitives: every primitive is AWS-LC's. Its algorithm inventory is sized by what applications need and by what lets one named profile differ from another, not by everything AWS-LC offers.
2. **One backend crate per module line.** A core crate, `crypto-profile`, holds the algorithm types, the capability model and the conformance suite, and has no aws-lc dependency. Each module line gets its own backend crate (`crypto-profile-awslc4` now, `crypto-profile-awslc3` in round 3), which pins its aws-lc-rs. Every backend exposes the same module paths and signatures and re-exports the core crate; core's conformance suite, run by every backend, is what proves they agree. There is no trait-based backend abstraction. Backends implement their whole inventory; narrowing it is a profile's job.
3. **Capabilities are keyed by `Module { line, linkage }`.** Because static and dynamic builds are separate modules, with separate certificates or submissions, each capability cell belongs to one module, and each sourced cell cites that module's own security policy and table. The backend declares `MODULE` from its build, and the build fails when the linkage cannot be determined.
4. **The algorithm enums are exhaustive.** `SignatureAlgorithm`, `TlsSignatureScheme`, `CipherSuite`, `KxGroup`, `HashAlgorithm`, `TlsVersion` and `Algorithm` are not `#[non_exhaustive]`, and every `match` on them, in core, in a backend or in the conformance macro, lists every variant with no `_` arm. A new algorithm then fails to compile until every backend mapping and every capability cell handles it. Adding a variant is a minor-version bump while the crate is 0.x. The error types (`CryptoError`, `CsrError`, `TlsError`, `Family`), `ModuleLine`, `Linkage` and `CertStatus` stay `#[non_exhaustive]`.
5. **Claim discipline.**
   - The crate reports the module a build links (`MODULE`) and that module's certificate status as of the crate version's release (`certificate()`). The CMVP lists are authoritative.
   - It never claims to be validated or certified itself.
   - It never claims that a deployment's operating system or processor is among a certificate's tested operational environments; that is the deployer's determination.
   - An approval no published source settles is `Approval::Unverified`, which is never treated as approved. Every 4.x approval is `Unverified` until a 4.x security policy is published.
   - It does not claim that a build is the certified or submitted module's exact source: the bundled AWS-LC versions (4.2.0 for the 4.x backend) differ from the module versions under certificate or review.
6. **No product or vendor names** in compatibility text. A compatibility limit names the class of peer, for example "legacy applications that aren't TLS 1.3 capable".

## Consequences

- An application's `Cargo.toml` shows its module line, and changing line is a dependency change, not a code change.
- Supporting the 3.x line needs its own backend and, because rustls 0.23.44 and later and rcgen 0.14.10 require aws-lc-rs 1.18, its own rustls provider. That is round 3.
- A new algorithm is a compile error until every cell and mapping is decided, which is the intent; it also makes each addition a semver event.
- The crate's statements about validation are limited to what a reviewer can check against a named security policy and table. Where none exists, the crate says `Unverified` and the documentation says why.
- A certificate status recorded in a released version can go stale; users are pointed to the CMVP lists.
