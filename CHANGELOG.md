# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it publishes. Nothing is published yet; the first release will be 0.1.0.

## [Unreleased]

### Added

- The core crate `crypto-profile`, with no aws-lc dependency:
  - exhaustive algorithm types: `SignatureAlgorithm`, `TlsSignatureScheme`, `CipherSuite`, `KxGroup`, `HashAlgorithm`, `TlsVersion` and `Algorithm`, with literal IANA codepoints (`iana()`), the canonical TLS signature-scheme order (`TlsSignatureScheme::preference`) and X.509 signature OIDs (`signature_oid()`), and `FromStr` and `Display` for `SignatureAlgorithm`;
  - the capability model: `Module { line, linkage }`, `certificate()` and `capability()`, where each 3.x cell cites the AWS-LC FIPS 3.1.0 security policy of its own certificate, #5314 (static) or #5298 (dynamic): an `Approved` cell cites Table 5 (pp. 8-11), a `NotApproved` cell cites its absence from Tables 5-8, and the hybrid key-exchange groups and TLS 1.3 are `Unverified`, with no source; every 4.x static cell is `Unverified`, and each 4.x dynamic cell is `Approval::AlgorithmTested`, citing the one AWS-LC FIPS 4.0.0 CAVP certificate that shows every operation it needs, or `Unverified` (decision record 0004); `AlgorithmTested`, like `Unverified`, is never approved;
  - the seven profiles `unrestricted`, `preferred`, `cnsa2`, `cnsa1`, `bsi`, `fips1403` and `fips1402` as the public `ProfileSpec` constants `UNRESTRICTED`, `PREFERRED`, `CNSA2`, `CNSA1`, `BSI`, `FIPS1403` and `FIPS1402`, each entry cited in its constant's doc comment (0.x API: names and contents may change before 0.1); `Profile`, with `Profile::ALL`, `as_str`, `spec` and `governing_text`, `FromStr` and `Display` over exact names, and `ParseProfileError` for a name that is not a profile; and `GoverningText`;
  - `Options` and its one option, post-quantum key exchange required (`pq_key_exchange_required`), with `Display` and `KxGroup::is_post_quantum`;
  - `crypto_profile::profile::select`, the backend-independent half of resolution, which returns a `Selection` and refuses an algorithm the module lacks rather than dropping it;
  - typed errors: `CryptoError`, with `Unavailable(Algorithm)`, `PolicyEmpty(Family)`, `PolicyDuplicate(Algorithm)`, `PolicyDrift`, `EmptyProfile`, `KeyNotInProfile` and `NotApproved`, `Family::KeyAlgorithm`, and the typed causes `CsrError` and `TlsError`;
  - the sealed box's version-1 framing (`sealbox_wire`);
  - the conformance suite behind the `conformance` feature, run by every backend through `conformance_tests!`, including the profile golden tables and distinction handshakes.
- The backend `crypto-profile-awslc4`, on the AWS-LC FIPS 4.x module through aws-lc-rs 1.18.2:
  - `MODULE`, with the linkage read from the build; the build fails if aws-lc-rs does not report it;
  - `digest`, `random`, `aead` (AES-256-GCM with module-chosen nonces), `sealbox` (P-384 ECDH, HKDF-SHA384, AES-256-GCM), `signature` (key generation, signing, verification and the SubjectPublicKeyInfo shape check) and `csr` (PKCS#10 requests with a DN, DNS, IP and URI SANs, EKU and key usage, signed by the request's own key);
  - `tls`: `Policy`, `crypto_provider`, the client and server builders, `install_default`, `assert_provider_matches`, `load_private_key` and the certificate-verifier builders, over the crate's own provider with TLS 1.2 enabled; a policy's signature schemes are a set, carried in `TlsSignatureScheme::preference` order, and a duplicate entry in any list is refused with `PolicyDuplicate`; the verification tables and key providers rustls takes by `'static` reference are cached per distinct set of signature schemes, at most 2^n − 1 for the n schemes in the inventory (2,047 today);
  - `fips`: `assert_fips_module`, `assert_fips_client_config`, `assert_fips_server_config`, `certificate` and `approval`;
  - the signing-scheme constraint: a key loaded through a provider built from a `tls::Policy` (the builders' `with_single_cert` and `with_client_auth_cert`, and `tls::load_private_key`, which now takes the policy) signs only with a scheme that is in both the peer's offer and `signature_schemes`, and when none is, a server's handshake fails and a client sends an empty Certificate (a failure only if the server requires client authentication); `Resolved::certified_key`, which also refuses a key the profile does not admit and a chain whose end-entity certificate does not carry the key (`TlsError::KeyMismatch`); and `assert_provider_matches` refuses a provider whose key provider is not the policy's;
  - `resolve`, `Resolved` and `Resolved::admit_key`, and `assert_module_approves`, which refuses with `NotFips` outside FIPS mode, with `PolicyEmpty` for an empty family, and then every cell that is not `Approved`;
  - `test_support::handshake_with_ca`, a handshake whose CA key algorithm the caller chooses;
  - `test_support::FIPS_LIBRARY`, the FIPS module's crypto library name, taken from aws-lc-rs's link metadata by the build script; the build fails if aws-lc-rs does not report it or reports anything but a bare file name;
  - the `rustls` re-export, and `rcgen` under the `test-support` feature.
- Known-answer tests: Wycheproof (ECDSA, Ed25519, RSA PKCS#1 v1.5 SHA-384, ML-DSA-87, AES-GCM), NIST CAVP SHA-2, RFC 8032 and a sealed-box version-1 blob.
- Documentation: `docs/usage.md`, `docs/profiles.md`, `CONTRIBUTING.md` (with the Developer Certificate of Origin and the AI-assistance disclosure), `SECURITY.md`, decision records 0001 to 0004 and the pull request template.
- `docs/sources.md`: every document a profile, citation or capability cell depends on, with the edition followed, the issuer's link and the SHA-256 of the copy the maintainers read; linked from `docs/profiles.md` and the README.
- The crate's own rustls `CryptoProvider`: written once in core and emitted by the core `provider!` macro, which `crypto-profile-awslc4` instantiates (decision record 0005). The cryptography is the module's through aws-lc-rs; rustls supplies the TLS protocol.
- QUIC on the provider's TLS 1.3 suites: packet and header protection and RFC 9001's packet limits, ported from rustls's built-in aws-lc-rs provider, so `rustls::quic` connections (HTTP/3, for example) keep working as they did on rustls's own suites; tested against RFC 9001 Appendix A, a QUIC handshake and rustls's suites (#12).
- `KxGroup::Secp384r1MlKem1024` (SecP384r1MLKEM1024, 0x11ED, RFC 10024), `Unverified` on every module, in `unrestricted`, `preferred` and `fips1403`.
- `crypto-profile-awslc4/tests/differential.rs`, which checks the provider against rustls's built-in one; `ci/shipped-graph.sh`, which refuses a stock rustls provider in the shipped graph; and the OpenSSL interop test (`crypto-profile-awslc4/tests/openssl_interop.rs`, `ci/openssl-interop.sh`), which negotiates SecP384r1MLKEM1024 with OpenSSL 3.5 in both directions.

### Changed

- `crypto-profile-awslc4` builds rustls with `std` and `tls12` only, so the re-exported `rustls` no longer has a built-in provider: `rustls::crypto::aws_lc_rs` (with its `Ticketer`, `hpke`, `cipher_suite`, `kx_group` and `sign`) and `rustls::crypto::default_fips_provider` are gone, and `ClientConfig::builder()`, `ServerConfig::builder()` and the WebPKI verifiers' `builder()` no longer install a provider: they panic unless one is installed as the process default (`tls::install_default`), or the features another crate in the build unifies onto rustls name exactly one of `aws_lc_rs` and `ring` and not `custom-provider`, in which case they install rustls's stock provider.

### Known 0.x items

These are known and left for a later 0.x release, which may change them incompatibly:

- `CryptoError`'s `Display` writes algorithms, approvals and causes with their `Debug` form (for example `Protocol(Tls13)` and `AlgorithmTested { cavp: "…" }`), so operator-facing messages carry Rust syntax.
- `Options` has a public field and is not `#[non_exhaustive]`, so adding an option is a breaking change.
