# 0012: One shape per family, and `#[non_exhaustive]` extension points

Date: 2026-11-01. Status: accepted.

## Context

By 0.9.0 every public enum and options struct was exhaustive (decision 0001 §4), so each new family, algorithm, option or profile was a breaking release. The families outside TLS had also drifted: `DerivedKey` lived in `hkdf`, `signature` and `sealbox` named key import differently, and `Family` named only the TLS families. ECDH (#33), AEAD (#44), hashing (#45) and signatures outside TLS (#46) all land in 0.10.0. The maintainer ruled on 2026-11-01 to make the API coherent now and to make 0.10.0 the last deliberate break.

## Decision

**One shape per family outside TLS.** Every family the crate governs outside TLS follows one pattern:

- It takes `&Admitted`, which only `admit(profile, options)` builds. Admission is its first profile check: after any check that its arguments are well formed (a `kdf::Spec` whose algorithm does not match its variant is refused with `CryptoError::KdfSpecMismatch`), it refuses what the profile does not admit (`CryptoError::NotInProfile`, or `CryptoError::Unavailable` for what the module line lacks), before any input rule.
- Keys cross the boundary as DER under uniform `*_der` names: `from_pkcs8_der`, `to_pkcs8_der`, `from_spki_der`, `spki_der`. `signature::KeyPair::from_pkcs8` and `pkcs8_der()` become `from_pkcs8_der` and `to_pkcs8_der()`, the names `sealbox` already used. The names are uniform; the return shapes are not yet. `signature::KeyPair::to_pkcs8_der()` borrows the PKCS#8 document the key was built from (`&[u8]`), while `sealbox::PrivateKey::to_pkcs8_der()` serialises on demand and returns a zeroizing owned buffer (`Result<Zeroizing<Vec<u8>>, CryptoError>`). A public key is borrowed in both, but `signature::KeyPair::public_key()` is the raw key (the SPKI BIT STRING contents) and `sealbox::PublicKey::spki_der()` the whole SubjectPublicKeyInfo. `sealbox`'s keys move onto `ecdh` in #33's ECDH change, which settles one export shape for both. *(Amended 2026-11-02, #33: settled by one rule (maintainer): **a key is held once, and exporting a key held elsewhere returns an owned, zeroizing copy.** SP 800-57 Part 1 Rev. 5 §5.5.2 item 9 lists "Destroying keys as soon as they are no longer needed", and §8.2 says "A key should be destroyed as soon as that key is no longer needed in order to reduce the risk of exposure"; a second, resident copy kept only so an export can be borrowed is a copy no operation needs. `sealbox::PrivateKey` holds its key in its `ecdh::StaticKey` only, and its `to_pkcs8_der()` keeps 0.9.0's `Result<Zeroizing<Vec<u8>>, CryptoError>`, encoded on each call. `signature::KeyPair` is unchanged: its PKCS#8 document is its only copy of the key, so `to_pkcs8_der()` borrows it. `public_key()` is the raw key in both, the uncompressed point for the sealed box; `sealbox::PrivateKey::recipient()` is the `sealbox::PublicKey`; [decision 0011](0011-ecdh-and-one-step-kdf.md).)*
- A derivation returns `kdf::DerivedKey`, zeroized on drop, from `kdf::derive(&admitted, secret, &spec, len)`. `kdf::Spec` carries the KDF and every input but the secret, so a later KDF is a new `Spec` variant, not a new function. A `Spec` whose variant does not match its algorithm is refused with `CryptoError::KdfSpecMismatch`, before admission. The unreleased `hkdf` module became `kdf`.
- Each operation has one implementation, in the shared backend body, and a family that needs another family's operation calls it, not the library. `sealbox` does not yet: it still calls aws-lc-rs's HKDF directly, and moves onto `ecdh` and `kdf` in #33's ECDH change, as ECDH completing into a KDF will. *(Amended 2026-11-02, #33: done; `sealbox` calls `ecdh` and `kdf`, and `ecdh` completes into `kdf`.)*
- One enum names a family everywhere: `Family` has the TLS families of a policy and `Mac`, `Kdf` and `KeyAgreement`.

**Approval per family.** `assert_admitted_approved(&admitted, families)` checks the families the caller uses (maintainer, 2026-11-01: "As we expand beyond TLS we need to address the pieces that matter in the context they belong."). In order: `CryptoError::NotFips` outside FIPS mode; `CryptoError::FamilyNotAdmitted` for a TLS family named, or any family the backend does not walk, because `assert_module_approves` checks TLS and the backend walks no other family; `CryptoError::KdfInfoMayBeEmpty` only when `Family::Kdf` is named and the profile admits KDFs and an empty `info` (decision 0010); then the cells of the named families, `Mac`, then `Kdf`, then `KeyAgreement`, whatever order they were named in, failing on the first that is not `Approved`. Asserting nothing approves nothing: an empty list, or a family the profile admits nothing in, is not a refusal. A caller that uses only HMAC under `unrestricted` is no longer refused for the KDF `info` rule.

**Types before operations.** `KeyAgreementAlgorithm` (ECDH on P-256, P-384 and P-521, and X25519) and the one-step KDF variants of `KdfAlgorithm` (SP 800-56C Rev. 2 §4.1) land as types before their operations, so the operations add no break. Until a backend implements one, its cell is unavailable and `Unverified` on every module: `ensure_available` refuses it with `CryptoError::Unavailable`, no profile lists it, and a one-step algorithm in `kdf::Spec::Hkdf` is refused with `KdfSpecMismatch`. A one-step KDF's `max_output_len()` is 2^30 bytes, the bound AWS-LC's `SSKDF` enforces on both module lines (`SSKDF_MAX_INPUT_LEN`), inside SP 800-56C Rev. 2 §4.1's (2^32 − 1) × HashLen bits. *(Note 2026-11-02, #33: both backends now implement them, and the profiles admit them; [decision 0011](0011-ecdh-and-one-step-kdf.md).)*

**`#[non_exhaustive]` on the extension points.** A new variant of one of these enums, or a new field of one of these structs, is an addition, not a breaking change:

| Type | Why it may grow |
|---|---|
| `SignatureAlgorithm`, `TlsSignatureScheme`, `CipherSuite`, `KxGroup`, `HashAlgorithm`, `MacAlgorithm`, `KdfAlgorithm`, `KeyAgreementAlgorithm`, `TlsVersion` | New algorithms: ML-KEM in more profiles, AEAD (#44), hashing (#45), signatures outside TLS (#46) |
| `Algorithm` | A new family |
| `Profile`, `GoverningText` | A new profile, or a profile governed by a new kind of text |
| `Options`, `ProfileSpec`, `Selection`, `AdmittedSelection` | A new option, or a new family's list |
| `tls::Policy`, `Resolved` (each backend) | A new policy field, or a new family in a resolved profile (maintainer, 2026-11-01). `Policy` is built from `Policy::default()`, `Resolved` only by `resolve` |
| `ParseAlgorithmError`, `ParseProfileError` | A parse error may later name what was being parsed |
| `kdf::Spec` | A new KDF (the one-step KDF, #33) |
| `PeerCertificateRuleId`, `PeerCertificateRule`, `PeerKeyRule`, `RsaSizeRule` | One rule per `Profile`, so a new profile is a new rule; a new key family is a new `PeerKeyRule` field |
| `PeerCurve`, `PeerKey`, `CertificateSignature`, `PeerCertificateViolation` | A new curve (Brainpool) or signature algorithm (#46, SLH-DSA) in a certificate |
| `csr::KeyUsage`, `csr::ExtendedKeyUsage`, `csr::CsrParams` (each backend) | More of RFC 5280's key usages and extended key usages, and new request fields. `CsrParams` is built from `CsrParams::default()` |
| `test_support::Negotiated` (each backend, `test-support` feature) | A new negotiated parameter a third-party backend's tests read |
| `CryptoError::EmptyProfile` (the variant) | A new field naming why the family is empty |

`CryptoError`, `CsrError`, `TlsError`, `Family`, `ModuleLine`, `Linkage` and `CertStatus` were already `#[non_exhaustive]`. These stay exhaustive, each for its reason:

| Type | Why it stays exhaustive |
|---|---|
| `Approval` | A security outcome: a new status must fail to compile until every site that decides approval decides it |
| `Module`, `Certificate`, `Capability` | Built by struct literal in the backend crates (`MODULE`, and capability tables in tests) |
| `PeerVerifierIdentity` | The backend's certificate verifier matches it to decide whether the profile's path rule runs; a wildcard there would have to choose between checking and skipping |
| `MlDsaParameterSet` | FIPS 204 defines exactly three parameter sets; a pre-hash ML-DSA would be a new `CertificateSignature` variant |

`PeerLeaf` (a borrowed view, built only by the backend) and `sealbox_wire` (constants of a versioned format) are not extension points and are unchanged.

Every `ALL` list (each algorithm enum's, and `Profile::ALL`) is a `&'static [T]`, so a new variant changes its length, not its type. Code outside the crate iterates it (`for &a in HashAlgorithm::ALL`) and does not depend on its length.

The handshake-scheme mask in `PeerVerifierIdentity::Owned` is a `u64`, with bit `preference()` per `TlsSignatureScheme`. Core asserts at compile time that `TlsSignatureScheme::ALL` fits it, so the 65th scheme fails to compile instead of wrapping a shift.

`CryptoError`'s other struct-like variants, `TlsError`'s, and the new `KeyAgreementPeerKey` and `KeyAgreementPrivateKey` are not per-variant `#[non_exhaustive]`: the backends build them (and the ECDH change builds the two key-agreement ones), and the attribute would forbid that outside the core crate. Adding a field to one of them is a breaking change, accepted here. `kdf::Spec`'s variant is not either, because callers build `Spec::Hkdf`.

**The backend wildcard rule.** Inside the core crate every `match` on these enums still lists every variant with no `_` arm, so core does not compile until each cell and identifier is decided. The backends are other crates (the shared body and provider are expanded into each), so their matches carry a `_` arm, always the last, and it refuses: `CryptoError::Unavailable` naming the algorithm (digest, HMAC, KDF, signature, TLS and provider mappings; `kdf` maps the one-step variants to `KdfSpecMismatch` in their own arm, and its `_` is "not on this module"), or the family's own refusal (`FamilyNotAdmitted` in `assert_admitted_approved`, `false` from the `matches_spki` predicate, `false` for a peer key or RSA size rule the certificate check does not know, `CertificateSignature::Unknown` for a signature it cannot classify, and a refused certificate for a `PeerCertificateRuleId` the verifier cannot map to a profile). Never a default algorithm. One deliberate compile-time stop remains in the backends: `kdf.rs` matches `HashAlgorithm::ALL` against `[a, b, c]` in a `const` block to bound its zero salt, and any other length panics there, so a new hash fails to compile until the salt table is checked. A mapping that could not refuse now can: `digest::digest` and `digest::Hasher::new` return `Result`. In test code the `_` arm panics, naming the value. The `ALL` walks (`conformance_capability_honesty`, the registry-codepoint tests, the known-answer tests) are what catch a variant core gains and a backend lacks: the variant reaches the refusal or the panic, and the walk fails.

**`Options`, `Policy` and `CsrParams` are built from their default.** Outside the defining crate, `let mut o = Options::default(); o.pq_key_exchange_required = true;`, and likewise `Policy::default()` and `CsrParams::default()`; `Resolved` comes only from `resolve`, and the peer-certificate rules only from `peer_certificate_rule`. A struct expression, with or without `..Options::default()`, does not compile. Inside the defining crate the struct literals stay, which `clippy::field_reassign_with_default` prefers there.

**0.10.0 is the last deliberate break** (maintainer, 2026-11-01). Later families, algorithms, options and profiles ship as 0.10.x additions.

## Consequences

- Decision 0001 §4 ("the algorithm enums are exhaustive") is superseded for these types and amended in place, as are CONTRIBUTING §5 and decisions 0004, 0005, 0006, 0008 and 0010.
- The backends lose compile-time exhaustiveness. A new core variant compiles in a backend that does not map it; there it is refused at run time, and the `ALL` walks fail until the backend maps it. This is the named residual of this design, accepted in #33.
- Each refusing `_` arm is unreachable while every variant is mapped, so it is an uncovered line under decision 0003's 95% bar. Its named sibling arms are tested through cargo-mutants' "delete match arm" mutants, which the `ALL` walks catch.
- The 4.x `ensure` mutant exception in `.cargo/mutants.toml` (kept under decision 0003's rule) is removed: the new cells make some 4.x cells unavailable, and a test now kills the mutant. If every 4.x cell becomes available again, the exception's premise returns and the change that does it restores the exception. *(Amended 2026-11-02, #33: the ECDH change made every 4.x cell available and restored the exception; [decision 0011](0011-ecdh-and-one-step-kdf.md).)*
- Breaking, once, for 0.9.0 callers: `docs/usage.md` §15 lists each change.
