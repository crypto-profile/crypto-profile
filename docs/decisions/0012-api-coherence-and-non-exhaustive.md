# 0012: One shape per family, and `#[non_exhaustive]` extension points

Date: 2026-11-01. Status: accepted.

## Context

By 0.9.0 every public enum and options struct was exhaustive (decision 0001 §4), so each new family, algorithm, option or profile was a breaking release. The families outside TLS had also drifted: `DerivedKey` lived in `hkdf`, `signature` and `sealbox` named key import differently, and `Family` named only the TLS families. ECDH (#33), AEAD (#44), hashing (#45) and signatures outside TLS (#46) all land in 0.10.0. The maintainer ruled on 2026-11-01 to make the API coherent now and to make 0.10.0 the last deliberate break.

## Decision

**One shape per family outside TLS.** Every family the crate governs outside TLS follows one pattern, so a caller who knows one knows the rest:

- It takes `&Admitted`, which only `admit(profile, options)` builds. Admission is its first profile check: after any check that its arguments are well formed (a `kdf::Spec` whose algorithm does not match its variant is refused with `CryptoError::KdfSpecMismatch`), it refuses what the profile does not admit (`CryptoError::NotInProfile`, or `CryptoError::Unavailable` for what the module line lacks), before any input rule.
- Keys cross the boundary as DER under `*_der` names: `from_pkcs8_der`, `to_pkcs8_der`, `from_spki_der`. `signature::KeyPair::from_pkcs8` and `pkcs8_der()` become `from_pkcs8_der` and `to_pkcs8_der()`, the names `sealbox` already used, and a raw public key is borrowed: `public_key() -> &[u8]`.
- A derivation returns `kdf::DerivedKey`, zeroized on drop, from `kdf::derive(&admitted, secret, &spec, len)`. `kdf::Spec` carries the KDF and every input but the secret, so a later KDF is a new `Spec` variant, not a new function. A `Spec` whose variant does not match its algorithm is refused with `CryptoError::KdfSpecMismatch`, before admission. The unreleased `hkdf` module became `kdf`.
- Each operation has one implementation, in the shared backend body. A later family that needs it (ECDH completing into a KDF, `sealbox`) calls it, not the library.
- One enum names a family everywhere: `Family` has the TLS families of a policy and `Mac`, `Kdf` and `KeyAgreement`.

**Approval per family.** `assert_admitted_approved(&admitted, families)` checks the families the caller uses (maintainer, 2026-11-01: "As we expand beyond TLS we need to address the pieces that matter in the context they belong."). In order: `CryptoError::NotFips` outside FIPS mode; `CryptoError::FamilyNotAdmitted` for a TLS family named, or any family the backend does not walk, because `assert_module_approves` checks TLS and the backend walks no other family; `CryptoError::KdfInfoMayBeEmpty` only when `Family::Kdf` is named and the profile admits KDFs and an empty `info` (decision 0010); then the cells of the named families, `Mac`, then `Kdf`, then `KeyAgreement`, whatever order they were named in, failing on the first that is not `Approved`. Asserting nothing approves nothing: an empty list, or a family the profile admits nothing in, is not a refusal. A caller that uses only HMAC under `unrestricted` is no longer refused for the KDF `info` rule.

**Types before operations.** `KeyAgreementAlgorithm` (ECDH on P-256, P-384 and P-521, and X25519) and the one-step KDF variants of `KdfAlgorithm` (SP 800-56C Rev. 2 §4.1) land as types before their operations, so the operations add no break. Until a backend implements one, its cell is unavailable and `Unverified` on every module: `ensure_available` refuses it with `CryptoError::Unavailable`, no profile lists it, and a one-step algorithm in `kdf::Spec::Hkdf` is refused with `KdfSpecMismatch`. A one-step KDF's `max_output_len()` is 2^30 bytes, the bound AWS-LC's `SSKDF` enforces on both module lines (`SSKDF_MAX_INPUT_LEN`), inside SP 800-56C Rev. 2 §4.1's (2^32 − 1) × HashLen bits.

**`#[non_exhaustive]` on the extension points.** A new variant or field of these is not a breaking change:

| Type | Why it may grow |
|---|---|
| `SignatureAlgorithm`, `TlsSignatureScheme`, `CipherSuite`, `KxGroup`, `HashAlgorithm`, `MacAlgorithm`, `KdfAlgorithm`, `KeyAgreementAlgorithm`, `TlsVersion` | New algorithms: ML-KEM in more profiles, AEAD (#44), hashing (#45), signatures outside TLS (#46) |
| `Algorithm` | A new family |
| `Profile`, `GoverningText` | A new profile, or a profile governed by a new kind of text |
| `Options`, `ProfileSpec`, `Selection`, `AdmittedSelection` | A new option, or a new family's list |
| `tls::Policy`, `Resolved` (each backend) | A new policy field, or a new family in a resolved profile (maintainer, 2026-11-01). `Policy` is built from `Policy::default()`, `Resolved` only by `resolve` |
| `ParseAlgorithmError`, `ParseProfileError` | A parse error may later name what was being parsed |
| `kdf::Spec` | A new KDF (the one-step KDF, #33) |

`CryptoError`, `CsrError`, `TlsError`, `Family`, `ModuleLine`, `Linkage` and `CertStatus` were already `#[non_exhaustive]`. These stay exhaustive, each for its reason:

| Type | Why it stays exhaustive |
|---|---|
| `Approval` | A security outcome: a new status must fail to compile until every site that decides approval decides it |
| `Module`, `Certificate`, `Capability` | Built by struct literal in the backend crates (`MODULE`, and capability tables in tests) |
| `PeerVerifierIdentity` | The backend's certificate verifier matches it to decide whether the profile's path rule runs; a wildcard there would have to choose between checking and skipping |

The peer-certificate types (decision 0007), `CsrParams`, `KeyUsage`, `ExtendedKeyUsage`, `PeerLeaf` and `sealbox_wire` are not extension points and are unchanged.

**The backend wildcard rule.** Inside the core crate every `match` on these enums still lists every variant with no `_` arm, so core does not compile until each cell and identifier is decided. The backends are other crates (the shared body and provider are expanded into each), so their matches carry a `_` arm, always the last, and it refuses: `CryptoError::Unavailable` naming the algorithm (digest, HMAC, KDF, signature, TLS and provider mappings; `kdf` maps the one-step variants to `KdfSpecMismatch` in their own arm, and its `_` is "not on this module"), or the family's own refusal (`FamilyNotAdmitted` in `assert_admitted_approved`, `false` from the `matches_spki` predicate). Never a default algorithm. One deliberate compile-time stop remains in the backends: `kdf.rs` destructures `HashAlgorithm::ALL` (`let [a, b, c] = HashAlgorithm::ALL;`) in a `const` block to bound its zero salt, so a new hash fails to compile there until the salt table is checked. A mapping that could not refuse now can: `digest::digest` and `digest::Hasher::new` return `Result`. In test code the `_` arm panics, naming the value. The `ALL` walks (`conformance_capability_honesty`, the registry-codepoint tests, the known-answer tests) are what catch a variant core gains and a backend lacks: the variant reaches the refusal or the panic, and the walk fails.

**`Options` and `Policy` are built from their default.** Outside the defining crate, `let mut o = Options::default(); o.pq_key_exchange_required = true;`, and likewise `Policy::default()`; `Resolved` comes only from `resolve`. A struct expression, with or without `..Options::default()`, does not compile. Inside the defining crate the struct literals stay, which `clippy::field_reassign_with_default` prefers there.

**0.10.0 is the last deliberate break** (maintainer, 2026-11-01). Later families, algorithms, options and profiles ship as 0.10.x additions.

## Consequences

- Decision 0001 §4 ("the algorithm enums are exhaustive") is superseded for these types and amended in place, as are CONTRIBUTING §5 and decisions 0004, 0005, 0006, 0008 and 0010.
- The backends lose compile-time exhaustiveness. A new core variant compiles in a backend that does not map it; there it is refused at run time, and the `ALL` walks fail until the backend maps it. This is the named residual of this design, accepted in #33.
- Each refusing `_` arm is unreachable while every variant is mapped, so it is an uncovered line under decision 0003's 95% bar. Its named sibling arms are tested through cargo-mutants' "delete match arm" mutants, which the `ALL` walks catch.
- The 4.x `ensure` mutant exception in `.cargo/mutants.toml` (kept under decision 0003's rule) is removed: the new cells make some 4.x cells unavailable, and a test now kills the mutant. If every 4.x cell becomes available again, the exception's premise returns and the change that does it restores the exception.
- Breaking, once, for 0.9.0 callers: `docs/usage.md` §15 lists each change.
