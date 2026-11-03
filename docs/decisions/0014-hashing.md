# 0014: Hashing under a profile, with SHA-3

Date: 2026-11-03. Status: accepted.

## Context

Before this decision `digest::digest(h, data)`, `digest::Hasher::new(h)`, `digest::sha256(data)` and `digest::sha256_hex(data)` took no `Admitted`: no profile governed hashing, so a `cnsa2` caller could hash with SHA-256, which CNSSP 15 (December 2024) Annex B does not admit. `HashAlgorithm` named SHA-256, SHA-384 and SHA-512 only, although both module lines implement SHA3-256, SHA3-384 and SHA3-512 inside the module boundary, aws-lc-rs exposes them on both pins, and `bsi`, `fips1403` and `fips1402` admit them. The SHA-256 helpers fixed an algorithm a profile should choose.

## Decision

**SHA-3 (maintainer, 2026-11-03).** `HashAlgorithm` gains `Sha3_256`, `Sha3_384` and `Sha3_512` (FIPS 202), the three aws-lc-rs exposes on both pins, beside `Sha256`, `Sha384` and `Sha512` (FIPS 180-4). Its configuration names are `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384` and `sha3-512` (`as_str`, `Display`, `FromStr`), and `output_len()` is 32, 48 or 64 bytes. The enum was already `#[non_exhaustive]` (decision 0012), so the variants are an addition; the deliberate compile stops change with them (decision 0012, amended).

**Types and API (maintainer, 2026-11-03).** `Family::Hash`, `ProfileSpec::hashes`, `AdmittedSelection::hashes`, `Admitted::hashes()` and `Admitted::admit_hash` follow the other families outside TLS (decision 0008). `assert_admitted_approved` walks the hash cells last, after the AEAD cells.

```rust
pub fn digest(a: &Admitted, h: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
impl Hasher {
    pub fn new(a: &Admitted, h: HashAlgorithm) -> Result<Hasher, CryptoError>;
    pub fn algorithm(&self) -> HashAlgorithm;
    pub fn update(&mut self, data: &[u8]);
    pub fn finish(self) -> Vec<u8>;
}
```

- **Refusal order:** admission (`Admitted::admit_hash`: `NotInProfile`, or `Unavailable` for a hash the module line lacks), then the module (`Unavailable` for a hash this backend does not map). The admission is in a helper that `digest` and `Hasher::new` call, because cargo-mutants does not mutate a method named `new` (#40).
- **The module mapping** is `aws_lc_rs::digest::{SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512}`; the backend's `match` ends in an `_` arm that refuses (decision 0012).
- **`Hasher` is not `Clone`,** so a partial hash cannot be forked, and its `Debug` names the algorithm only.

**The SHA-256 helpers are removed (maintainer, 2026-11-03).** `digest::sha256` and `digest::sha256_hex` fixed an algorithm the profile should choose, and hexadecimal formatting is not cryptography. `digest::digest(&admitted, HashAlgorithm::Sha256, data)` replaces the first; a caller that needs `[u8; 32]` or hexadecimal converts the `Vec<u8>` itself.

**No input-length check.** FIPS 180-4 §1 (Figure 1, p. 3) limits SHA-256's message to fewer than 2^64 bits, and SHA-384's and SHA-512's to fewer than 2^128; FIPS 202 sets no limit. The crate does not count:

- a `&[u8]` passed to `digest` cannot reach 2^64 bits (2^61 bytes) on a supported platform: an x86_64 or aarch64 address space holds at most 2^57 bytes;
- a `Hasher` fed through `update` would need 2^61 bytes fed to one hasher. aws-lc-rs counts the bytes fed and panics in `update` once the total passes `u64::MAX` (`Context::try_update`), which is beyond SHA-256's limit; the module's SHA-256 counter, two 32-bit words of bits, wraps without refusing (`crypto/fipsmodule/digest/md32_common.h`, both lines).

No test allocates or feeds such a message.

**No truncation.** `digest` and `Hasher::finish` return the full-length digest. FIPS 140-3 IG C.L (p. 163) and SP 800-107 Rev. 1 §5.1 (p. 9) set the rules for a truncated digest; the crate offers none, so neither applies.

**`CertificateSignature` can name a SHA-3 hash.** `CertificateSignature::{Ecdsa, RsaPss, RsaPkcs1}` carry a `HashAlgorithm`, so `Ecdsa(P384, Sha3_384)` is now a value of the type. The certificate parser produces none (it maps only the SHA-2 OIDs), no profile's peer-certificate rule lists one, and the crate's certificate verifiers name SHA-2 signature algorithms only, so a certificate signed with a SHA-3 hash is refused as before. `MacAlgorithm::hash()` and `KdfAlgorithm::hash()` return SHA-2 hashes only.

**Profiles (maintainer, 2026-11-03).** Each profile admits from its own text (decision 0008):

| Profile | Admits, in preference order | Governing text |
|---|---|---|
| `unrestricted` | SHA-512, SHA-384, SHA-256, SHA3-512, SHA3-384, SHA3-256 | The backends' inventory |
| `preferred` | SHA-512, SHA-384, SHA-256 | ISM (September 2026) p. 6: "The only approved hashing algorithm for general-purpose use is Secure Hashing Algorithm 2 (SHA-2)"; ISM-1767 (p. 11), an output size of at least 256 bits, "preferably SHA-384 or SHA-512". SHA-3 refused: "approved exclusively for use within ML-DSA and ML-KEM" (p. 6), "restricted to use within internal steps of ML-DSA and ML-KEM" (p. 11) |
| `bsi` | SHA-512, SHA-384, SHA-256, SHA3-512, SHA3-384, SHA3-256 | TR-02102-1 (2026-01) Table 4.1 (p. 47), "Recommended hash functions" |
| `fips1403` | SHA-512, SHA-384, SHA-256, SHA3-512, SHA3-384, SHA3-256 | The CMVP SP 800-140C list §6.2.4.1 (FIPS 180-4) and §6.2.4.2 (FIPS 202), through SP 800-140C r2 §6.2 (p. 2); SP 800-131A r2 Table 8 (pp. 18-19); FIPS 140-3 IG C.C Resolution 1 (p. 138), SHA-3 "as the standalone functions" |
| `fips1402` | SHA-512, SHA-384, SHA-256, SHA3-512, SHA3-384, SHA3-256 | FIPS 140-2 Annex A (p. 2); FIPS 140-2 IG A.11 Resolution 1 (p. 216) |
| `cnsa1` | SHA-384; SHA-256 with `Options::cnsa1_unclassified_nss` | CNSSP 15 (20 October 2016) Annex B ¶1 (p. B-1), "Use SHA-384 to protect up to TOP SECRET"; ¶2b (p. B-2), "SHA-256 in the near term". The edition names neither SHA-512 nor SHA3, so both are refused (decision 0008) |
| `cnsa2` | SHA-384, SHA-512, the order of its MACs and KDFs | CNSSP 15 (December 2024) Annex B ¶1 (p. B-1), "Use SHA-384 or SHA-512 to protect up to TOP SECRET". SHA3 refused: SHA3-384 or SHA3-512 "allowed for internal hardware functionality (e.g. boot-up integrity checks) only" (p. B-2), and ¶2a (p. B-2) says that approving an algorithm that uses SHA3 as a component "does not imply approval of SHA3 as a hash function". Annex B governs over RFC 9206 §4, which names SHA-384 alone: footnote 1 (p. 5) says RFC 9206 and RFC 9151 "will need to be updated for CNSA 2.0 algorithms" |

`preferred` follows the ISM's SECRET-level control ISM-1767. Its TOP SECRET control, ISM-1768 (p. 11), asks for at least 384 bits; that is the caller's to apply, as for HMAC (decision 0008). The ISM says "SHA-224 and SHA-256 will not be approved beyond 2030" (p. 11); `preferred` keeps SHA-256 until a later transition point, with a warning first, as it does HMAC-SHA256. NIST sets no end date for SHA-256 or SHA-3 (IR 8547).

**The near-term option reaches hashing (maintainer, 2026-11-03).** `Options::cnsa1_unclassified_nss` adds SHA-256 to `cnsa1`'s hashes, under CNSSP 15 (2016) Annex B ¶2b (p. B-2), by decision 0010's reading: ¶2b's near-term SHA-256 allowance is not limited to one use. Its scope widens from message authentication and key derivation to include hashing (decisions 0008 and 0010, amended).

**Module cells.**

| Cell | 3.x (#5314 / #5298) | 4.x dynamic | 4.x static |
|---|---|---|---|
| SHA-256, SHA-384, SHA-512 | `Approved`: Table 5 (p. 11) | `AlgorithmTested` on A7855 | `AlgorithmTested` on A7902 |
| SHA3-256, SHA3-384, SHA3-512 | `Approved`: Table 5 (p. 11), on A6294 (#5314) and A6183 (#5298) | `AlgorithmTested` on A7855 | `AlgorithmTested` on A7902 |

- **3.x SHA-3 is `Approved`.** Table 5 (p. 11 of both security policies) lists SHA3-256, SHA3-384 and SHA3-512, FIPS 202, and each policy says "SHA-3 is implemented as a standalone message digest algorithm … all SHA-3 functions and the higher-level algorithms that use SHA-3 have been tested and validated on all of the module's operating environments" (#5314 p. 20, #5298 p. 21). Table 12 lists the message-digest service with indicator 1 (#5314 p. 24, #5298 p. 25). The cells cite Table 5 (`table5`), as the SHA-2 cells do.
- **4.x hashes are `AlgorithmTested`** on the lowest-numbered certificate of each build that shows any of the six: A7855 (dynamic) and A7902 (static), each listing every one with "Message Length: 0-65536 Increment 8" and large-message tests of 1, 2, 4 and 8 GB. The same SHA-2 and SHA-3 lines appear on the arm64 certificates A7871 and A7872 (dynamic) and A7910 and A7911 (static).
- **The sources hold outside TLS.** Neither 3.x policy, and no 4.x certificate, scopes hashing to a protocol; §2.11 of the policies names the SSH KDF, internal-IV GCM and the TLS KDFs only.

`assert_admitted_approved(&admitted, &[Family::Hash])` passes every profile on the 3.x line, and refuses every profile on 4.x.

## Named residuals

1. **The cells claim the tested ranges only.** The certificates tested messages of 0-65536 bits and large messages of 1, 2, 4 and 8 (gigabytes on the 4.x certificates; the 3.x policies give no unit); `digest` hashes any length (decision 0004 §5).
2. **The approval indicator is invisible.** aws-lc-rs does not expose AWS-LC's service indicator, which the module sets after every SHA-2 and SHA-3 digest (`crypto/fipsmodule/sha/sha3.c`, `crypto/fipsmodule/digest/digest.c`).
3. **No SHA-224, SHA-512/224, SHA-512/256, SHA3-224 or SHAKE.** aws-lc-rs exposes SHA-224 and SHA-512/256, but no profile need for them is in scope; it does not expose SHA3-224 or SHAKE. `HashAlgorithm` is `#[non_exhaustive]`, so any of them can come in a 0.10.x release. No profile's text admits SHAKE as a hash function (FIPS 202 §7, p. 22).
4. **A hash is not a MAC or a KDF.** `digest` gives no keyed integrity; use `hmac` or `kdf`.
5. **A SHA-256 `Hasher` past FIPS 180-4's limit.** Between 2^61 and 2^64 bytes fed to one SHA-256 `Hasher`, the module's 64-bit bit count wraps silently (aws-lc-fips-sys 0.13.17 and 0.14.2, `aws-lc/crypto/fipsmodule/digest/md32_common.h:107-113`) and `finish` then gives a digest that does not conform to FIPS 180-4; aws-lc-rs panics only past `u64::MAX` bytes. SHA-384 and SHA-512 keep a 128-bit count, and SHA-3 keeps none, so the wrap applies to SHA-256 alone. The crate adds no check; `Hasher::update`'s documentation names it.

## Consequences

- `digest::sha256` and `digest::sha256_hex` are removed, and `digest::digest` and `digest::Hasher::new` take `&Admitted`: breaking, once, for 0.9.0 callers (`docs/usage.md` §15).
- A format whose hash is fixed at SHA-256, such as a content address, cannot be produced under `cnsa2`, or under `cnsa1` without the option. The crate refuses it rather than carving out an exception, as for HMAC-SHA256 and HKDF-SHA256 (decisions 0008 and 0010).
- Decisions 0008, 0010, 0012 and 0013 note what this decision settles.
