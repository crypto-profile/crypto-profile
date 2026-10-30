# Profiles

A profile is an algorithm set, not a validation claim. It names the protocol versions, cipher suites, key-exchange groups, handshake signature schemes and key algorithms a text admits. Whether the running module is validated for that set is a separate call, `assert_module_approves`, which fails closed; on the 4.x module it fails today, because a cell is `Approved` only where a published security policy lists it (section 6).

The profiles are 0.x API: their names and contents may change before 1.0. The contents below match the constants in `crypto-profile/src/profile.rs`, whose doc comments carry each entry's citation.

## 1. Using a profile

```rust
use crypto_profile_awslc4 as crypto;
use crypto::rustls::ServerConfig;
use crypto::rustls::pki_types::CertificateDer;
use crypto::rustls::sign::SingleCertAndKey;
use crypto::signature::KeyPair;
use crypto::{Options, Profile, assert_module_approves, resolve, tls};
use std::sync::Arc;

fn server(
    name: &str,
    chain: Vec<CertificateDer<'static>>,
    key: &KeyPair,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let profile: Profile = name.parse()?;
    let r = resolve(profile, Options { peer_certificates_match_profile: false, pq_key_exchange_required: true })?;
    assert_module_approves(&r)?;
    let certified = r.certified_key(chain, key)?;
    Ok(tls::server_builder(&r.tls)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified))))
}
```

- **Module approval.** The example returns every refusal from `assert_module_approves`: `NotFips` when the module is not in FIPS mode, `PolicyEmpty` when a family is empty, and `NotApproved` for a cell that is not `Approved`. On the 4.x module it refuses every profile with `NotApproved` (section 6), so this example builds no configuration on 4.x today. That is the behaviour a deployment with a validation obligation needs.
- **This side's certificate and key.** `Resolved::certified_key` refuses a key the profile does not admit (`KeyNotInProfile`) and a chain whose end-entity certificate does not carry the key (`TlsError::KeyMismatch`). The key it returns signs only with a scheme that is both in the peer's offer and in the profile's `signature_schemes`; when none is, a server's handshake fails and a client sends an empty Certificate, which fails the handshake only if the server requires client authentication. Under `cnsa1`, an RSA-3072 key offered RSA-PSS with SHA-512 and SHA-384 signs with SHA-384 (test `a_certified_key_signs_only_with_a_scheme_the_profile_lists`). A key installed through the builder's `with_single_cert` or `with_client_auth_cert` has its schemes narrowed the same way, but its algorithm is not checked. A client installs its certificate the same way, with `with_client_cert_resolver`.

### Report-only use

A deployment with no validation obligation can log the `NotApproved` refusal and go on, while still returning every other refusal. Use this only there: the profile's algorithm set still governs every connection, but nothing then says the module is approved for it.

```rust
use crypto_profile_awslc4::{CryptoError, Resolved, assert_module_approves};

fn report_approval(r: &Resolved) -> Result<(), CryptoError> {
    match assert_module_approves(r) {
        Ok(()) => Ok(()),
        Err(e @ CryptoError::NotApproved { .. }) => {
            eprintln!("{} ({}): {e}", r.profile, r.options);
            Ok(())
        }
        Err(e) => Err(e),
    }
}
```

### Notes

- **What to log.** `Resolved` carries the `profile` and `options` it was resolved with, beside the `tls` policy and the admitted `keys`. Log these alongside `excluded`, which records the module-line entries omitted after Options.
- **`Resolved`'s fields are public.** They are what `resolve` produced. A caller who changes them owns the result: `profile`, `options` and `excluded` then no longer describe `tls` and `keys`. Struct literals must supply all five fields, including `excluded: Vec<Algorithm>`.
- **Names are matched exactly.** `Profile::from_str` accepts `unrestricted`, `preferred`, `cnsa2`, `cnsa1`, `bsi`, `fips1403` and `fips1402`, and nothing else: no trimming and no case folding, so `"fips1403\n"`, `" bsi"` and `"FIPS1403"` are refused with `ParseProfileError` naming the input.
- **No silent exclusions (amended 2026-10-29).** Resolution intersects the published set with module-line availability after Options. `Resolved::excluded` records each unavailable entry in versions, suites, groups, schemes, keys order, preserving preference order. Options-only removals are not line exclusions. Scheme and key ML-DSA are separate tagged entries. Approval never filters this set. Any family left empty is refused with `CryptoError::EmptyProfile` in the same family order. Direct operations still refuse unavailable algorithms with `CryptoError::Unavailable`. See [decision 0006](decisions/0006-per-line-profile-resolution.md).
- **Profiles mix per connection.** Each `Resolved` carries its own `tls::Policy`, so one process can run a `preferred` server and a `fips1402` client side by side. `tls::Policy` stays public and hand-writable; a profile is the main way in, not the only one.
- **rustls's FIPS classification.** `fips::assert_fips_client_config` and `fips::assert_fips_server_config` pass for a client and a server configuration built from every profile except `unrestricted`, which carries X25519 on its own and ChaCha20-Poly1305 (test `rustls_classifies_every_profile_but_unrestricted_as_fips`, which checks both sides). A FIPS-classified profile that enables TLS 1.2 requires Extended Master Secret from its peer.

## 2. The option: post-quantum key exchange required

`Options { peer_certificates_match_profile: false, pq_key_exchange_required: true }` narrows any profile:

- **Key exchange only.** It keeps only the pure ML-KEM and hybrid groups (`KxGroup::is_post_quantum`). Signatures are not narrowed: post-quantum signatures in TLS wait for composite certificates (section 4, item 7).
- **TLS 1.3 only.** TLS 1.2 has no post-quantum group, so the option removes TLS 1.2, its cipher suites, and the RSA PKCS#1 v1.5 handshake schemes, which only TLS 1.2 uses.
- **Three profiles become empty.** `bsi`, `cnsa1` and `fips1402` list no post-quantum group, so with the option `resolve` refuses each with `EmptyProfile`, family key-exchange groups. `cnsa1` follows CNSA 1.0, which names no post-quantum algorithm; `bsi`'s edition lists no hybrid group (section 4, item 3); FIPS 140-2 Annex A and Annex D name no ML-KEM.

| Profile | With the option |
|---|---|
| `unrestricted` | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768; TLS 1.3 and its three suites; eight schemes and nine keys on 4.x; seven schemes and eight keys on 3.x |
| `preferred` | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768; otherwise unchanged apart from the 3.x ML-DSA exclusions |
| `cnsa2` | unchanged |
| `cnsa1`, `bsi`, `fips1402` | refused: `EmptyProfile`, key-exchange groups |
| `fips1403` | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768; TLS 1.3 and its two suites; eight schemes and nine keys on 4.x; seven schemes and eight keys on 3.x |

### Contents by module line

The tables below describe the published sets and the complete 4.x results. On 3.x, apply these differences after Options; all other entries and their order stay identical. This is resolution of the published set against availability, without changing its governing text or claiming approval.

| Profile | 4.x | 3.x |
|---|---|---|
| `unrestricted`, `preferred`, `fips1403` | Full lists; `excluded` empty | Omit only ML-DSA-87 from schemes and keys; `excluded = [Algorithm::Scheme(TlsSignatureScheme::MlDsa87), Algorithm::Signature(SignatureAlgorithm::MlDsa87)]` |
| `cnsa2` | Full lists; `excluded` empty | Refused: `EmptyProfile`, signature schemes, with either Options value |
| `cnsa1`, `bsi`, `fips1402` | Full lists; `excluded` empty | Same lists and empty `excluded` |

The three existing post-quantum-option refusals remain on both lines. Resolving `fips1403` on 3.x does not mean `assert_module_approves` passes on the unmodified result: TLS 1.3 and hybrid group cells are `Unverified`. Inspect `Resolved::excluded` after successful resolution; a refusal returns no `Resolved`. Across the fourteen profile/Options cases, eleven resolve on 4.x and nine on 3.x.

## 3. The profiles

Every list is in preference order. Schemes are the handshake signature schemes a side accepts from its peer and signs with; keys are the key algorithms `admit_key` admits. "PKCS#1" means RSASSA-PKCS1-v1_5, which rustls uses on TLS 1.2 only.

### `unrestricted`

**Governing text:** `GoverningText::CrateRecommendation`. Not a government profile: it is every algorithm in the crate's inventory, post-quantum key exchange first.

| Family | Contents |
|---|---|
| Versions | TLS 1.3, TLS 1.2 |
| Groups | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, secp384r1, secp256r1, x25519 |
| Suites | TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256; ECDHE-ECDSA and ECDHE-RSA with AES-256-GCM, AES-128-GCM and ChaCha20-Poly1305 |
| Schemes | mldsa87, ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512, ed25519, rsa_pss_rsae_sha384, _sha512, _sha256, rsa_pkcs1_sha384, _sha512, _sha256 |
| Keys | MlDsa87, EcdsaP384Sha384, EcdsaP256Sha256, EcdsaP521Sha512, EcdsaP521Sha384, Ed25519, Rsa3072Sha384, Rsa4096Sha384, Rsa2048Sha384 |

It differs from `fips1403` only in TLS: X25519 on its own and the ChaCha20-Poly1305 suites. rustls does not classify a configuration built from it as FIPS.

### `preferred`

**Governing text:** `GoverningText::CrateRecommendation`. Not a government profile. The strictest current reading it follows is the ASD ISM; edition and hash: [sources](sources.md).

`preferred` is the crate's recommendation: post-quantum first, TLS 1.3 only, and nothing a FIPS 140-3 or allied boundary would reject, the strictest current reading being ASD's ISM. So it excludes X25519 on its own, ChaCha20 and Ed25519.

"ISM" below is ASD, *Information security manual, Guidelines for cryptography*, September 2026; pages are its footers. `preferred` follows the ISM's SECRET-level controls. The ISM's TOP SECRET controls are stricter, and `preferred` does not meet them: they exclude P-256 for ECDH and ECDSA (ISM-1762, ISM-1764, p. 8), AES-128 (ISM-1770, p. 11) and SHA-256 (ISM-1768, p. 11). Its controls for NC, OFFICIAL: Sensitive and PROTECTED (applicability NC, OS, P) are looser: RSA from 2048 bits (ISM-0476, p. 10), any SP 800-186 curve of at least 224 bits (ISM-0474, ISM-0475, p. 8), SHA-224 (ISM-1766, p. 11).

| Family | Contents | Source |
|---|---|---|
| Versions | TLS 1.3 | ISM-1139, p. 19 |
| Groups | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, secp384r1, secp256r1 | ISM-1995, p. 10; hybrids: ISM p. 12, ISM-1996, p. 13, FIPS 140-3 IG D.S Scenario 2 and Additional Comment 8a; curves: ISM-1446, p. 7, ISM-0474 and ISM-1761, p. 8 |
| Suites | TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256 | ISM-1369, p. 20; ISM-1769, p. 11 |
| Schemes | mldsa87, ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha384, _sha512, _sha256 | ISM-1991, p. 9; ISM-1763, p. 8; ISM-1765, p. 10; ISM-1374, p. 20 |
| Keys | MlDsa87, EcdsaP384Sha384, EcdsaP256Sha256, EcdsaP521Sha512, EcdsaP521Sha384, Rsa3072Sha384, Rsa4096Sha384 | ISM-1991, p. 9; ISM-1763, p. 8; ISM-1765, p. 10; ISM-1767, p. 11 |

Exclusions and their reasons:

- **TLS 1.2:** the ISM requires the latest TLS version (ISM-1139, p. 19).
- **X25519 on its own:** FIPS 140-3 IG C.K Resolution 5 (p. 160) does not approve X25519 for key agreement. Inside the X25519MLKEM768 hybrid it is allowed, as the non-ML-KEM component (IG D.S Scenario 2).
- **ChaCha20-Poly1305:** AES is the ISM's only approved symmetric algorithm (p. 6), and SP 800-140C r2 §6.1 does not list ChaCha20.
- **Ed25519:** EdDSA is not on the ISM's list of approved asymmetric algorithms (pp. 5-6).
- **RSA PKCS#1 v1.5 handshake schemes:** TLS 1.3 forbids them in handshake signatures (RFC 8446 §4.2.3).
- **RSA 2048 keys:** the ISM's SECRET-level minimum is 3072 bits (ISM-1765, p. 10).
- **Hybrid groups are admitted, though the ISM does not recommend them:** "The use of post-quantum traditional hybrid schemes is not recommended; however, it is not prohibited" (p. 12). Each hybrid has an approved ML-KEM component, which is what ISM-1996 (p. 13) requires: ML-KEM-1024 in SecP384r1MLKEM1024, ML-KEM-768 in the other two.

### `cnsa2`

**Governing text:** CNSSP 15 (December 2024), Annex B, pp. B-1 to B-2: the CNSA 2.0 algorithm set. Edition and hash: [sources](sources.md).

| Family | Contents |
|---|---|
| Versions | TLS 1.3 |
| Groups | MLKEM1024 |
| Suites | TLS_AES_256_GCM_SHA384 |
| Schemes | mldsa87 |
| Keys | MlDsa87 |

The Annex B ¶1 table (pp. B-1 to B-2) lists, as general-purpose algorithms, AES with 256-bit keys, ML-KEM-1024, ML-DSA-87, and SHA-384 or SHA-512; as algorithms allowed in specific applications, LMS and XMSS for signatures of software and firmware, and SHA3-384 or SHA3-512 for internal hardware functionality only. `cnsa2` implements the table's entries that apply to TLS: ML-KEM-1024 for key establishment, ML-DSA-87 for handshake signatures and keys, and AES-256 with SHA-384 in its one suite. TLS 1.3 defines no cipher suite with SHA-512 (RFC 8446 §B.4), so SHA-512 is not used. **The TLS 1.3 mapping is the crate's.** No CNSA 2.0 TLS profile is published: CNSSP 15 says "RFC 9206 and RFC 9151 still apply for protocol guidance, but will need to be updated for CNSA 2.0 algorithms" (¶8a, footnote 1, p. 5). TLS 1.2 is excluded because its key exchange is ECDHE or FFDHE (RFC 8422, RFC 7919), and ML-KEM-1024 is the set's only key establishment. The post-quantum key-exchange option changes nothing.

- **Peer certificates:** With `Options::peer_certificates_match_profile` off, the baseline chain algorithms apply. Turn it on to enforce the profile rule (section 9).

### `cnsa1`

**Governing text:** CNSSP 15 (20 October 2016), Annex B (p. B-1), for the algorithms; RFC 9151 (April 2022), the CNSA Suite profile for TLS 1.2 and 1.3. § references below are RFC 9151's. Editions and hashes: [sources](sources.md).

`cnsa1` is a **transition profile** for CNSA 1.0 counterparts. CNSSP 15 (December 2024) ¶18 (p. 8) sets the dates: CNSA 1.0 algorithms "are acceptable in all products through 31 December 2025"; from 1 January 2027, CNSA 2.0 algorithms "will be required in all new products and services" unless excepted or waived; and "CNSA 2.0 algorithms are mandated for all protocol use by 31 December 2031".

| Family | Contents | Source |
|---|---|---|
| Versions | TLS 1.3, TLS 1.2 | §5 |
| Groups | secp384r1 | §5.1, §7 |
| Suites | TLS_AES_256_GCM_SHA384; TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | §7; §6 |
| Schemes | ecdsa_secp384r1_sha384, rsa_pss_rsae_sha384, rsa_pkcs1_sha384 (TLS 1.2 only) | §6.2, §7.1 |
| Keys | EcdsaP384Sha384, Rsa3072Sha384, Rsa4096Sha384 | §5.1, §5.2 |

What RFC 9151 names and the stack does not implement is in section 4 (item 2): RSA key transport, which §5.2 says MUST be supported for TLS 1.2; and `TLS_RSA_WITH_AES_256_GCM_SHA384`, `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` and the ffdhe groups, which are options in "at least one of" lists (§6, §7). RFC 9151 makes Extended Master Secret a SHOULD (§6.1); rustls requires it on TLS 1.2 here, because a configuration built from `cnsa1` is FIPS-classified.

- **Peer certificates:** With `Options::peer_certificates_match_profile` off, the baseline chain algorithms apply. Turn it on to enforce the profile rule (section 9).

### `bsi`

**Governing text:** BSI TR-02102-2 (TLS) and TR-02102-1, version 2026-01. Edition and hash: [sources](sources.md).

| Family | Contents | Source |
|---|---|---|
| Versions | TLS 1.3, TLS 1.2 | TR-02102-2 §3.2, Table 2 |
| Groups | secp384r1, secp256r1 | TR-02102-2 Table 10 (TLS 1.3), Table 6 (TLS 1.2) |
| Suites | TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256; ECDHE-ECDSA and ECDHE-RSA with AES-256-GCM and AES-128-GCM | TR-02102-2 §3.4.4, Table 13; §3.3.1.1, Table 3 |
| Schemes | ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha384, _sha512, _sha256 | TR-02102-2 §3.4.3, Table 11; for TLS 1.2, the Table 7 note |
| Keys | EcdsaP384Sha384, EcdsaP256Sha256, EcdsaP521Sha512 | TR-02102-2 Table 12, Table 14 |

Exclusions and their reasons:

- **RSA keys and the PKCS#1 v1.5 schemes:** the crate's RSA keys sign with PKCS#1 v1.5, which the 2026-01 edition discontinues after 2025 (TR-02102-2 Table 7 and Table 12 notes).
- **EcdsaP521Sha384:** TR-02102-2 Table 12 pairs P-521 with SHA-512.
- **ML-DSA:** TR-02102-1 §5.3.4 admits ML-DSA only in combination with a classical signature.
- **The hybrid groups:** the edition does not list them (section 4, item 3).
- **X25519, Ed25519 and ChaCha20-Poly1305:** neither TR names them.

TLS 1.2 is admitted to the end of 2031 (TR-02102-2 Table 2). The profile moves when BSI publishes a new edition.

- **Peer certificates:** With `Options::peer_certificates_match_profile` off, the baseline chain algorithms apply. Turn it on to enforce the profile rule (section 9).

### `fips1403`

**Governing text:** NIST SP 800-140C r2 and SP 800-140D r2, with the CMVP lists (updated 21 August 2026); the FIPS 140-3 Implementation Guidance (August 2026), IG C.K, D.Q and D.S; NIST SP 800-52r2; NIST SP 800-131A r2. The set a FIPS 140-3 boundary approves under the published texts. Editions and hashes: [sources](sources.md).

| Family | Contents |
|---|---|
| Versions | TLS 1.3, TLS 1.2 |
| Groups | MLKEM1024, SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768, secp384r1, secp256r1 |
| Suites | TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256; ECDHE-ECDSA and ECDHE-RSA with AES-256-GCM and AES-128-GCM |
| Schemes | mldsa87, ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512, ed25519, rsa_pss_rsae_sha384, _sha512, _sha256, rsa_pkcs1_sha384, _sha512, _sha256 |
| Keys | all nine |

- **Versions and suites:** SP 800-52r2 §3.1 (p. 8), §3.3.1.1.1-2 (pp. 16-17), §3.3.1.2 (p. 19), §4.1 (p. 33). TLS 1.2 requires Extended Master Secret (IG D.Q, pp. 220-221); rustls enforces it for a FIPS-classified configuration.
- **Groups:** ML-KEM-1024, CMVP SP 800-140D list §6.2.10 and IG D.S Scenario 1 (p. 223); the hybrids SecP384r1MLKEM1024, X25519MLKEM768 and SecP256r1MLKEM768, IG D.S Scenario 2 and Additional Comment 8a (pp. 223-226), which name exactly these three; the NIST curves, SP 800-56A r3 Appendix D, Table 24 (p. 132).
- **Signatures:** ECDSA, EdDSA and ML-DSA, CMVP SP 800-140C list §6.2.3.1; Ed25519, IG C.A (p. 136) and IG C.K Additional Comment 8 (p. 161); RSA-PSS and PKCS#1 v1.5 with SHA-256, 384 and 512 and RSA 2048 to 4096, FIPS 186-5 §5.1 and §5.4, IG C.F (pp. 142-143), SP 800-131A r2 Table 2 (p. 9).
- **EcdsaP521Sha384:** FIPS 186-5 §6.4 (pp. 23-24) requires both the hash's and the curve's security strength to "meet or exceed the security strength required for the digital signature process", so SHA-384 with P-521 is permitted only where the signature needs 192 bits of strength or less. The same section says a weaker hash than the curve "ordinarily should not be used".
- **Excluded:** X25519 on its own (IG C.K Resolution 5, p. 160) and ChaCha20-Poly1305 (SP 800-140C r2 §6.1; SP 800-52r2 §3.3.1.2).
- **Peer certificates:** With `Options::peer_certificates_match_profile` off, the baseline chain algorithms apply. Turn it on to enforce the profile rule (section 9).

### `fips1402`

**Governing text:** FIPS 140-2 Annex A and Annex D (2021); FIPS 186-4; NIST SP 800-131A r2; NIST SP 800-52r2. The set a FIPS 140-2 boundary approved, for peers whose boundary is 140-2. Editions and hashes: [sources](sources.md).

| Family | Contents |
|---|---|
| Versions | TLS 1.3, TLS 1.2 |
| Groups | secp384r1, secp256r1 |
| Suites | as `fips1403` |
| Schemes | ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512, rsa_pss_rsae_sha384, _sha512, _sha256, rsa_pkcs1_sha384, _sha512, _sha256 |
| Keys | EcdsaP384Sha384, EcdsaP256Sha256, EcdsaP521Sha512, EcdsaP521Sha384, Rsa3072Sha384, Rsa4096Sha384, Rsa2048Sha384 |

- **Versions and suites:** SP 800-52r2 §3.1, §3.3.1.1.1-2, §3.3.1.2; the TLS 1.3 key schedule is Annex D item 11 (RFC 8446 §7.1).
- **Groups:** Annex D item 3 (SP 800-56A r3), Table 24.
- **Signatures:** FIPS 186-4 (Annex A, p. 2), §§5.4–5.5 (pp. 23–24), Appendix D.1.2; SP 800-131A r2 Table 2 (p. 9). ECDSA keys, FIPS 186-4 §6.4 (pp. 29-30); RSA 2048 and 3072, FIPS 186-4 §5.1 (p. 22); RSA 4096, FIPS 140-2 IG A.14 (p. 221).
- **EcdsaP521Sha384:** FIPS 186-4 §6.4 (pp. 29-30) permits it on the same terms as FIPS 186-5 §6.4 (see `fips1403`), and says a hash weaker than the curve "ordinarily should not be used".
- **Excluded:** ML-KEM and the hybrids (Annex A; Annex D items 12 and 13, which name SP 800-56C Revision 1 (April 2018) and the original SP 800-56C (November 2011), not the hybrid rule of Revision 2); X25519 (not in SP 800-56A r3 Table 24); Ed25519 and ML-DSA (Annex A); ChaCha20-Poly1305 (Annex A).
- **Peer certificates:** With `Options::peer_certificates_match_profile` off, the baseline chain algorithms apply. Turn it on to enforce the profile rule (section 9).

## 4. Named residuals

1. **The peer certificate’s key size and curve.** With `Options::peer_certificates_match_profile` off, the baseline verifier can accept keys outside a profile’s rule. Turn the option on to check the leaf and selected chain (section 9). `admit_key` governs local keys only.
2. **`cnsa1` and RFC 9151 §5.2, §6 and §7.** For TLS 1.2, RFC 9151 says RSAES-PKCS1-v1_5 key transport "MUST be supported" (§5.2). The suites `TLS_RSA_WITH_AES_256_GCM_SHA384` and `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` are two of the four suites a TLS 1.2 client "MUST offer at least one of" (§6), and ffdhe3072 and ffdhe4096 (defined in §5.3) are two of the three groups a TLS 1.3 client "MUST include at least one of" (§7). rustls implements none of them, and SP 800-131A r2 Table 5 (p. 15) disallows PKCS#1 v1.5 key transport after 2023. As a client, `cnsa1` conforms: §6 requires a client to offer at least one of the four suites, and it offers the two ECDHE ones. As a server, it refuses a peer that offers only RSA key transport or finite-field DHE.
3. **`bsi` and the hybrid groups.** TR-02102-2 (2026-01) §3.4.2, in the Table 10 note, states BSI's intent to recommend SecP256r1MLKEM768 and SecP384r1MLKEM1024 once the corresponding RFC is adopted. RFC 10024 has since been published (August 2026), but no edition of TR-02102-2 lists the hybrids, so `bsi` does not offer them, and `bsi` with the option is empty. The profile waits on a new edition; a statement of intent is not admitted.
4. **`fips1402` and the CMVP Historical list.** Every FIPS 140-2 certificate moved to the CMVP Historical list on 22 September 2026. `fips1402` is historical: it serves peers whose boundary is still 140-2.
5. **Classical signature transition.** NIST IR 8547 final (October 2026), §4.1.1 Table 2, deprecates ECDSA, EdDSA and RSA at every approved strength after 2030 and disallows them after 2035.
6. **Brainpool, AES-CCM and P-521 key exchange.** TR-02102-2 lists all three, and SP 800-52r2 lists AES-CCM suites and permits P-521 (§3.4.2.2), but the crate's provider implements none of them, as rustls 0.23.46's built-in provider did not, so no profile lists them.
7. **Dual-signature and composite certificates.** These certificates, discussed in NIST IR 8547 §3.2, are not supported.
8. **ECDSA P-521 with SHA-384.** `fips1402` and `fips1403` admit `EcdsaP521Sha384`, though FIPS 186-4 §6.4 and FIPS 186-5 §6.4 say a hash weaker than the curve "ordinarily should not be used"; FIPS 186-5 §6.4 permits the pairing only where the signature needs 192 bits of strength or less. `preferred` admits it under ISM-1763 (p. 8) and ISM-1767 (p. 11); `bsi` does not.

## 5. What a profile does not restrict

- **Peer certificate keys and chain signatures, by default.** With `Options::peer_certificates_match_profile` off, the baseline verifier accepts its full certificate signature list. Turn the option on to enforce the selected profile’s leaf and chain rules (section 9). Handshake signature schemes are separate from certificate signatures.
- **The peer leaf’s key size and curve, by default.** The option checks these when enabled (section 4, item 1).
- **A signing key built outside the profile's provider.** A key loaded through `tls::load_private_key`, `Resolved::certified_key` or the builder's own key loading signs only with the profile's schemes. A `rustls::sign::SigningKey` built any other way signs with whatever scheme rustls picks from the peer's offer and the key's type.
- **The algorithm of a key passed to `tls::load_private_key` or a builder.** It is not checked against any profile; `Resolved::certified_key` checks it.
- **Key generation.** `signature::KeyPair::generate` generates any algorithm it is asked for. Call `Resolved::admit_key` where a key is generated or a certificate request is made.
- **Certificate requests.** `csr::generate_csr` generates a key of any algorithm it is asked for and signs the request with it.
- **`aead`, `digest` and `sealbox`.** No profile governs them. `aead` is AES-256-GCM. `digest` hashes with SHA-256, SHA-384 or SHA-512, whichever is asked for. `sealbox` is fixed at P-384 ECDH, HKDF-SHA384 and AES-256-GCM, so it uses none of `cnsa2`'s algorithms for key establishment.

## 6. Module approval and `AlgorithmTested`

`assert_module_approves(&r)` refuses with `CryptoError::NotFips` when the module does not report FIPS mode, before it looks at `r`. It then refuses with `CryptoError::PolicyEmpty`, naming the first empty family in the order versions, suites, groups, schemes and keys, an `r` that leaves a family empty; `resolve` never returns one, but the fields are public. Otherwise it walks every algorithm `r` names, in that order (versions as `Protocol` cells), and fails on the first whose capability cell is not `Approved`, with `CryptoError::NotApproved` naming the algorithm and its approval. A cell is `Approved` only where a published security policy lists it.

**`Approval::AlgorithmTested { cavp }`** means: one published CAVP certificate shows every operation the cell needs, with the parameters `cavp` names, and no security policy lists it as approved. It is never approved, and `assert_module_approves` refuses it ([decision 0004](decisions/0004-algorithm-tested.md)).

- **A cell claims only the parameters it names.** A `Scheme` cell's verifier accepts a wider range of peer keys than its certificate tested: RSA moduli from 2048 to 8192 bits, and, on TLS 1.2, a key on any of the three NIST curves under each ECDSA scheme. That gap is section 4's item 1.
- **The processor variant.** Each 4.x dynamic cell that is `AlgorithmTested` cites one AWS-LC FIPS 4.0.0 CAVP certificate (A7839-A7876), so it is tested on that certificate's processor variant. Which variant a build uses depends on the CPU. The cited certificates, as their CAVP pages list them:
  - A7855 (SHA_AVX2) and A7856 (SHA_AVX) are x86 variants, tested on Intel Ice Lake and AMD Genoa. Every capability the A7855 cells cite appears, with the same parameters, on the arm64 certificates A7871 (SHA_CE) and A7872 (NEON). The ECDSA and RSA SigVer (FIPS186-5) capabilities the A7856 cells cite appear with the same parameters on A7872; A7871's FIPS186-5 SigVer capabilities list SHA3 hashes only.
  - A7864 (GENERIC_C) lists Intel Ice Lake, AMD Genoa and AWS Graviton4 for each capability its cells cite.
  - A7873 (NARROW_MULTIPLIER) is an arm64 variant, tested on AWS Graviton4 only.
- **The 4.x dynamic build:** 22 cells are `AlgorithmTested`: the three RSA keys on A7873; the ML-DSA-87 and Ed25519 keys and schemes, ML-KEM-1024 and SHA-256, SHA-384 and SHA-512 on A7855; the three ECDSA and six RSA handshake schemes on A7856; secp384r1 and secp256r1 on A7864. 19 are `Unverified`, by reason:
  - X25519 and the three hybrid groups: CAVP has no algorithm for them;
  - the nine cipher suites: no ChaCha20 certificate exists, and no single certificate shows every operation the AES-GCM suites need;
  - TLS 1.2 and TLS 1.3: no certificate shows a TLS 1.2 KDF with extended master secret or a TLS 1.3 KDF;
  - the four ECDSA keys: no single certificate shows every operation they need.
- **The 4.x static build:** every cell is `Unverified`; no static-build CAVP certificate was found.

The three SHA-2 cells are not walked by `assert_module_approves`, which covers what a profile names. Every profile names a TLS version, and both are `Unverified` on 4.x, so `assert_module_approves` refuses every profile there until a 4.x security policy is published and its tables replace these cells.

## 7. After 2030

What each issuer's text says about the years after 2030, and which profile, with or without the option, carries the algorithms it names, or which part of them. This table makes no claim of conformance with any text. Each text's edition, link and hash are in [sources](sources.md).

| Issuer and text | The dates, as written | Profile |
|---|---|---|
| **US:** CNSSP 15 (December 2024), ¶18 (pp. 7-8; the dates are on p. 8) [^us] | CNSA 1.0 algorithms "are acceptable in all products through 31 December 2025". From 1 January 2027, CNSA 2.0 algorithms "will be required in all new products and services", unless excepted or waived. Equipment that cannot be updated is phased out "by 31 December 2030". CNSA 2.0 algorithms "are mandated for all protocol use by 31 December 2031". Transition complete by 2035 (NSM-10). | `cnsa2` carries the Annex B entries that apply to TLS (pp. B-1 to B-2): ML-KEM-1024, ML-DSA-87, and AES-256 with SHA-384. It does not use SHA-512, which no RFC 8446 cipher suite uses, or LMS, XMSS and SHA3, which the table allows only for software and firmware signatures and internal hardware functionality. The post-quantum key-exchange option changes nothing. Its TLS 1.3 mapping is the crate's, because no CNSA 2.0 TLS profile is published (¶8a, footnote 1, p. 5). `cnsa1` carries the part of the CNSA 1.0 set that ¶18 phases out which applies to TLS and which rustls implements: AES-256, ECDH and ECDSA on P-384, SHA-384, and RSA signatures with 3072- and 4096-bit moduli; not finite-field DH or RSA key establishment (section 4, item 2). The peer-certificate option enforces their chain rules (section 9). |
| **US:** NIST IR 8547 final (October 2026), §4.1.1 Table 2 | ECDSA, EdDSA and RSA at every approved strength are deprecated after 2030 and disallowed after 2035. | Plan migration to post-quantum signatures; see section 9. |
| **Australia:** ASD ISM, Guidelines for cryptography (September 2026) [^au] | DH, ECDH, ECDSA and RSA "will not be approved beyond 2030" (DH p. 7; ECDH and ECDSA p. 8; RSA p. 10); ML-DSA-65 (p. 9), ML-KEM-768 (p. 10), SHA-224 and SHA-256, and AES-128 and AES-192 (p. 11) likewise. ISM-1917 (p. 12): new equipment, applications and libraries support ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512 and AES-256 "by no later than 2030". | Of the five algorithms ISM-1917 names, `cnsa2` carries ML-DSA-87, ML-KEM-1024, SHA-384 and AES-256. It does not use SHA-512, which no RFC 8446 cipher suite uses. Of the hybrid groups, only SecP384r1MLKEM1024 keeps an ISM-1917 component after 2030 (ML-KEM-1024), so it is the hybrid that stays eligible under ISM-1996 (p. 13), which needs one approved component; ML-KEM-768, the other hybrids' component, is not approved beyond 2030 (p. 10). This is derived from the text, not stated by ASD. `preferred` and `unrestricted` carry it. |
| **EU:** EU PQC Workstream of the NIS Cooperation Group, *A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography*, Part 1, v1.1 (11.06.2025), §4.1 [^eu] | By 31.12.2026, first steps and national roadmaps. By 31.12.2030, the transition of high-risk use cases completed, and quantum-safe software and firmware upgrades enabled by default. By 31.12.2035, medium-risk use cases completed, and low-risk ones as far as feasible. | The text names no algorithm set. |
| **UK:** NCSC, *Timelines for migration to post-quantum cryptography* (v1.0, 2025; PDF of August 2026) [^uk1] | By 2028, discovery and an initial plan. By 2031, the highest-priority migration. By 2035, migration complete. The dates are indicative. | The text names no algorithm set. NCSC's *Using TLS to protect data* v1.2 (15 October 2026) [^uk2] names hybrid and pure ML-KEM TLS groups and keeps AES-128-GCM, as a current recommendation rather than an end state. |
| **Germany:** BSI TR-02102-2 and TR-02102-1, version 2026-01 [^de] | TLS 1.2 to the end of 2031 (TR-02102-2 Table 2). Classical key agreement alone to the end of 2031 (Table 10 note; TR-02102-1). Classical signatures alone to the end of 2035 (TR-02102-1). | To the end of 2031, `bsi` carries the TR-02102-2 TLS entries that rustls implements; Brainpool, AES-CCM and P-521 key exchange, which the TR lists, are absent (section 4, item 6). For key exchange after 2031 the text names no algorithm set: the edition lists no post-quantum TLS group, so no profile with the option matches it. |
| **Canada:** CCCS ITSM.40.001 (June 2025) [^ca1] and ITSP.40.111 v5 (29 May 2026) [^ca2] | High-priority systems migrated by the end of 2031, the rest by the end of 2035. RSA of at least 3072 bits by the end of 2030. RSA, ECDH, ECDSA and EdDSA phased out "without a PQC scheme" by the end of 2035. | The texts name ML-KEM and ML-DSA, each in all three parameter sets, and no TLS groups: they name no algorithm set for TLS. |

[^us]: CNSS Policy No. 15, *Use of Public Standards for Secure Information Sharing*, December 2024, Committee on National Security Systems. Link and hash: [sources](sources.md).
[^au]: Australian Signals Directorate, *Information security manual: Guidelines for cryptography*, September 2026. Page numbers are the PDF's footers. Link and hash: [sources](sources.md).
[^eu]: <https://ec.europa.eu/newsroom/dae/redirection/document/117507>
[^uk1]: <https://www.ncsc.gov.uk/guidance/pqc-migration-timelines>
[^uk2]: <https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data>
[^de]: Bundesamt für Sicherheit in der Informationstechnik, *Technical Guideline TR-02102-1* and *TR-02102-2*, version 2026-01.
[^ca1]: <https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001>
[^ca2]: <https://www.cyber.gc.ca/en/guidance/cryptographic-algorithms-unclassified-protected-protected-b-information-itsp40111>

## 8. How profiles change

A regime-named profile (`cnsa2`, `cnsa1`, `bsi`, `fips1403`, `fips1402`) follows the published text, never a statement of intent, and moves only when its issuer publishes a new edition. The move is a reviewed change that names the new edition in `Profile::governing_text` and in the constant's citations, and updates the golden table in `crypto-profile/src/conformance/golden.rs`. `preferred` and `unrestricted` are the crate's own and change by the same review. The profiles are 0.x API.

## 9. Impact of peer certificate enforcement

`Options::peer_certificates_match_profile` is off by default. When enabled, the crate checks the peer leaf key and each signature and issuer key in the path selected by WebPKI. The trust anchor's signature on its child is checked; its self-signature is not. Normal name, time, path and revocation checks still apply. A rule is independent of the handshake signature schemes. Backend support and baseline verification can further limit the sets below.

In this table, EC means P-256, P-384 or P-521; SHA-2 means SHA-256, SHA-384 or SHA-512. RSA-PSS uses matching digest and MGF1 and digest-length salt. Issuer key rules match leaf rules except where stated.

| Profile | Leaf key rule | Chain signature and issuer key rule | Source |
|---|---|---|---|
| `unrestricted` | EC, RSA at least 2048, Ed25519, ML-DSA-87 | ECDSA with any EC and SHA-2; RSA-PSS or PKCS#1 v1.5 with SHA-2; Ed25519 or ML-DSA-87 | Crate recommendation, sections 3 and 5 |
| `preferred` | EC, RSA at least 3072, ML-DSA-65 or -87 | ECDSA with any EC and SHA-2; RSA-PSS or PKCS#1 v1.5 with SHA-2. Issuers: EC or RSA at least 3072 | ASD ISM September 2026, ISM-1763 p. 8, ISM-1991 p. 9, ISM-1765 p. 10, ISM-1374 p. 20 |
| `cnsa2` | ML-DSA-87 only | ML-DSA-87 only | CNSSP 15 December 2024, Annex B ¶1, pp. B-1–B-2 |
| `cnsa1` | P-384 or exactly RSA-3072 or RSA-4096 | ECDSA P-384/SHA-384, RSA-PSS/SHA-384 or RSA PKCS#1 v1.5/SHA-384 | RFC 8603 §4.1; RFC 9151 §§5.2, 5.4, 6.3, 7.2 |
| `bsi` | EC or RSA at least 3000 | ECDSA P-256/SHA-256, P-384/SHA-384 or P-521/SHA-512; RSA-PSS with SHA-2 | TR-02102-2 2026-01 §§3.4.3, 3.6, Tables 12 and 14 |
| `fips1403` | EC, even-bit RSA at least 2048, Ed25519, ML-DSA-87 | ECDSA with any EC and SHA-2; RSA-PSS or PKCS#1 v1.5 with SHA-2; Ed25519 or ML-DSA-87 | SP 800-52r2 §3.3.3; FIPS 186-5 §§5.1, 5.4, 6.4, 7; CMVP approved algorithm lists |
| `fips1402` | EC or RSA at least 2048 | ECDSA with any EC and SHA-2; RSA-PSS or PKCS#1 v1.5 with SHA-2 | SP 800-52r2 §3.3.3; SP 800-131A r2 Table 2; FIPS 140-2 IG A.14 pp. 221–222; FIPS 186-4 §§5.5, 6.4 |

`preferred` with the option refuses an all-ML-DSA chain until ASD publishes a TLS certificate rule for ML-DSA: ISM-1374 requires SHA-2-based TLS certificates. On 3.x, `cnsa2` fails resolution before this rule applies.

| Setting | Benefit | Downside and audience |
|---|---|---|
| Off | Supports mixed PKIs during transition; existing behavior remains. | Does not enforce profile certificate rules. Use during migration where peers still need the baseline. |
| On | Refuses leaf keys and selected chains outside the profile. | May reject existing peers. Enable when the deployment requires the profile's certificate rules and its PKI is ready. |

Without the option, `cnsa1` can accept a path that violates RFC 9151; such a connection is not a CNSA-compliant connection. SP 800-52r2 §§3.5.3 and 4.5.3 require checking client and server public key length when a mechanism is available; the option supplies that mechanism. Other conformance requirements remain.

| Date | Transition |
|---|---|
| Now through 2030 | Classical and post-quantum PKIs coexist (IR 8547 §3.2; CNSSP 15 ¶18). Non-updatable NSS equipment is phased out by 31 December 2030. |
| After 2030 | ECDSA, EdDSA and RSA at every approved strength are deprecated (IR 8547 §4.1.1 Table 2). |
| 31 December 2031 | CNSA 2.0 is mandatory for all protocol use (CNSSP 15 ¶18); a strict `cnsa2` chain is required for that use. |
| After 2035 | ECDSA, EdDSA and RSA at every approved strength are disallowed (IR 8547 §4.1.1 Table 2). |

**Direct-rustls bypass:** Code driving rustls directly bypasses crate enforcement; `crypto_provider` alone does not enforce certificate rules. The crate makes consistent policy easy; adoption closes the gap.

**Server resumption:** Never share server session storage or ticket keys between configurations enforcing a rule and configurations that do not, or between different rules. A resumed session skips certificate verification. Default stores are isolated.

**Selected-path alternative rejection:** If WebPKI selects a non-compliant path, the connection is refused even if a compliant alternative exists. No alternative path search weakens this fail-closed decision. CRL signatures use the baseline list, not the profile rule. Dual-signature and composite certificates are unsupported (IR 8547 §3.2).
