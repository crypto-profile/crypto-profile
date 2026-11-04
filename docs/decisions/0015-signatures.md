# 0015: Signatures under a profile, with RSA-PSS and strict key input

Date: 2026-11-04. Status: accepted.

## Context

Before this decision `signature::KeyPair::generate`, `KeyPair::from_pkcs8_der` and `signature::verify` checked only that the module line had the algorithm, so a `cnsa2` caller could generate, import and sign with an ECDSA P-256 key, and verify under one. This decision governs those three functions; it does not govern the key `csr::generate_csr` returns, which signs and exports under no profile (#57). The key inputs were lenient on both module lines (#48): a PKCS#8 key followed by other bytes was taken and exported again with them, two concatenated keys gave the first, attributes out of X.690 order, an undefined trailing field, version v2 without a publicKey and an explicit-curve EC key were taken, and for ML-DSA-87 bytes after the private key, the expanded key alone and a publicKey that was not the key's own were taken too; `verify` took a SubjectPublicKeyInfo, and one followed by other bytes, where a raw key is documented, for ECDSA, Ed25519 and ML-DSA-87, and a compressed P-256 point. `KeyPair::sign` parsed the key's PKCS#8 encoding again on every call (#5). RSA signed RSASSA-PKCS1-v1_5 only, though RFC 8017 §8 says "RSASSA-PSS is REQUIRED in new applications" and BSI TR-02102-1 §1.5 (p. 22) does not recommend PKCS#1 v1.5 for signature generation in new systems.

## Decision

**API (maintainer, 2026-11-03).** `Family::Signature`, `ProfileSpec::signatures`, `AdmittedSelection::signatures`, `Admitted::signatures()` and `Admitted::admit_signature` follow the other families outside TLS (decision 0008). `ProfileSpec::signatures` is separate from the TLS `key_algorithms`, which `resolve` and `Resolved::admit_key` keep. `assert_admitted_approved` walks the signature cells last, after the hash cells.

```rust
pub fn verify(a: &Admitted, alg: SignatureAlgorithm, public_key: &[u8], msg: &[u8], sig: &[u8])
    -> Result<(), CryptoError>;
impl KeyPair {
    pub fn generate(a: &Admitted, alg: SignatureAlgorithm) -> Result<KeyPair, CryptoError>;
    pub fn from_pkcs8_der(a: &Admitted, alg: SignatureAlgorithm, der: &[u8]) -> Result<KeyPair, CryptoError>;
    pub fn algorithm(&self) -> SignatureAlgorithm;
    pub fn public_key(&self) -> &[u8];
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}
```

- **Refusal order:** admission (`Admitted::admit_signature`: `NotInProfile`, or `Unavailable` for an algorithm the module line lacks); then the input's shape, a raw public key (`CryptoError::SignaturePublicKey`) or the PKCS#8 structure (`CryptoError::SignaturePrivateKey`); then the module (`SignaturePrivateKey` for a key it refuses, `Verify` for a signature that does not verify). The admission is in a helper the three functions call, so mutation reaches it (#40).
- **A key is held once** (decision 0012). A `KeyPair` holds the module's parsed key and its raw public key, and no copy of its encoding, so `sign` no longer parses the key. `to_pkcs8_der()` encodes the held key on each call into an owned `Zeroizing<Vec<u8>>` the caller drops: ECDSA, RSA and ML-DSA-87 (the seed form) as version v1, Ed25519 as version v2 with its publicKey, the form the crate already emitted. The export is the canonical encoding, not the imported bytes: attributes are dropped, and an Ed25519 key imported as v1 is exported as v2. `KeyPair` is not `Clone` on either backend: aws-lc-rs 1.19.0's key types are `Clone`, but a clone shares the module's key, and the crate does not expose it.
- **Strict PKCS#8** (#48 item 2; decision 0011's rule). The DER helpers decision 0011 gave `ecdh` move to one crate-private module that both families use; `ecdh` takes what it took, except that an identifier is now read as X.690 §8.1.2.4 defines it, so a tag number above 30, and only such a number, takes the high-tag-number form, minimally encoded: an attribute value tagged `1f 01` is refused, and one tagged `1f 1f` taken. For each key type the crate checks, before the module parses the key, exactly one DER SEQUENCE spanning the input, an RFC 5958 §2 OneAsymmetricKey whose privateKeyAlgorithm is byte for byte the algorithm's, optional `[0]` attributes in X.690 §11.6 order, version v2 exactly when a `[1]` publicKey is present, and nothing the RFCs do not define:
  - ECDSA: version v1, `id-ecPublicKey` with the key's namedCurve (RFC 5480 §2.1.1), privateKey one RFC 5915 §3 `ECPrivateKey` with a scalar of the curve's length, optional parameters naming the same curve and an optional uncompressed publicKey. Explicit curve parameters are refused. Only the PKCS#8 form is taken; the bare `ECPrivateKey`, which `ecdh` also takes, is refused, as it was;
  - Ed25519: `id-Ed25519` without parameters (RFC 8410 §3), privateKey exactly `04 20` and 32 bytes (RFC 8410 §7, RFC 8032 §5.1.5), version v1, or v2 with a 32-byte publicKey;
  - RSA: version v1, `rsaEncryption` with NULL parameters (RFC 3279 §2.3.1, RFC 8017 A.1), absent parameters refused; privateKey one RFC 8017 A.1.2 `RSAPrivateKey` of version 0, so two primes only, then eight positive, DER-minimal INTEGERs and nothing after them, the modulus exactly the variant's bit length and the public exponent 65537. A "stripped" key whose exponents and primes are zero is refused;
  - ML-DSA-87: `id-ml-dsa-87` without parameters (RFC 9881 §2), privateKey the 32-byte seed or both the seed and the 4,896-byte expanded key (RFC 9881 §6), with nothing after the choice; version v1, or v2 with a 2,592-byte publicKey. The expanded key alone is refused: the module cannot export such a key again, which the held-once rule needs.

  After the import, a carried publicKey must be the key's own: RFC 5915 §3 makes the field a convenience, and RFC 8410 §7 and RFC 9881 §6 define it as the key's public key. On both module lines the module refuses an ECDSA or Ed25519 key whose carried publicKey is not its own (`EC_KEY_check_key`, called from `aws-lc-fips-sys-0.14.2/aws-lc/crypto/ec_extra/ec_asn1.c:192` and `aws-lc-fips-sys-0.13.17/aws-lc/crypto/ec_extra/ec_asn1.c:183`; `crypto/evp_extra/p_ed25519_asn1.c:56-59` on both), and on 4.x it ignores an ML-DSA-87 key's (`aws-lc-fips-sys-0.14.2/aws-lc/crypto/evp_extra/p_pqdsa_asn1.c:143`, `pqdsa_priv_decode` never reads `pubkey`). The crate checks all three. Only DER is taken, as decision 0011 rules.
- **Exact raw public keys in `verify`** (#48 item 1): an uncompressed SEC 1 point of 65, 97 or 133 bytes starting `04` (SEC 1 §2.3.3); a 32-byte Ed25519 key (RFC 8032 §5.1.5); a 2,592-byte ML-DSA-87 key (FIPS 204 Table 2; §3.6.2 says an implementation that can accept another length "shall return false"); an RFC 8017 `RSAPublicKey` whose modulus is exactly the variant's bit length and whose public exponent is 65537. A SubjectPublicKeyInfo, a compressed or hybrid point, or a key of another length is refused before the module sees it.
- **ML-DSA-87** signs pure ML-DSA, hedged, with the empty context (FIPS 204 §5.2; RFC 9881 §3), as before.

**RSA-PSS (maintainer, 2026-11-03).** `SignatureAlgorithm` gains `Rsa2048Sha384Pss`, `Rsa3072Sha384Pss` and `Rsa4096Sha384Pss` (`rsa2048-sha384-pss`, `rsa3072-sha384-pss`, `rsa4096-sha384-pss`): RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt, the hash length (RFC 8017 §9.1; RFC 4055 §3.1 recommends it; RFC 7518 §3.5 requires it; FIPS 186-5 §5.4(g), p. 18, caps the salt at the hash length). Verification accepts only that salt length: aws-lc-rs passes the module `RSA_PSS_SALTLEN_DIGEST`, which it checks exactly (`crypto/fipsmodule/rsa/padding.c`, both lines). The key is an ordinary RSA key, `rsaEncryption` in its PKCS#8 and SubjectPublicKeyInfo. Their `signature_oid()` is `id-RSASSA-PSS` (RFC 4055 §3.1). The enum was already `#[non_exhaustive]` (decision 0012), so the variants are an addition.

**The PSS variants stay outside TLS.** No TLS `key_algorithms` list holds them. `SignatureAlgorithm::tls_scheme()` returns `Option<TlsSignatureScheme>`, `None` for them. `csr::generate_csr` generates its key through a crate-private constructor that refuses a variant with no TLS scheme with `CryptoError::NotTlsKey`, then one the module line lacks, so a certificate request keeps the TLS key rules; `Resolved::admit_key` and `Resolved::certified_key` refuse them with `KeyNotInProfile`. rcgen has no RSA-PSS descriptor, so a PSS `KeyPair` refuses to sign for rcgen (`rcgen::Error::UnsupportedSignatureAlgorithm`) rather than sign under a PKCS#1 v1.5 label.

**Fixed-width ECDSA (maintainer, 2026-11-03)** for JOSE (RFC 7518 §3.4) is not in this decision: it is #56, a 0.10.x addition. ECDSA signatures are DER `Ecdsa-Sig-Value`.

**Profiles (maintainer, 2026-11-03).** Each profile admits from its own text (decision 0008), separately from its TLS keys:

| Profile | Admits, in preference order | Governing text |
|---|---|---|
| `unrestricted` | ML-DSA-87; ECDSA P-384, P-521 with SHA-512, P-521 with SHA-384, P-256; Ed25519; RSA 4096, 3072 and 2048 with PSS, then with PKCS#1 v1.5 | The inventory |
| `preferred` | ML-DSA-87; ECDSA P-384, P-521 with SHA-512, P-256; RSA 4096 and 3072 with PSS, then with PKCS#1 v1.5 | ISM (September 2026): ISM-1991 (p. 9), "preferably ML-DSA-87"; ISM-1763 (p. 8), P-256, P-384 or P-521, "preferably the NIST P-384 curve"; ISM-1765 (p. 10), "a modulus of at least 3072 bits". The ISM names no RSA padding, so both are admitted. Ed25519 refused: not on the approved list (pp. 5-6). P-521 with SHA-384 refused, below |
| `cnsa2` | ML-DSA-87 | CNSSP 15 (December 2024) Annex B ¶1 (p. B-1), "ML-DSA-87 to protect up to TOP SECRET" |
| `cnsa1` | ECDSA P-384; RSA 4096 and 3072 with PSS, then with PKCS#1 v1.5; RSA 2048 with PSS and with PKCS#1 v1.5 too with `Options::cnsa1_unclassified_nss` | CNSSP 15 (20 October 2016) Annex B ¶1 (p. B-1): ECDSA "Use Curve P-384", RSA "Minimum 3072 bit-modulus", both under FIPS 186-4, whose §5.5 (p. 24) approves both paddings; ¶2b (p. B-2) for the option, below |
| `bsi` | RSA 4096 and 3072 with PSS | TR-02102-1 (2026-01) Table 5.4 (p. 52), EMSA-PSS; §5.3.1 (p. 52), "The length of the modulus n should be at least 3000 bits"; §1.5 (p. 22), PKCS#1 v1.5 "not recommended to use … in new systems, neither for encryption nor for signature generation". ECDSA refused: Table B.3 (p. 75) recommends only Brainpool curves, as for ECDH (decision 0011). ML-DSA refused: §5.3.4 (p. 54) recommends a quantum-safe signature "only in combination with a classic signature scheme", which the crate does not offer. Ed25519 refused: not in Table 5.3 (p. 51) |
| `fips1403` | the eleven of `unrestricted` but P-521 with SHA-384, in its order | The CMVP SP 800-140C list §6.2.3.1 (FIPS 186-5, FIPS 204), through SP 800-140C r2 §6.2 (p. 2); FIPS 186-5 §5.1 (p. 16), §5.4 (p. 18), §7.1 (p. 26); SP 800-131A r2 Table 2 (p. 9). P-521 with SHA-384 refused, below |
| `fips1402` | ECDSA P-384, P-521 with SHA-512, P-521 with SHA-384, P-256; RSA 4096, 3072 and 2048 with PSS, then with PKCS#1 v1.5 | FIPS 140-2 Annex A (p. 2), FIPS 186-4: §5.5 (p. 24), both paddings; RSA 4096, FIPS 140-2 IG A.14 (p. 221). ML-DSA and Ed25519 refused: not in Annex A |

The ECDSA order is the order of each profile's key agreement curves (P-384, P-521, P-256), and RSA runs strongest first, PSS before PKCS#1 v1.5. No profile's text splits generation from verification for these algorithms: SP 800-131A r2 Table 2's legacy-use split covers keys below 112 bits and DSA only, so one list serves `generate`, `from_pkcs8_der` and `verify`.

**P-521 with SHA-384 (maintainer, 2026-11-03).** FIPS 186-5 §6.1.1 (p. 21): "A hash function that provides a lower security strength than is associated with the bit length of n shall not be used." P-521's n gives at least 256 bits (Table 1, p. 21), SHA-384 192. So `fips1403` refuses `EcdsaP521Sha384` outside TLS, and `preferred`, which admits nothing a FIPS 140-3 boundary would reject, refuses it too. FIPS 186-4 puts the same sentence in its domain-parameter text (§6.1.1, pp. 27-28) and says in its signature text only that such a hash "ordinarily should not be used" (§6.4, p. 30), so `fips1402` keeps it, as does `unrestricted`. The TLS key lists are unchanged: a P-521 TLS key signs handshakes with `ecdsa_secp521r1_sha512`, and the pairing names only its certificate request's signature.

**The near-term option reaches signatures (maintainer, 2026-11-03).** `Options::cnsa1_unclassified_nss` adds `Rsa2048Sha384Pss` and `Rsa2048Sha384` to `cnsa1`'s signatures, under CNSSP 15 (2016) Annex B ¶2b (p. B-2): such deployments "may continue to use RSA and Diffie-Hellman at the 2048 bit level and SHA-256 in the near term". By decision 0010's reading, ¶2b's allowance is not limited to one use; ¶2a (p. B-2) puts the 2048-bit RSA in PKI. The hash stays SHA-384, under ¶1. The option does not admit ECDSA P-256: ¶2b requires NSA consultation for "curves other than P-384". Its scope widens to signatures outside TLS (decisions 0008, 0010 and 0014, amended); it widens no TLS list.

**Module cells.**

| Cell | 3.x static (#5314) | 3.x dynamic (#5298) | 4.x dynamic | 4.x static |
|---|---|---|---|---|
| RSA-PSS, 2048, 3072, 4096 | `Approved`: Table 5 | `Approved`: Table 5 | `AlgorithmTested` on A7873 | `AlgorithmTested` on A7912 |
| Ed25519, `Signature` and `Scheme` | **`NotApproved`**: Table 12, pp. 24-25 | `Approved`: Table 5, unchanged | `AlgorithmTested` on A7855, unchanged | `AlgorithmTested` on A7902, unchanged |
| Every other signature cell | unchanged | unchanged | unchanged; ECDSA stays `Unverified` | unchanged; ECDSA stays `Unverified` |

- **3.x RSA.** Table 5 of both policies lists RSA SigGen and SigVer (FIPS 186-5) at 2048, 3072 and 4096 with "Signature Type - pkcs1v1.5, pss" and names no hash (p. 10). Each of the nine RSA certificates it lists for #5314 (A6288-A6291, A6295, A6312-A6315) and for #5298 (A6176-A6180, A6184, A6278-A6280) shows SigGen and SigVer at those moduli with SHA2-384 for PKCS#1 v1.5, and with SHA2-384, MGF1 and a 48-byte salt for PSS. The cells cite Table 5, as the other 3.x cells do.
- **3.x static Ed25519 is `NotApproved`.** #5314's Approved Services table lists "Signature Generation with RSA, Signature Generation with ECDSA" (p. 24) and "Signature Verification with ECDSA, Signature Verification with RSA" and their legacy forms (p. 25), and no EdDSA service, though its Table 5 lists EDDSA SigGen and SigVer. #5298 lists "Signature Generation with EDDSA" (p. 25) and "Signature Verification with EDDSA" (p. 26). The crate reads a service the table does not list as not approved, as decision 0011 read the ECDH text. The cell is the same for `Signature(Ed25519)` and `Scheme(Ed25519)`. No TLS outcome changes: on 3.x every resolved profile lists TLS 1.3 first, whose cell is `Unverified`, so `assert_module_approves` refuses there before it reaches an Ed25519 cell.
- **4.x RSA-PSS** is `AlgorithmTested` on the certificates the PKCS#1 v1.5 cells cite, A7873 (dynamic) and A7912 (static), which show RSA KeyGen, SigGen and SigVer (FIPS186-5) with "Mask Function: mgf1", "SHA2-384", "Salt Length: 48" at each modulus.
- **4.x ECDSA stays `Unverified`.** ECDSA KeyGen (FIPS186-5) is on A7864 and A7919 only, and neither shows ECDSA SigGen or SigVer (decision 0004 §2).
- **The sources hold outside TLS.** Neither 3.x policy scopes a signature service to a protocol, and no 4.x certificate scopes one.

`assert_admitted_approved(&admitted, &[Family::Signature])` refuses every profile on 4.x (`AlgorithmTested` or `Unverified`), refuses on 3.x static every profile that admits Ed25519 (`unrestricted` and `fips1403`), and passes every other profile on 3.x; `cnsa2` passes there because it admits no signature on 3.x, which is not a refusal.

## Named residuals

1. **ECDSA cells stay `Unverified` on 4.x:** no certificate shows ECDSA key generation with SigGen and SigVer.
2. **The approval indicator is invisible, and looser than the evidence.** aws-lc-rs keeps AWS-LC's service indicator private. The module sets it for RSA signing at any even modulus of 2048 bits or more and for Ed25519 always (`crypto/fipsmodule/service_indicator/service_indicator.c`); the profiles and the cells are the controls.
3. **No hybrid signatures**, so `bsi` admits no ML-DSA; **no Brainpool**, so `bsi` admits no ECDSA.
4. **Canonical export.** `to_pkcs8_der` returns the module's encoding, not the bytes imported.
5. **ECDSA nonces** are AWS-LC's hedged random k ("a SHA512 hash of the private key and digest as additional data into the RBG", `crypto/fipsmodule/ecdsa/ecdsa.c`), not RFC 6979; FIPS 186-5 §6.3 approves both.
6. **No FIPS 204 context strings.** aws-lc-rs passes none, so ML-DSA-87 signs with the empty context.
7. **Fixed-width ECDSA** (JOSE) is #56.
8. **The key `csr::generate_csr` returns** is a `signature::KeyPair` made without an `Admitted`: it signs and exports under no profile (#57). The `signature` family governs keys made through `KeyPair::generate` and `KeyPair::from_pkcs8_der`, and `signature::verify`.
9. **One RSA key, one scheme.** The RSA-PSS variants use `rsaEncryption` keys (RFC 4055 §1.2's `id-RSASSA-PSS` key is not used), so `from_pkcs8_der` takes one key under either padding of its size. RFC 8017 §6 (pp. 17-18) does not recommend using one RSA key pair in more than one scheme, and RFC 4055 §8 (p. 22) says a key that signs RSASSA-PSS should not be used for other purposes; keeping a key to one variant is the caller's (#59).

## Consequences

- `KeyPair::generate`, `KeyPair::from_pkcs8_der` and `verify` take `&Admitted`; `to_pkcs8_der()` returns `Result<Zeroizing<Vec<u8>>, CryptoError>`; `verify` refuses a SubjectPublicKeyInfo; `from_pkcs8_der` refuses what the RFCs do not define; `SignatureAlgorithm::tls_scheme()` returns an `Option`; refusals are `SignaturePrivateKey` and `SignaturePublicKey` where they were `PrivateKey` and `Verify`. Breaking, once, for 0.9.0 callers (`docs/usage.md` §15).
- A key whose PKCS#8 another tool wrote with attributes is taken, and exported without them.
- Decisions 0004, 0008, 0010, 0011, 0012 and 0014 note what this decision settles.
