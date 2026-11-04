# 0016: TLS certificate keys under the profile's TLS key list

Date: 2026-11-04. Status: accepted.

## Context

Before this decision `csr::generate_csr(alg, &params)` took no profile. It generated a key of any TLS key algorithm and returned it as a `signature::KeyPair`, which signs any message and exports, so a `cnsa2` caller could still get an ECDSA P-256 signature (#57; decision 0015, residual 8). Behind it was a second gap. A TLS key is admitted against the profile's TLS key list (`Resolved::keys`), and `signature::KeyPair::generate` and `KeyPair::from_pkcs8_der` admit against its signatures outside TLS (`Admitted::signatures`). The two lists differ: every `bsi` TLS key (ECDSA P-384, P-256, and P-521 with SHA-512) is outside `bsi`'s signatures, which are RSA-PSS only, and ECDSA P-521 with SHA-384 is in the TLS list but not the signature list under `preferred` and `fips1403`. Those callers had no governed route to a TLS key: `docs/usage.md` told them to take the key `generate_csr` returned, or to generate under `admit(Profile::Unrestricted, ..)`, and both gave a key that signed outside TLS under no profile.

## Decision

**The approach (maintainer, 2026-11-04):** `generate_csr` takes the profile, through its key: it requests a certificate for a key made under a `Resolved`, and that key has no `sign`; it signs through the TLS key provider with the policy's TLS schemes, and its PKCS#8 export is the private key, which imports as a `signature::KeyPair` only under an `Admitted` whose signatures admit the algorithm (residuals 2 and 4).

```rust
pub struct CertificateKey; // in `tls`
impl CertificateKey {
    pub fn generate(r: &Resolved, a: SignatureAlgorithm) -> Result<CertificateKey, CryptoError>;
    pub fn from_pkcs8_der(r: &Resolved, a: SignatureAlgorithm, der: &[u8]) -> Result<CertificateKey, CryptoError>;
    pub fn algorithm(&self) -> SignatureAlgorithm;
    pub fn public_key(&self) -> &[u8];
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}
pub fn generate_csr(key: &CertificateKey, p: &CsrParams) -> Result<String, CryptoError>; // in `csr`
impl Resolved {
    pub fn certified_key(&self, chain: Vec<CertificateDer<'static>>, key: &CertificateKey)
        -> Result<CertifiedKey, CryptoError>;
}
```

- **Admitted against the TLS key list.** A certificate key is a TLS key, so `generate` and `from_pkcs8_der` admit it against `Resolved::keys`, the list `certified_key` and the profile's TLS rules already use, not against the signatures outside TLS. So every TLS key of every profile is made under that profile's own `Resolved`, the `bsi` keys and P-521 with SHA-384 under `preferred` and `fips1403` among them.
- **Refusal order.** `generate`: `KeyNotInProfile` for an algorithm not in `r.keys`, then `Unavailable` for one the module line lacks, then `KeyGeneration`. `from_pkcs8_der`: `KeyNotInProfile`, then `Unavailable`, then `SignaturePrivateKey` for any structure or key `KeyPair::from_pkcs8_der` refuses (decision 0015). `resolve` already moves what the module line lacks into `Resolved::excluded`, so `Unavailable` is reached only through a `Resolved` whose `keys` were reassigned; it stays, failing closed. The admission is a named helper, `admit_certificate_key`, not a function named `new` (#40).
- **One implementation.** A `CertificateKey` holds a `signature::KeyPair` privately and is built through `KeyPair`'s crate-private generation and import path, after its own admission, so the key is held once, as the module's parsed key (decision 0012), with the import checks of decision 0015, and is not `Clone`. Its `Debug` prints the algorithm only.
- **No `sign`.** A `CertificateKey` has no `sign`, no `Deref` or `AsRef` to `KeyPair`, no conversion into one, and no `rcgen` trait implementation. rcgen signs a request through `rcgen::SigningKey`, which `serialize_request` needs; `generate_csr` passes rcgen the held `KeyPair` through a crate-private accessor, so the trait is implemented on a type a caller cannot get from a `CertificateKey`, except as a `signature::KeyPair` imported from its export under an `Admitted` whose signatures admit the algorithm. Outside a request the key signs through the TLS key provider, which `certified_key` and `tls::load_private_key` load it into, with the policy's TLS schemes (residual 2); what its export imports as is below. `compile_fail` doctests on both backends pin that a `CertificateKey` does not sign, does not implement `rcgen::SigningKey`, is not a `KeyPair`, does not convert into one (`AsRef`, `Into`), is neither an `rcgen::PublicKeyData` nor a `Borrow<KeyPair>` and is not `Clone`, and that `generate_csr` and `certified_key` refuse a `KeyPair`; each was observed to compile once the route it forbids was added. rustdoc on stable does not check their error codes, so the compiling sibling block, which holds every prelude line, is what keeps each block failing on its last line.
- **The export is the private key.** `to_pkcs8_der()` is the module's canonical encoding, as `KeyPair::to_pkcs8_der` gives it. In this crate, outside the `test-support` rcgen re-export (residual 2), it imports as a `CertificateKey` under a `Resolved` whose `keys` hold the algorithm; as a `signature::KeyPair` only under an `Admitted` whose signatures admit the algorithm (a `bsi` ECDSA key does not come back as a `KeyPair` under `bsi`, and does under a profile whose signatures admit it, which the caller names; `docs/profiles.md` section 15 lists each profile's signatures); into the TLS key provider through `tls::load_private_key` and the builders' key loading (residual 2); and, for an EC key, as an `ecdh::StaticKey` (`from_pkcs8_der`, or `from_scalar` of its scalar) or a `sealbox::PrivateKey` (residual 4). Any other library that holds the bytes signs with them under no profile (residual 2).
- **What `csr` became.** `generate_csr` requests a certificate for a key the caller keeps, so a renewal can request again for the same key. It refuses the request's names and parameters, and a key rcgen cannot sign with (`CsrError::Signing`, residual 1), with `CryptoError::Csr`. It no longer generates a key, so `KeyPair::generate_tls_key` is removed.
- **`certified_key` keeps `admit_key`,** because a `CertificateKey` made under one `Resolved` can be presented under another: a P-256 key made under `bsi` is refused under `cnsa1` with `KeyNotInProfile`. It keeps the key-match check and the scheme restriction.
- **`CryptoError::NotTlsKey` is removed.** Its only producers were `generate_csr` and the crate-private TLS key constructor. The RSA-PSS variants are in no profile's TLS key list, so `generate` and `from_pkcs8_der` refuse them with `KeyNotInProfile`. The variant was added in this release cycle, so no 0.9.0 caller names it.

## Named residuals

1. **A reassigned key list.** `Resolved`'s fields are public, so a caller can put an RSA-PSS variant into `keys`. `generate` then makes an RSA key labelled with that variant: `generate_csr` refuses it with `CryptoError::Csr(CsrError::Signing)`, because rcgen has no RSA-PSS descriptor (decision 0015), and `certified_key` loads it as an RSA key that signs only with the policy's schemes. A reassigned `keys` is also the only way to reach the `Unavailable` refusal in the refusal order above, because `resolve` moves what the module line lacks into `excluded`. The profile's own lists never do either.
2. **The TLS signer signs what it is given.** A rustls `Signer` signs whatever bytes it is handed. A `CertificateKey` reached through `Resolved::certified_key` (`certified.key.choose_scheme(..)`) or its export loaded through `tls::load_private_key` or the builders' `with_single_cert` and `with_client_auth_cert` therefore signs any message a caller passes, but only under a scheme in the policy's `signature_schemes`: the policy bounds the algorithm, not the message. The crate does not wrap rustls's `SigningKey`. The bound is the `Policy` the key is loaded under: `Resolved::tls` is public like `keys`, and `tls::load_private_key` takes any `Policy`, so a caller that reassigns or builds one widens the schemes. The export is the private key too: the PKCS#8 bytes are the key, and any library that holds them signs with them under no profile, including rcgen as the `test-support` feature re-exports it.
3. **One RSA key, two paddings.** A `CertificateKey`'s RSA export imports as a `KeyPair` under either padding of its size where the profile's signatures admit it (#59; decision 0015, residual 9).
4. **One key, more than one use.** The EC export of a `CertificateKey` also imports as an `ecdh::StaticKey` (P-256, P-384 or P-521) or a `sealbox::PrivateKey` (P-384) under an `Admitted` whose key agreements admit it: none under `bsi` or `cnsa2`, P-384 only under `cnsa1`. The other way, an EC private key in the PKCS#8 form `ecdh::StaticKey::from_pkcs8_der` takes, or a `sealbox::PrivateKey` export, imports as a `CertificateKey` under a `Resolved` whose `keys` hold it. The crate does not separate key usage across those types (the same class as #59).

## Consequences

- `csr::generate_csr` takes `&CertificateKey` and returns the request only, and `Resolved::certified_key` takes `&CertificateKey`: breaking, once, for 0.9.0 callers (`docs/usage.md` §15).
- `CryptoError::NotTlsKey` is removed. It was added and removed within 0.10.0's cycle, so no released version has it.
- `docs/usage.md` no longer tells a caller to take a TLS key from `generate_csr` or to generate one under `unrestricted`.
- Decision 0015's residual 8 is closed, and its PSS paragraph amended.
