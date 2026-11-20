# 0018: `fips1403` keeps Ed25519 out of TLS, and chain verification follows the capability table

Date: 2026-11-20. Status: accepted. Amends [decision 0007](0007-peer-certificate-rules.md) and [decision 0015](0015-signatures.md).

## Context

#77. A policy's `signature_schemes` restricts only the handshake-signature mapping. The list rustls and rustls-webpki verify certificate-chain signatures with, `WebPkiSupportedAlgorithms::all`, was one process-wide list that every provider the crate builds carried unfiltered. It held Ed25519. So on the 3.x static build a crate-built provider verified Ed25519 signatures on certificate chains, and every verifier reported the module's FIPS mode as its `fips()`, so rustls classified the configuration as FIPS. Decision 0015 had made the 3.x static Ed25519 cell `NotApproved` and said "No TLS outcome changes"; the chain list is the outcome it missed.

The evidence, retrieved 2026-11-20 (editions and hashes in [sources](../sources.md)):

- **#5314, AWS-LC FIPS 3.1.0 static, Table 12 (Approved Services).** Signature Generation lists "with RSA" and "with ECDSA" (p. 24). Signature Verification lists "with ECDSA", "with RSA", "with RSA (Legacy)" and "with ECDSA (Legacy)" (p. 25). Neither lists EdDSA, though Table 5 lists EDDSA SigGen and SigVer and Table 9 defines the functions.
- **#5298, the dynamic build.** Its Signature Verification service lists "with EDDSA" (p. 25).
- **NIST SP 800-52r2.** It does not mention EdDSA. §3.2 (p. 9) names the certificates that meet NIST-approved cryptography for a TLS server: RSA, ECDSA, DSA, DH and ECDH, with "at a minimum … an RSA signature certificate or an ECDSA signature certificate". Table 3-1 (pp. 10-11) and Table 4-1 (p. 34) list the issuer signature algorithms: sha256WithRSAEncryption or stronger, id-RSASSA-PSS, and ecdsa-with-SHA256 or stronger.
- **Field practice (maintainer, 2026-11-20).** RHEL 10, validated after FIPS 186-5, excludes Ed25519 in FIPS mode.

A first design kept Ed25519 in `fips1403` and labelled its verifier non-FIPS on 3.x static. rustls's `fips()` is one conjunction over every component (`rustls-0.23.46/src/crypto/mod.rs:294-307`, and over every verifier in `src/webpki/verify.rs:107-113`), and it also sets `require_ems` (`src/client/builder.rs:166`, `src/server/builder.rs:104`). So that design would have stopped `fips1403` requiring Extended Master Secret on TLS 1.2 on that build, and nothing would have reported it.

## Decision

**The approach (maintainer, 2026-11-20):** a FIPS profile does not offer an algorithm that the TLS guideline, the validated module and the field all exclude. Fix the profile; do not keep the algorithm and label it.

1. **`fips1403` drops Ed25519 from TLS on every module.** Its handshake schemes and TLS key list no longer hold Ed25519, citing SP 800-52r2 §3.2 (p. 9), Table 3-1 (pp. 10-11) and Table 4-1 (p. 34). Its signatures outside TLS are unchanged: FIPS 186-5 governs those, and `assert_admitted_approved` keeps refusing Ed25519 on the 3.x static build. `fips1403` stays FIPS-classified, so rustls keeps requiring EMS where TLS 1.2 is enabled.
2. **The `fips1403` peer-certificate rule drops Ed25519,** from leaf keys, issuer keys and path signatures. This amends decision 0007's updated-approval reading.
3. **Each verifier names the capability cell that governs it.** `provider::verify::Verifier` has a required `scheme`: the handshake scheme whose cell covers the verification service it uses, grouped as rustls's own mapping groups it, by hash. A verifier with no cell in the inventory (ML-DSA-44 and ML-DSA-65 on 4.x) has `None`, which is treated as `Unverified`: never refused.
4. **The chain list follows the capability table, for every algorithm.** `all` leaves out every verifier whose cell on the build's module is `NotApproved` (`provider::verify::chain`, called once by `provider::assembly::verification`). Today that is Ed25519 on the 3.x static build and nothing else. It is still one list, so the server and client certificate verifiers, the strict peer-certificate verifiers and any platform verifier built from the provider all use it. `Approved`, `AlgorithmTested` and `Unverified` cells keep their verifiers: refusing those would empty the 4.x list until a 4.x security policy is published, and `assert_module_approves` remains the approval gate.
5. **`fips()` follows the cell.** A verifier reports the module's FIPS mode only where its cell is not `NotApproved` (`provider::verify::fips_given`).
6. **A policy's `signature_schemes` does not govern `all`.** Path signatures and handshake schemes differ (decision 0007), and the peer-certificate rule is the per-profile chain control. The module's refusals are a floor under every policy.
7. **`assert_provider_matches` compares by identity,** in order: the suites, the groups, each handshake scheme's verifiers, `all`, the random source and the key provider; it destructures the provider, so a field rustls adds fails to compile here. A substitute that reports the same codepoint or algorithm identifiers is refused. Before, it compared suites, groups and schemes by name and did not look at the verifiers.

## Consequences

| | 3.x static | 3.x dynamic | 4.x |
|---|---|---|---|
| `fips1403` TLS schemes and keys | no Ed25519 | no Ed25519 | no Ed25519 |
| `fips1403` provider `fips()` and `require_ems` | true | true | true |
| `fips1403` peer-certificate rule | refuses Ed25519 | refuses Ed25519 | refuses Ed25519 |
| Chain list | no Ed25519 | unchanged | unchanged |
| Ed25519 verifier `fips()` | false | module mode | module mode |
| A policy listing the Ed25519 scheme | not FIPS-classified; EMS not required | unchanged | unchanged |

A peer whose selected path carries an Ed25519 signature that WebPKI checks is refused on the 3.x static build under every policy, `unrestricted` included, with `CertificateError::UnsupportedSignatureAlgorithmContext`, before any peer-certificate rule runs. A `fips1403` peer presenting an Ed25519 certificate is refused everywhere: there is no handshake scheme to verify its signature with.

## Named residuals

1. **ML-DSA-87 in `fips1403` TLS.** SP 800-52r2 predates FIPS 204 and names no ML-DSA. The scheme and key stay, as they do in `preferred` and `cnsa2`; a contributor or adopter may argue for removing them (maintainer, 2026-11-20).
2. **A hand-written policy with the Ed25519 scheme on the 3.x static build** carries a refused verifier in its mapping, so rustls does not classify it as FIPS and does not require EMS on TLS 1.2, as for a policy with X25519. `fips::assert_fips_client_config` and `assert_fips_server_config` refuse it.
3. **Verifiers outside the inventory** (`None`) are not refused, as an `Unverified` cell is not.
4. **4.x is unchanged** until a published 4.x security policy makes a cell `NotApproved`; the table then removes it from the chain list with no code change.
5. **Handshake signatures on the 3.x static build.** A policy that lists the Ed25519 scheme (`unrestricted`, or a hand-written one) still verifies an Ed25519 handshake signature from a peer whose leaf key is Ed25519, under a chain without Ed25519 signatures; the policy governs the mapping, and residual 2 says how it is classified.
6. **Scheme cells stand for the signature-verification service.** A chain verifier is governed by its handshake scheme's cell. A future scheme cell made `NotApproved` for a TLS-protocol reason would also remove its chain verifiers.
7. **Cells are per scheme, not per key size.** The RSA chain verifiers take moduli up to 8192 bits, beyond #5314's SigVer sizes; the chain list follows the cell, which is per scheme (#78).
8. **A trust anchor's own signature is not checked.** WebPKI verifies each signature on the selected path from the anchor's key down; an ECDSA- or RSA-keyed anchor whose own certificate an Ed25519 CA issued (a cross-signed certificate, say) still anchors a path whose checked signatures are ECDSA or RSA. An Ed25519-keyed anchor does not: its child's signature is Ed25519, and is refused.
