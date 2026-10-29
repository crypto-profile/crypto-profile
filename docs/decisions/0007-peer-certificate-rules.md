# 0007: Peer certificate rules

## Decision

`Options::peer_certificates_match_profile` is opt-in and defaults to false. It checks peer leaf keys and every signature and issuing key on the selected validated path against the profile's cited rule. Regime profiles follow published text, not inferred intent. Exact lists remain exact; a published minimum remains a minimum. The local key rule is unchanged.

The maintainer resolved three rule derivations:

- `preferred` follows ISM-1763, ISM-1991 and ISM-1765 for leaf keys. ISM-1374 limits TLS certificate signatures to classical SHA-2 rules; an all-ML-DSA chain is refused.
- `bsi` uses TR-02102-2 2026-01 Table 12's three curve-bound ECDSA pairs and Table 14's RSA-PSS minimum of 3000 bits. PKCS#1 v1.5 is excluded after its 2025 allowance.
- `fips1403` uses the updated-approval reading: ECDSA with SHA-2, Ed25519, ML-DSA-87, RSA-PSS and PKCS#1 v1.5, with an even RSA modulus of at least 2048 bits under SP 800-52r2 §3.3.3.

See [profiles](../profiles.md#9-impact-of-peer-certificate-enforcement) for the complete cited rules. Certificate path signatures differ from handshake schemes: `cnsa1` permits RSA PKCS#1 v1.5 with SHA-384 on a path even for TLS 1.3. The anchor-issued child signature is checked; the anchor's self-signature is not. CRL signatures remain on the baseline list.

`resolve` puts the rule in `tls::Policy`; a hand-written policy can use `None`. Verifier builders produce owned handles with roots, revocation configuration, rule and canonical handshake-scheme identity. Strict client and server completion builders install those handles only when rule and scheme set match. Opaque or mismatched handles return `TlsError::IncompatiblePeerVerifier`. Old completion builders refuse a rule-bearing policy with `TlsError::StrictBuilderRequired`. Rule violations carry `TlsError::PeerCertificate`. The cache is bounded by the finite rule identities and canonical scheme sets, not peer certificates or roots.

## Consequences

Mixed PKIs can continue with the default; strict deployments can enforce the cited rules. The verifier inspects the exact path selected after baseline and revocation validation. A non-compliant selected path is refused even if a compliant alternative exists. Code driving rustls directly bypasses enforcement; `crypto_provider` alone is insufficient. Adoption makes consistent policy easy. Never share server session storage or ticket keys between configurations with different peer-certificate rules: resumed sessions skip certificate verification. Default stores are isolated. Dual-signature and composite certificates are unsupported.
