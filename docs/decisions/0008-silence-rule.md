# 0008: Silence refuses, and families outside TLS are admitted on their own

Date: 2026-10-31. Status: accepted.

## Decision

**The silence rule.** A profile admits an algorithm only where its governing text admits it. When the text names no construction for a family, the profile refuses that family, unless a guidance document the text itself cites or contains names the construction over primitives the text admits. Silence is not approval.

Message authentication is the first family the rule decides. CNSSP 15 names no MAC in either edition, and the ISM names none among its general-purpose controls. Those profiles reach HMAC through these chains:

- **`cnsa2`:** CNSSP 15 (December 2024) Annex B (p. B-1) admits SHA-384 and SHA-512. ¶8a (p. 5) names RFC 9206 and RFC 9151 as examples of NSA's guidance on the approved protocols, and footnote 1 keeps them in force as protocol guidance. RFC 9206 §8 admits PRF_HMAC_SHA2_384 and PRF_HMAC_SHA2_512 and says that any other "MUST NOT be used"; §4 names SHA-384 the CNSA hash "for all purposes". `cnsa2` admits HMAC-SHA384, then HMAC-SHA512.
- **`cnsa1`:** CNSSP 15 (20 October 2016) Annex B (p. B-1) admits SHA-384. The profile follows RFC 9151, whose §4 approves SHA-384 for the TLS 1.2 PRF and the TLS 1.3 HKDF, both HMAC. `cnsa1` admits HMAC-SHA384 only; RFC 9206's HMAC-SHA512 is not taken, because Annex B names SHA-384 alone.
- **`preferred`:** the ASD ISM names HMAC only inside its protocol controls: ISM-1772 (p. 15) and ISM-0998 (p. 16) for IPsec, and ISM-1375 (p. 20) for TLS, each over SHA-2. `preferred` admits HMAC-SHA512, HMAC-SHA384 and HMAC-SHA256. The ISM says HMAC-SHA256 "will not be approved beyond 2030" (pp. 15-16); `preferred` keeps it until a later transition point and will warn before it removes it.

`fips1403`, `fips1402` and `bsi` name HMAC directly: FIPS 198-1 with SP 800-131A r2 Table 9 (p. 20), FIPS 140-2 Annex A (p. 3), and TR-02102-1 §5.2 (pp. 49-50).

**The near-term allowance.** CNSSP 15 (2016) Annex B ¶2b (p. B-2) lets UNCLASSIFIED NSS data and community-of-interest separation keep SHA-256 "in the near term". `Options::cnsa1_unclassified_nss` admits HMAC-SHA256 under `cnsa1` on those terms. It is off by default, every other profile ignores it, and it covers message authentication only. `cnsa1` retires when the transition to `cnsa2` completes, and the option with it.

**Key length.** An HMAC key is at least 112 bits under every profile and 128 under `bsi`. 112 is the module's approved minimum, not a profile rule: SP 800-131A r2 §10 Table 9 (p. 20) disallows shorter keys for MAC generation, and the AWS-LC FIPS 3.1.0 security policies list "Key Length: 112-524288" (Table 5, p. 9). `bsi` takes the 128 of TR-02102-1 Table 5.2 (p. 50). CNSSP 15 states no HMAC key length, and `cnsa2` covers UNCLASSIFIED through TOP SECRET, so no profile sizes a key to the data. SP 800-107 r1 §5.3.2 (pp. 13-14) puts that on the caller: a key "shall have a security strength that meets or exceeds the security strength required to protect the data". Keys are at most 524288 bits, the module's tested maximum.

**Admission outside TLS.** Families outside TLS are admitted by `admit(profile, options)`, which returns an `Admitted` and never refuses. A family left empty refuses each of its constructors with `CryptoError::NotInProfile`. `resolve` and its refusals are unchanged. `assert_admitted_approved` checks the admitted cells separately from `assert_module_approves`.

## Consequences

`cnsa2` HMAC works on the 3.x line, where `resolve(Cnsa2, ..)` refuses for want of ML-DSA, and a caller that only uses TLS is never refused for a cell outside TLS. Later families (HKDF, ECDH, ML-KEM, RSA-OAEP) join `Admitted` and are decided under the same rule.

A format whose MAC is fixed at HMAC-SHA256 cannot be produced under `cnsa2`, or under `cnsa1` without the option. The crate refuses it; it does not carve out an exception.
