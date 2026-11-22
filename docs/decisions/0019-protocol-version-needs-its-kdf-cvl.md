# 0019: A TLS protocol version is approved only with its key-derivation CVL

Date: 2026-11-22. Status: accepted. Amends [decision 0001](0001-founding.md) §5, [decision 0003](0003-quality-bar.md) §4 and [decision 0004](0004-algorithm-tested.md) §3.

## Context

#93. On the 3.x line `Protocol(Tls12)` was `Approved`, citing Table 5 of #5314 and #5298. On the 4.x line it was `Unverified`, because "no certificate shows a TLS 1.2 KDF with extended master secret" ([profiles](../profiles.md), section 6). Both lines lack the same thing, a CAVP test of the TLS 1.2 KDF with the extended master secret, so one of the two verdicts was wrong. Only the 3.x line has its security policy's tables in the code today; the 4.x cells move onto theirs in #81.

The evidence, retrieved 2026-11-22 (editions and hashes in [sources](../sources.md)):

- **The TLS 1.2 KDF the module was tested for.**
  - #5314 and #5298 Table 5 (p. 10 of each) list "KDF TLS (CVL)", SP 800-135 Rev. 1, "TLS Version - v1.0/1.1, v1.2". This is the RFC 5246 master secret.
  - Neither policy lists "TLS v1.2 KDF RFC7627", and the string "7627" appears nowhere in either. Table 5 lists every CAVP certificate the policy claims (A6283-A6310 and A6312-A6315 static; A6160-A6184, A6273-A6280 and A8121-A8124 dynamic), and it has no RFC 7627 row, so the policy claims no such test.
  - The CAVP capability records for the KDF TLS rows of A6288 and A6176, the first certificate each 3.x Table 5 lists, read "TLS Version: v1.0/1.1, v1.2; Hash Algorithm: SHA2-256, SHA2-384, SHA2-512" and nothing else ([sources](../sources.md)). The six 4.x records read the same (A7902, A7855, A7910, A7911, A7871, A7872; captured for knowledgebase#797). The other 3.x certificates in the KDF TLS row were not fetched; the policy's Table 5 settles what it claims.
- **What the policies exclude.** Table 8 (p. 12 of each) and the Non-Approved Services table list "TLS KDF using non-extended master secret" as not allowed.
- **What the policies approve.** This is counter-evidence. Table 12, Approved Services (p. 25 static, p. 26 dynamic), lists "Key Derivation with TLS KDF" with an approved indicator. §2.11 (p. 21) says the module "implements the TLS 1.2 and TLS 1.3 key derivation functions". Read as listing an approved service, which is how [decision 0015](0015-signatures.md) reads that table in the other direction, the policies approve the TLS 1.2 KDF with the extended master secret (EMS).
- **The FIPS 140-3 IG.** The edition in force at certification is "Last Update April 9, 2026" (#5298 validated 2026-06-03, #5314 2026-06-05). Its D.Q text is identical to every later edition's, and CSRC records D.Q's last change as 2023-03-17.
  - IG D.Q, p. 205: a validation submitted more than a year after 2022-05-16 "shall use the extended master secret in the TLS 1.2 KDF"; "The CVL algorithm validation certificate will indicate if the tested TLS 1.2 KDF was implemented with the extended master secret"; and "If a version of the TLS 1.2 KDF is not tested by the CAVP then it shall not be used in the approved mode".
  - IG 2.4.B item 6, p. 31: "KDF TLS" and "TLS v1.2 KDF RFC7627" are separately denoted CAVP tests.
  - The 3.x Test Reports came after their CAVP certificates, which CAVP first validated on 2024-11-25 (A6288) and 2024-11-16 (A6176), so D.Q applies. The CMVP certificate pages give the validation dates ([sources](../sources.md)).
- **What runs.** rustls requires EMS on TLS 1.2 when its provider is FIPS ([usage](../usage.md), section 7), so a FIPS TLS 1.2 handshake derives its keys with the EMS variant. No certificate shows that variant tested. The module's power-on self-test exercises the TLS PRF both variants share (label "FIPS self test", `self_check.c`). That meets IG 10.3.A Note 20, but it is not CAVP testing.

## Decision

1. **A TLS protocol version is `Approved` only when the module's evidence includes the CVL for that version's key-derivation function.**
   - TLS 1.2 needs "TLS v1.2 KDF RFC7627" (IG 2.4.B item 6, D.Q).
   - TLS 1.3 needs "TLS v1.3 KDF" (IG 2.4.B item 7). This restates decision 0004 §3 for cells sourced from a security policy.
2. **The IG together with CAVP evidence can override a security policy's Approved Services row.** If the IG says an untested version "shall not be used in the approved mode", the policy's algorithm table lists no such test, and the CAVP records read show none, the cell is `NotApproved`. Its source cites the policy's own tables and the IG, and names the Approved Services row it overrides. This is the first cell where the IG overrides a policy's affirmative listing. X25519, `NotApproved` under IG C.K Resolution 5 ([decision 0011](0011-ecdh-and-one-step-kdf.md)), is the nearest precedent, but no 3.x policy lists it as approved.
3. **`Protocol(Tls12)` is `NotApproved` on #5314 and #5298** (`capability.rs`, `tls12_ems`). On 4.x it stays `Unverified` until #81 moves the 4.x cells onto their security policies. Under this decision it then becomes `NotApproved` on the same evidence.
4. **An IG citation names its edition.** From this decision on, a cell sourced to a certificate cites the IG edition in force at that certificate's validation, with that edition's pages. Earlier citations name the edition [sources](../sources.md) pins (August 19, 2026). The 3.x X25519 cells cite IG C.K Resolution 5 at p. 160 of that edition; its text is identical in the April 9, 2026 edition (p. 145) and the November 20, 2026 edition (p. 164).

## Consequences

- `assert_module_approves` refuses every profile on both lines:
  - every resolved profile names TLS 1.3, whose cell no module's evidence approves;
  - a result narrowed to TLS 1.2 is refused at `Protocol(Tls12)`.

  It passes again only when a module's certificate carries the RFC 7627 test (requested upstream in aws/aws-lc#2921) or the TLS 1.3 KDF test (the AWS-LC 5 line, #82).
- The change ships as a conformance fix (CHANGELOG, Fixed): the earlier `Approved` was an overclaim.
- Protocol cells do not affect rustls's FIPS classification or the certificate-chain list. Those key on verifier cells only ([decision 0018](0018-chain-verification-follows-capability.md)), so `fips::assert_fips_*_config` is unchanged.
- [Decision 0003](0003-quality-bar.md) §4's second residual, that every walk stops at a version cell, now holds on 3.x too.
