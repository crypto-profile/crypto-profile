# 0004: `AlgorithmTested`, a CAVP-only status that is never an approval

- **Status:** Accepted, 2026-10-28

## Context

Decision 0001 §5 makes every approval no published security policy settles `Unverified`. The AWS-LC FIPS 4.x module is in CMVP review with no security policy published, but the CAVP has published 38 algorithm certificates for AWS-LC FIPS 4.0.0 (A7839-A7876, all dynamic build, one per processor variant). A certificate shows that an implementation passed algorithm testing with named parameters. It does not show that the module's approved mode offers the algorithm, so it is weaker evidence than a security policy's table, and stronger than none.

## Decision

1. **A fourth approval status, `Approval::AlgorithmTested { cavp }`,** sits between `Unverified` and `Approved`. `is_approved()` is false for it, as for `Unverified` and `NotApproved`; nothing in the crate treats it as approved, and `assert_module_approves` refuses it.
2. **The evidence rule.** A cell is `AlgorithmTested` only when one CAVP certificate for that module shows every operation the cell needs, each with the cell's exact parameters (curve, hash, modulus, padding, parameter set). For ECDSA and RSA, only the FIPS 186-5 capabilities count; a FIPS 186-4 capability never qualifies a cell. Capabilities are never combined across certificates, because each certificate is one processor variant. `cavp` names that certificate, lowest-numbered where several qualify, and the capabilities and parameters it shows. Without such a certificate the cell stays `Unverified`.
3. **Evidence for one operation is not evidence for another.** An ECDH group's cell needs both KAS-ECC-SSC (SP 800-56A r3) and ECDSA key generation (FIPS 186-5) for its curve, on one certificate: SP 800-56A r3 §5.6.1.2 generates the ephemeral key pair with a FIPS 186 method, and the KAS-ECC-SSC test covers only the shared-secret computation, so neither capability is evidence alone. A KDA HKDF capability (SP 800-56C r1) is not evidence for the TLS 1.3 key schedule: `Protocol(Tls13)` needs a TLS 1.3 KDF capability.
4. **Scope.** Only for a module with CAVP certificates and no published security policy: today the 4.x dynamic build. The 4.x static build has no CAVP certificate found, so its cells stay `Unverified`. A cell is never `Approved` on CAVP evidence alone; when the 4.x security policy is published, its tables replace these cells.
5. **A cell claims only the parameters `cavp` names.** A `Scheme` cell names the moduli or the curve its certificate tested, while rustls verifies a wider range under the same scheme: RSA moduli from 2048 to 8192 bits, and, on TLS 1.2, ECDSA keys on any of the three NIST curves under each ECDSA scheme (`rustls-0.23.46/src/crypto/aws_lc_rs/mod.rs:171-179,185-233`). That gap is the peer-key residual `docs/profiles.md` names.
6. **The variant caveat.** A cell is tested on its certificate's processor variant; which variant a build uses depends on the CPU, and the crate does not claim a deployment's processor is that variant. *(Amended 2026-10-28: the lowest-numbered rule picks x86 variants for the A7855 and A7856 cells. Their CAVP pages list x86 environments only; the same capabilities, with the same parameters, appear on the arm64 certificates A7872 (NEON), for both, and A7871 (SHA_CE), for A7855's. A7864 lists x86 and arm64 environments, and A7873 is arm64. `docs/profiles.md` §6 gives the detail. The cells still cite one certificate each.)*

## Consequences

- Decision 0001 §5's "every 4.x approval is `Unverified`" becomes "every 4.x approval is `Unverified` or `AlgorithmTested`", and §3's "each sourced cell cites that module's own security policy and table" admits one CAVP certificate for an `AlgorithmTested` cell, each with a dated note there pointing here. Every document and doc comment that states the claim rule names both sources.
- A cell whose operations no single certificate shows stays `Unverified`, even where the module's certificates show each operation separately. That understates the evidence rather than overstating it.
- A code change to a cell's `cavp` text is a change to a claim, reviewed against the certificate's expanded capabilities.
