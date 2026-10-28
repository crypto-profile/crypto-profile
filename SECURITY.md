# Security policy

## Reporting a vulnerability

Report a vulnerability privately, through GitHub's private vulnerability reporting for this repository: the **Security** tab, then **Report a vulnerability**. Never report one in a public issue, pull request or discussion.

crypto-profile is pre-release, and no version is supported for production use yet. Fixes land on `main`.

## Scope

In scope is this repository's own code and its claims:

- the core crate `crypto-profile`: the algorithm types, the capability table and its citations, the sealed-box framing and the conformance suite;
- the backend `crypto-profile-awslc4`: how it selects, composes and checks AWS-LC's primitives, its TLS policy and provider construction, its key, CSR, AEAD and sealed-box code, and its FIPS checks;
- the claims the crate makes: a capability cell that misstates its source (a security policy's table, or for an `AlgorithmTested` cell the CAVP certificate it names), a certificate status that is wrong for the release, or documentation that implies a validation the crate does not have.

Out of scope here, and to be reported to the project that owns the code:

- **AWS-LC, aws-lc-rs and aws-lc-fips-sys:** AWS asks that potential security issues be reported through its [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/), not a public GitHub issue (`aws-lc-rs-1.18.2/README.md:255-258`; `aws-lc-fips-sys-0.14.2/README.md:228-233`).
- **rustls:** report through [rustls's GitHub security advisories](https://github.com/rustls/rustls/security/advisories/new), as its [security policy](https://github.com/rustls/rustls/blob/main/SECURITY.md) describes.
- **rustls-webpki and rcgen:** through their own repositories' security reporting.

If you are not sure where a defect lies, report it here; we will help route it.

## What to include

- The crate, version or commit, and the backend.
- The linkage (static or dynamic), the target triple, and the Rust version.
- What you expected and what happened, with the smallest reproduction you can give: a test, a `Policy`, or the input bytes.
- For a claim defect: the capability cell or document, and the security-policy table or CAVP certificate that contradicts it.
- Whether you used AI assistance to find or describe the issue.
- Whether the issue is public anywhere else, and any disclosure deadline you are working to.
