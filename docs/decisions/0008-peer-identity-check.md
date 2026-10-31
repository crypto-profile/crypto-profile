# 0008: Application identity checks on the crate's verifiers

- **Status:** Accepted, 2026-10-31

## Context

The crate's verifiers identify a server by DNS name. An application whose peer is identified otherwise (a URI-SAN workload identity, a pinned peer) had to write its own verifier, which needs the provider's verification algorithms and rustls's free verification functions, and which the strict builders refuse under a rule-bearing policy (decision 0007). So such an application could not use the peer-certificate rule at all.

## Decision

1. `tls::PeerIdentity` is an application check on the end-entity certificate, added with `with_peer_identity` on either verifier builder. It runs last: after the path to the roots, EKU, revocation and the policy's peer-certificate rule. It adds a refusal after the crate's checks; its error is returned unchanged. On the server verifier it is also the only identity decision (item 2).
2. On the server verifier it replaces the DNS-name check. Combining the two would leave a URI-identified server unverifiable. The method has the same name on both builders; replacing is stated in the server method's first doc line.
3. The handle's compatibility with the strict builders is still its rule and handshake-scheme set. The identity check does not change it.
4. `PeerLeaf::uri_names` returns rustls-webpki's subjectAltName URIs only when the crate's own DER count of URI entries agrees. rustls-webpki stops at the first entry it cannot decode, and drops a URI that is not UTF-8, so a check such as "exactly one URI" over its list alone could accept a certificate with a second entry it never read. The crate refuses any GeneralName form rustls-webpki does not decode, and any disagreement between the two counts.
5. A panic in the check unwinds out of the handshake, which fails. It is not caught.

This is the pattern of Go's `tls.Config.VerifyConnection` and of Envoy's subject-alternative-name matchers: the library's verification first, the application's identity decision after it.

## Consequences

- **Client resumption is safe by construction.** rustls resumes a client session only under the same verifier object (`rustls-0.23.46/src/msgs/persist.rs`, `compatible_config`), and the check lives in the verifier.
- **Server resumption is a residual, as in decision 0007.** rustls resumes a server session after checking the suite, EMS and SNI, and does not re-verify the client. Default stores are per configuration, so isolation holds unless an application shares `session_storage` or a `ticketer` between configurations with different identity checks. Never share them. The test `shared_server_session_storage_skips_the_identity_check` pins the residual.
- The check sees only the leaf the crate validated, never an intermediate.
- The check does not see the server name the client connected with, so a verifier handle, and the client configuration built on it, expect one identity; use one per expected peer.
- A client verifier built with `allow_unauthenticated` admits a client that presents no certificate without running the check, because rustls verifies only a presented certificate. An application that needs an identity for every client keeps authentication mandatory (the default). The test `an_unauthenticated_client_skips_the_identity_check_when_allowed` pins it.
- DNS-name and IP-address accessors, and any identity scheme's own parsing (SPIFFE trust domains), are the application's.
