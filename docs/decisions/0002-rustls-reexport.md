# 0002: Re-export rustls; never re-export aws-lc-rs

- **Status:** Accepted, 2026-10-28

## Context

The backend's TLS API is made of rustls types: `CryptoProvider`, `ClientConfig`, `ServerConfig`, the configuration builders and the certificate verifiers. An application that uses `tls::client_builder` needs those types in scope.

If the application declares `rustls` itself, it chooses the features. rustls's default features are `aws_lc_rs`, `logging`, `prefer-post-quantum`, `std` and `tls12` (`rustls-0.23.46/Cargo.toml`, `[features] default`), and Cargo unifies them onto the one rustls in the build. A direct dependency also makes rustls's own entry points the natural ones to reach for, and `ClientConfig::builder()` and `ServerConfig::builder()` install rustls's stock aws-lc-rs provider when no process default is installed (`rustls-0.23.46/src/crypto/mod.rs:243-286`). That provider carries rustls's defaults, not the application's policy. *(Amended 2026-10-29, round 3a: the backend builds rustls with no provider feature, so the re-exported `rustls` has no built-in provider surface: no `rustls::crypto::aws_lc_rs` module (and no `Ticketer`, `hpke`, `cipher_suite`, `kx_group` or `sign` from it) and no `rustls::crypto::default_fips_provider`; and `ClientConfig::builder()`, `ServerConfig::builder()` and the WebPKI verifiers' `builder()` no longer install a provider. They panic unless a process default is installed, and install rustls's stock one only when the features unified onto rustls name exactly one of `aws_lc_rs` and `ring` and do not include `custom-provider` (`rustls-0.23.46/src/crypto/mod.rs:265-286`; `docs/usage.md` section 5; `ci/shipped-graph.sh`).)*

aws-lc-rs is different: its types are not part of the backend's API, and a re-export would let an application call primitives around the crate.

## Decision

- `crypto-profile-awslc4` re-exports `rustls` (`pub use rustls;`), and the documentation tells applications to use `crypto_profile_awslc4::rustls` and not to declare `rustls` themselves.
- It does not re-export `aws_lc_rs`.
- It re-exports `rcgen` only under the `test-support` feature.
- This is kept for now and revisited when the repository is public and users can give feedback.

## Consequences

- The rustls version an application builds with is the one the backend pins and was tested with (`=0.23.46`). Its features are not fixed: Cargo unifies features across the whole dependency graph, so they are the union of what every crate depending on rustls enables. An async TLS adapter with its default features, for example, adds rustls's `aws_lc_rs`, `logging` and `tls12` (`tokio-rustls-0.26.6/Cargo.toml`, `[features] default`).
- The re-export does not stop an application from calling rustls's stock-provider entry points through it. This repository's `clippy.toml` refuses them in the crate's own code, but that lint does not reach a dependent crate. The documentation names this residual, and the provider internals reachable through `CryptoProvider`'s public fields (`docs/usage.md` section 5). *(Amended 2026-10-29, round 3a: in the backend's own build the stock-provider entry points no longer exist in the re-exported crate; they come back only when another crate in the graph enables a rustls provider feature, and the residual is limited to that case.)*
- rustls's semver becomes part of the backend's: a rustls minor version that changes its API changes ours.
- Round 3 replaces the built-in provider with one this project owns, which narrows what the re-exported types can reach.
