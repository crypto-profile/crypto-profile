//! Profiles resolved against this backend's module.
use crate::tls::Policy;
use crate::{Algorithm, Approval, CryptoError, Options, Profile, SignatureAlgorithm};

/// A profile resolved against this backend's module. `profile` and `options` say what `resolve`
/// was called with; `tls` goes to `tls::client_builder`, `tls::server_builder` and the verifier
/// builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The profile.
    pub profile: Profile,
    /// The options it was narrowed by.
    pub options: Options,
    /// The TLS policy.
    pub tls: Policy,
    /// The key algorithms the profile admits, in preference order.
    pub keys: Vec<SignatureAlgorithm>,
}

/// Resolves `profile`, narrowed by `options`, against this backend's module. Refuses with
/// `CryptoError::Unavailable` naming the first algorithm the module lacks (never dropping it),
/// and with `CryptoError::EmptyProfile` when a family comes out empty.
pub fn resolve(profile: Profile, options: Options) -> Result<Resolved, CryptoError> {
    let s = crypto_profile::profile::select(profile, options, crate::MODULE)?;
    Ok(Resolved {
        profile,
        options,
        tls: Policy {
            versions: s.versions,
            cipher_suites: s.cipher_suites,
            kx_groups: s.kx_groups,
            signature_schemes: s.signature_schemes,
        },
        keys: s.key_algorithms,
    })
}

impl Resolved {
    /// Refuses a key algorithm the profile does not admit. Call it where a key is generated or a
    /// certificate request is made; `signature::KeyPair::generate` does not.
    pub fn admit_key(&self, a: SignatureAlgorithm) -> Result<(), CryptoError> {
        if self.keys.contains(&a) {
            Ok(())
        } else {
            Err(CryptoError::KeyNotInProfile {
                profile: self.profile,
                algorithm: a,
            })
        }
    }
}

fn walk(r: &Resolved) -> Vec<Algorithm> {
    let mut v: Vec<Algorithm> = r
        .tls
        .versions
        .iter()
        .map(|x| Algorithm::Protocol(*x))
        .collect();
    v.extend(r.tls.cipher_suites.iter().map(|x| Algorithm::Cipher(*x)));
    v.extend(r.tls.kx_groups.iter().map(|x| Algorithm::Kx(*x)));
    v.extend(
        r.tls
            .signature_schemes
            .iter()
            .map(|x| Algorithm::Scheme(*x)),
    );
    v.extend(r.keys.iter().map(|x| Algorithm::Signature(*x)));
    v
}

fn approves_under(
    r: &Resolved,
    approval: impl Fn(Algorithm) -> Approval,
) -> Result<(), CryptoError> {
    for algorithm in walk(r) {
        let approval = approval(algorithm);
        if !approval.is_approved() {
            return Err(CryptoError::NotApproved {
                algorithm,
                approval,
            });
        }
    }
    Ok(())
}

fn approves_given(
    fips_mode: bool,
    r: &Resolved,
    cell: impl Fn(Algorithm) -> Approval,
) -> Result<(), CryptoError> {
    approves_under(r, |a| crate::fips::approval_given(fips_mode, cell(a)))
}

/// Refuses unless every algorithm `r` names, each protocol version included, is `Approved` for
/// the running module, and only while the module is in FIPS mode (as [`crate::fips::approval`]
/// reports it). Fails on the first cell that is not `Approved`; `AlgorithmTested` is not. On the
/// 4.x module it fails today: with no security policy published, no 4.x cell is `Approved`.
pub fn assert_module_approves(r: &Resolved) -> Result<(), CryptoError> {
    approves_given(aws_lc_rs::try_fips_mode().is_ok(), r, |a| {
        crypto_profile::capability(crate::MODULE, a).approval
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
        TlsVersion as V,
    };

    const PQ: Options = Options {
        pq_key_exchange_required: true,
    };

    fn every_resolved() -> Vec<Resolved> {
        let mut v = Vec::new();
        for p in Profile::ALL {
            for o in [Options::default(), PQ] {
                if let Ok(r) = resolve(p, o) {
                    v.push(r);
                }
            }
        }
        assert_eq!(v.len(), 11);
        v
    }

    fn synthetic(_: Algorithm) -> Approval {
        Approval::Approved {
            source: "synthetic",
        }
    }

    fn module_cell(a: Algorithm) -> Approval {
        crypto_profile::capability(crate::MODULE, a).approval
    }

    #[test]
    fn resolve_carries_the_profile_the_options_and_the_policy() {
        let r = resolve(Profile::Cnsa2, PQ).unwrap();
        assert_eq!((r.profile, r.options), (Profile::Cnsa2, PQ));
        assert_eq!(
            r.tls,
            Policy {
                versions: vec![V::Tls13],
                cipher_suites: vec![C::Tls13Aes256GcmSha384],
                kx_groups: vec![K::MlKem1024],
                signature_schemes: vec![T::MlDsa87],
            }
        );
        assert_eq!(r.keys, vec![S::MlDsa87]);
        assert_eq!(
            resolve(Profile::Bsi, PQ),
            Err(CryptoError::EmptyProfile {
                profile: Profile::Bsi,
                options: PQ,
                category: crate::Family::KxGroup,
            })
        );
    }

    #[test]
    fn admit_key_admits_exactly_the_profile_keys() {
        for p in Profile::ALL {
            let admitted: &[S] = match p {
                Profile::Unrestricted | Profile::Fips1403 => &S::ALL,
                Profile::Preferred => &[
                    S::MlDsa87,
                    S::EcdsaP256Sha256,
                    S::EcdsaP384Sha384,
                    S::EcdsaP521Sha384,
                    S::EcdsaP521Sha512,
                    S::Rsa3072Sha384,
                    S::Rsa4096Sha384,
                ],
                Profile::Cnsa2 => &[S::MlDsa87],
                Profile::Cnsa1 => &[S::EcdsaP384Sha384, S::Rsa3072Sha384, S::Rsa4096Sha384],
                Profile::Bsi => &[S::EcdsaP256Sha256, S::EcdsaP384Sha384, S::EcdsaP521Sha512],
                Profile::Fips1402 => &[
                    S::EcdsaP256Sha256,
                    S::EcdsaP384Sha384,
                    S::EcdsaP521Sha384,
                    S::EcdsaP521Sha512,
                    S::Rsa2048Sha384,
                    S::Rsa3072Sha384,
                    S::Rsa4096Sha384,
                ],
            };
            for o in [Options::default(), PQ] {
                let Ok(r) = resolve(p, o) else { continue };
                for a in S::ALL {
                    let want = if admitted.contains(&a) {
                        Ok(())
                    } else {
                        Err(CryptoError::KeyNotInProfile {
                            profile: p,
                            algorithm: a,
                        })
                    };
                    assert_eq!(r.admit_key(a), want, "{p} {o} {a}");
                }
            }
        }
    }

    #[test]
    fn the_walk_is_versions_suites_groups_schemes_then_keys() {
        let r = resolve(Profile::Cnsa1, Options::default()).unwrap();
        assert_eq!(
            walk(&r),
            vec![
                Algorithm::Protocol(V::Tls13),
                Algorithm::Protocol(V::Tls12),
                Algorithm::Cipher(C::Tls13Aes256GcmSha384),
                Algorithm::Cipher(C::Tls12EcdheEcdsaAes256GcmSha384),
                Algorithm::Cipher(C::Tls12EcdheRsaAes256GcmSha384),
                Algorithm::Kx(K::Secp384r1),
                Algorithm::Scheme(T::EcdsaNistp384Sha384),
                Algorithm::Scheme(T::RsaPssSha384),
                Algorithm::Scheme(T::RsaPkcs1Sha384),
                Algorithm::Signature(S::EcdsaP384Sha384),
                Algorithm::Signature(S::Rsa3072Sha384),
                Algorithm::Signature(S::Rsa4096Sha384),
            ]
        );
    }

    #[test]
    fn every_profile_passes_a_module_that_approves_everything() {
        for r in every_resolved() {
            assert_eq!(
                approves_under(&r, synthetic),
                Ok(()),
                "{} {}",
                r.profile,
                r.options
            );
        }
    }

    #[test]
    fn the_first_unapproved_algorithm_is_named() {
        for r in every_resolved() {
            for a in walk(&r) {
                let all_but_a = |b: Algorithm| {
                    if b == a {
                        Approval::Unverified
                    } else {
                        synthetic(b)
                    }
                };
                assert_eq!(
                    approves_under(&r, all_but_a),
                    Err(CryptoError::NotApproved {
                        algorithm: a,
                        approval: Approval::Unverified,
                    }),
                    "{} {}",
                    r.profile,
                    r.options
                );
            }
        }
    }

    #[test]
    fn the_4x_module_is_not_approved_today() {
        for p in [
            Profile::Fips1403,
            Profile::Cnsa2,
            Profile::Cnsa1,
            Profile::Fips1402,
        ] {
            let r = resolve(p, Options::default()).unwrap();
            assert_eq!(
                assert_module_approves(&r),
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Protocol(V::Tls13),
                    approval: Approval::Unverified,
                }),
                "{p}"
            );
        }
    }

    #[test]
    fn approves_given_voids_every_approval_outside_fips_mode() {
        for r in every_resolved() {
            assert_eq!(
                approves_given(true, &r, synthetic),
                Ok(()),
                "{} {}",
                r.profile,
                r.options
            );
            assert_eq!(
                approves_given(false, &r, synthetic),
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Protocol(V::Tls13),
                    approval: Approval::Unverified,
                }),
                "{} {}",
                r.profile,
                r.options
            );
        }
    }

    #[test]
    fn assert_module_approves_reports_each_cell_as_fips_approval_does() {
        for a in S::ALL {
            let r = Resolved {
                profile: Profile::Unrestricted,
                options: Options::default(),
                tls: Policy {
                    versions: vec![],
                    cipher_suites: vec![],
                    kx_groups: vec![],
                    signature_schemes: vec![],
                },
                keys: vec![a],
            };
            let cell = Algorithm::Signature(a);
            let want = Err(CryptoError::NotApproved {
                algorithm: cell,
                approval: crate::fips::approval(cell),
            });
            assert_eq!(assert_module_approves(&r), want, "{a}");
            assert_eq!(approves_given(true, &r, module_cell), want, "{a}");
        }
        for r in every_resolved() {
            assert_eq!(
                assert_module_approves(&r),
                approves_under(&r, crate::fips::approval),
                "{} {}",
                r.profile,
                r.options
            );
        }
    }

    #[test]
    fn no_profile_is_refused_for_want_of_an_algorithm_on_this_module() {
        for p in Profile::ALL {
            assert!(resolve(p, Options::default()).is_ok(), "{p}");
            let empty_with_pq = match p {
                Profile::Cnsa1 | Profile::Bsi | Profile::Fips1402 => true,
                Profile::Unrestricted | Profile::Preferred | Profile::Cnsa2 | Profile::Fips1403 => {
                    false
                }
            };
            let want = if empty_with_pq {
                Err(CryptoError::EmptyProfile {
                    profile: p,
                    options: PQ,
                    category: crate::Family::KxGroup,
                })
            } else {
                Ok(())
            };
            assert_eq!(resolve(p, PQ).map(|_| ()), want, "{p}");
        }
    }
}
