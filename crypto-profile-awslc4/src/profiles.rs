//! Profiles resolved against this backend's module.
use crate::signature::KeyPair;
use crate::tls::{Policy, load_private_key};
use crate::{
    Algorithm, Approval, CryptoError, Family, Options, Profile, SignatureAlgorithm, TlsError,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

/// A profile resolved against this backend's module. `profile` and `options` say what `resolve`
/// was called with; `tls` goes to `tls::client_builder`, `tls::server_builder` and the verifier
/// builders; [`Resolved::certified_key`] binds this side's certificate and key to the profile.
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

    /// The certificate chain and key for this side of a connection, for
    /// `rustls::sign::SingleCertAndKey` or a resolver of the caller's. Refuses a key the profile
    /// does not admit, and a chain whose end-entity certificate does not carry the key. The key
    /// signs only with a scheme in `tls.signature_schemes`. When the peer offers none of them, a
    /// server handshake fails; a client sends an empty Certificate, which fails only if the server
    /// requires client authentication.
    pub fn certified_key(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: &KeyPair,
    ) -> Result<CertifiedKey, CryptoError> {
        self.admit_key(key.algorithm())?;
        let der = PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into());
        let certified = CertifiedKey::new(chain, load_private_key(&self.tls, der)?);
        certified
            .keys_match()
            .map_err(|_| CryptoError::Tls(TlsError::KeyMismatch))?;
        Ok(certified)
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
    for (empty, family) in [
        (r.tls.versions.is_empty(), Family::Version),
        (r.tls.cipher_suites.is_empty(), Family::CipherSuite),
        (r.tls.kx_groups.is_empty(), Family::KxGroup),
        (r.tls.signature_schemes.is_empty(), Family::SignatureScheme),
        (r.keys.is_empty(), Family::KeyAlgorithm),
    ] {
        if empty {
            return Err(CryptoError::PolicyEmpty(family));
        }
    }
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
    if !fips_mode {
        return Err(CryptoError::NotFips);
    }
    approves_under(r, cell)
}

/// Refuses with `CryptoError::NotFips` unless the module is in FIPS mode, with
/// `CryptoError::PolicyEmpty` naming the first family `r` leaves empty, and otherwise unless every
/// algorithm `r` names, each protocol version included, is `Approved` for the running module.
/// Fails on the first cell that is not `Approved`; `AlgorithmTested` is not. On the 4.x module it
/// fails today: a cell is `Approved` only where a published security policy lists it.
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
                category: Family::KxGroup,
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

    fn empty() -> Resolved {
        Resolved {
            profile: Profile::Unrestricted,
            options: Options::default(),
            tls: Policy {
                versions: vec![],
                cipher_suites: vec![],
                kx_groups: vec![],
                signature_schemes: vec![],
            },
            keys: vec![],
        }
    }

    #[test]
    fn outside_fips_mode_the_refusal_is_not_fips_before_anything_else() {
        for r in every_resolved().into_iter().chain([empty()]) {
            assert_eq!(
                approves_given(false, &r, synthetic),
                Err(CryptoError::NotFips),
                "{} {}",
                r.profile,
                r.options
            );
        }
        for r in every_resolved() {
            assert_eq!(
                approves_given(true, &r, synthetic),
                Ok(()),
                "{} {}",
                r.profile,
                r.options
            );
        }
    }

    #[test]
    fn a_resolved_with_an_empty_family_is_refused() {
        let base = resolve(Profile::Unrestricted, Options::default()).unwrap();
        type Clear = fn(&mut Resolved);
        let clear: [(Family, Clear); 5] = [
            (Family::Version, |r| r.tls.versions.clear()),
            (Family::CipherSuite, |r| r.tls.cipher_suites.clear()),
            (Family::KxGroup, |r| r.tls.kx_groups.clear()),
            (Family::SignatureScheme, |r| r.tls.signature_schemes.clear()),
            (Family::KeyAlgorithm, |r| r.keys.clear()),
        ];
        for (i, (family, _)) in clear.iter().enumerate() {
            let mut r = base.clone();
            for (_, f) in &clear[i..] {
                f(&mut r);
            }
            let want = Err(CryptoError::PolicyEmpty(*family));
            assert_eq!(approves_under(&r, synthetic), want, "{family:?} on");
            assert_eq!(approves_given(true, &r, synthetic), want, "{family:?} on");
            assert_eq!(assert_module_approves(&r), want, "{family:?} on");
            let mut only = base.clone();
            clear[i].1(&mut only);
            assert_eq!(approves_under(&only, synthetic), want, "{family:?} only");
        }
        assert_eq!(
            assert_module_approves(&empty()),
            Err(CryptoError::PolicyEmpty(Family::Version))
        );
    }

    #[test]
    fn assert_module_approves_reports_each_cell_as_fips_approval_does() {
        let base = resolve(Profile::Unrestricted, Options::default()).unwrap();
        for a in S::ALL {
            let r = Resolved {
                keys: vec![a],
                ..base.clone()
            };
            let key = Algorithm::Signature(a);
            let only_the_key = |b: Algorithm| {
                if b == key {
                    module_cell(b)
                } else {
                    synthetic(b)
                }
            };
            let want = if module_cell(key).is_approved() {
                Ok(())
            } else {
                Err(CryptoError::NotApproved {
                    algorithm: key,
                    approval: crate::fips::approval(key),
                })
            };
            assert_eq!(approves_given(true, &r, only_the_key), want, "{a}");
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
                    category: Family::KxGroup,
                })
            } else {
                Ok(())
            };
            assert_eq!(resolve(p, PQ).map(|_| ()), want, "{p}");
        }
    }
}
