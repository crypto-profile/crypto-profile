//! Profiles resolved against this backend's module.
use crate::signature::KeyPair;
use crate::tls::{Policy, load_private_key};
use crate::{
    Algorithm, Approval, CryptoError, Family, MacAlgorithm, Options, Profile, SignatureAlgorithm,
    TlsError,
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
    /// Entries unavailable on the module line after Options, in family and preference order.
    pub excluded: Vec<Algorithm>,
}

/// Resolves `profile`, narrowed by `options`, against this backend's module. Refuses with
/// `CryptoError::EmptyProfile` when a family comes out empty. Entries the module line lacks
/// are recorded in `Resolved::excluded`; approval is checked separately.
pub fn resolve(profile: Profile, options: Options) -> Result<Resolved, CryptoError> {
    let s = crypto_profile::profile::select(profile, options, crate::MODULE)?;
    Ok(Resolved {
        profile,
        options,
        tls: Policy {
            peer_certificate_rule: options
                .peer_certificates_match_profile
                .then(|| crypto_profile::peer_certificate_rule(profile).id),
            versions: s.versions,
            cipher_suites: s.cipher_suites,
            kx_groups: s.kx_groups,
            signature_schemes: s.signature_schemes,
        },
        keys: s.key_algorithms,
        excluded: s.excluded,
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

/// A profile's non-TLS families on this backend's module, narrowed by `options`. Independent of
/// `resolve`: a profile whose TLS lists are empty on this module still admits its MACs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The profile.
    pub profile: Profile,
    /// The options it was narrowed by.
    pub options: Options,
    /// The MACs the profile admits, in preference order.
    pub macs: Vec<MacAlgorithm>,
    /// Entries unavailable on the module line, in family and preference order.
    pub excluded: Vec<Algorithm>,
}

/// `profile`'s non-TLS families on this backend's module, narrowed by `options`. Never refuses: a
/// family left empty refuses each of its constructors instead.
pub fn admit(profile: Profile, options: Options) -> Admitted {
    let s = crypto_profile::select_admitted(profile, options, crate::MODULE);
    Admitted {
        profile,
        options,
        macs: s.macs,
        excluded: s.excluded,
    }
}

impl Admitted {
    /// Refuses a MAC the profile does not admit.
    pub fn admit_mac(&self, m: MacAlgorithm) -> Result<(), CryptoError> {
        if self.macs.contains(&m) {
            Ok(())
        } else {
            Err(CryptoError::NotInProfile {
                profile: self.profile,
                algorithm: Algorithm::Mac(m),
            })
        }
    }
}

fn admitted_approved_given(
    fips_mode: bool,
    a: &Admitted,
    cell: impl Fn(Algorithm) -> Approval,
) -> Result<(), CryptoError> {
    if !fips_mode {
        return Err(CryptoError::NotFips);
    }
    for algorithm in a.macs.iter().map(|m| Algorithm::Mac(*m)) {
        let approval = cell(algorithm);
        if !approval.is_approved() {
            return Err(CryptoError::NotApproved {
                algorithm,
                approval,
            });
        }
    }
    Ok(())
}

/// Refuses with `CryptoError::NotFips` unless the module is in FIPS mode, and otherwise unless
/// every algorithm `a` admits is `Approved` for the running module, failing on the first that is
/// not. An empty family is not a refusal. Independent of `assert_module_approves`.
pub fn assert_admitted_approved(a: &Admitted) -> Result<(), CryptoError> {
    admitted_approved_given(aws_lc_rs::try_fips_mode().is_ok(), a, |x| {
        crypto_profile::capability(crate::MODULE, x).approval
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
        peer_certificates_match_profile: false,
        pq_key_exchange_required: true,
        cnsa1_unclassified_nss: false,
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
        assert_eq!(
            v.len(),
            if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                9
            } else {
                assert_eq!(crate::MODULE.line, crate::ModuleLine::AwsLcFips4);
                11
            }
        );
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
        if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
            assert_eq!(
                resolve(Profile::Cnsa2, PQ),
                Err(CryptoError::EmptyProfile {
                    profile: Profile::Cnsa2,
                    options: PQ,
                    category: Family::SignatureScheme
                })
            );
            return;
        }
        let r = resolve(Profile::Cnsa2, PQ).unwrap();
        assert_eq!((r.profile, r.options), (Profile::Cnsa2, PQ));
        assert_eq!(
            r.tls,
            Policy {
                peer_certificate_rule: None,
                versions: vec![V::Tls13],
                cipher_suites: vec![C::Tls13Aes256GcmSha384],
                kx_groups: vec![K::MlKem1024],
                signature_schemes: vec![T::MlDsa87],
            }
        );
        assert_eq!(r.keys, vec![S::MlDsa87]);
        assert!(r.excluded.is_empty());
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
                    let want = if admitted.contains(&a)
                        && crate::capability(crate::MODULE, Algorithm::Signature(a)).available
                    {
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
            let r = match resolve(p, Options::default()) {
                Ok(r) => r,
                Err(e) => {
                    assert_eq!(crate::MODULE.line, crate::ModuleLine::AwsLcFips3);
                    assert_eq!(p, Profile::Cnsa2);
                    assert_eq!(
                        e,
                        CryptoError::EmptyProfile {
                            profile: p,
                            options: Options::default(),
                            category: Family::SignatureScheme
                        }
                    );
                    continue;
                }
            };
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
    fn three_x_approval_requires_only_table_five_cells() {
        if crate::MODULE.line == crate::ModuleLine::AwsLcFips4 {
            return;
        }
        for profile in [Profile::Fips1402, Profile::Fips1403] {
            let mut resolved = resolve(profile, Options::default()).unwrap();
            assert_eq!(
                assert_module_approves(&resolved),
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Protocol(V::Tls13),
                    approval: Approval::Unverified,
                })
            );
            let excluded = resolved.excluded.clone();
            resolved.tls.versions.retain(|v| *v == V::Tls12);
            resolved.tls.cipher_suites.retain(|c| {
                matches!(
                    c,
                    C::Tls12EcdheEcdsaAes128GcmSha256
                        | C::Tls12EcdheEcdsaAes256GcmSha384
                        | C::Tls12EcdheRsaAes128GcmSha256
                        | C::Tls12EcdheRsaAes256GcmSha384
                )
            });
            resolved
                .tls
                .kx_groups
                .retain(|g| matches!(g, K::Secp256r1 | K::Secp384r1));
            assert!(!resolved.keys.is_empty());
            assert!(!resolved.tls.signature_schemes.is_empty());
            assert_eq!(resolved.excluded, excluded);
            for algorithm in walk(&resolved) {
                assert!(
                    matches!(crate::fips::approval(algorithm), Approval::Approved { .. }),
                    "{algorithm:?}"
                );
            }
            assert_eq!(assert_module_approves(&resolved), Ok(()));
            resolved.tls.kx_groups.push(K::X25519MlKem768);
            assert_eq!(
                assert_module_approves(&resolved),
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Kx(K::X25519MlKem768),
                    approval: Approval::Unverified,
                })
            );
        }
    }

    fn empty() -> Resolved {
        Resolved {
            profile: Profile::Unrestricted,
            options: Options::default(),
            tls: Policy {
                peer_certificate_rule: None,
                versions: vec![],
                cipher_suites: vec![],
                kx_groups: vec![],
                signature_schemes: vec![],
            },
            keys: vec![],
            excluded: vec![],
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
            if p == Profile::Cnsa2 && crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                for options in [Options::default(), PQ] {
                    assert_eq!(
                        resolve(p, options),
                        Err(CryptoError::EmptyProfile {
                            profile: p,
                            options,
                            category: Family::SignatureScheme
                        })
                    );
                }
                continue;
            }
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

#[cfg(test)]
mod peer_certificate_tests {
    use super::*;

    #[test]
    fn peer_certificate_resolution_is_canonical_and_default_off() {
        assert_eq!(Policy::default().peer_certificate_rule, None);
        for profile in Profile::ALL {
            for pq in [false, true] {
                let off = Options {
                    pq_key_exchange_required: pq,
                    peer_certificates_match_profile: false,
                    cnsa1_unclassified_nss: false,
                };
                let on = Options {
                    peer_certificates_match_profile: true,
                    ..off
                };
                match (resolve(profile, off), resolve(profile, on)) {
                    (Ok(off), Ok(mut on)) => {
                        assert_eq!(off.tls.peer_certificate_rule, None);
                        assert_eq!(
                            on.tls.peer_certificate_rule,
                            Some(crypto_profile::peer_certificate_rule(profile).id)
                        );
                        on.tls.peer_certificate_rule = None;
                        assert_eq!(off.tls, on.tls);
                        assert_eq!(off.keys, on.keys);
                        assert_eq!(off.excluded, on.excluded);
                    }
                    (
                        Err(CryptoError::EmptyProfile {
                            profile: p,
                            options: o,
                            category: c,
                        }),
                        Err(CryptoError::EmptyProfile {
                            profile: ep,
                            options: eo,
                            category: ec,
                        }),
                    ) => {
                        assert_eq!((p, o, c), (ep, off, ec));
                        assert_eq!(eo, on);
                        if profile == Profile::Cnsa2
                            && crate::MODULE.line == crate::ModuleLine::AwsLcFips3
                        {
                            assert_eq!(c, Family::SignatureScheme);
                        }
                    }
                    (off, on) => panic!("{off:?} != {on:?}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod admitted_tests {
    use super::*;
    use crate::MacAlgorithm as M;

    const ON: Options = Options {
        peer_certificates_match_profile: false,
        pq_key_exchange_required: false,
        cnsa1_unclassified_nss: true,
    };

    #[test]
    fn admit_never_refuses_and_carries_its_inputs() {
        for p in Profile::ALL {
            for o in [Options::default(), ON] {
                let a = admit(p, o);
                assert_eq!((a.profile, a.options), (p, o));
                assert_eq!(
                    a.macs,
                    crypto_profile::select_admitted(p, o, crate::MODULE).macs
                );
                assert_eq!(a.excluded, []);
            }
        }
        assert_eq!(
            admit(Profile::Cnsa2, Options::default()).macs,
            [M::HmacSha384, M::HmacSha512]
        );
        assert_eq!(
            admit(Profile::Cnsa1, ON).macs,
            [M::HmacSha384, M::HmacSha256]
        );
    }

    #[test]
    fn admit_mac_admits_exactly_the_profile_macs() {
        for p in Profile::ALL {
            for o in [Options::default(), ON] {
                let a = admit(p, o);
                for m in MacAlgorithm::ALL {
                    let want = if a.macs.contains(&m) {
                        Ok(())
                    } else {
                        Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Mac(m),
                        })
                    };
                    assert_eq!(a.admit_mac(m), want, "{p} {o} {m:?}");
                }
            }
        }
        assert_eq!(
            admit(Profile::Cnsa2, ON).admit_mac(M::HmacSha256),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Mac(M::HmacSha256),
            })
        );
    }

    #[test]
    fn admitted_approval_follows_this_modules_cells() {
        for p in Profile::ALL {
            let a = admit(p, Options::default());
            if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                assert_eq!(assert_admitted_approved(&a), Ok(()), "{p}");
            } else {
                let first = Algorithm::Mac(a.macs[0]);
                assert_eq!(
                    assert_admitted_approved(&a),
                    Err(CryptoError::NotApproved {
                        algorithm: first,
                        approval: crypto_profile::capability(crate::MODULE, first).approval,
                    }),
                    "{p}"
                );
            }
        }
    }

    #[test]
    fn admitted_approval_checks_fips_mode_first_and_passes_an_empty_family() {
        let approved = |_: Algorithm| Approval::Approved { source: "test" };
        let a = admit(Profile::Cnsa2, Options::default());
        assert_eq!(
            admitted_approved_given(false, &a, approved),
            Err(CryptoError::NotFips)
        );
        assert_eq!(admitted_approved_given(true, &a, approved), Ok(()));
        let sha512 = Algorithm::Mac(M::HmacSha512);
        assert_eq!(
            admitted_approved_given(true, &a, |x| if x == sha512 {
                Approval::Unverified
            } else {
                approved(x)
            }),
            Err(CryptoError::NotApproved {
                algorithm: sha512,
                approval: Approval::Unverified,
            })
        );
        let empty = Admitted {
            macs: vec![],
            ..a.clone()
        };
        assert_eq!(
            admitted_approved_given(true, &empty, |_| Approval::Unverified),
            Ok(())
        );
        assert_eq!(
            admitted_approved_given(false, &empty, approved),
            Err(CryptoError::NotFips)
        );
    }
}
