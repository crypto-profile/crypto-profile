//! Profiles resolved against this backend's module.
use crate::tls::{CertificateKey, Policy, load_private_key};
use crate::{
    AeadAlgorithm, Algorithm, Approval, CryptoError, Family, HashAlgorithm, KdfAlgorithm,
    KeyAgreementAlgorithm, MacAlgorithm, Options, Profile, SignatureAlgorithm, TlsError,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

/// A profile resolved against this backend's module. `profile` and `options` say what `resolve`
/// was called with; `tls` goes to `tls::client_builder`, `tls::server_builder` and the verifier
/// builders; [`Resolved::certified_key`] binds this side's certificate and key to the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Refuses a TLS certificate key algorithm the profile does not admit.
    /// `tls::CertificateKey::generate`, `CertificateKey::from_pkcs8_der` and
    /// [`Resolved::certified_key`] call it.
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
    /// does not admit, whichever `Resolved` made it, and a chain whose end-entity certificate does
    /// not carry the key. The key signs only with a scheme in `tls.signature_schemes`. When the
    /// peer offers none of them, a server handshake fails; a client sends an empty Certificate,
    /// which fails only if the server requires client authentication.
    pub fn certified_key(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: &CertificateKey,
    ) -> Result<CertifiedKey, CryptoError> {
        self.admit_key(key.algorithm())?;
        let der = PrivateKeyDer::Pkcs8(key.to_pkcs8_der()?.to_vec().into());
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

/// A profile's non-TLS families on this backend's module, under `options`. Independent of
/// `resolve`: a profile whose TLS lists are empty on this module still admits its MACs, KDFs, key
/// agreement, AEADs, hashes and signatures.
/// Built only by [`admit`], and read-only, so a constructor that takes it checks the profile's
/// own admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    profile: Profile,
    options: Options,
    macs: Vec<MacAlgorithm>,
    kdfs: Vec<KdfAlgorithm>,
    key_agreements: Vec<KeyAgreementAlgorithm>,
    aeads: Vec<AeadAlgorithm>,
    hashes: Vec<HashAlgorithm>,
    signatures: Vec<SignatureAlgorithm>,
    excluded: Vec<Algorithm>,
}

/// `profile`'s non-TLS families on this backend's module, under `options`. Never refuses: a
/// family left empty refuses each of its constructors instead.
pub fn admit(profile: Profile, options: Options) -> Admitted {
    let s = crypto_profile::select_admitted(profile, options, crate::MODULE);
    Admitted {
        profile,
        options,
        macs: s.macs,
        kdfs: s.kdfs,
        key_agreements: s.key_agreements,
        aeads: s.aeads,
        hashes: s.hashes,
        signatures: s.signatures,
        excluded: s.excluded,
    }
}

impl Admitted {
    /// The profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The options it was admitted under.
    pub fn options(&self) -> Options {
        self.options
    }

    /// The MACs the profile admits, in preference order.
    pub fn macs(&self) -> &[MacAlgorithm] {
        &self.macs
    }

    /// The KDFs the profile admits, in preference order.
    pub fn kdfs(&self) -> &[KdfAlgorithm] {
        &self.kdfs
    }

    /// The key-agreement curves the profile admits, in preference order.
    pub fn key_agreements(&self) -> &[KeyAgreementAlgorithm] {
        &self.key_agreements
    }

    /// The AEADs the profile admits, in preference order.
    pub fn aeads(&self) -> &[AeadAlgorithm] {
        &self.aeads
    }

    /// The hash functions the profile admits, in preference order.
    pub fn hashes(&self) -> &[HashAlgorithm] {
        &self.hashes
    }

    /// The signature algorithms the profile admits outside TLS, in preference order.
    pub fn signatures(&self) -> &[SignatureAlgorithm] {
        &self.signatures
    }

    /// Entries unavailable on the module line, in family and preference order.
    pub fn excluded(&self) -> &[Algorithm] {
        &self.excluded
    }

    /// Refuses a MAC the profile does not admit, and one the module line lacks with
    /// `CryptoError::Unavailable`.
    pub fn admit_mac(&self, m: MacAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.macs.contains(&m), Algorithm::Mac(m))
    }

    /// Refuses a KDF the profile does not admit, and one the module line lacks with
    /// `CryptoError::Unavailable`.
    pub fn admit_kdf(&self, k: KdfAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.kdfs.contains(&k), Algorithm::Kdf(k))
    }

    /// Refuses a key-agreement curve the profile does not admit, and one the module line lacks
    /// with `CryptoError::Unavailable`.
    pub fn admit_key_agreement(&self, k: KeyAgreementAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.key_agreements.contains(&k), Algorithm::KeyAgreement(k))
    }

    /// Refuses an AEAD the profile does not admit, and one the module line lacks with
    /// `CryptoError::Unavailable`.
    pub fn admit_aead(&self, d: AeadAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.aeads.contains(&d), Algorithm::Aead(d))
    }

    /// Refuses a hash function the profile does not admit, and one the module line lacks with
    /// `CryptoError::Unavailable`.
    pub fn admit_hash(&self, h: HashAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.hashes.contains(&h), Algorithm::Hash(h))
    }

    /// Refuses a signature algorithm the profile does not admit outside TLS, and one the module
    /// line lacks with `CryptoError::Unavailable`.
    pub fn admit_signature(&self, s: SignatureAlgorithm) -> Result<(), CryptoError> {
        self.admit_one(self.signatures.contains(&s), Algorithm::Signature(s))
    }

    fn cells(&self, family: Family) -> Result<Vec<Algorithm>, CryptoError> {
        match family {
            Family::Mac => Ok(self.macs.iter().map(|m| Algorithm::Mac(*m)).collect()),
            Family::Kdf => Ok(self.kdfs.iter().map(|k| Algorithm::Kdf(*k)).collect()),
            Family::KeyAgreement => Ok(self
                .key_agreements
                .iter()
                .map(|k| Algorithm::KeyAgreement(*k))
                .collect()),
            Family::Aead => Ok(self.aeads.iter().map(|d| Algorithm::Aead(*d)).collect()),
            Family::Hash => Ok(self.hashes.iter().map(|h| Algorithm::Hash(*h)).collect()),
            Family::Signature => Ok(self
                .signatures
                .iter()
                .map(|s| Algorithm::Signature(*s))
                .collect()),
            _ => Err(CryptoError::FamilyNotAdmitted(family)),
        }
    }

    /// `self` without `algorithm`, as a profile that does not list it.
    #[cfg(test)]
    pub(crate) fn without(mut self, algorithm: Algorithm) -> Self {
        self.macs.retain(|m| Algorithm::Mac(*m) != algorithm);
        self.kdfs.retain(|k| Algorithm::Kdf(*k) != algorithm);
        self.key_agreements
            .retain(|k| Algorithm::KeyAgreement(*k) != algorithm);
        self.aeads.retain(|d| Algorithm::Aead(*d) != algorithm);
        self.hashes.retain(|h| Algorithm::Hash(*h) != algorithm);
        self.signatures
            .retain(|s| Algorithm::Signature(*s) != algorithm);
        self
    }

    fn admit_one(&self, admitted: bool, algorithm: Algorithm) -> Result<(), CryptoError> {
        if admitted {
            Ok(())
        } else if self.excluded.contains(&algorithm) {
            Err(CryptoError::Unavailable(algorithm))
        } else {
            Err(CryptoError::NotInProfile {
                profile: self.profile,
                algorithm,
            })
        }
    }
}

fn admitted_approved_given(
    fips_mode: bool,
    a: &Admitted,
    families: &[Family],
    cell: impl Fn(Algorithm) -> Approval,
) -> Result<(), CryptoError> {
    if !fips_mode {
        return Err(CryptoError::NotFips);
    }
    for f in families {
        a.cells(*f)?;
    }
    if families.contains(&Family::Kdf)
        && crypto_profile::kdf_info_may_be_empty(a.profile)
        && !a.kdfs.is_empty()
    {
        return Err(CryptoError::KdfInfoMayBeEmpty { profile: a.profile });
    }
    for f in [
        Family::Mac,
        Family::Kdf,
        Family::KeyAgreement,
        Family::Aead,
        Family::Hash,
        Family::Signature,
    ] {
        if !families.contains(&f) {
            continue;
        }
        for algorithm in a.cells(f)? {
            let approval = cell(algorithm);
            if !approval.is_approved() {
                return Err(CryptoError::NotApproved {
                    algorithm,
                    approval,
                });
            }
        }
    }
    Ok(())
}

/// Checks the families the caller uses from `a`. Refuses with `CryptoError::NotFips` unless the
/// module is in FIPS mode; then with `CryptoError::FamilyNotAdmitted` for the first family in
/// `families` that is not walked here (every TLS family, which `assert_module_approves` checks
/// instead, and any family this backend does not walk); then, when `families` names
/// `Family::Kdf`, with `CryptoError::KdfInfoMayBeEmpty` if `a`'s profile admits KDFs and an empty
/// `info`, which the module does not approve (`unrestricted`); then unless every algorithm `a`
/// admits in each named family is `Approved` for the running module, walking `Family::Mac`,
/// `Family::Kdf`, `Family::KeyAgreement`, `Family::Aead`, `Family::Hash`, then
/// `Family::Signature`, and failing on the first that is not. Asserting nothing approves
/// nothing: an empty `families`, or a named family `a` admits nothing in, is not a refusal.
/// Independent of `assert_module_approves`.
pub fn assert_admitted_approved(a: &Admitted, families: &[Family]) -> Result<(), CryptoError> {
    admitted_approved_given(aws_lc_rs::try_fips_mode().is_ok(), a, families, |x| {
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
    use crypto_profile::conformance::__empty_profile;

    fn pq() -> Options {
        let mut o = Options::default();
        o.pq_key_exchange_required = true;
        o
    }

    fn empty_profile(r: Result<Resolved, CryptoError>) -> Option<(Profile, Options, Family)> {
        r.err().as_ref().and_then(__empty_profile)
    }

    fn every_resolved() -> Vec<Resolved> {
        let mut v = Vec::new();
        for &p in Profile::ALL {
            for o in [Options::default(), pq()] {
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
                empty_profile(resolve(Profile::Cnsa2, pq())),
                Some((Profile::Cnsa2, pq(), Family::SignatureScheme))
            );
            return;
        }
        let r = resolve(Profile::Cnsa2, pq()).unwrap();
        assert_eq!((r.profile, r.options), (Profile::Cnsa2, pq()));
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
            empty_profile(resolve(Profile::Bsi, pq())),
            Some((Profile::Bsi, pq(), Family::KxGroup))
        );
    }

    #[test]
    fn admit_key_admits_exactly_the_profile_keys() {
        for &p in Profile::ALL {
            let admitted: &[S] = match p {
                Profile::Unrestricted | Profile::Fips1403 => &[
                    S::MlDsa87,
                    S::EcdsaP256Sha256,
                    S::EcdsaP384Sha384,
                    S::EcdsaP521Sha384,
                    S::EcdsaP521Sha512,
                    S::Ed25519,
                    S::Rsa2048Sha384,
                    S::Rsa3072Sha384,
                    S::Rsa4096Sha384,
                ],
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
                _ => panic!("{p}: no expected key list"),
            };
            for o in [Options::default(), pq()] {
                let Ok(r) = resolve(p, o) else { continue };
                for &a in S::ALL {
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
                        __empty_profile(&e),
                        Some((p, Options::default(), Family::SignatureScheme))
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
    fn every_resolved_profile_is_first_refused_at_tls_1_3() {
        let tls13 = Err(CryptoError::NotApproved {
            algorithm: Algorithm::Protocol(V::Tls13),
            approval: Approval::Unverified,
        });
        let mut ed25519 = 0;
        for r in every_resolved() {
            assert_eq!(
                r.tls.versions.first(),
                Some(&V::Tls13),
                "{} {}",
                r.profile,
                r.options
            );
            assert_eq!(
                assert_module_approves(&r),
                tls13,
                "{} {}",
                r.profile,
                r.options
            );
            ed25519 += usize::from(r.tls.signature_schemes.contains(&T::Ed25519));
        }
        assert_eq!(ed25519, 4);
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
            if crate::MODULE.linkage == crate::Linkage::Static && profile == Profile::Fips1403 {
                let scheme = Algorithm::Scheme(T::Ed25519);
                let key = Algorithm::Signature(S::Ed25519);
                for a in [scheme, key] {
                    assert!(
                        matches!(module_cell(a), Approval::NotApproved { .. }),
                        "{a:?}"
                    );
                }
                assert_eq!(
                    assert_module_approves(&resolved),
                    Err(CryptoError::NotApproved {
                        algorithm: scheme,
                        approval: module_cell(scheme),
                    })
                );
                resolved.tls.signature_schemes.retain(|t| *t != T::Ed25519);
                assert_eq!(
                    assert_module_approves(&resolved),
                    Err(CryptoError::NotApproved {
                        algorithm: key,
                        approval: module_cell(key),
                    })
                );
                resolved.keys.retain(|k| *k != S::Ed25519);
            }
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
        for &a in S::ALL {
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
        for &p in Profile::ALL {
            if p == Profile::Cnsa2 && crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                for options in [Options::default(), pq()] {
                    assert_eq!(
                        empty_profile(resolve(p, options)),
                        Some((p, options, Family::SignatureScheme))
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
                _ => panic!("{p}: no expected post-quantum result"),
            };
            let want = empty_with_pq.then(|| (p, pq(), Family::KxGroup));
            let got = resolve(p, pq());
            assert_eq!(got.is_ok(), !empty_with_pq, "{p}");
            assert_eq!(empty_profile(got), want, "{p}");
        }
    }
}

#[cfg(test)]
mod peer_certificate_tests {
    use super::*;
    use crypto_profile::conformance::__empty_profile;

    #[test]
    fn peer_certificate_resolution_is_canonical_and_default_off() {
        assert_eq!(Policy::default().peer_certificate_rule, None);
        for &profile in Profile::ALL {
            for pq in [false, true] {
                let mut off = Options::default();
                off.pq_key_exchange_required = pq;
                let mut on = off;
                on.peer_certificates_match_profile = true;
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
                    (Err(off_err), Err(on_err)) => {
                        let (Some((p, o, c)), Some((ep, eo, ec))) =
                            (__empty_profile(&off_err), __empty_profile(&on_err))
                        else {
                            panic!("{off_err:?} != {on_err:?}");
                        };
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
    use crate::KdfAlgorithm as Kd;
    use crate::MacAlgorithm as M;

    fn on() -> Options {
        let mut o = Options::default();
        o.cnsa1_unclassified_nss = true;
        o
    }

    #[test]
    fn admit_never_refuses_and_carries_its_inputs() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                assert_eq!((a.profile(), a.options()), (p, o));
                assert_eq!(
                    a.macs(),
                    crypto_profile::select_admitted(p, o, crate::MODULE).macs
                );
                assert_eq!(
                    a.kdfs(),
                    crypto_profile::select_admitted(p, o, crate::MODULE).kdfs
                );
                assert_eq!(
                    a.aeads(),
                    crypto_profile::select_admitted(p, o, crate::MODULE).aeads
                );
                assert_eq!(
                    a.hashes(),
                    crypto_profile::select_admitted(p, o, crate::MODULE).hashes
                );
                assert_eq!(
                    a.signatures(),
                    crypto_profile::select_admitted(p, o, crate::MODULE).signatures
                );
                let ml_dsa = Algorithm::Signature(SignatureAlgorithm::MlDsa87);
                let excluded: &[Algorithm] = match crate::MODULE.line {
                    crate::ModuleLine::AwsLcFips3
                        if p.spec().signatures.contains(&SignatureAlgorithm::MlDsa87) =>
                    {
                        &[ml_dsa]
                    }
                    crate::ModuleLine::AwsLcFips3 | crate::ModuleLine::AwsLcFips4 => &[],
                    other => panic!("{other:?}: no expected exclusions"),
                };
                assert_eq!(a.excluded(), excluded, "{p} {o}");
            }
        }
        assert_eq!(
            admit(Profile::Cnsa2, Options::default()).macs(),
            [M::HmacSha384, M::HmacSha512]
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).macs(),
            [M::HmacSha384, M::HmacSha256]
        );
        assert_eq!(
            admit(Profile::Cnsa2, Options::default()).kdfs(),
            [Kd::HkdfSha384, Kd::HkdfSha512]
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).kdfs(),
            [Kd::HkdfSha384, Kd::HkdfSha256]
        );
        assert_eq!(
            admit(Profile::Cnsa2, Options::default()).hashes(),
            [HashAlgorithm::Sha384, HashAlgorithm::Sha512]
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).hashes(),
            [HashAlgorithm::Sha384, HashAlgorithm::Sha256]
        );
        assert_eq!(
            admit(Profile::Bsi, Options::default()).signatures(),
            [
                SignatureAlgorithm::Rsa4096Sha384Pss,
                SignatureAlgorithm::Rsa3072Sha384Pss
            ]
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).signatures()[5..],
            [
                SignatureAlgorithm::Rsa2048Sha384Pss,
                SignatureAlgorithm::Rsa2048Sha384
            ]
        );
        assert_eq!(admit(Profile::Cnsa1, on()).options(), on());
    }

    #[test]
    fn admit_mac_admits_exactly_the_profile_macs() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                for &m in MacAlgorithm::ALL {
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
            admit(Profile::Cnsa2, on()).admit_mac(M::HmacSha256),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Mac(M::HmacSha256),
            })
        );
    }

    #[test]
    fn a_mac_the_module_lacks_is_unavailable() {
        let mut a = admit(Profile::Fips1403, Options::default());
        a.macs.retain(|m| *m != M::HmacSha384);
        a.excluded = vec![Algorithm::Mac(M::HmacSha384)];
        assert_eq!(
            a.admit_mac(M::HmacSha384),
            Err(CryptoError::Unavailable(Algorithm::Mac(M::HmacSha384)))
        );
        assert_eq!(a.excluded(), [Algorithm::Mac(M::HmacSha384)]);
        assert_eq!(a.admit_mac(M::HmacSha512), Ok(()));
    }

    #[test]
    fn admit_kdf_admits_exactly_the_profile_kdfs() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                for &k in KdfAlgorithm::ALL {
                    let want = if a.kdfs.contains(&k) {
                        Ok(())
                    } else {
                        Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Kdf(k),
                        })
                    };
                    assert_eq!(a.admit_kdf(k), want, "{p} {o} {k:?}");
                }
            }
        }
        assert_eq!(
            admit(Profile::Cnsa2, on()).admit_kdf(Kd::HkdfSha256),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Kdf(Kd::HkdfSha256),
            })
        );
    }

    #[test]
    fn a_kdf_the_module_lacks_is_unavailable() {
        let mut a = admit(Profile::Fips1403, Options::default());
        a.kdfs.retain(|k| *k != Kd::HkdfSha384);
        a.excluded.push(Algorithm::Kdf(Kd::HkdfSha384));
        assert_eq!(
            a.admit_kdf(Kd::HkdfSha384),
            Err(CryptoError::Unavailable(Algorithm::Kdf(Kd::HkdfSha384)))
        );
        assert_eq!(a.admit_kdf(Kd::HkdfSha512), Ok(()));
        assert_eq!(a.admit_mac(M::HmacSha384), Ok(()));
    }

    #[test]
    fn admit_aead_admits_exactly_the_profile_aeads() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                for &d in AeadAlgorithm::ALL {
                    let want = if a.aeads.contains(&d) {
                        Ok(())
                    } else {
                        Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Aead(d),
                        })
                    };
                    assert_eq!(a.admit_aead(d), want, "{p} {o} {d:?}");
                }
            }
        }
        assert_eq!(
            admit(Profile::Cnsa1, on()).aeads(),
            [AeadAlgorithm::Aes256Gcm]
        );
    }

    #[test]
    fn an_aead_the_module_lacks_is_unavailable() {
        let mut a = admit(Profile::Fips1403, Options::default());
        a.aeads.retain(|d| *d != AeadAlgorithm::Aes128Gcm);
        a.excluded.push(Algorithm::Aead(AeadAlgorithm::Aes128Gcm));
        assert_eq!(
            a.admit_aead(AeadAlgorithm::Aes128Gcm),
            Err(CryptoError::Unavailable(Algorithm::Aead(
                AeadAlgorithm::Aes128Gcm
            )))
        );
        assert_eq!(a.admit_aead(AeadAlgorithm::Aes256Gcm), Ok(()));
        let without = admit(Profile::Fips1403, Options::default())
            .without(Algorithm::Aead(AeadAlgorithm::Aes256Gcm));
        assert_eq!(without.aeads(), [AeadAlgorithm::Aes128Gcm]);
    }

    #[test]
    fn the_aead_family_is_walked_after_key_agreement() {
        let a = admit(Profile::Fips1403, Options::default());
        let ecdh = Algorithm::KeyAgreement(KeyAgreementAlgorithm::EcdhP384);
        let gcm = Algorithm::Aead(AeadAlgorithm::Aes256Gcm);
        let neither = |x: Algorithm| {
            if x == ecdh || x == gcm {
                Approval::Unverified
            } else {
                approved(x)
            }
        };
        for families in [
            [Family::Aead, Family::KeyAgreement],
            [Family::KeyAgreement, Family::Aead],
        ] {
            assert_eq!(
                admitted_approved_given(true, &a, &families, neither),
                Err(CryptoError::NotApproved {
                    algorithm: ecdh,
                    approval: Approval::Unverified,
                }),
                "{families:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Aead], neither),
            Err(CryptoError::NotApproved {
                algorithm: gcm,
                approval: Approval::Unverified,
            })
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Aead], all_but(ecdh)),
            Ok(())
        );
    }

    #[test]
    fn admitted_aead_approval_follows_this_modules_cells() {
        let cell = |d| crypto_profile::capability(crate::MODULE, Algorithm::Aead(d)).approval;
        let refused = |d| {
            Err(CryptoError::NotApproved {
                algorithm: Algorithm::Aead(d),
                approval: cell(d),
            })
        };
        for &p in Profile::ALL {
            let a = admit(p, Options::default());
            let want = match (crate::MODULE.line, p) {
                (crate::ModuleLine::AwsLcFips3, Profile::Unrestricted) => {
                    refused(AeadAlgorithm::Chacha20Poly1305)
                }
                (crate::ModuleLine::AwsLcFips3, _) => Ok(()),
                (crate::ModuleLine::AwsLcFips4, _) => refused(AeadAlgorithm::Aes256Gcm),
                (other, _) => panic!("{other:?}: no expected approval"),
            };
            assert_eq!(assert_admitted_approved(&a, &[Family::Aead]), want, "{p}");
        }
        match crate::MODULE.line {
            crate::ModuleLine::AwsLcFips3 => {
                assert!(cell(AeadAlgorithm::Aes128Gcm).is_approved());
                assert!(matches!(
                    cell(AeadAlgorithm::Chacha20Poly1305),
                    Approval::NotApproved { .. }
                ));
            }
            crate::ModuleLine::AwsLcFips4 => {
                assert!(matches!(
                    cell(AeadAlgorithm::Aes256Gcm),
                    Approval::AlgorithmTested { .. }
                ));
                assert_eq!(cell(AeadAlgorithm::Chacha20Poly1305), Approval::Unverified);
            }
            other => panic!("{other:?}: no expected approval"),
        }
    }

    #[test]
    fn admit_hash_admits_exactly_the_profile_hashes() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                for &h in HashAlgorithm::ALL {
                    let want = if a.hashes.contains(&h) {
                        Ok(())
                    } else {
                        Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Hash(h),
                        })
                    };
                    assert_eq!(a.admit_hash(h), want, "{p} {o} {h:?}");
                }
            }
        }
        assert_eq!(
            admit(Profile::Cnsa2, on()).admit_hash(HashAlgorithm::Sha256),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa2,
                algorithm: Algorithm::Hash(HashAlgorithm::Sha256),
            })
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).admit_hash(HashAlgorithm::Sha256),
            Ok(())
        );
    }

    #[test]
    fn a_hash_the_module_lacks_is_unavailable() {
        let mut a = admit(Profile::Fips1403, Options::default());
        a.hashes.retain(|h| *h != HashAlgorithm::Sha3_256);
        a.excluded.push(Algorithm::Hash(HashAlgorithm::Sha3_256));
        assert_eq!(
            a.admit_hash(HashAlgorithm::Sha3_256),
            Err(CryptoError::Unavailable(Algorithm::Hash(
                HashAlgorithm::Sha3_256
            )))
        );
        assert_eq!(a.admit_hash(HashAlgorithm::Sha3_512), Ok(()));
        let without = admit(Profile::Cnsa2, Options::default())
            .without(Algorithm::Hash(HashAlgorithm::Sha384));
        assert_eq!(without.hashes(), [HashAlgorithm::Sha512]);
    }

    #[test]
    fn the_hash_family_is_walked_after_aead() {
        let a = admit(Profile::Fips1403, Options::default());
        let gcm = Algorithm::Aead(AeadAlgorithm::Aes256Gcm);
        let sha = Algorithm::Hash(HashAlgorithm::Sha512);
        let neither = |x: Algorithm| {
            if x == gcm || x == sha {
                Approval::Unverified
            } else {
                approved(x)
            }
        };
        for families in [[Family::Hash, Family::Aead], [Family::Aead, Family::Hash]] {
            assert_eq!(
                admitted_approved_given(true, &a, &families, neither),
                Err(CryptoError::NotApproved {
                    algorithm: gcm,
                    approval: Approval::Unverified,
                }),
                "{families:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Hash], neither),
            Err(CryptoError::NotApproved {
                algorithm: sha,
                approval: Approval::Unverified,
            })
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Hash], all_but(gcm)),
            Ok(())
        );
    }

    #[test]
    fn the_hash_walk_visits_exactly_the_admitted_hashes() {
        use HashAlgorithm as H;
        for (p, o, want) in [
            (
                Profile::Cnsa2,
                Options::default(),
                &[H::Sha384, H::Sha512][..],
            ),
            (Profile::Cnsa1, Options::default(), &[H::Sha384]),
            (Profile::Cnsa1, on(), &[H::Sha384, H::Sha256]),
            (
                Profile::Preferred,
                Options::default(),
                &[H::Sha512, H::Sha384, H::Sha256],
            ),
            (
                Profile::Bsi,
                Options::default(),
                &[
                    H::Sha512,
                    H::Sha384,
                    H::Sha256,
                    H::Sha3_512,
                    H::Sha3_384,
                    H::Sha3_256,
                ],
            ),
        ] {
            let seen = std::cell::RefCell::new(Vec::new());
            let record = |x: Algorithm| {
                seen.borrow_mut().push(x);
                approved(x)
            };
            assert_eq!(
                admitted_approved_given(true, &admit(p, o), &[Family::Hash], record),
                Ok(()),
                "{p} {o}"
            );
            let want: Vec<Algorithm> = want.iter().map(|h| Algorithm::Hash(*h)).collect();
            assert_eq!(seen.into_inner(), want, "{p} {o}");
        }
    }

    #[test]
    fn admitted_hash_approval_follows_this_modules_cells() {
        let cell = |h| crypto_profile::capability(crate::MODULE, Algorithm::Hash(h)).approval;
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                let first = a.hashes[0];
                let want = match crate::MODULE.line {
                    crate::ModuleLine::AwsLcFips3 => Ok(()),
                    crate::ModuleLine::AwsLcFips4 => Err(CryptoError::NotApproved {
                        algorithm: Algorithm::Hash(first),
                        approval: cell(first),
                    }),
                    other => panic!("{other:?}: no expected approval"),
                };
                assert_eq!(
                    assert_admitted_approved(&a, &[Family::Hash]),
                    want,
                    "{p} {o}"
                );
            }
        }
        for &h in HashAlgorithm::ALL {
            match crate::MODULE.line {
                crate::ModuleLine::AwsLcFips3 => assert!(cell(h).is_approved(), "{h:?}"),
                crate::ModuleLine::AwsLcFips4 => {
                    assert!(matches!(cell(h), Approval::AlgorithmTested { .. }), "{h:?}")
                }
                other => panic!("{other:?}: no expected approval"),
            }
        }
        assert_eq!(
            assert_admitted_approved(
                &admit(Profile::Fips1403, Options::default()),
                &[Family::Hash]
            ),
            if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                Ok(())
            } else {
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Hash(HashAlgorithm::Sha512),
                    approval: cell(HashAlgorithm::Sha512),
                })
            }
        );
    }

    #[test]
    fn admit_signature_admits_exactly_the_profile_signatures() {
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                for &s in SignatureAlgorithm::ALL {
                    let want = if a.signatures.contains(&s) {
                        Ok(())
                    } else if a.excluded.contains(&Algorithm::Signature(s)) {
                        Err(CryptoError::Unavailable(Algorithm::Signature(s)))
                    } else {
                        Err(CryptoError::NotInProfile {
                            profile: p,
                            algorithm: Algorithm::Signature(s),
                        })
                    };
                    assert_eq!(a.admit_signature(s), want, "{p} {o} {s}");
                }
            }
        }
        assert_eq!(
            admit(Profile::Cnsa1, Options::default())
                .admit_signature(SignatureAlgorithm::Rsa2048Sha384Pss),
            Err(CryptoError::NotInProfile {
                profile: Profile::Cnsa1,
                algorithm: Algorithm::Signature(SignatureAlgorithm::Rsa2048Sha384Pss),
            })
        );
        assert_eq!(
            admit(Profile::Cnsa1, on()).admit_signature(SignatureAlgorithm::Rsa2048Sha384Pss),
            Ok(())
        );
        assert_eq!(
            admit(Profile::Bsi, on()).admit_signature(SignatureAlgorithm::Rsa4096Sha384),
            Err(CryptoError::NotInProfile {
                profile: Profile::Bsi,
                algorithm: Algorithm::Signature(SignatureAlgorithm::Rsa4096Sha384),
            })
        );
    }

    #[test]
    fn a_signature_the_module_lacks_is_unavailable() {
        let ml_dsa = Algorithm::Signature(SignatureAlgorithm::MlDsa87);
        let mut a = admit(Profile::Fips1403, Options::default());
        a.signatures.retain(|s| *s != SignatureAlgorithm::MlDsa87);
        a.excluded = vec![ml_dsa];
        assert_eq!(
            a.admit_signature(SignatureAlgorithm::MlDsa87),
            Err(CryptoError::Unavailable(ml_dsa))
        );
        assert_eq!(a.admit_signature(SignatureAlgorithm::Ed25519), Ok(()));
        let cnsa2 = admit(Profile::Cnsa2, Options::default());
        assert_eq!(
            cnsa2.admit_signature(SignatureAlgorithm::MlDsa87),
            if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                Err(CryptoError::Unavailable(ml_dsa))
            } else {
                Ok(())
            }
        );
        let without = admit(Profile::Bsi, Options::default())
            .without(Algorithm::Signature(SignatureAlgorithm::Rsa4096Sha384Pss));
        assert_eq!(without.signatures(), [SignatureAlgorithm::Rsa3072Sha384Pss]);
    }

    #[test]
    fn the_signature_family_is_walked_last() {
        let a = admit(Profile::Fips1403, Options::default());
        let sha = Algorithm::Hash(HashAlgorithm::Sha512);
        let p384 = Algorithm::Signature(SignatureAlgorithm::EcdsaP384Sha384);
        let neither = |x: Algorithm| {
            if x == sha || x == p384 {
                Approval::Unverified
            } else {
                approved(x)
            }
        };
        for families in [
            [Family::Signature, Family::Hash],
            [Family::Hash, Family::Signature],
        ] {
            assert_eq!(
                admitted_approved_given(true, &a, &families, neither),
                Err(CryptoError::NotApproved {
                    algorithm: sha,
                    approval: Approval::Unverified,
                }),
                "{families:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Signature], neither),
            Err(CryptoError::NotApproved {
                algorithm: p384,
                approval: Approval::Unverified,
            })
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Signature], all_but(sha)),
            Ok(())
        );
    }

    #[test]
    fn the_signature_walk_visits_exactly_the_admitted_signatures() {
        use SignatureAlgorithm as S;
        for (p, o, want) in [
            (
                Profile::Bsi,
                Options::default(),
                &[S::Rsa4096Sha384Pss, S::Rsa3072Sha384Pss][..],
            ),
            (
                Profile::Cnsa1,
                Options::default(),
                &[
                    S::EcdsaP384Sha384,
                    S::Rsa4096Sha384Pss,
                    S::Rsa3072Sha384Pss,
                    S::Rsa4096Sha384,
                    S::Rsa3072Sha384,
                ],
            ),
            (
                Profile::Cnsa1,
                on(),
                &[
                    S::EcdsaP384Sha384,
                    S::Rsa4096Sha384Pss,
                    S::Rsa3072Sha384Pss,
                    S::Rsa4096Sha384,
                    S::Rsa3072Sha384,
                    S::Rsa2048Sha384Pss,
                    S::Rsa2048Sha384,
                ],
            ),
        ] {
            let seen = std::cell::RefCell::new(Vec::new());
            let record = |x: Algorithm| {
                seen.borrow_mut().push(x);
                approved(x)
            };
            assert_eq!(
                admitted_approved_given(true, &admit(p, o), &[Family::Signature], record),
                Ok(()),
                "{p} {o}"
            );
            let want: Vec<Algorithm> = want.iter().map(|s| Algorithm::Signature(*s)).collect();
            assert_eq!(seen.into_inner(), want, "{p} {o}");
        }
    }

    #[test]
    fn admitted_signature_approval_follows_this_modules_cells() {
        let cell = |s| crypto_profile::capability(crate::MODULE, Algorithm::Signature(s)).approval;
        for &p in Profile::ALL {
            for o in [Options::default(), on()] {
                let a = admit(p, o);
                let want = match a.signatures.iter().find(|s| !cell(**s).is_approved()) {
                    Some(&s) => Err(CryptoError::NotApproved {
                        algorithm: Algorithm::Signature(s),
                        approval: cell(s),
                    }),
                    None => Ok(()),
                };
                assert_eq!(
                    assert_admitted_approved(&a, &[Family::Signature]),
                    want,
                    "{p} {o}"
                );
            }
        }
        let unrestricted = admit(Profile::Unrestricted, Options::default());
        let first = match (crate::MODULE.line, crate::MODULE.linkage) {
            (crate::ModuleLine::AwsLcFips3, crate::Linkage::Static) => {
                Some(SignatureAlgorithm::Ed25519)
            }
            (crate::ModuleLine::AwsLcFips3, crate::Linkage::Dynamic) => None,
            (crate::ModuleLine::AwsLcFips4, _) => Some(SignatureAlgorithm::MlDsa87),
            other => panic!("{other:?}: no expected approval"),
        };
        assert_eq!(
            assert_admitted_approved(&unrestricted, &[Family::Signature]),
            first.map_or(Ok(()), |s| Err(CryptoError::NotApproved {
                algorithm: Algorithm::Signature(s),
                approval: cell(s),
            }))
        );
        assert_eq!(
            assert_admitted_approved(
                &admit(Profile::Bsi, Options::default()),
                &[Family::Signature]
            ),
            if crate::MODULE.line == crate::ModuleLine::AwsLcFips3 {
                Ok(())
            } else {
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Signature(SignatureAlgorithm::Rsa4096Sha384Pss),
                    approval: cell(SignatureAlgorithm::Rsa4096Sha384Pss),
                })
            }
        );
    }

    const NON_TLS: [Family; 6] = [
        Family::Mac,
        Family::Kdf,
        Family::KeyAgreement,
        Family::Aead,
        Family::Hash,
        Family::Signature,
    ];
    const TLS: [Family; 5] = [
        Family::Version,
        Family::CipherSuite,
        Family::KxGroup,
        Family::SignatureScheme,
        Family::KeyAlgorithm,
    ];

    fn approved(_: Algorithm) -> Approval {
        Approval::Approved { source: "test" }
    }

    fn all_but(x: Algorithm) -> impl Fn(Algorithm) -> Approval {
        move |y| {
            if y == x {
                Approval::Unverified
            } else {
                approved(y)
            }
        }
    }

    #[test]
    fn admitted_approval_walks_macs_then_kdfs_whatever_the_order_named() {
        let a = admit(Profile::Cnsa2, Options::default());
        let m384 = Algorithm::Mac(M::HmacSha384);
        let k512 = Algorithm::Kdf(Kd::HkdfSha512);
        let both = |x: Algorithm| {
            if x == m384 || x == k512 {
                Approval::Unverified
            } else {
                approved(x)
            }
        };
        for families in [[Family::Mac, Family::Kdf], [Family::Kdf, Family::Mac]] {
            assert_eq!(
                admitted_approved_given(true, &a, &families, both),
                Err(CryptoError::NotApproved {
                    algorithm: m384,
                    approval: Approval::Unverified,
                }),
                "{families:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Kdf], both),
            Err(CryptoError::NotApproved {
                algorithm: k512,
                approval: Approval::Unverified,
            })
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Mac], all_but(k512)),
            Ok(())
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Kdf], all_but(m384)),
            Ok(())
        );
        assert_eq!(
            admitted_approved_given(true, &a, &[Family::Mac, Family::Mac], all_but(k512)),
            Ok(())
        );
    }

    #[test]
    fn a_tls_family_is_refused_after_fips_mode_and_before_everything_else() {
        let u = admit(Profile::Unrestricted, Options::default());
        let c = admit(Profile::Cnsa2, Options::default());
        for f in TLS {
            assert_eq!(
                admitted_approved_given(true, &c, &[Family::Mac, f], |_| Approval::Unverified),
                Err(CryptoError::FamilyNotAdmitted(f)),
                "{f:?}"
            );
            assert_eq!(
                admitted_approved_given(true, &u, &[f], approved),
                Err(CryptoError::FamilyNotAdmitted(f)),
                "{f:?}"
            );
            assert_eq!(
                admitted_approved_given(true, &u, &[Family::Kdf, Family::Mac, f], |_| {
                    Approval::Unverified
                }),
                Err(CryptoError::FamilyNotAdmitted(f)),
                "{f:?}"
            );
            assert_eq!(
                admitted_approved_given(false, &u, &[f], approved),
                Err(CryptoError::NotFips),
                "{f:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &u, &[Family::KxGroup, Family::Version], approved),
            Err(CryptoError::FamilyNotAdmitted(Family::KxGroup))
        );
    }

    #[test]
    fn asserting_nothing_approves_nothing() {
        for &p in Profile::ALL {
            let a = admit(p, Options::default());
            assert_eq!(
                admitted_approved_given(true, &a, &[], |_| Approval::Unverified),
                Ok(()),
                "{p}"
            );
            assert_eq!(assert_admitted_approved(&a, &[]), Ok(()), "{p}");
            let want = match a.key_agreements.first() {
                None => Ok(()),
                Some(k) => Err(CryptoError::NotApproved {
                    algorithm: Algorithm::KeyAgreement(*k),
                    approval: Approval::Unverified,
                }),
            };
            assert_eq!(
                admitted_approved_given(true, &a, &[Family::KeyAgreement], |_| {
                    Approval::Unverified
                }),
                want,
                "{p}"
            );
            assert_eq!(
                admitted_approved_given(false, &a, &[], approved),
                Err(CryptoError::NotFips),
                "{p}"
            );
        }
        let empty = Admitted {
            macs: vec![],
            kdfs: vec![],
            key_agreements: vec![],
            aeads: vec![],
            hashes: vec![],
            signatures: vec![],
            ..admit(Profile::Unrestricted, Options::default())
        };
        assert_eq!(
            admitted_approved_given(true, &empty, &NON_TLS, |_| Approval::Unverified),
            Ok(())
        );
    }

    #[test]
    fn a_profile_that_admits_an_empty_kdf_info_is_refused_only_when_kdf_is_named() {
        let refused = Err(CryptoError::KdfInfoMayBeEmpty {
            profile: Profile::Unrestricted,
        });
        let u = admit(Profile::Unrestricted, Options::default());
        assert!(!u.kdfs.is_empty());
        for families in [&[Family::Kdf][..], &[Family::Mac, Family::Kdf], &NON_TLS] {
            assert_eq!(
                admitted_approved_given(true, &u, families, approved),
                refused,
                "{families:?}"
            );
            assert_eq!(
                admitted_approved_given(true, &u, families, |_| Approval::Unverified),
                refused,
                "{families:?}"
            );
        }
        assert_eq!(
            admitted_approved_given(true, &u, &[Family::Mac], approved),
            Ok(())
        );
        assert_eq!(
            admitted_approved_given(true, &u, &[Family::Mac, Family::KeyAgreement], approved),
            Ok(())
        );
        let no_kdfs = Admitted {
            kdfs: vec![],
            ..u.clone()
        };
        assert_eq!(
            admitted_approved_given(true, &no_kdfs, &NON_TLS, approved),
            Ok(())
        );
        let bsi = admit(Profile::Bsi, Options::default());
        assert!(!bsi.kdfs.is_empty());
        assert_eq!(
            admitted_approved_given(true, &bsi, &NON_TLS, approved),
            Ok(())
        );
    }

    #[test]
    fn admitted_approval_follows_this_modules_cells() {
        let three_x = crate::MODULE.line == crate::ModuleLine::AwsLcFips3;
        for &p in Profile::ALL {
            let a = admit(p, Options::default());
            for (families, first) in [
                (
                    &[Family::Mac][..],
                    a.macs.first().map(|m| Algorithm::Mac(*m)),
                ),
                (
                    &[Family::Kdf][..],
                    a.kdfs.first().map(|k| Algorithm::Kdf(*k)),
                ),
                (
                    &[Family::Mac, Family::Kdf][..],
                    a.macs.first().map(|m| Algorithm::Mac(*m)),
                ),
                (
                    &[Family::KeyAgreement][..],
                    a.key_agreements
                        .first()
                        .map(|k| Algorithm::KeyAgreement(*k)),
                ),
            ] {
                let key_agreement = families == [Family::KeyAgreement];
                let want = if p == Profile::Unrestricted && families.contains(&Family::Kdf) {
                    Err(CryptoError::KdfInfoMayBeEmpty { profile: p })
                } else if (three_x && !key_agreement) || first.is_none() {
                    Ok(())
                } else {
                    let first = first.unwrap_or_else(|| panic!("{p}: nothing admitted"));
                    Err(CryptoError::NotApproved {
                        algorithm: first,
                        approval: crypto_profile::capability(crate::MODULE, first).approval,
                    })
                };
                assert_eq!(
                    assert_admitted_approved(&a, families),
                    want,
                    "{p} {families:?}"
                );
            }
            assert_eq!(
                assert_admitted_approved(&a, &[Family::Version]),
                Err(CryptoError::FamilyNotAdmitted(Family::Version)),
                "{p}"
            );
        }
        let fips = admit(Profile::Fips1403, Options::default());
        let p384 = Algorithm::KeyAgreement(KeyAgreementAlgorithm::EcdhP384);
        let refused = Err(CryptoError::NotApproved {
            algorithm: p384,
            approval: crypto_profile::capability(crate::MODULE, p384).approval,
        });
        assert_eq!(
            assert_admitted_approved(&fips, &[Family::Mac, Family::Kdf, Family::KeyAgreement]),
            if three_x {
                refused
            } else {
                Err(CryptoError::NotApproved {
                    algorithm: Algorithm::Mac(MacAlgorithm::HmacSha512),
                    approval: crypto_profile::capability(
                        crate::MODULE,
                        Algorithm::Mac(MacAlgorithm::HmacSha512),
                    )
                    .approval,
                })
            }
        );
        assert_eq!(
            assert_admitted_approved(&fips, &[Family::KeyAgreement]),
            refused
        );
        let approval = crypto_profile::capability(crate::MODULE, p384).approval;
        match (crate::MODULE.line, crate::MODULE.linkage) {
            (crate::ModuleLine::AwsLcFips3, crate::Linkage::Static | crate::Linkage::Dynamic) => {
                assert!(matches!(approval, Approval::NotApproved { .. }))
            }
            (crate::ModuleLine::AwsLcFips4, crate::Linkage::Static | crate::Linkage::Dynamic) => {
                assert!(matches!(approval, Approval::AlgorithmTested { .. }))
            }
            other => panic!("{other:?}: no expected approval"),
        }
    }
}
