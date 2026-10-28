#![allow(missing_docs)]
use crypto_profile_awslc4::test_support::{Negotiated, handshake, handshake_with_ca};
use crypto_profile_awslc4::tls::{Policy, client_builder};
use crypto_profile_awslc4::{
    CipherSuite as C, CryptoError, Family, KxGroup as K, Options, Profile, Resolved,
    SignatureAlgorithm as S, TlsSignatureScheme as T, TlsVersion as V, resolve, rustls,
};

const PQ: Options = Options {
    pq_key_exchange_required: true,
};
const NO_GROUP: &str = "peer is incompatible: NoKxGroupsInCommon";
const NO_SUITE: &str = "peer is incompatible: NoCipherSuitesInCommon";
const NO_SCHEME: &str = "peer is incompatible: NoSignatureSchemesInCommon";
const NO_TLS12: &str = "peer is incompatible: Tls12NotOfferedOrEnabled";
const PKCS1: [u16; 3] = [0x0401, 0x0501, 0x0601];

fn r(p: Profile) -> Result<Resolved, CryptoError> {
    resolve(p, Options::default())
}

fn err<X>(s: &str) -> Result<X, String> {
    Err(s.to_string())
}

fn peer(v: V, c: C, k: &[K]) -> Policy {
    Policy {
        versions: vec![v],
        cipher_suites: vec![c],
        kx_groups: k.to_vec(),
        signature_schemes: T::ALL.to_vec(),
    }
}

fn tls13(k: &[K]) -> Policy {
    peer(V::Tls13, C::Tls13Aes256GcmSha384, k)
}

fn tls12() -> Policy {
    peer(V::Tls12, C::Tls12EcdheEcdsaAes256GcmSha384, &[K::Secp384r1])
}

fn served(client: &Policy, server: &Resolved, pick: fn(Negotiated) -> u16) -> Result<u16, String> {
    handshake(client, &server.tls, S::EcdsaP384Sha384).map(pick)
}

fn verifies(client: &Policy, key: S) -> Result<u16, String> {
    let server = r(Profile::Unrestricted).map_err(|e| e.to_string())?;
    handshake(client, &server.tls, key).map(|n| n.scheme.iana())
}

fn pkcs1(client: &Resolved, v: V) -> Policy {
    Policy {
        versions: client
            .tls
            .versions
            .iter()
            .copied()
            .filter(|x| *x == v)
            .collect(),
        signature_schemes: client
            .tls
            .signature_schemes
            .iter()
            .copied()
            .filter(|t| PKCS1.contains(&t.iana()))
            .collect(),
        ..client.tls.clone()
    }
}

fn has_pkcs1(r: &Resolved) -> bool {
    r.tls
        .signature_schemes
        .iter()
        .any(|t| PKCS1.contains(&t.iana()))
}

fn empty_with_the_option(p: Profile) -> bool {
    match p {
        Profile::Cnsa1 | Profile::Bsi | Profile::Fips1402 => true,
        Profile::Unrestricted | Profile::Preferred | Profile::Cnsa2 | Profile::Fips1403 => false,
    }
}

struct Golden {
    profile: Profile,
    pq: bool,
    versions: &'static [u16],
    suites: &'static [u16],
    groups: &'static [u16],
    schemes: &'static [u16],
    keys: &'static [&'static str],
}

const ALL_SCHEMES: &[u16] = &[
    0x0906, 0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804, 0x0501, 0x0601, 0x0401,
];
const ALL_SCHEMES_BUT_PKCS1: &[u16] = &[
    0x0906, 0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804,
];
const ALL_KEYS: &[&str] = &[
    "ml-dsa-87",
    "ecdsa-p384-sha384",
    "ecdsa-p256-sha256",
    "ecdsa-p521-sha512",
    "ecdsa-p521-sha384",
    "ed25519",
    "rsa3072-sha384",
    "rsa4096-sha384",
    "rsa2048-sha384",
];
const FIPS_SUITES: &[u16] = &[0x1302, 0x1301, 0xC02C, 0xC030, 0xC02B, 0xC02F];
const PREFERRED_SCHEMES: &[u16] = &[0x0906, 0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804];
const PREFERRED_KEYS: &[&str] = &[
    "ml-dsa-87",
    "ecdsa-p384-sha384",
    "ecdsa-p256-sha256",
    "ecdsa-p521-sha512",
    "ecdsa-p521-sha384",
    "rsa3072-sha384",
    "rsa4096-sha384",
];

const GOLDEN: &[Golden] = &[
    Golden {
        profile: Profile::Unrestricted,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: &[
            0x1302, 0x1301, 0x1303, 0xC02C, 0xC030, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
        ],
        groups: &[0x0202, 0x11EC, 0x11EB, 0x0018, 0x0017, 0x001D],
        schemes: ALL_SCHEMES,
        keys: ALL_KEYS,
    },
    Golden {
        profile: Profile::Unrestricted,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301, 0x1303],
        groups: &[0x0202, 0x11EC, 0x11EB],
        schemes: ALL_SCHEMES_BUT_PKCS1,
        keys: ALL_KEYS,
    },
    Golden {
        profile: Profile::Preferred,
        pq: false,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11EC, 0x11EB, 0x0018, 0x0017],
        schemes: PREFERRED_SCHEMES,
        keys: PREFERRED_KEYS,
    },
    Golden {
        profile: Profile::Preferred,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11EC, 0x11EB],
        schemes: PREFERRED_SCHEMES,
        keys: PREFERRED_KEYS,
    },
    Golden {
        profile: Profile::Cnsa2,
        pq: false,
        versions: &[0x0304],
        suites: &[0x1302],
        groups: &[0x0202],
        schemes: &[0x0906],
        keys: &["ml-dsa-87"],
    },
    Golden {
        profile: Profile::Cnsa2,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302],
        groups: &[0x0202],
        schemes: &[0x0906],
        keys: &["ml-dsa-87"],
    },
    Golden {
        profile: Profile::Cnsa1,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: &[0x1302, 0xC02C, 0xC030],
        groups: &[0x0018],
        schemes: &[0x0503, 0x0805, 0x0501],
        keys: &["ecdsa-p384-sha384", "rsa3072-sha384", "rsa4096-sha384"],
    },
    Golden {
        profile: Profile::Bsi,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: FIPS_SUITES,
        groups: &[0x0018, 0x0017],
        schemes: &[0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804],
        keys: &[
            "ecdsa-p384-sha384",
            "ecdsa-p256-sha256",
            "ecdsa-p521-sha512",
        ],
    },
    Golden {
        profile: Profile::Fips1403,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: FIPS_SUITES,
        groups: &[0x0202, 0x11EC, 0x11EB, 0x0018, 0x0017],
        schemes: ALL_SCHEMES,
        keys: ALL_KEYS,
    },
    Golden {
        profile: Profile::Fips1403,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11EC, 0x11EB],
        schemes: ALL_SCHEMES_BUT_PKCS1,
        keys: ALL_KEYS,
    },
    Golden {
        profile: Profile::Fips1402,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: FIPS_SUITES,
        groups: &[0x0018, 0x0017],
        schemes: &[
            0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804, 0x0501, 0x0601, 0x0401,
        ],
        keys: &[
            "ecdsa-p384-sha384",
            "ecdsa-p256-sha256",
            "ecdsa-p521-sha512",
            "ecdsa-p521-sha384",
            "rsa3072-sha384",
            "rsa4096-sha384",
            "rsa2048-sha384",
        ],
    },
];

#[test]
fn resolve_matches_the_golden_tables() -> Result<(), CryptoError> {
    let mut checked = 0;
    for p in Profile::ALL {
        for pq in [false, true] {
            let options = Options {
                pq_key_exchange_required: pq,
            };
            let got = resolve(p, options);
            if pq && empty_with_the_option(p) {
                assert_eq!(
                    got,
                    Err(CryptoError::EmptyProfile {
                        profile: p,
                        options,
                        category: Family::KxGroup,
                    }),
                    "{p} {options}"
                );
                continue;
            }
            let g = GOLDEN
                .iter()
                .find(|g| g.profile == p && g.pq == pq)
                .expect("a golden row for every profile that resolves");
            let r = got.expect("the profile resolves");
            assert_eq!(
                r.tls.versions.iter().map(|x| x.iana()).collect::<Vec<_>>(),
                g.versions,
                "{p} {options}"
            );
            assert_eq!(
                r.tls
                    .cipher_suites
                    .iter()
                    .map(|x| x.iana())
                    .collect::<Vec<_>>(),
                g.suites,
                "{p} {options}"
            );
            assert_eq!(
                r.tls.kx_groups.iter().map(|x| x.iana()).collect::<Vec<_>>(),
                g.groups,
                "{p} {options}"
            );
            assert_eq!(
                r.tls
                    .signature_schemes
                    .iter()
                    .map(|x| x.iana())
                    .collect::<Vec<_>>(),
                g.schemes,
                "{p} {options}"
            );
            assert_eq!(
                r.keys.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                g.keys,
                "{p} {options}"
            );
            checked += 1;
        }
    }
    assert_eq!((checked, GOLDEN.len()), (11, 11));
    Ok(())
}

#[test]
fn unrestricted_vs_fips1403() -> Result<(), CryptoError> {
    let (u, f) = (r(Profile::Unrestricted)?, r(Profile::Fips1403)?);
    let x25519 = tls13(&[K::X25519]);
    assert_eq!(served(&x25519, &u, |n| n.kx.iana()), Ok(0x001D));
    assert_eq!(served(&x25519, &f, |n| n.kx.iana()), err(NO_GROUP));
    let chacha = peer(V::Tls13, C::Tls13Chacha20Poly1305Sha256, &[K::Secp384r1]);
    assert_eq!(served(&chacha, &u, |n| n.suite.iana()), Ok(0x1303));
    assert_eq!(served(&chacha, &f, |n| n.suite.iana()), err(NO_SUITE));
    Ok(())
}

#[test]
fn fips1403_vs_fips1402() -> Result<(), CryptoError> {
    let (a, b) = (r(Profile::Fips1403)?, r(Profile::Fips1402)?);
    for (group, cp) in [(K::MlKem1024, 0x0202), (K::X25519MlKem768, 0x11EC)] {
        assert_eq!(served(&tls13(&[group]), &a, |n| n.kx.iana()), Ok(cp));
        assert_eq!(served(&tls13(&[group]), &b, |n| n.kx.iana()), err(NO_GROUP));
    }
    for key in [S::Ed25519, S::MlDsa87] {
        assert_eq!(a.admit_key(key), Ok(()));
        assert_eq!(
            b.admit_key(key),
            Err(CryptoError::KeyNotInProfile {
                profile: Profile::Fips1402,
                algorithm: key
            })
        );
    }
    assert_eq!(verifies(&a.tls, S::MlDsa87), Ok(0x0906));
    assert_eq!(verifies(&b.tls, S::MlDsa87), err(NO_SCHEME));
    assert_eq!(verifies(&a.tls, S::Ed25519), Ok(0x0807));
    assert_eq!(verifies(&b.tls, S::Ed25519), err(NO_SCHEME));
    Ok(())
}

#[test]
fn preferred_vs_fips1403() -> Result<(), CryptoError> {
    let (p, f) = (r(Profile::Preferred)?, r(Profile::Fips1403)?);
    assert_eq!(served(&tls12(), &f, |n| n.version.iana()), Ok(0x0303));
    assert_eq!(served(&tls12(), &p, |n| n.version.iana()), err(NO_TLS12));
    assert_eq!(verifies(&f.tls, S::Ed25519), Ok(0x0807));
    assert_eq!(verifies(&p.tls, S::Ed25519), err(NO_SCHEME));
    for key in [S::Ed25519, S::Rsa2048Sha384] {
        assert_eq!(f.admit_key(key), Ok(()));
        assert_eq!(
            p.admit_key(key),
            Err(CryptoError::KeyNotInProfile {
                profile: Profile::Preferred,
                algorithm: key
            })
        );
    }
    assert_eq!(verifies(&pkcs1(&f, V::Tls12), S::Rsa3072Sha384), Ok(0x0601));
    assert!(!has_pkcs1(&p));
    Ok(())
}

#[test]
fn cnsa2_vs_cnsa1() -> Result<(), CryptoError> {
    let (two, one) = (r(Profile::Cnsa2)?, r(Profile::Cnsa1)?);
    let mlkem = tls13(&[K::MlKem1024]);
    let p384 = tls13(&[K::Secp384r1]);
    assert_eq!(served(&mlkem, &two, |n| n.kx.iana()), Ok(0x0202));
    assert_eq!(served(&mlkem, &one, |n| n.kx.iana()), err(NO_GROUP));
    assert_eq!(served(&p384, &one, |n| n.kx.iana()), Ok(0x0018));
    assert_eq!(served(&p384, &two, |n| n.kx.iana()), err(NO_GROUP));
    assert_eq!(verifies(&two.tls, S::MlDsa87), Ok(0x0906));
    assert_eq!(verifies(&one.tls, S::MlDsa87), err(NO_SCHEME));
    assert_eq!(two.admit_key(S::MlDsa87), Ok(()));
    assert_eq!(
        one.admit_key(S::MlDsa87),
        Err(CryptoError::KeyNotInProfile {
            profile: Profile::Cnsa1,
            algorithm: S::MlDsa87
        })
    );
    assert_eq!(served(&tls12(), &one, |n| n.version.iana()), Ok(0x0303));
    assert_eq!(served(&tls12(), &two, |n| n.version.iana()), err(NO_TLS12));
    Ok(())
}

#[test]
fn cnsa1_vs_fips1402() -> Result<(), CryptoError> {
    let (one, f) = (r(Profile::Cnsa1)?, r(Profile::Fips1402)?);
    let p256 = tls13(&[K::Secp256r1]);
    assert_eq!(served(&p256, &f, |n| n.kx.iana()), Ok(0x0017));
    assert_eq!(served(&p256, &one, |n| n.kx.iana()), err(NO_GROUP));
    let aes128 = peer(V::Tls13, C::Tls13Aes128GcmSha256, &[K::Secp384r1]);
    assert_eq!(served(&aes128, &f, |n| n.suite.iana()), Ok(0x1301));
    assert_eq!(served(&aes128, &one, |n| n.suite.iana()), err(NO_SUITE));
    assert_eq!(f.admit_key(S::Rsa2048Sha384), Ok(()));
    assert_eq!(
        one.admit_key(S::Rsa2048Sha384),
        Err(CryptoError::KeyNotInProfile {
            profile: Profile::Cnsa1,
            algorithm: S::Rsa2048Sha384
        })
    );
    assert_eq!(
        verifies(&pkcs1(&one, V::Tls12), S::Rsa3072Sha384),
        Ok(0x0501)
    );
    Ok(())
}

#[test]
fn bsi_vs_fips1402() -> Result<(), CryptoError> {
    let (b, f) = (r(Profile::Bsi)?, r(Profile::Fips1402)?);
    assert_eq!(f.admit_key(S::Rsa3072Sha384), Ok(()));
    assert_eq!(
        b.admit_key(S::Rsa3072Sha384),
        Err(CryptoError::KeyNotInProfile {
            profile: Profile::Bsi,
            algorithm: S::Rsa3072Sha384
        })
    );
    assert_eq!(verifies(&pkcs1(&f, V::Tls12), S::Rsa3072Sha384), Ok(0x0601));
    assert!(has_pkcs1(&f));
    assert!(!has_pkcs1(&b));
    Ok(())
}

#[test]
fn bsi_vs_preferred() -> Result<(), CryptoError> {
    let (b, p) = (r(Profile::Bsi)?, r(Profile::Preferred)?);
    assert_eq!(served(&tls12(), &b, |n| n.version.iana()), Ok(0x0303));
    assert_eq!(served(&tls12(), &p, |n| n.version.iana()), err(NO_TLS12));
    let hybrid = tls13(&[K::X25519MlKem768]);
    assert_eq!(served(&hybrid, &p, |n| n.kx.iana()), Ok(0x11EC));
    assert_eq!(served(&hybrid, &b, |n| n.kx.iana()), err(NO_GROUP));
    assert_eq!(verifies(&p.tls, S::MlDsa87), Ok(0x0906));
    assert_eq!(verifies(&b.tls, S::MlDsa87), err(NO_SCHEME));
    assert_eq!(p.admit_key(S::MlDsa87), Ok(()));
    assert_eq!(
        b.admit_key(S::MlDsa87),
        Err(CryptoError::KeyNotInProfile {
            profile: Profile::Bsi,
            algorithm: S::MlDsa87
        })
    );
    Ok(())
}

#[test]
fn rustls_refuses_pkcs1_in_a_tls13_handshake() -> Result<(), CryptoError> {
    assert_eq!(
        verifies(&pkcs1(&r(Profile::Fips1403)?, V::Tls13), S::Rsa3072Sha384),
        err(NO_SCHEME)
    );
    Ok(())
}

#[test]
fn preferred_with_the_option_refuses_a_classical_only_peer() -> Result<(), CryptoError> {
    let p = resolve(Profile::Preferred, PQ)?;
    let classical = tls13(&[K::Secp384r1, K::Secp256r1, K::X25519]);
    assert_eq!(served(&classical, &p, |n| n.kx.iana()), err(NO_GROUP));
    let hybrid = tls13(&[K::Secp256r1MlKem768]);
    assert_eq!(served(&hybrid, &p, |n| n.kx.iana()), Ok(0x11EB));
    Ok(())
}

#[test]
fn cnsa2_with_the_option_is_cnsa2() -> Result<(), CryptoError> {
    let (a, b) = (r(Profile::Cnsa2)?, resolve(Profile::Cnsa2, PQ)?);
    assert_eq!((a.tls, a.keys), (b.tls, b.keys));
    Ok(())
}

#[test]
fn the_option_refuses_a_tls12_peer() -> Result<(), CryptoError> {
    let f = resolve(Profile::Fips1403, PQ)?;
    assert_eq!(served(&tls12(), &f, |n| n.version.iana()), err(NO_TLS12));
    Ok(())
}

#[test]
fn the_option_removes_the_pkcs1_schemes() -> Result<(), CryptoError> {
    for p in [Profile::Unrestricted, Profile::Fips1403] {
        assert!(has_pkcs1(&r(p)?), "{p}");
        assert!(!has_pkcs1(&resolve(p, PQ)?), "{p}");
    }
    Ok(())
}

#[test]
fn profiles_mix_per_connection_in_one_process() -> Result<(), CryptoError> {
    let (p, f) = (r(Profile::Preferred)?, r(Profile::Fips1402)?);
    let cp = |n: Negotiated| {
        (
            n.version.iana(),
            n.suite.iana(),
            n.kx.iana(),
            n.scheme.iana(),
        )
    };
    std::thread::scope(|s| {
        let a = s.spawn(|| handshake(&f.tls, &p.tls, S::EcdsaP384Sha384));
        let b = s.spawn(|| handshake(&f.tls, &f.tls, S::Rsa3072Sha384));
        let c = s.spawn(|| handshake(&p.tls, &p.tls, S::MlDsa87));
        assert_eq!(
            a.join().unwrap().map(cp),
            Ok((0x0304, 0x1302, 0x0018, 0x0503))
        );
        assert_eq!(
            b.join().unwrap().map(cp),
            Ok((0x0304, 0x1302, 0x0018, 0x0806))
        );
        assert_eq!(
            c.join().unwrap().map(cp),
            Ok((0x0304, 0x1302, 0x0202, 0x0906))
        );
    });
    Ok(())
}

#[test]
fn rustls_classifies_every_profile_but_unrestricted_as_fips() -> Result<(), CryptoError> {
    for p in Profile::ALL {
        let fips = match p {
            Profile::Unrestricted => false,
            Profile::Preferred
            | Profile::Cnsa2
            | Profile::Cnsa1
            | Profile::Bsi
            | Profile::Fips1403
            | Profile::Fips1402 => true,
        };
        let cfg = client_builder(&r(p)?.tls)
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert_eq!((cfg.fips(), cfg.require_ems), (fips, fips), "{p}");
        assert_eq!(
            crypto_profile_awslc4::fips::assert_fips_client_config(&cfg).is_ok(),
            fips,
            "{p}"
        );
    }
    Ok(())
}

#[test]
fn a_profile_does_not_restrict_the_chain_signature() -> Result<(), CryptoError> {
    let n = handshake_with_ca(
        &r(Profile::Fips1402)?.tls,
        &r(Profile::Unrestricted)?.tls,
        S::Ed25519,
        S::EcdsaP384Sha384,
    )
    .unwrap();
    assert_eq!(n.scheme.iana(), 0x0503);
    Ok(())
}
