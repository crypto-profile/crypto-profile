//! The profile golden tables every backend's `resolve` is checked against; literal IANA
//! codepoints and key names. The three rows the option leaves empty (`cnsa1`, `bsi` and `fips1402`
//! with the option) specify the refusal `resolve` gives; their lists are never compared with a
//! resolved profile.
use crate::{
    Algorithm, CryptoError, Family, Module, ModuleLine, Options, Profile, SignatureAlgorithm,
    TlsSignatureScheme,
};

/// One profile's lists, with or without the option.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Golden {
    /// The profile.
    pub profile: Profile,
    /// Whether post-quantum key exchange is required.
    pub pq: bool,
    /// Protocol versions.
    pub versions: &'static [u16],
    /// Cipher suites.
    pub suites: &'static [u16],
    /// Key-exchange groups.
    pub groups: &'static [u16],
    /// Handshake signature schemes.
    pub schemes: &'static [u16],
    /// Key algorithms.
    pub keys: &'static [&'static str],
    /// Entries excluded by the module line, in family and preference order.
    pub excluded: &'static [Algorithm],
}

/// Every handshake scheme, in canonical order.
#[doc(hidden)]
pub const ALL_SCHEMES: &[u16] = &[
    0x0906, 0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804, 0x0501, 0x0601, 0x0401,
];
/// Every handshake scheme but RSA PKCS#1 v1.5, in canonical order.
#[doc(hidden)]
pub const ALL_SCHEMES_BUT_PKCS1: &[u16] = &[
    0x0906, 0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804,
];
/// Every key algorithm, in preference order.
#[doc(hidden)]
pub const ALL_KEYS: &[&str] = &[
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
/// The cipher suites of `bsi`, `fips1403` and `fips1402`.
#[doc(hidden)]
pub const FIPS_SUITES: &[u16] = &[0x1302, 0x1301, 0xC02C, 0xC030, 0xC02B, 0xC02F];
/// `preferred`'s handshake schemes.
#[doc(hidden)]
pub const PREFERRED_SCHEMES: &[u16] = &[0x0906, 0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804];
/// `preferred`'s key algorithms.
#[doc(hidden)]
pub const PREFERRED_KEYS: &[&str] = &[
    "ml-dsa-87",
    "ecdsa-p384-sha384",
    "ecdsa-p256-sha256",
    "ecdsa-p521-sha512",
    "ecdsa-p521-sha384",
    "rsa3072-sha384",
    "rsa4096-sha384",
];

/// One row per profile and option value.
#[doc(hidden)]
pub const GOLDEN: &[Golden] = &[
    Golden {
        excluded: &[],
        profile: Profile::Unrestricted,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: &[
            0x1302, 0x1301, 0x1303, 0xC02C, 0xC030, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
        ],
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB, 0x0018, 0x0017, 0x001D],
        schemes: ALL_SCHEMES,
        keys: ALL_KEYS,
    },
    Golden {
        excluded: &[],
        profile: Profile::Unrestricted,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301, 0x1303],
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB],
        schemes: ALL_SCHEMES_BUT_PKCS1,
        keys: ALL_KEYS,
    },
    Golden {
        excluded: &[],
        profile: Profile::Preferred,
        pq: false,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB, 0x0018, 0x0017],
        schemes: PREFERRED_SCHEMES,
        keys: PREFERRED_KEYS,
    },
    Golden {
        excluded: &[],
        profile: Profile::Preferred,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB],
        schemes: PREFERRED_SCHEMES,
        keys: PREFERRED_KEYS,
    },
    Golden {
        excluded: &[],
        profile: Profile::Cnsa2,
        pq: false,
        versions: &[0x0304],
        suites: &[0x1302],
        groups: &[0x0202],
        schemes: &[0x0906],
        keys: &["ml-dsa-87"],
    },
    Golden {
        excluded: &[],
        profile: Profile::Cnsa2,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302],
        groups: &[0x0202],
        schemes: &[0x0906],
        keys: &["ml-dsa-87"],
    },
    Golden {
        excluded: &[],
        profile: Profile::Cnsa1,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: &[0x1302, 0xC02C, 0xC030],
        groups: &[0x0018],
        schemes: &[0x0503, 0x0805, 0x0501],
        keys: &["ecdsa-p384-sha384", "rsa3072-sha384", "rsa4096-sha384"],
    },
    Golden {
        excluded: &[],
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
        excluded: &[],
        profile: Profile::Fips1403,
        pq: false,
        versions: &[0x0304, 0x0303],
        suites: FIPS_SUITES,
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB, 0x0018, 0x0017],
        schemes: ALL_SCHEMES,
        keys: ALL_KEYS,
    },
    Golden {
        excluded: &[],
        profile: Profile::Fips1403,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[0x0202, 0x11ED, 0x11EC, 0x11EB],
        schemes: ALL_SCHEMES_BUT_PKCS1,
        keys: ALL_KEYS,
    },
    Golden {
        excluded: &[],
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
    Golden {
        excluded: &[],
        profile: Profile::Cnsa1,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302],
        groups: &[],
        schemes: &[0x0503, 0x0805],
        keys: &["ecdsa-p384-sha384", "rsa3072-sha384", "rsa4096-sha384"],
    },
    Golden {
        excluded: &[],
        profile: Profile::Bsi,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[],
        schemes: &[0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804],
        keys: &[
            "ecdsa-p384-sha384",
            "ecdsa-p256-sha256",
            "ecdsa-p521-sha512",
        ],
    },
    Golden {
        excluded: &[],
        profile: Profile::Fips1402,
        pq: true,
        versions: &[0x0304],
        suites: &[0x1302, 0x1301],
        groups: &[],
        schemes: &[0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804],
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

/// The independent per-line golden row, or the first empty-family refusal.
#[doc(hidden)]
pub fn expected(module: Module, profile: Profile, options: Options) -> Result<Golden, CryptoError> {
    let mut g = GOLDEN
        .iter()
        .find(|g| g.profile == profile && g.pq == options.pq_key_exchange_required)
        .unwrap_or_else(|| panic!("no golden row for {profile} {options}"))
        .clone();
    match module.line {
        ModuleLine::AwsLcFips4 => {}
        ModuleLine::AwsLcFips3 => {
            match profile {
                Profile::Unrestricted | Profile::Fips1403 => {
                    g.schemes = if options.pq_key_exchange_required {
                        &[0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804]
                    } else {
                        &[
                            0x0503, 0x0403, 0x0603, 0x0807, 0x0805, 0x0806, 0x0804, 0x0501, 0x0601,
                            0x0401,
                        ]
                    };
                    g.keys = &[
                        "ecdsa-p384-sha384",
                        "ecdsa-p256-sha256",
                        "ecdsa-p521-sha512",
                        "ecdsa-p521-sha384",
                        "ed25519",
                        "rsa3072-sha384",
                        "rsa4096-sha384",
                        "rsa2048-sha384",
                    ];
                }
                Profile::Preferred => {
                    g.schemes = &[0x0503, 0x0403, 0x0603, 0x0805, 0x0806, 0x0804];
                    g.keys = &[
                        "ecdsa-p384-sha384",
                        "ecdsa-p256-sha256",
                        "ecdsa-p521-sha512",
                        "ecdsa-p521-sha384",
                        "rsa3072-sha384",
                        "rsa4096-sha384",
                    ];
                }
                Profile::Cnsa2 => {
                    g.schemes = &[];
                    g.keys = &[];
                }
                Profile::Cnsa1 | Profile::Bsi | Profile::Fips1402 => {}
            }
            match profile {
                Profile::Unrestricted | Profile::Preferred | Profile::Fips1403 | Profile::Cnsa2 => {
                    g.excluded = &[
                        Algorithm::Scheme(TlsSignatureScheme::MlDsa87),
                        Algorithm::Signature(SignatureAlgorithm::MlDsa87),
                    ];
                }
                Profile::Cnsa1 | Profile::Bsi | Profile::Fips1402 => {}
            }
        }
    }
    for (empty, category) in [
        (g.versions.is_empty(), Family::Version),
        (g.suites.is_empty(), Family::CipherSuite),
        (g.groups.is_empty(), Family::KxGroup),
        (g.schemes.is_empty(), Family::SignatureScheme),
        (g.keys.is_empty(), Family::KeyAlgorithm),
    ] {
        if empty {
            return Err(CryptoError::EmptyProfile {
                profile,
                options,
                category,
            });
        }
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Linkage, ModuleLine};
    use crate::error::Family;
    use crate::profile::select;
    use crate::{Algorithm, TlsSignatureScheme};

    const M3S: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Static,
    };
    const M3D: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Dynamic,
    };
    const M4S: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Static,
    };
    const M4D: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Dynamic,
    };
    const PQ: Options = Options {
        peer_certificates_match_profile: false,
        pq_key_exchange_required: true,
    };

    type Lists = (
        Vec<u16>,
        Vec<u16>,
        Vec<u16>,
        Vec<u16>,
        Vec<&'static str>,
        Vec<Algorithm>,
    );

    #[test]
    fn every_profile_and_option_has_exactly_one_golden_row() {
        assert_eq!(GOLDEN.len(), 14);
        for p in Profile::ALL {
            for pq in [false, true] {
                let n = GOLDEN
                    .iter()
                    .filter(|g| g.profile == p && g.pq == pq)
                    .count();
                assert_eq!(n, 1, "{p} {pq}");
            }
        }
    }

    #[test]
    fn select_agrees_with_the_golden_rows_on_every_module() {
        for m in [M3S, M3D, M4S, M4D] {
            let mut successes = 0;
            for p in Profile::ALL {
                for pq in [false, true] {
                    let o = Options {
                        peer_certificates_match_profile: false,
                        pq_key_exchange_required: pq,
                    };
                    let got: Result<Lists, CryptoError> = select(p, o, m).map(|s| {
                        (
                            s.versions.iter().map(|x| x.iana()).collect(),
                            s.cipher_suites.iter().map(|x| x.iana()).collect(),
                            s.kx_groups.iter().map(|x| x.iana()).collect(),
                            s.signature_schemes.iter().map(|x| x.iana()).collect(),
                            s.key_algorithms.iter().map(|x| x.as_str()).collect(),
                            s.excluded,
                        )
                    });
                    let want: Result<Lists, CryptoError> = expected(m, p, o).map(|g| {
                        (
                            g.versions.to_vec(),
                            g.suites.to_vec(),
                            g.groups.to_vec(),
                            g.schemes.to_vec(),
                            g.keys.to_vec(),
                            g.excluded.to_vec(),
                        )
                    });
                    assert_eq!(got, want, "{m:?} {p} {o}");
                    successes += usize::from(got.is_ok());
                }
            }
            assert_eq!(
                successes,
                match m.line {
                    ModuleLine::AwsLcFips3 => 9,
                    ModuleLine::AwsLcFips4 => 11,
                }
            );
        }
    }

    #[test]
    fn expected_records_the_3x_refusals() {
        let d = Options::default();
        assert_eq!(
            expected(M3S, Profile::Cnsa2, d).map(|_| ()),
            Err(CryptoError::EmptyProfile {
                profile: Profile::Cnsa2,
                options: d,
                category: Family::SignatureScheme,
            })
        );
        assert_eq!(
            expected(M3S, Profile::Preferred, PQ).unwrap().excluded,
            &[
                Algorithm::Scheme(TlsSignatureScheme::MlDsa87),
                Algorithm::Signature(SignatureAlgorithm::MlDsa87)
            ]
        );
        assert!(expected(M3S, Profile::Cnsa1, d).is_ok());
        assert_eq!(
            expected(M3S, Profile::Fips1402, PQ).map(|_| ()),
            Err(CryptoError::EmptyProfile {
                profile: Profile::Fips1402,
                options: PQ,
                category: Family::KxGroup,
            })
        );
        assert!(expected(M4S, Profile::Cnsa2, d).is_ok());
    }
}
