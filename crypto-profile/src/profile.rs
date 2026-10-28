//! Named profiles: algorithm sets a backend resolves into a TLS policy and the key algorithms it
//! admits. A profile is an algorithm set, not a validation claim; whether the running module is
//! validated for it is a separate check.
use std::fmt;
use std::str::FromStr;

/// A named profile. Each one that is named for a regime follows that regime's published text, in
/// the edition [`Profile::governing_text`] names, and changes only when a new edition is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Every algorithm in the inventory, post-quantum key exchange first. Not a government profile.
    Unrestricted,
    /// The crate's recommendation. Not a government profile; see `docs/profiles.md`.
    Preferred,
    /// The CNSA 2.0 algorithm set of CNSSP 15 (December 2024), Annex B, on TLS 1.3.
    Cnsa2,
    /// The CNSA 1.0 algorithm set of CNSSP 15 (20 October 2016), Annex B, in RFC 9151's TLS
    /// profile, as far as the stack implements it. A transition profile for CNSA 1.0 counterparts.
    Cnsa1,
    /// BSI TR-02102-2 and TR-02102-1, version 2026-01.
    Bsi,
    /// What a FIPS 140-3 boundary approves under the published texts.
    Fips1403,
    /// What a FIPS 140-2 boundary approves under the published texts.
    Fips1402,
}

/// The text a profile follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoverningText {
    /// The crate's own recommendation, following no published text.
    CrateRecommendation,
    /// Published documents, each with its edition.
    Published {
        /// The documents, each naming its edition.
        documents: &'static [&'static str],
    },
}

impl Profile {
    /// Every profile.
    pub const ALL: [Profile; 7] = [
        Profile::Unrestricted,
        Profile::Preferred,
        Profile::Cnsa2,
        Profile::Cnsa1,
        Profile::Bsi,
        Profile::Fips1403,
        Profile::Fips1402,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            Profile::Unrestricted => 0,
            Profile::Preferred => 1,
            Profile::Cnsa2 => 2,
            Profile::Cnsa1 => 3,
            Profile::Bsi => 4,
            Profile::Fips1403 => 5,
            Profile::Fips1402 => 6,
        }
    }

    /// The profile's stable configuration name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Profile::Unrestricted => "unrestricted",
            Profile::Preferred => "preferred",
            Profile::Cnsa2 => "cnsa2",
            Profile::Cnsa1 => "cnsa1",
            Profile::Bsi => "bsi",
            Profile::Fips1403 => "fips1403",
            Profile::Fips1402 => "fips1402",
        }
    }

    /// The texts the profile follows, with each document's edition. The profile constant's doc
    /// comment also cites the standards and implementation guidance these texts rely on.
    pub const fn governing_text(self) -> GoverningText {
        match self {
            Profile::Unrestricted | Profile::Preferred => GoverningText::CrateRecommendation,
            Profile::Cnsa2 => GoverningText::Published {
                documents: &["CNSSP 15 (December 2024), Annex B, pp. B-1 to B-2"],
            },
            Profile::Cnsa1 => GoverningText::Published {
                documents: &[
                    "CNSSP 15 (20 October 2016), Annex B, p. B-1",
                    "RFC 9151 (April 2022)",
                ],
            },
            Profile::Bsi => GoverningText::Published {
                documents: &[
                    "BSI TR-02102-2, version 2026-01",
                    "BSI TR-02102-1, version 2026-01",
                ],
            },
            Profile::Fips1403 => GoverningText::Published {
                documents: &[
                    "NIST SP 800-140C r2 and SP 800-140D r2, with the CMVP lists (August 2026)",
                    "FIPS 140-3 Implementation Guidance (August 2026): IG C.K, D.Q, D.S",
                    "NIST SP 800-52r2",
                    "NIST SP 800-131A r2",
                ],
            },
            Profile::Fips1402 => GoverningText::Published {
                documents: &[
                    "FIPS 140-2 Annex A and Annex D (2021)",
                    "FIPS 186-4",
                    "NIST SP 800-131A r2",
                    "NIST SP 800-52r2",
                ],
            },
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name that is not one of the crate's profiles. Names are matched exactly: no trimming and no
/// case folding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProfileError(pub String);

impl fmt::Display for ParseProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown profile {:?}", self.0)
    }
}

impl std::error::Error for ParseProfileError {}

impl FromStr for Profile {
    type Err = ParseProfileError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Profile::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| ParseProfileError(s.to_string()))
    }
}

/// Narrowing applied on top of any profile. The default narrows nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Options {
    /// Keep only post-quantum key exchange (pure ML-KEM and hybrid groups), and so remove TLS 1.2,
    /// which has none. Signatures are not narrowed.
    pub pq_key_exchange_required: bool,
}

impl fmt::Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.pq_key_exchange_required {
            "post-quantum key exchange required"
        } else {
            "no options"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_are_stable_and_exact() {
        assert_eq!(
            Profile::ALL.map(Profile::as_str),
            [
                "unrestricted",
                "preferred",
                "cnsa2",
                "cnsa1",
                "bsi",
                "fips1403",
                "fips1402"
            ]
        );
        for p in Profile::ALL {
            assert_eq!(p.as_str().parse::<Profile>(), Ok(p));
            assert_eq!(p.to_string(), p.as_str());
        }
        for bad in [
            "",
            "CNSA2",
            "Cnsa2",
            "FIPS1403",
            "fips140-3",
            "fips-140-3",
            " fips1403",
            "fips1403 ",
            "fips1403\n",
            " bsi",
            "cnsa",
            "bsi2026",
            "preferred,",
            "default",
        ] {
            assert_eq!(
                bad.parse::<Profile>(),
                Err(ParseProfileError(bad.to_string())),
                "{bad:?}"
            );
        }
        assert_eq!(
            ParseProfileError("FIPS1403".to_string()).to_string(),
            "unknown profile \"FIPS1403\""
        );
    }

    #[test]
    fn profile_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            Profile::ALL.map(Profile::ordinal),
            std::array::from_fn::<usize, 7, _>(|i| i)
        );
    }

    #[test]
    fn governing_texts_are_the_published_editions() {
        use GoverningText::{CrateRecommendation as Own, Published};
        let table: [(Profile, GoverningText); 7] = [
            (Profile::Unrestricted, Own),
            (Profile::Preferred, Own),
            (
                Profile::Cnsa2,
                Published {
                    documents: &["CNSSP 15 (December 2024), Annex B, pp. B-1 to B-2"],
                },
            ),
            (
                Profile::Cnsa1,
                Published {
                    documents: &[
                        "CNSSP 15 (20 October 2016), Annex B, p. B-1",
                        "RFC 9151 (April 2022)",
                    ],
                },
            ),
            (
                Profile::Bsi,
                Published {
                    documents: &[
                        "BSI TR-02102-2, version 2026-01",
                        "BSI TR-02102-1, version 2026-01",
                    ],
                },
            ),
            (
                Profile::Fips1403,
                Published {
                    documents: &[
                        "NIST SP 800-140C r2 and SP 800-140D r2, with the CMVP lists (August 2026)",
                        "FIPS 140-3 Implementation Guidance (August 2026): IG C.K, D.Q, D.S",
                        "NIST SP 800-52r2",
                        "NIST SP 800-131A r2",
                    ],
                },
            ),
            (
                Profile::Fips1402,
                Published {
                    documents: &[
                        "FIPS 140-2 Annex A and Annex D (2021)",
                        "FIPS 186-4",
                        "NIST SP 800-131A r2",
                        "NIST SP 800-52r2",
                    ],
                },
            ),
        ];
        for (p, text) in table {
            assert_eq!(p.governing_text(), text, "{p}");
        }
    }

    #[test]
    fn options_default_narrows_nothing_and_display_names_the_option() {
        assert_eq!(
            Options::default(),
            Options {
                pq_key_exchange_required: false
            }
        );
        assert_eq!(Options::default().to_string(), "no options");
        assert_eq!(
            Options {
                pq_key_exchange_required: true
            }
            .to_string(),
            "post-quantum key exchange required"
        );
    }
}
