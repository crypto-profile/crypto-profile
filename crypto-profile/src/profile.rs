//! Named profiles: algorithm sets a backend resolves into a TLS policy and the key algorithms it
//! admits. A profile is an algorithm set, not a validation claim; whether the running module is
//! validated for it is a separate check.
use crate::algorithm::{
    Algorithm, CipherSuite as C, KxGroup as K, MacAlgorithm, SignatureAlgorithm as S,
    TlsSignatureScheme as T, TlsVersion as V,
};
use crate::capability::{Module, capability};
use crate::error::{CryptoError, Family};
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
    /// profile. A transition profile for CNSA 1.0 counterparts. Not every RFC 9151 requirement is
    /// met: `docs/profiles.md` names the algorithm gaps (the `cnsa1` entry in section 3, sections 4
    /// and 5), and the RFC 8603 certificate profile that §5.4 requires is not implemented.
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

/// Options applied on top of any profile. The default changes nothing; `cnsa1_unclassified_nss`
/// widens `cnsa1`'s MACs, and the others narrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Options {
    /// Keep only post-quantum key exchange (pure ML-KEM and hybrid groups), and so remove TLS 1.2,
    /// which has none. Signatures are not narrowed.
    pub pq_key_exchange_required: bool,
    /// Require peer leaf keys and certification paths to match the profile. Off by default.
    pub peer_certificates_match_profile: bool,
    /// Admit HMAC-SHA256 under `cnsa1`, as CNSSP 15 (20 October 2016) Annex B ¶2b (p. B-2) allows
    /// in the near term for UNCLASSIFIED NSS data and community-of-interest separation only.
    /// Ignored by every other profile, and by every family but message authentication. Off by
    /// default.
    pub cnsa1_unclassified_nss: bool,
}

impl fmt::Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = [
            (
                self.pq_key_exchange_required,
                "post-quantum key exchange required",
            ),
            (
                self.peer_certificates_match_profile,
                "peer certificates match profile",
            ),
            (self.cnsa1_unclassified_nss, "cnsa1 UNCLASSIFIED NSS"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect();
        if names.is_empty() {
            f.write_str("no options")
        } else {
            f.write_str(&names.join(", "))
        }
    }
}

/// A profile's contents, each list in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSpec {
    /// Protocol versions.
    pub versions: &'static [V],
    /// Cipher suites.
    pub cipher_suites: &'static [C],
    /// Key-exchange groups.
    pub kx_groups: &'static [K],
    /// Handshake signature schemes accepted from the peer.
    pub signature_schemes: &'static [T],
    /// Key algorithms the profile admits for keys generated or used under it.
    pub key_algorithms: &'static [S],
    /// Message authentication codes, for `hmac`; admitted through `admit`, not `resolve`.
    pub macs: &'static [MacAlgorithm],
}

impl Profile {
    /// The profile's contents. Each entry's source is cited on the constant it comes from.
    pub const fn spec(self) -> &'static ProfileSpec {
        match self {
            Profile::Unrestricted => &UNRESTRICTED,
            Profile::Preferred => &PREFERRED,
            Profile::Cnsa2 => &CNSA2,
            Profile::Cnsa1 => &CNSA1,
            Profile::Bsi => &BSI,
            Profile::Fips1403 => &FIPS1403,
            Profile::Fips1402 => &FIPS1402,
        }
    }
}

/// `unrestricted`: the crate's own set, following no published text. Not a government profile.
///
/// - Versions: TLS 1.3, TLS 1.2. Suites: all nine. Groups: all seven. Schemes: all eleven. Keys:
///   all nine (`crypto_profile::algorithm`, each family's `ALL`).
/// - MACs: every HMAC in the inventory.
pub const UNRESTRICTED: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13, V::Tls12],
    cipher_suites: &[
        C::Tls13Aes256GcmSha384,
        C::Tls13Aes128GcmSha256,
        C::Tls13Chacha20Poly1305Sha256,
        C::Tls12EcdheEcdsaAes256GcmSha384,
        C::Tls12EcdheRsaAes256GcmSha384,
        C::Tls12EcdheEcdsaAes128GcmSha256,
        C::Tls12EcdheRsaAes128GcmSha256,
        C::Tls12EcdheEcdsaChacha20Poly1305Sha256,
        C::Tls12EcdheRsaChacha20Poly1305Sha256,
    ],
    kx_groups: &[
        K::MlKem1024,
        K::Secp384r1MlKem1024,
        K::X25519MlKem768,
        K::Secp256r1MlKem768,
        K::Secp384r1,
        K::Secp256r1,
        K::X25519,
    ],
    signature_schemes: &[
        T::MlDsa87,
        T::EcdsaNistp384Sha384,
        T::EcdsaNistp256Sha256,
        T::EcdsaNistp521Sha512,
        T::Ed25519,
        T::RsaPssSha384,
        T::RsaPssSha512,
        T::RsaPssSha256,
        T::RsaPkcs1Sha384,
        T::RsaPkcs1Sha512,
        T::RsaPkcs1Sha256,
    ],
    key_algorithms: &[
        S::MlDsa87,
        S::EcdsaP384Sha384,
        S::EcdsaP256Sha256,
        S::EcdsaP521Sha512,
        S::EcdsaP521Sha384,
        S::Ed25519,
        S::Rsa3072Sha384,
        S::Rsa4096Sha384,
        S::Rsa2048Sha384,
    ],
    macs: &[
        MacAlgorithm::HmacSha512,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha256,
    ],
};

/// `preferred`: the crate's recommendation. Not a government profile; see `docs/profiles.md`.
///
/// "ISM" is ASD, *Information security manual, Guidelines for cryptography*, September 2026;
/// SECRET-level controls ISM-1761 and ISM-1763 (p. 8), ISM-1765 (p. 10), ISM-1769 (p. 11).
/// - TLS 1.3 only: ISM-1139, p. 19.
/// - TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256: ISM-1369, p. 20; ISM-1769, p. 11.
/// - ML-KEM-1024: ISM-1995, p. 10.
/// - SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768: ISM p. 12; ISM-1996, p. 13; FIPS 140-3 IG D.S
///   Scenario 2 and Additional Comment 8a (August 2026, pp. 223-226), which names all three.
/// - secp384r1, secp256r1: ISM-0474 and ISM-1761, p. 8; ISM-1446, p. 7.
/// - X25519 on its own excluded: FIPS 140-3 IG C.K Resolution 5 (p. 160).
/// - ChaCha20-Poly1305 excluded: ISM p. 6; SP 800-140Cr2 §6.1.
/// - Schemes ML-DSA-87 (ISM-1991, p. 9), ECDSA P-384, P-256, P-521 (ISM-1763, p. 8), RSA-PSS
///   with SHA-2 (ISM-1765, p. 10; ISM-1374, p. 20).
/// - Ed25519 excluded: ISM pp. 5-6.
/// - RSA PKCS#1 v1.5 schemes excluded: RFC 8446 §4.2.3.
/// - Keys ML-DSA-87 (ISM-1991, p. 9), ECDSA P-384, P-256, P-521 (ISM-1763, p. 8), RSA 3072 and
///   4096 (ISM-1765, p. 10); RSA 2048 excluded: ISM-1765, p. 10.
/// - ECDSA P-521 with SHA-384: ISM-1763, p. 8; SHA-2 output of at least 256 bits, ISM-1767,
///   p. 11.
/// - MACs: HMAC with SHA-2 for IPsec and TLS, ISM-1772 (p. 15), ISM-0998 (p. 16) and ISM-1375
///   (p. 20); SHA-2 output of at least 224 bits, ISM-1766 (p. 11). HMAC-SHA256 "will not be
///   approved beyond 2030" (pp. 15-16).
pub const PREFERRED: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13],
    cipher_suites: &[C::Tls13Aes256GcmSha384, C::Tls13Aes128GcmSha256],
    kx_groups: &[
        K::MlKem1024,
        K::Secp384r1MlKem1024,
        K::X25519MlKem768,
        K::Secp256r1MlKem768,
        K::Secp384r1,
        K::Secp256r1,
    ],
    signature_schemes: &[
        T::MlDsa87,
        T::EcdsaNistp384Sha384,
        T::EcdsaNistp256Sha256,
        T::EcdsaNistp521Sha512,
        T::RsaPssSha384,
        T::RsaPssSha512,
        T::RsaPssSha256,
    ],
    key_algorithms: &[
        S::MlDsa87,
        S::EcdsaP384Sha384,
        S::EcdsaP256Sha256,
        S::EcdsaP521Sha512,
        S::EcdsaP521Sha384,
        S::Rsa3072Sha384,
        S::Rsa4096Sha384,
    ],
    macs: &[
        MacAlgorithm::HmacSha512,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha256,
    ],
};

/// `cnsa2`: the CNSA 2.0 algorithm set of CNSSP 15 (December 2024), Annex B, pp. B-1 to B-2, on
/// TLS 1.3. No CNSA 2.0 TLS profile is published: CNSSP 15 ¶8a, footnote 1 (p. 5).
/// - ML-KEM-1024: Annex B ¶1 table, p. B-1.
/// - ML-DSA-87 scheme and key: Annex B ¶1 table, p. B-1.
/// - TLS_AES_256_GCM_SHA384: Annex B ¶1 table, p. B-1.
/// - TLS 1.3 only: ML-KEM-1024 is the set's only key establishment (Annex B ¶1 table, p. B-1);
///   TLS 1.2 key exchange is ECDHE or FFDHE (RFC 8422, RFC 7919).
/// - MACs: hash "SHA-384 or SHA-512", Annex B p. B-1; protocol guidance RFC 9206 and RFC 9151,
///   ¶8a and fn. 1 (p. 5); RFC 9206 §4 (SHA-384 "for all purposes") and §8 (PRF_HMAC_SHA2_384 or
///   PRF_HMAC_SHA2_512 only).
pub const CNSA2: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13],
    cipher_suites: &[C::Tls13Aes256GcmSha384],
    kx_groups: &[K::MlKem1024],
    signature_schemes: &[T::MlDsa87],
    key_algorithms: &[S::MlDsa87],
    macs: &[MacAlgorithm::HmacSha384, MacAlgorithm::HmacSha512],
};

/// `cnsa1`: the CNSA 1.0 algorithm set of CNSSP 15 (20 October 2016), Annex B (p. B-1), in the
/// TLS 1.2 and 1.3 profile of RFC 9151 (April 2022). Transition dates: CNSSP 15 (December 2024)
/// ¶18 (pp. 7-8).
/// - AES-256, ECDH and ECDSA on P-384, SHA-384, RSA of at least 3072 bits: CNSSP 15 (2016)
///   Annex B ¶1 table, p. B-1.
/// - TLS 1.3 and 1.2: RFC 9151 §5. The § references below are RFC 9151's.
/// - TLS_AES_256_GCM_SHA384: §7.
/// - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: §6.
/// - secp384r1: §5.1, §7.
/// - ecdsa_secp384r1_sha384: §6.2, §7.1. rsa_pss_rsae_sha384: §6.2, §7.1. rsa_pkcs1_sha384:
///   §6.2; TLS 1.2 only, §7.1.
/// - Keys ECDSA P-384 with SHA-384 (§5.1); RSA 3072 and 4096 (§5.2).
/// - Not implemented by the stack: TLS_RSA_WITH_AES_256_GCM_SHA384 and
///   TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (§6), ffdhe3072 and ffdhe4096 (§5.3, §7).
/// - MACs: hash "Use SHA-384", Annex B p. B-1; RFC 9151 §4 (SHA-384 for the TLS 1.2 PRF and the
///   TLS 1.3 HKDF). `Options::cnsa1_unclassified_nss` adds HMAC-SHA256 under ¶2b (p. B-2).
pub const CNSA1: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13, V::Tls12],
    cipher_suites: &[
        C::Tls13Aes256GcmSha384,
        C::Tls12EcdheEcdsaAes256GcmSha384,
        C::Tls12EcdheRsaAes256GcmSha384,
    ],
    kx_groups: &[K::Secp384r1],
    signature_schemes: &[T::EcdsaNistp384Sha384, T::RsaPssSha384, T::RsaPkcs1Sha384],
    key_algorithms: &[S::EcdsaP384Sha384, S::Rsa3072Sha384, S::Rsa4096Sha384],
    macs: &[MacAlgorithm::HmacSha384],
};

/// `bsi`: BSI TR-02102-2 (TLS) and TR-02102-1, version 2026-01.
/// - TLS 1.3 and TLS 1.2: TR-02102-2 §3.2, Table 2.
/// - TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256: TR-02102-2 §3.4.4, Table 13.
/// - ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM and AES-256-GCM: TR-02102-2 §3.3.1.1, Table 3.
/// - secp384r1, secp256r1: TR-02102-2 Table 10 (TLS 1.3) and Table 6 (TLS 1.2).
/// - ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256, ecdsa_secp521r1_sha512 and rsa_pss_rsae
///   with SHA-384, 512, 256: TR-02102-2 §3.4.3, Table 11; for TLS 1.2, the Table 7 note.
/// - rsa_pkcs1_* excluded: TR-02102-2 Table 7 and Table 12 notes.
/// - Keys ECDSA P-384/SHA-384, P-256/SHA-256, P-521/SHA-512: TR-02102-2 Table 12 and Table 14.
/// - RSA keys excluded: TR-02102-2 Table 12.
/// - ML-DSA excluded: TR-02102-1 §5.3.4.
/// - Hybrid groups excluded: TR-02102-2 Table 10 note.
/// - MACs: HMAC with a Table 4.1 hash (TR-02102-1 §5.2, pp. 49-50; Table 4.1, p. 47).
pub const BSI: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13, V::Tls12],
    cipher_suites: &[
        C::Tls13Aes256GcmSha384,
        C::Tls13Aes128GcmSha256,
        C::Tls12EcdheEcdsaAes256GcmSha384,
        C::Tls12EcdheRsaAes256GcmSha384,
        C::Tls12EcdheEcdsaAes128GcmSha256,
        C::Tls12EcdheRsaAes128GcmSha256,
    ],
    kx_groups: &[K::Secp384r1, K::Secp256r1],
    signature_schemes: &[
        T::EcdsaNistp384Sha384,
        T::EcdsaNistp256Sha256,
        T::EcdsaNistp521Sha512,
        T::RsaPssSha384,
        T::RsaPssSha512,
        T::RsaPssSha256,
    ],
    key_algorithms: &[S::EcdsaP384Sha384, S::EcdsaP256Sha256, S::EcdsaP521Sha512],
    macs: &[
        MacAlgorithm::HmacSha512,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha256,
    ],
};

/// `fips1403`: NIST SP 800-140C r2 and SP 800-140D r2 with the CMVP lists (updated August 21,
/// 2026), the FIPS 140-3 Implementation Guidance (August 19, 2026), SP 800-52r2 and SP 800-131A
/// r2. An algorithm set, not a validation claim.
/// - TLS 1.3 and 1.2: SP 800-52r2 §3.1 (p. 8), §4.1 (p. 33). TLS 1.2 extended master secret
///   (RFC 7627): IG D.Q (pp. 220-221).
/// - TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256: SP 800-52r2 §3.3.1.2 (p. 19); CMVP
///   SP 800-140C list §6.2.2.1.
/// - ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM and AES-256-GCM: SP 800-52r2 §3.3.1.1.1-2
///   (pp. 16-17).
/// - ChaCha20-Poly1305 excluded: SP 800-140Cr2 §6.1; SP 800-52r2 §3.3.1.2.
/// - ML-KEM-1024: CMVP SP 800-140D list §6.2.10; IG D.S Scenario 1 (p. 223).
/// - SecP384r1MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768: IG D.S Scenario 2 and Additional
///   Comment 8a (pp. 223-226), the three IANA parameter sets it names.
/// - secp384r1, secp256r1: SP 800-56A r3 Appendix D, Table 24 (p. 132); SP 800-52r2 §3.4.2.2
///   (pp. 24-25).
/// - X25519 on its own excluded: IG C.K Resolution 5 (p. 160).
/// - ECDSA P-256, P-384, P-521 schemes and keys: SP 800-140C list §6.2.3.1; SP 800-186 Table 2
///   (p. 7); SP 800-131A r2 Table 2 (p. 9).
/// - ECDSA P-521 with SHA-384: FIPS 186-5 §6.4 (p. 23).
/// - Ed25519 scheme and key: SP 800-140C list §6.2.3.1; IG C.A (p. 136); IG C.K Additional
///   Comment 8 (p. 161).
/// - RSA-PSS and RSA PKCS#1 v1.5 with SHA-256, 384, 512: FIPS 186-5 §5.4; IG C.F (pp. 142-143);
///   PKCS#1 v1.5 on TLS 1.2 only, RFC 8446 §4.2.3.
/// - RSA 2048, 3072, 4096 keys: FIPS 186-5 §5.1; SP 800-131A r2 Table 2.
/// - ML-DSA-87 scheme and key: SP 800-140C list §6.2.3.1 (FIPS 204).
/// - MACs: FIPS 198-1 with SHA-2; SP 800-131A r2 Table 8 (p. 18) and Table 9 (p. 20).
pub const FIPS1403: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13, V::Tls12],
    cipher_suites: &[
        C::Tls13Aes256GcmSha384,
        C::Tls13Aes128GcmSha256,
        C::Tls12EcdheEcdsaAes256GcmSha384,
        C::Tls12EcdheRsaAes256GcmSha384,
        C::Tls12EcdheEcdsaAes128GcmSha256,
        C::Tls12EcdheRsaAes128GcmSha256,
    ],
    kx_groups: &[
        K::MlKem1024,
        K::Secp384r1MlKem1024,
        K::X25519MlKem768,
        K::Secp256r1MlKem768,
        K::Secp384r1,
        K::Secp256r1,
    ],
    signature_schemes: &[
        T::MlDsa87,
        T::EcdsaNistp384Sha384,
        T::EcdsaNistp256Sha256,
        T::EcdsaNistp521Sha512,
        T::Ed25519,
        T::RsaPssSha384,
        T::RsaPssSha512,
        T::RsaPssSha256,
        T::RsaPkcs1Sha384,
        T::RsaPkcs1Sha512,
        T::RsaPkcs1Sha256,
    ],
    key_algorithms: &[
        S::MlDsa87,
        S::EcdsaP384Sha384,
        S::EcdsaP256Sha256,
        S::EcdsaP521Sha512,
        S::EcdsaP521Sha384,
        S::Ed25519,
        S::Rsa3072Sha384,
        S::Rsa4096Sha384,
        S::Rsa2048Sha384,
    ],
    macs: &[
        MacAlgorithm::HmacSha512,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha256,
    ],
};

/// `fips1402`: FIPS 140-2 Annex A and Annex D (2021-10-12 editions), FIPS 186-4, SP 800-131A r2
/// and SP 800-52r2. An algorithm set, not a validation claim.
/// - TLS 1.3 and 1.2, and the AES-GCM suites: SP 800-52r2 §3.1, §3.3.1.1.1-2, §3.3.1.2; TLS 1.3
///   key schedule, Annex D item 11 (RFC 8446 §7.1).
/// - ChaCha20-Poly1305 excluded: Annex A.
/// - secp384r1, secp256r1: Annex D item 3 (SP 800-56A r3), Table 24.
/// - ML-KEM and the hybrids excluded: Annex A; Annex D items 12-13.
/// - X25519 excluded: SP 800-56A r3 Table 24.
/// - ECDSA P-256, P-384, P-521 schemes; RSA-PSS and PKCS#1 v1.5 with SHA-256, 384, 512: FIPS 186-4
///   (Annex A, p. 2), §5.4-5.5, Appendix D.1.2; SP 800-131A r2 Table 2 (p. 9).
/// - Ed25519 and ML-DSA excluded: Annex A.
/// - ECDSA keys P-384/SHA-384, P-256/SHA-256, P-521/SHA-512, P-521/SHA-384: FIPS 186-4 §6.4
///   (pp. 29-30).
/// - RSA 3072 and 2048 keys: FIPS 186-4 §5.1; RSA 4096: FIPS 140-2 IG A.14 (p. 221).
/// - MACs: FIPS 140-2 Annex A, Message Authentication 3 (p. 3); SP 800-131A r2 Table 9 (p. 20).
pub const FIPS1402: ProfileSpec = ProfileSpec {
    versions: &[V::Tls13, V::Tls12],
    cipher_suites: &[
        C::Tls13Aes256GcmSha384,
        C::Tls13Aes128GcmSha256,
        C::Tls12EcdheEcdsaAes256GcmSha384,
        C::Tls12EcdheRsaAes256GcmSha384,
        C::Tls12EcdheEcdsaAes128GcmSha256,
        C::Tls12EcdheRsaAes128GcmSha256,
    ],
    kx_groups: &[K::Secp384r1, K::Secp256r1],
    signature_schemes: &[
        T::EcdsaNistp384Sha384,
        T::EcdsaNistp256Sha256,
        T::EcdsaNistp521Sha512,
        T::RsaPssSha384,
        T::RsaPssSha512,
        T::RsaPssSha256,
        T::RsaPkcs1Sha384,
        T::RsaPkcs1Sha512,
        T::RsaPkcs1Sha256,
    ],
    key_algorithms: &[
        S::EcdsaP384Sha384,
        S::EcdsaP256Sha256,
        S::EcdsaP521Sha512,
        S::EcdsaP521Sha384,
        S::Rsa3072Sha384,
        S::Rsa4096Sha384,
        S::Rsa2048Sha384,
    ],
    macs: &[
        MacAlgorithm::HmacSha512,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha256,
    ],
};

/// A profile narrowed by its options, every entry implemented by the module's backend, in the
/// profile's preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Protocol versions.
    pub versions: Vec<V>,
    /// Cipher suites, each of a version in `versions`.
    pub cipher_suites: Vec<C>,
    /// Key-exchange groups.
    pub kx_groups: Vec<K>,
    /// Handshake signature schemes.
    pub signature_schemes: Vec<T>,
    /// Key algorithms.
    pub key_algorithms: Vec<S>,
    /// Entries unavailable on the module line after Options, in family and preference order.
    pub excluded: Vec<Algorithm>,
}

const fn is_tls12_only(t: T) -> bool {
    match t {
        T::RsaPkcs1Sha256 | T::RsaPkcs1Sha384 | T::RsaPkcs1Sha512 => true,
        T::EcdsaNistp256Sha256
        | T::EcdsaNistp384Sha384
        | T::EcdsaNistp521Sha512
        | T::Ed25519
        | T::RsaPssSha256
        | T::RsaPssSha384
        | T::RsaPssSha512
        | T::MlDsa87 => false,
    }
}

fn keep<X: Copy>(items: &[X], mut wanted: impl FnMut(X) -> bool) -> Vec<X> {
    items.iter().copied().filter(|x| wanted(*x)).collect()
}

/// The backend-independent half of a backend's `resolve`: `profile`'s lists, narrowed by
/// `options`; `pq_key_exchange_required` also removes TLS 1.2, its suites and the RSA PKCS#1 v1.5
/// handshake schemes. Records entries the module line lacks in [`Selection::excluded`], then
/// refuses a family left empty with [`CryptoError::EmptyProfile`]. Both use versions, suites,
/// groups, schemes and keys order, preserving preference order. Approval is a separate check.
pub fn select(
    profile: Profile,
    options: Options,
    module: Module,
) -> Result<Selection, CryptoError> {
    select_spec(profile, profile.spec(), options, module)
}

fn select_spec(
    profile: Profile,
    spec: &ProfileSpec,
    options: Options,
    module: Module,
) -> Result<Selection, CryptoError> {
    let pq = options.pq_key_exchange_required;
    let versions = keep(spec.versions, |v| !(pq && v == V::Tls12));
    let cipher_suites = keep(spec.cipher_suites, |c| versions.contains(&c.version()));
    let kx_groups = keep(spec.kx_groups, |k| !pq || k.is_post_quantum());
    let signature_schemes = keep(spec.signature_schemes, |t| !(pq && is_tls12_only(t)));
    let key_algorithms = spec.key_algorithms.to_vec();
    let mut excluded = Vec::new();
    let mut available = |a| {
        let on = capability(module, a).available;
        if !on {
            excluded.push(a);
        }
        on
    };
    let versions = keep(&versions, |v| available(Algorithm::Protocol(v)));
    let cipher_suites = keep(&cipher_suites, |c| available(Algorithm::Cipher(c)));
    let kx_groups = keep(&kx_groups, |k| available(Algorithm::Kx(k)));
    let signature_schemes = keep(&signature_schemes, |t| available(Algorithm::Scheme(t)));
    let key_algorithms = keep(&key_algorithms, |s| available(Algorithm::Signature(s)));
    for (empty, category) in [
        (versions.is_empty(), Family::Version),
        (cipher_suites.is_empty(), Family::CipherSuite),
        (kx_groups.is_empty(), Family::KxGroup),
        (signature_schemes.is_empty(), Family::SignatureScheme),
        (key_algorithms.is_empty(), Family::KeyAlgorithm),
    ] {
        if empty {
            return Err(CryptoError::EmptyProfile {
                profile,
                options,
                category,
            });
        }
    }
    Ok(Selection {
        versions,
        cipher_suites,
        kx_groups,
        signature_schemes,
        key_algorithms,
        excluded,
    })
}

/// A profile's non-TLS families under its options, every entry implemented by the module's
/// backend, in preference order. Never refused: an empty family means every constructor of that
/// family refuses under the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSelection {
    /// Message authentication codes.
    pub macs: Vec<MacAlgorithm>,
    /// Entries unavailable on the module line, in family and preference order.
    pub excluded: Vec<Algorithm>,
}

/// The backend-independent half of a backend's `admit`: `profile`'s non-TLS families, under
/// `options`, less what `module` lacks. Independent of [`select`].
pub fn select_admitted(profile: Profile, options: Options, module: Module) -> AdmittedSelection {
    select_admitted_with(profile, profile.spec(), options, |a| {
        capability(module, a).available
    })
}

fn select_admitted_with(
    profile: Profile,
    spec: &ProfileSpec,
    options: Options,
    available: impl Fn(Algorithm) -> bool,
) -> AdmittedSelection {
    let mut macs = spec.macs.to_vec();
    if options.cnsa1_unclassified_nss {
        macs.extend_from_slice(unclassified_nss_macs(profile));
    }
    let mut excluded = Vec::new();
    macs.retain(|m| {
        let on = available(Algorithm::Mac(*m));
        if !on {
            excluded.push(Algorithm::Mac(*m));
        }
        on
    });
    AdmittedSelection { macs, excluded }
}

const fn unclassified_nss_macs(p: Profile) -> &'static [MacAlgorithm] {
    match p {
        Profile::Cnsa1 => &[MacAlgorithm::HmacSha256],
        Profile::Unrestricted
        | Profile::Preferred
        | Profile::Cnsa2
        | Profile::Bsi
        | Profile::Fips1403
        | Profile::Fips1402 => &[],
    }
}

/// The shortest HMAC key, in bits, `profile` admits. 112 is the module's approved minimum: SP
/// 800-131A r2 §10 Table 9 (p. 20) disallows shorter keys for MAC generation, and the AWS-LC FIPS
/// 3.1.0 security policies list "Key Length: 112-524288" (Table 5, p. 9). `bsi` takes the 128 of
/// TR-02102-1 Table 5.2 (p. 50). SP 800-107 r1 §5.3.2 (pp. 13-14): a key "shall have a security
/// strength that meets or exceeds the security strength required to protect the data".
pub const fn mac_key_floor_bits(profile: Profile) -> usize {
    match profile {
        Profile::Bsi => 128,
        Profile::Unrestricted
        | Profile::Preferred
        | Profile::Cnsa2
        | Profile::Cnsa1
        | Profile::Fips1403
        | Profile::Fips1402 => 112,
    }
}

/// The longest HMAC key, in bits, the module was tested with: "Key Length: 112-524288" in the
/// AWS-LC FIPS 3.1.0 security policies (Table 5, p. 9) and on CAVP certificate A7855.
pub const MAC_KEY_MAX_BITS: usize = 524_288;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::*;
    use crate::capability::{Linkage, Module, ModuleLine};
    use crate::error::{CryptoError, Family};

    #[test]
    fn every_profile_lists_its_schemes_in_the_canonical_order() {
        assert_eq!(
            Profile::Unrestricted.spec().signature_schemes.len(),
            TlsSignatureScheme::ALL.len()
        );
        for p in Profile::ALL {
            let s = p.spec().signature_schemes;
            assert!(
                s.windows(2).all(|w| w[0].preference() < w[1].preference()),
                "{p}"
            );
        }
    }

    const M3S: Module = Module {
        line: ModuleLine::AwsLcFips3,
        linkage: Linkage::Static,
    };
    const M4S: Module = Module {
        line: ModuleLine::AwsLcFips4,
        linkage: Linkage::Static,
    };
    const PQ: Options = Options {
        peer_certificates_match_profile: false,
        pq_key_exchange_required: true,
        cnsa1_unclassified_nss: false,
    };
    const PKCS1: [TlsSignatureScheme; 3] = [
        TlsSignatureScheme::RsaPkcs1Sha256,
        TlsSignatureScheme::RsaPkcs1Sha384,
        TlsSignatureScheme::RsaPkcs1Sha512,
    ];

    fn no_duplicates<X: PartialEq + std::fmt::Debug>(xs: &[X]) {
        for (i, x) in xs.iter().enumerate() {
            assert!(!xs[i + 1..].contains(x), "{x:?} twice");
        }
    }

    #[test]
    fn every_spec_is_well_formed() {
        for p in Profile::ALL {
            let s = p.spec();
            no_duplicates(s.versions);
            no_duplicates(s.cipher_suites);
            no_duplicates(s.kx_groups);
            no_duplicates(s.signature_schemes);
            no_duplicates(s.key_algorithms);
            assert!(!s.versions.is_empty() && !s.kx_groups.is_empty(), "{p}");
            assert!(
                !s.signature_schemes.is_empty() && !s.key_algorithms.is_empty(),
                "{p}"
            );
            assert!(
                s.cipher_suites
                    .iter()
                    .all(|c| s.versions.contains(&c.version())),
                "{p}"
            );
            let has_pkcs1 = s.signature_schemes.iter().any(|t| PKCS1.contains(t));
            assert!(!has_pkcs1 || s.versions.contains(&TlsVersion::Tls12), "{p}");
        }
    }

    #[test]
    fn preferred_excludes_what_its_definition_names() {
        let s = Profile::Preferred.spec();
        assert_eq!(s.versions, &[TlsVersion::Tls13]);
        assert!(!s.kx_groups.contains(&KxGroup::X25519));
        assert!(
            !s.cipher_suites
                .contains(&CipherSuite::Tls13Chacha20Poly1305Sha256)
        );
        assert!(!s.signature_schemes.contains(&TlsSignatureScheme::Ed25519));
        assert!(!s.key_algorithms.contains(&SignatureAlgorithm::Ed25519));
    }

    #[test]
    fn bsi_admits_only_ecdsa_keys() {
        assert_eq!(
            Profile::Bsi.spec().key_algorithms,
            &[
                SignatureAlgorithm::EcdsaP384Sha384,
                SignatureAlgorithm::EcdsaP256Sha256,
                SignatureAlgorithm::EcdsaP521Sha512,
            ]
        );
    }

    #[test]
    fn select_records_line_exclusions_after_options() {
        for module in [
            M3S,
            Module {
                linkage: Linkage::Dynamic,
                ..M3S
            },
        ] {
            for p in [Profile::Unrestricted, Profile::Preferred, Profile::Fips1403] {
                for options in [Options::default(), PQ] {
                    let s = select(p, options, module).unwrap();
                    assert_eq!(
                        s.excluded,
                        vec![
                            Algorithm::Scheme(T::MlDsa87),
                            Algorithm::Signature(S::MlDsa87),
                        ]
                    );
                    no_duplicates(&s.excluded);
                    assert!(!s.signature_schemes.contains(&T::MlDsa87));
                    assert!(!s.key_algorithms.contains(&S::MlDsa87));
                }
            }
            for options in [Options::default(), PQ] {
                assert_eq!(
                    select(Profile::Cnsa2, options, module),
                    Err(CryptoError::EmptyProfile {
                        profile: Profile::Cnsa2,
                        options,
                        category: Family::SignatureScheme,
                    })
                );
            }
            for p in [Profile::Cnsa1, Profile::Bsi, Profile::Fips1402] {
                assert!(
                    select(p, Options::default(), module)
                        .unwrap()
                        .excluded
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn select_checks_keys_and_options_precede_line_emptiness() {
        const KEY_ONLY: ProfileSpec = ProfileSpec {
            signature_schemes: &[T::EcdsaNistp384Sha384],
            ..CNSA2
        };
        assert_eq!(
            select_spec(Profile::Cnsa2, &KEY_ONLY, Options::default(), M3S),
            Err(CryptoError::EmptyProfile {
                profile: Profile::Cnsa2,
                options: Options::default(),
                category: Family::KeyAlgorithm,
            })
        );
        const BSI_WITH_ML_DSA: ProfileSpec = ProfileSpec {
            signature_schemes: &[T::MlDsa87],
            ..BSI
        };
        for spec in [&BSI_WITH_ML_DSA, &BSI] {
            assert_eq!(
                select_spec(Profile::Bsi, spec, PQ, M3S),
                Err(CryptoError::EmptyProfile {
                    profile: Profile::Bsi,
                    options: PQ,
                    category: Family::KxGroup,
                })
            );
        }
    }

    #[test]
    fn select_refuses_each_empty_family_in_order() {
        const EMPTY: ProfileSpec = ProfileSpec {
            versions: &[],
            cipher_suites: &[],
            kx_groups: &[],
            signature_schemes: &[],
            key_algorithms: &[],
            macs: &[],
        };
        let empty = |category| {
            Err(CryptoError::EmptyProfile {
                profile: Profile::Bsi,
                options: Options::default(),
                category,
            })
        };
        let cases: [(ProfileSpec, Family); 5] = [
            (EMPTY, Family::Version),
            (
                ProfileSpec {
                    versions: BSI.versions,
                    ..EMPTY
                },
                Family::CipherSuite,
            ),
            (
                ProfileSpec {
                    kx_groups: &[],
                    signature_schemes: &[],
                    key_algorithms: &[],
                    ..BSI
                },
                Family::KxGroup,
            ),
            (
                ProfileSpec {
                    signature_schemes: &[],
                    key_algorithms: &[],
                    ..BSI
                },
                Family::SignatureScheme,
            ),
            (
                ProfileSpec {
                    key_algorithms: &[],
                    ..BSI
                },
                Family::KeyAlgorithm,
            ),
        ];
        for (spec, category) in cases {
            assert_eq!(
                select_spec(Profile::Bsi, &spec, Options::default(), M4S),
                empty(category),
                "{category:?}"
            );
        }
    }

    #[test]
    fn select_without_options_is_the_spec_on_a_module_that_has_everything() {
        for p in Profile::ALL {
            let s = select(p, Options::default(), M4S).unwrap();
            let spec = p.spec();
            assert!(s.excluded.is_empty());
            assert_eq!(s.versions, spec.versions.to_vec(), "{p}");
            assert_eq!(s.cipher_suites, spec.cipher_suites.to_vec(), "{p}");
            assert_eq!(s.kx_groups, spec.kx_groups.to_vec(), "{p}");
            assert_eq!(s.signature_schemes, spec.signature_schemes.to_vec(), "{p}");
            assert_eq!(s.key_algorithms, spec.key_algorithms.to_vec(), "{p}");
        }
    }

    #[test]
    fn the_option_keeps_post_quantum_groups_tls13_and_no_pkcs1_schemes() {
        for p in Profile::ALL {
            let refused = match p {
                Profile::Unrestricted | Profile::Preferred | Profile::Cnsa2 | Profile::Fips1403 => {
                    false
                }
                Profile::Cnsa1 | Profile::Bsi | Profile::Fips1402 => true,
            };
            match select(p, PQ, M4S) {
                Ok(s) => {
                    assert!(!refused, "{p}");
                    let spec = p.spec();
                    assert_eq!(s.versions, vec![TlsVersion::Tls13], "{p}");
                    let suites: Vec<_> = spec
                        .cipher_suites
                        .iter()
                        .copied()
                        .filter(|c| c.version() == TlsVersion::Tls13)
                        .collect();
                    assert_eq!(s.cipher_suites, suites, "{p}");
                    let groups: Vec<_> = spec
                        .kx_groups
                        .iter()
                        .copied()
                        .filter(|k| k.is_post_quantum())
                        .collect();
                    assert_eq!(s.kx_groups, groups, "{p}");
                    let schemes: Vec<_> = spec
                        .signature_schemes
                        .iter()
                        .copied()
                        .filter(|t| !PKCS1.contains(t))
                        .collect();
                    assert_eq!(s.signature_schemes, schemes, "{p}");
                    assert_eq!(s.key_algorithms, spec.key_algorithms.to_vec(), "{p}");
                }
                Err(e) => {
                    assert!(refused, "{p}");
                    assert_eq!(
                        e,
                        CryptoError::EmptyProfile {
                            profile: p,
                            options: PQ,
                            category: Family::KxGroup
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn the_option_removes_every_pkcs1_scheme_from_unrestricted_and_fips1403() {
        use TlsSignatureScheme as T;
        let expected = vec![
            T::MlDsa87,
            T::EcdsaNistp384Sha384,
            T::EcdsaNistp256Sha256,
            T::EcdsaNistp521Sha512,
            T::Ed25519,
            T::RsaPssSha384,
            T::RsaPssSha512,
            T::RsaPssSha256,
        ];
        for p in [Profile::Unrestricted, Profile::Fips1403] {
            assert_eq!(
                select(p, PQ, M4S).unwrap().signature_schemes,
                expected,
                "{p}"
            );
            assert_eq!(
                select(p, Options::default(), M4S)
                    .unwrap()
                    .signature_schemes
                    .len(),
                expected.len() + 3,
                "{p}"
            );
        }
    }

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
                peer_certificates_match_profile: false,
                pq_key_exchange_required: false,
                cnsa1_unclassified_nss: false,
            }
        );
        assert_eq!(Options::default().to_string(), "no options");
        assert_eq!(
            Options {
                peer_certificates_match_profile: false,
                pq_key_exchange_required: true,
                cnsa1_unclassified_nss: false,
            }
            .to_string(),
            "post-quantum key exchange required"
        );
    }
    #[test]
    fn peer_certificate_options_combinations_preserve_selection() {
        for (pq, peer, display) in [
            (false, false, "no options"),
            (true, false, "post-quantum key exchange required"),
            (false, true, "peer certificates match profile"),
            (
                true,
                true,
                "post-quantum key exchange required, peer certificates match profile",
            ),
        ] {
            let options = Options {
                pq_key_exchange_required: pq,
                peer_certificates_match_profile: peer,
                cnsa1_unclassified_nss: false,
            };
            assert_eq!(options.to_string(), display);
            for profile in Profile::ALL {
                for module in [M3S, M4S] {
                    let baseline = Options {
                        peer_certificates_match_profile: false,
                        ..options
                    };
                    let actual = select(profile, options, module);
                    let expected = select(profile, baseline, module);
                    match (actual, expected) {
                        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
                        (
                            Err(CryptoError::EmptyProfile {
                                profile: p,
                                options: o,
                                category: f,
                            }),
                            Err(CryptoError::EmptyProfile {
                                profile: ep,
                                options: eo,
                                category: ef,
                            }),
                        ) => {
                            assert_eq!((p, o, f), (ep, options, ef));
                            assert_eq!(eo, baseline);
                        }
                        (actual, expected) => panic!("{actual:?} != {expected:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn cnsa1_unclassified_nss_names_itself_and_leaves_tls_selection_alone() {
        let on = Options {
            cnsa1_unclassified_nss: true,
            ..Options::default()
        };
        assert_eq!(on.to_string(), "cnsa1 UNCLASSIFIED NSS");
        assert_eq!(
            Options {
                pq_key_exchange_required: true,
                peer_certificates_match_profile: true,
                cnsa1_unclassified_nss: true,
            }
            .to_string(),
            "post-quantum key exchange required, peer certificates match profile, cnsa1 UNCLASSIFIED NSS"
        );
        for profile in Profile::ALL {
            for module in [M3S, M4S] {
                for pq in [false, true] {
                    let off = Options {
                        pq_key_exchange_required: pq,
                        ..Options::default()
                    };
                    let on = Options {
                        cnsa1_unclassified_nss: true,
                        ..off
                    };
                    match (select(profile, on, module), select(profile, off, module)) {
                        (Ok(a), Ok(b)) => assert_eq!(a, b),
                        (
                            Err(CryptoError::EmptyProfile {
                                profile: p,
                                options: o,
                                category: f,
                            }),
                            Err(CryptoError::EmptyProfile {
                                profile: ep,
                                options: eo,
                                category: ef,
                            }),
                        ) => {
                            assert_eq!((p, f), (ep, ef));
                            assert_eq!((o, eo), (on, off));
                        }
                        (a, b) => panic!("{a:?} != {b:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn select_admitted_never_refuses_an_empty_family() {
        let spec = ProfileSpec { macs: &[], ..BSI };
        assert_eq!(
            select_admitted_with(Profile::Bsi, &spec, Options::default(), |_| true),
            AdmittedSelection {
                macs: vec![],
                excluded: vec![],
            }
        );
    }

    #[test]
    fn select_admitted_records_what_the_module_lacks() {
        use MacAlgorithm as M;
        assert_eq!(
            select_admitted_with(Profile::Fips1403, &FIPS1403, Options::default(), |a| {
                a != Algorithm::Mac(M::HmacSha384)
            }),
            AdmittedSelection {
                macs: vec![M::HmacSha512, M::HmacSha256],
                excluded: vec![Algorithm::Mac(M::HmacSha384)],
            }
        );
    }

    #[test]
    fn the_unclassified_nss_option_adds_hmac_sha256_to_cnsa1_only() {
        let on = Options {
            cnsa1_unclassified_nss: true,
            ..Options::default()
        };
        for p in Profile::ALL {
            let mut want = select_admitted(p, Options::default(), M4S).macs;
            if p == Profile::Cnsa1 {
                want.push(MacAlgorithm::HmacSha256);
            }
            assert_eq!(select_admitted(p, on, M4S).macs, want, "{p}");
        }
    }

    #[test]
    fn mac_keys_are_bounded_by_the_module_and_by_bsi() {
        for p in Profile::ALL {
            let floor = match p {
                Profile::Bsi => 128,
                Profile::Unrestricted
                | Profile::Preferred
                | Profile::Cnsa2
                | Profile::Cnsa1
                | Profile::Fips1403
                | Profile::Fips1402 => 112,
            };
            assert_eq!(mac_key_floor_bits(p), floor, "{p}");
        }
        assert_eq!(MAC_KEY_MAX_BITS, 524_288);
    }
}
