//! The algorithms the crate names: signature keys, TLS signature schemes, key-exchange groups,
//! cipher suites, hashes and TLS versions.
use std::fmt;
use std::str::FromStr;

/// A signature key algorithm: what a key is generated as, and what its CSR is signed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
    /// ECDSA on P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ECDSA on P-521 with SHA-384.
    EcdsaP521Sha384,
    /// ECDSA on P-521 with SHA-512.
    EcdsaP521Sha512,
    /// Ed25519 (FIPS 186-5 EdDSA).
    Ed25519,
    /// A 2048-bit RSA key; its CSR is signed RSASSA-PKCS1-v1_5 with SHA-384.
    Rsa2048Sha384,
    /// A 3072-bit RSA key; its CSR is signed RSASSA-PKCS1-v1_5 with SHA-384.
    Rsa3072Sha384,
    /// A 4096-bit RSA key; its CSR is signed RSASSA-PKCS1-v1_5 with SHA-384.
    Rsa4096Sha384,
}

impl SignatureAlgorithm {
    /// Every signature key algorithm.
    pub const ALL: [SignatureAlgorithm; 9] = [
        SignatureAlgorithm::MlDsa87,
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP521Sha384,
        SignatureAlgorithm::EcdsaP521Sha512,
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::Rsa2048Sha384,
        SignatureAlgorithm::Rsa3072Sha384,
        SignatureAlgorithm::Rsa4096Sha384,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            SignatureAlgorithm::MlDsa87 => 0,
            SignatureAlgorithm::EcdsaP256Sha256 => 1,
            SignatureAlgorithm::EcdsaP384Sha384 => 2,
            SignatureAlgorithm::EcdsaP521Sha384 => 3,
            SignatureAlgorithm::EcdsaP521Sha512 => 4,
            SignatureAlgorithm::Ed25519 => 5,
            SignatureAlgorithm::Rsa2048Sha384 => 6,
            SignatureAlgorithm::Rsa3072Sha384 => 7,
            SignatureAlgorithm::Rsa4096Sha384 => 8,
        }
    }

    /// The algorithm's stable configuration name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
            SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            SignatureAlgorithm::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            SignatureAlgorithm::EcdsaP521Sha384 => "ecdsa-p521-sha384",
            SignatureAlgorithm::EcdsaP521Sha512 => "ecdsa-p521-sha512",
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Rsa2048Sha384 => "rsa2048-sha384",
            SignatureAlgorithm::Rsa3072Sha384 => "rsa3072-sha384",
            SignatureAlgorithm::Rsa4096Sha384 => "rsa4096-sha384",
        }
    }

    /// The X.509 signature-algorithm OID a CSR or certificate signed by this key carries
    /// (RFC 5758, RFC 8410, RFC 4055, and draft-ietf-lamps-dilithium-certificates for ML-DSA).
    pub const fn signature_oid(self) -> &'static str {
        match self {
            SignatureAlgorithm::MlDsa87 => "2.16.840.1.101.3.4.3.19",
            SignatureAlgorithm::EcdsaP256Sha256 => "1.2.840.10045.4.3.2",
            SignatureAlgorithm::EcdsaP384Sha384 | SignatureAlgorithm::EcdsaP521Sha384 => {
                "1.2.840.10045.4.3.3"
            }
            SignatureAlgorithm::EcdsaP521Sha512 => "1.2.840.10045.4.3.4",
            SignatureAlgorithm::Ed25519 => "1.3.101.112",
            SignatureAlgorithm::Rsa2048Sha384
            | SignatureAlgorithm::Rsa3072Sha384
            | SignatureAlgorithm::Rsa4096Sha384 => "1.2.840.113549.1.1.12",
        }
    }

    /// The TLS signature scheme this crate pairs with a key of this algorithm: the scheme the key
    /// signs a handshake with when the peer offers this scheme alone.
    ///
    /// An ECDSA, Ed25519 or ML-DSA key has no other scheme. An RSA key's scheme comes from the
    /// peer's offer, whatever the key's CSR was signed with: rustls signs with the first of RSA-PSS
    /// with SHA-512, SHA-384 and SHA-256, then PKCS#1 v1.5 with SHA-512, SHA-384 and SHA-256, that
    /// the peer offers (`rustls-0.23.46/src/crypto/aws_lc_rs/sign.rs:104-111,137-142`), and TLS 1.3
    /// admits only the RSA-PSS ones (`src/enums.rs:554-579`). So an RSA key signs with RSA-PSS with
    /// SHA-384 only when the peer offers it and does not offer RSA-PSS with SHA-512.
    pub const fn tls_scheme(self) -> TlsSignatureScheme {
        match self {
            SignatureAlgorithm::MlDsa87 => TlsSignatureScheme::MlDsa87,
            SignatureAlgorithm::EcdsaP256Sha256 => TlsSignatureScheme::EcdsaNistp256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384 => TlsSignatureScheme::EcdsaNistp384Sha384,
            SignatureAlgorithm::EcdsaP521Sha384 | SignatureAlgorithm::EcdsaP521Sha512 => {
                TlsSignatureScheme::EcdsaNistp521Sha512
            }
            SignatureAlgorithm::Ed25519 => TlsSignatureScheme::Ed25519,
            SignatureAlgorithm::Rsa2048Sha384
            | SignatureAlgorithm::Rsa3072Sha384
            | SignatureAlgorithm::Rsa4096Sha384 => TlsSignatureScheme::RsaPssSha384,
        }
    }
}

/// A name that is not one of the crate's algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAlgorithmError(pub String);

impl fmt::Display for ParseAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown signature algorithm {:?}", self.0)
    }
}

impl std::error::Error for ParseAlgorithmError {}

impl FromStr for SignatureAlgorithm {
    type Err = ParseAlgorithmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignatureAlgorithm::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .ok_or_else(|| ParseAlgorithmError(s.to_string()))
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A TLS handshake signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsSignatureScheme {
    /// `ecdsa_secp256r1_sha256`.
    EcdsaNistp256Sha256,
    /// `ecdsa_secp384r1_sha384`.
    EcdsaNistp384Sha384,
    /// `ecdsa_secp521r1_sha512`.
    EcdsaNistp521Sha512,
    /// `ed25519`.
    Ed25519,
    /// `rsa_pss_rsae_sha256`.
    RsaPssSha256,
    /// `rsa_pss_rsae_sha384`.
    RsaPssSha384,
    /// `rsa_pss_rsae_sha512`.
    RsaPssSha512,
    /// `rsa_pkcs1_sha256`.
    RsaPkcs1Sha256,
    /// `rsa_pkcs1_sha384`.
    RsaPkcs1Sha384,
    /// `rsa_pkcs1_sha512`.
    RsaPkcs1Sha512,
    /// `mldsa87`.
    MlDsa87,
}

impl TlsSignatureScheme {
    /// The IANA TLS SignatureScheme codepoint.
    pub const fn iana(self) -> u16 {
        match self {
            TlsSignatureScheme::EcdsaNistp256Sha256 => 0x0403,
            TlsSignatureScheme::EcdsaNistp384Sha384 => 0x0503,
            TlsSignatureScheme::EcdsaNistp521Sha512 => 0x0603,
            TlsSignatureScheme::Ed25519 => 0x0807,
            TlsSignatureScheme::RsaPssSha256 => 0x0804,
            TlsSignatureScheme::RsaPssSha384 => 0x0805,
            TlsSignatureScheme::RsaPssSha512 => 0x0806,
            TlsSignatureScheme::RsaPkcs1Sha256 => 0x0401,
            TlsSignatureScheme::RsaPkcs1Sha384 => 0x0501,
            TlsSignatureScheme::RsaPkcs1Sha512 => 0x0601,
            TlsSignatureScheme::MlDsa87 => 0x0906,
        }
    }

    /// Every TLS signature scheme.
    pub const ALL: [TlsSignatureScheme; 11] = [
        TlsSignatureScheme::EcdsaNistp256Sha256,
        TlsSignatureScheme::EcdsaNistp384Sha384,
        TlsSignatureScheme::EcdsaNistp521Sha512,
        TlsSignatureScheme::Ed25519,
        TlsSignatureScheme::RsaPssSha256,
        TlsSignatureScheme::RsaPssSha384,
        TlsSignatureScheme::RsaPssSha512,
        TlsSignatureScheme::RsaPkcs1Sha256,
        TlsSignatureScheme::RsaPkcs1Sha384,
        TlsSignatureScheme::RsaPkcs1Sha512,
        TlsSignatureScheme::MlDsa87,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            TlsSignatureScheme::EcdsaNistp256Sha256 => 0,
            TlsSignatureScheme::EcdsaNistp384Sha384 => 1,
            TlsSignatureScheme::EcdsaNistp521Sha512 => 2,
            TlsSignatureScheme::Ed25519 => 3,
            TlsSignatureScheme::RsaPssSha256 => 4,
            TlsSignatureScheme::RsaPssSha384 => 5,
            TlsSignatureScheme::RsaPssSha512 => 6,
            TlsSignatureScheme::RsaPkcs1Sha256 => 7,
            TlsSignatureScheme::RsaPkcs1Sha384 => 8,
            TlsSignatureScheme::RsaPkcs1Sha512 => 9,
            TlsSignatureScheme::MlDsa87 => 10,
        }
    }
}

/// A TLS cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// `TLS_AES_256_GCM_SHA384`.
    Tls13Aes256GcmSha384,
    /// `TLS_AES_128_GCM_SHA256`.
    Tls13Aes128GcmSha256,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    Tls13Chacha20Poly1305Sha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    Tls12EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    Tls12EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    Tls12EcdheEcdsaChacha20Poly1305Sha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    Tls12EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    Tls12EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    Tls12EcdheRsaChacha20Poly1305Sha256,
}

impl CipherSuite {
    /// Every cipher suite.
    pub const ALL: [CipherSuite; 9] = [
        CipherSuite::Tls13Aes256GcmSha384,
        CipherSuite::Tls13Aes128GcmSha256,
        CipherSuite::Tls13Chacha20Poly1305Sha256,
        CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
        CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
        CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256,
        CipherSuite::Tls12EcdheRsaAes256GcmSha384,
        CipherSuite::Tls12EcdheRsaAes128GcmSha256,
        CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            CipherSuite::Tls13Aes256GcmSha384 => 0,
            CipherSuite::Tls13Aes128GcmSha256 => 1,
            CipherSuite::Tls13Chacha20Poly1305Sha256 => 2,
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384 => 3,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256 => 4,
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256 => 5,
            CipherSuite::Tls12EcdheRsaAes256GcmSha384 => 6,
            CipherSuite::Tls12EcdheRsaAes128GcmSha256 => 7,
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => 8,
        }
    }

    /// The IANA TLS Cipher Suite codepoint.
    pub const fn iana(self) -> u16 {
        match self {
            CipherSuite::Tls13Aes256GcmSha384 => 0x1302,
            CipherSuite::Tls13Aes128GcmSha256 => 0x1301,
            CipherSuite::Tls13Chacha20Poly1305Sha256 => 0x1303,
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384 => 0xC02C,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256 => 0xC02B,
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256 => 0xCCA9,
            CipherSuite::Tls12EcdheRsaAes256GcmSha384 => 0xC030,
            CipherSuite::Tls12EcdheRsaAes128GcmSha256 => 0xC02F,
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => 0xCCA8,
        }
    }

    /// The TLS version the suite belongs to.
    pub const fn version(self) -> TlsVersion {
        match self {
            CipherSuite::Tls13Aes256GcmSha384
            | CipherSuite::Tls13Aes128GcmSha256
            | CipherSuite::Tls13Chacha20Poly1305Sha256 => TlsVersion::Tls13,
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384
            | CipherSuite::Tls12EcdheEcdsaAes128GcmSha256
            | CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256
            | CipherSuite::Tls12EcdheRsaAes256GcmSha384
            | CipherSuite::Tls12EcdheRsaAes128GcmSha256
            | CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => TlsVersion::Tls12,
        }
    }
}

/// A TLS key-exchange group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KxGroup {
    /// ML-KEM-1024 (FIPS 203).
    MlKem1024,
    /// The X25519 + ML-KEM-768 hybrid.
    X25519MlKem768,
    /// The P-256 + ML-KEM-768 hybrid.
    Secp256r1MlKem768,
    /// ECDH on P-384.
    Secp384r1,
    /// ECDH on P-256.
    Secp256r1,
    /// X25519.
    X25519,
}

impl KxGroup {
    /// The IANA TLS Supported Groups codepoint.
    pub const fn iana(self) -> u16 {
        match self {
            KxGroup::MlKem1024 => 0x0202,
            KxGroup::X25519MlKem768 => 0x11EC,
            KxGroup::Secp256r1MlKem768 => 0x11EB,
            KxGroup::Secp384r1 => 0x0018,
            KxGroup::Secp256r1 => 0x0017,
            KxGroup::X25519 => 0x001D,
        }
    }

    /// Every key-exchange group.
    pub const ALL: [KxGroup; 6] = [
        KxGroup::MlKem1024,
        KxGroup::X25519MlKem768,
        KxGroup::Secp256r1MlKem768,
        KxGroup::Secp384r1,
        KxGroup::Secp256r1,
        KxGroup::X25519,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            KxGroup::MlKem1024 => 0,
            KxGroup::X25519MlKem768 => 1,
            KxGroup::Secp256r1MlKem768 => 2,
            KxGroup::Secp384r1 => 3,
            KxGroup::Secp256r1 => 4,
            KxGroup::X25519 => 5,
        }
    }
}

/// A hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Every hash function.
    pub const ALL: [HashAlgorithm; 3] = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 0,
            HashAlgorithm::Sha384 => 1,
            HashAlgorithm::Sha512 => 2,
        }
    }

    /// The digest length in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl TlsVersion {
    /// The TLS ProtocolVersion codepoint.
    pub const fn iana(self) -> u16 {
        match self {
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
        }
    }

    /// Every TLS version.
    pub const ALL: [TlsVersion; 2] = [TlsVersion::Tls12, TlsVersion::Tls13];

    /// The position of `self` in [`Self::ALL`].
    #[cfg(test)]
    pub(crate) const fn ordinal(self) -> usize {
        match self {
            TlsVersion::Tls12 => 0,
            TlsVersion::Tls13 => 1,
        }
    }
}

/// Any algorithm the capability table has a cell for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// A signature key algorithm.
    Signature(SignatureAlgorithm),
    /// A TLS signature scheme.
    Scheme(TlsSignatureScheme),
    /// A key-exchange group.
    Kx(KxGroup),
    /// A cipher suite.
    Cipher(CipherSuite),
    /// A hash function.
    Hash(HashAlgorithm),
    /// A TLS version.
    Protocol(TlsVersion),
}

impl Algorithm {
    /// Every algorithm, in family order.
    pub fn all() -> Vec<Algorithm> {
        let mut v = Vec::new();
        v.extend(SignatureAlgorithm::ALL.map(Algorithm::Signature));
        v.extend(TlsSignatureScheme::ALL.map(Algorithm::Scheme));
        v.extend(KxGroup::ALL.map(Algorithm::Kx));
        v.extend(CipherSuite::ALL.map(Algorithm::Cipher));
        v.extend(HashAlgorithm::ALL.map(Algorithm::Hash));
        v.extend(TlsVersion::ALL.map(Algorithm::Protocol));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_names_are_stable_and_round_trip() {
        assert_eq!(
            SignatureAlgorithm::ALL.map(SignatureAlgorithm::as_str),
            [
                "ml-dsa-87",
                "ecdsa-p256-sha256",
                "ecdsa-p384-sha384",
                "ecdsa-p521-sha384",
                "ecdsa-p521-sha512",
                "ed25519",
                "rsa2048-sha384",
                "rsa3072-sha384",
                "rsa4096-sha384",
            ]
        );
        for a in SignatureAlgorithm::ALL {
            assert_eq!(a.as_str().parse::<SignatureAlgorithm>().unwrap(), a);
            assert_eq!(a.to_string(), a.as_str());
        }
        assert_eq!(
            ParseAlgorithmError("p384".to_string()).to_string(),
            "unknown signature algorithm \"p384\""
        );
        for bad in [
            "",
            "p384",
            "ML-DSA-87",
            "ml-dsa-65",
            "rsa-2048",
            "ecdsa-p256-sha384",
        ] {
            assert_eq!(
                bad.parse::<SignatureAlgorithm>(),
                Err(ParseAlgorithmError(bad.to_string())),
                "{bad}"
            );
        }
    }

    #[test]
    fn every_key_algorithm_has_its_tls_scheme() {
        use SignatureAlgorithm as S;
        use TlsSignatureScheme as T;
        let table = [
            (S::MlDsa87, T::MlDsa87),
            (S::EcdsaP256Sha256, T::EcdsaNistp256Sha256),
            (S::EcdsaP384Sha384, T::EcdsaNistp384Sha384),
            (S::EcdsaP521Sha384, T::EcdsaNistp521Sha512),
            (S::EcdsaP521Sha512, T::EcdsaNistp521Sha512),
            (S::Ed25519, T::Ed25519),
            (S::Rsa2048Sha384, T::RsaPssSha384),
            (S::Rsa3072Sha384, T::RsaPssSha384),
            (S::Rsa4096Sha384, T::RsaPssSha384),
        ];
        assert_eq!(table.len(), SignatureAlgorithm::ALL.len());
        for (s, t) in table {
            assert_eq!(s.tls_scheme(), t, "{s}");
        }
    }

    #[test]
    fn cipher_suites_know_their_version() {
        use TlsVersion::{Tls12, Tls13};
        assert_eq!(
            CipherSuite::ALL.map(CipherSuite::version),
            [
                Tls13, Tls13, Tls13, Tls12, Tls12, Tls12, Tls12, Tls12, Tls12
            ]
        );
    }

    #[test]
    fn iana_codepoints_are_the_registry_values() {
        use CipherSuite as C;
        use KxGroup as K;
        use TlsSignatureScheme as T;
        assert_eq!(
            C::ALL.map(C::iana),
            [
                0x1302, 0x1301, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8
            ]
        );
        assert_eq!(
            K::ALL.map(K::iana),
            [0x0202, 0x11EC, 0x11EB, 0x0018, 0x0017, 0x001D]
        );
        assert_eq!(
            T::ALL.map(T::iana),
            [
                0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                0x0906
            ]
        );
        assert_eq!(TlsVersion::ALL.map(TlsVersion::iana), [0x0303, 0x0304]);
    }

    #[test]
    fn signature_oids_are_the_registry_values() {
        use SignatureAlgorithm as S;
        assert_eq!(
            S::ALL.map(S::signature_oid),
            [
                "2.16.840.1.101.3.4.3.19",
                "1.2.840.10045.4.3.2",
                "1.2.840.10045.4.3.3",
                "1.2.840.10045.4.3.3",
                "1.2.840.10045.4.3.4",
                "1.3.101.112",
                "1.2.840.113549.1.1.12",
                "1.2.840.113549.1.1.12",
                "1.2.840.113549.1.1.12",
            ]
        );
    }

    #[test]
    fn hash_lengths() {
        assert_eq!(
            HashAlgorithm::ALL.map(HashAlgorithm::output_len),
            [32, 48, 64]
        );
    }

    #[test]
    fn algorithm_all_is_every_variant_once() {
        let all = Algorithm::all();
        let expected = SignatureAlgorithm::ALL.len()
            + TlsSignatureScheme::ALL.len()
            + KxGroup::ALL.len()
            + CipherSuite::ALL.len()
            + HashAlgorithm::ALL.len()
            + TlsVersion::ALL.len();
        assert_eq!(all.len(), expected);
        assert_eq!(expected, 9 + 11 + 6 + 9 + 3 + 2);
        for (i, a) in all.iter().enumerate() {
            assert!(!all[i + 1..].contains(a), "{a:?} twice");
        }
    }

    #[test]
    fn signature_algorithm_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            SignatureAlgorithm::ALL.map(SignatureAlgorithm::ordinal),
            std::array::from_fn::<usize, 9, _>(|i| i)
        );
    }

    #[test]
    fn tls_signature_scheme_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            TlsSignatureScheme::ALL.map(TlsSignatureScheme::ordinal),
            std::array::from_fn::<usize, 11, _>(|i| i)
        );
    }

    #[test]
    fn cipher_suite_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            CipherSuite::ALL.map(CipherSuite::ordinal),
            std::array::from_fn::<usize, 9, _>(|i| i)
        );
    }

    #[test]
    fn kx_group_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            KxGroup::ALL.map(KxGroup::ordinal),
            std::array::from_fn::<usize, 6, _>(|i| i)
        );
    }

    #[test]
    fn hash_algorithm_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            HashAlgorithm::ALL.map(HashAlgorithm::ordinal),
            std::array::from_fn::<usize, 3, _>(|i| i)
        );
    }

    #[test]
    fn tls_version_all_lists_every_variant_in_ordinal_order() {
        assert_eq!(
            TlsVersion::ALL.map(TlsVersion::ordinal),
            std::array::from_fn::<usize, 2, _>(|i| i)
        );
    }
}
