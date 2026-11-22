// Ported from rustls-webpki 0.103.17 (src/aws_lc_rs_algs.rs), Copyright 2015 Brian Smith, ISC
// license, and rustls 0.23.46 (src/crypto/aws_lc_rs/mod.rs), Copyright (c) 2016 Joseph
// Birr-Pixton, MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::signature;
use rustls::SignatureScheme;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

#[derive(Debug)]
pub(crate) struct Verifier {
    pub(crate) scheme: Option<crypto_profile::TlsSignatureScheme>,
    pub(crate) public_key_alg_id: AlgorithmIdentifier,
    pub(crate) signature_alg_id: AlgorithmIdentifier,
    pub(crate) verification_alg: &'static dyn signature::VerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for Verifier {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let is_ec = matches!(
            self.public_key_alg_id,
            alg_id::ECDSA_P256 | alg_id::ECDSA_P384 | alg_id::ECDSA_P521
        );
        if is_ec && !matches!(public_key.first(), Some(0x02..=0x04)) {
            return Err(InvalidSignature);
        }
        signature::UnparsedPublicKey::new(self.verification_alg, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn fips(&self) -> bool {
        fips_given(crate::MODULE, self.scheme, super::assembly::fips())
    }
}

pub(crate) fn refused_on(
    m: crypto_profile::Module,
    scheme: Option<crypto_profile::TlsSignatureScheme>,
) -> bool {
    scheme.is_some_and(|t| {
        matches!(
            crypto_profile::capability(m, crypto_profile::Algorithm::Scheme(t)).approval,
            crypto_profile::Approval::NotApproved { .. }
        )
    })
}

pub(crate) fn fips_given(
    m: crypto_profile::Module,
    scheme: Option<crypto_profile::TlsSignatureScheme>,
    mode: bool,
) -> bool {
    mode && !refused_on(m, scheme)
}

pub(crate) fn chain(
    m: crypto_profile::Module,
    verifiers: &[&'static Verifier],
) -> Vec<&'static dyn SignatureVerificationAlgorithm> {
    verifiers
        .iter()
        .copied()
        .filter(|v| !refused_on(m, v.scheme))
        .map(|v| v as &'static dyn SignatureVerificationAlgorithm)
        .collect()
}

pub(crate) static ECDSA_P256_SHA256: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp256Sha256),
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

pub(crate) static ECDSA_P256_SHA384: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp384Sha384),
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

pub(crate) static ECDSA_P256_SHA512: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp521Sha512),
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P256_SHA512_ASN1,
};

pub(crate) static ECDSA_P384_SHA256: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp256Sha256),
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

pub(crate) static ECDSA_P384_SHA384: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp384Sha384),
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

pub(crate) static ECDSA_P384_SHA512: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp521Sha512),
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P384_SHA512_ASN1,
};

pub(crate) static ECDSA_P521_SHA256: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp256Sha256),
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P521_SHA256_ASN1,
};

pub(crate) static ECDSA_P521_SHA384: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp384Sha384),
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P521_SHA384_ASN1,
};

pub(crate) static ECDSA_P521_SHA512: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::EcdsaNistp521Sha512),
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P521_SHA512_ASN1,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA256: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha256),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA384: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha384),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA512: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha512),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

const RSA_PKCS1_SHA256_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
const RSA_PKCS1_SHA384_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
]);
const RSA_PKCS1_SHA512_ABSENT_PARAMS: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
]);

pub(crate) static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha256),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA256_ABSENT_PARAMS,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha384),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA384_ABSENT_PARAMS,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPkcs1Sha512),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA512_ABSENT_PARAMS,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

pub(crate) static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPssSha256),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
};

pub(crate) static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPssSha384),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
};

pub(crate) static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::RsaPssSha512),
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
};

pub(crate) static ED25519: &Verifier = &Verifier {
    scheme: Some(crypto_profile::TlsSignatureScheme::Ed25519),
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    verification_alg: &signature::ED25519,
};

pub(crate) static COMMON_ALL: &[&Verifier] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P256_SHA512,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ECDSA_P384_SHA512,
    ECDSA_P521_SHA256,
    ECDSA_P521_SHA384,
    ECDSA_P521_SHA512,
    ED25519,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
];

pub(crate) static COMMON_MAPPING: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] = &[
    (
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &[ECDSA_P384_SHA384, ECDSA_P256_SHA384, ECDSA_P521_SHA384],
    ),
    (
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &[ECDSA_P256_SHA256, ECDSA_P384_SHA256, ECDSA_P521_SHA256],
    ),
    (
        SignatureScheme::ECDSA_NISTP521_SHA512,
        &[ECDSA_P521_SHA512, ECDSA_P384_SHA512, ECDSA_P256_SHA512],
    ),
    (SignatureScheme::ED25519, &[ED25519]),
    (
        SignatureScheme::RSA_PSS_SHA512,
        &[RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA384,
        &[RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PSS_SHA256,
        &[RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA512,
        &[RSA_PKCS1_2048_8192_SHA512],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384,
        &[RSA_PKCS1_2048_8192_SHA384],
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256,
        &[RSA_PKCS1_2048_8192_SHA256],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::{Linkage, Module, ModuleLine, TlsSignatureScheme as T};

    #[test]
    fn every_static_carries_webpkis_algorithm_identifiers() {
        let table: [(
            &dyn SignatureVerificationAlgorithm,
            AlgorithmIdentifier,
            AlgorithmIdentifier,
        ); 19] = [
            (ECDSA_P256_SHA256, alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
            (ECDSA_P256_SHA384, alg_id::ECDSA_P256, alg_id::ECDSA_SHA384),
            (ECDSA_P256_SHA512, alg_id::ECDSA_P256, alg_id::ECDSA_SHA512),
            (ECDSA_P384_SHA256, alg_id::ECDSA_P384, alg_id::ECDSA_SHA256),
            (ECDSA_P384_SHA384, alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
            (ECDSA_P384_SHA512, alg_id::ECDSA_P384, alg_id::ECDSA_SHA512),
            (ECDSA_P521_SHA256, alg_id::ECDSA_P521, alg_id::ECDSA_SHA256),
            (ECDSA_P521_SHA384, alg_id::ECDSA_P521, alg_id::ECDSA_SHA384),
            (ECDSA_P521_SHA512, alg_id::ECDSA_P521, alg_id::ECDSA_SHA512),
            (ED25519, alg_id::ED25519, alg_id::ED25519),
            (
                RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA256,
            ),
            (
                RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA384,
            ),
            (
                RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA512,
            ),
            (
                RSA_PKCS1_2048_8192_SHA256,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA256,
            ),
            (
                RSA_PKCS1_2048_8192_SHA384,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA384,
            ),
            (
                RSA_PKCS1_2048_8192_SHA512,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA512,
            ),
            (
                RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                RSA_PKCS1_SHA256_ABSENT_PARAMS,
            ),
            (
                RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                RSA_PKCS1_SHA384_ABSENT_PARAMS,
            ),
            (
                RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
                alg_id::RSA_ENCRYPTION,
                RSA_PKCS1_SHA512_ABSENT_PARAMS,
            ),
        ];
        assert_eq!(table.len(), COMMON_ALL.len());
        for ((alg, pk, sig), listed) in table.iter().zip(COMMON_ALL) {
            assert_eq!(
                (alg.public_key_alg_id(), alg.signature_alg_id()),
                (*pk, *sig)
            );
            assert_eq!(
                (listed.public_key_alg_id(), listed.signature_alg_id()),
                (*pk, *sig)
            );
            assert_eq!(
                alg.fips(),
                !(crate::MODULE == M3S && *pk == alg_id::ED25519),
                "{pk:?} {sig:?}"
            );
        }
    }

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

    #[test]
    fn every_static_names_the_scheme_whose_cell_governs_it() {
        let want = [
            T::EcdsaNistp256Sha256,
            T::EcdsaNistp384Sha384,
            T::EcdsaNistp521Sha512,
            T::EcdsaNistp256Sha256,
            T::EcdsaNistp384Sha384,
            T::EcdsaNistp521Sha512,
            T::EcdsaNistp256Sha256,
            T::EcdsaNistp384Sha384,
            T::EcdsaNistp521Sha512,
            T::Ed25519,
            T::RsaPssSha256,
            T::RsaPssSha384,
            T::RsaPssSha512,
            T::RsaPkcs1Sha256,
            T::RsaPkcs1Sha384,
            T::RsaPkcs1Sha512,
            T::RsaPkcs1Sha256,
            T::RsaPkcs1Sha384,
            T::RsaPkcs1Sha512,
        ];
        assert_eq!(
            COMMON_ALL.iter().map(|v| v.scheme).collect::<Vec<_>>(),
            want.map(Some)
        );
    }

    #[test]
    fn every_mapped_verifier_carries_its_entrys_scheme() {
        use rustls::SignatureScheme as R;
        let literal = [
            (R::ECDSA_NISTP384_SHA384, T::EcdsaNistp384Sha384),
            (R::ECDSA_NISTP256_SHA256, T::EcdsaNistp256Sha256),
            (R::ECDSA_NISTP521_SHA512, T::EcdsaNistp521Sha512),
            (R::ED25519, T::Ed25519),
            (R::RSA_PSS_SHA512, T::RsaPssSha512),
            (R::RSA_PSS_SHA384, T::RsaPssSha384),
            (R::RSA_PSS_SHA256, T::RsaPssSha256),
            (R::RSA_PKCS1_SHA512, T::RsaPkcs1Sha512),
            (R::RSA_PKCS1_SHA384, T::RsaPkcs1Sha384),
            (R::RSA_PKCS1_SHA256, T::RsaPkcs1Sha256),
        ];
        assert_eq!(literal.len(), COMMON_MAPPING.len());
        let ids =
            |a: &dyn SignatureVerificationAlgorithm| (a.public_key_alg_id(), a.signature_alg_id());
        for ((scheme, verifiers), (r, t)) in COMMON_MAPPING.iter().zip(literal) {
            assert_eq!(*scheme, r);
            for v in *verifiers {
                let listed = COMMON_ALL
                    .iter()
                    .find(|c| ids(**c) == ids(*v))
                    .unwrap_or_else(|| panic!("{:?}", ids(*v)));
                assert_eq!(listed.scheme, Some(t), "{r:?}");
            }
        }
        let absent = [
            RSA_PKCS1_SHA256_ABSENT_PARAMS,
            RSA_PKCS1_SHA384_ABSENT_PARAMS,
            RSA_PKCS1_SHA512_ABSENT_PARAMS,
        ];
        for c in COMMON_ALL {
            let mapped = COMMON_MAPPING
                .iter()
                .any(|(_, vs)| vs.iter().any(|v| ids(*v) == ids(*c)));
            assert!(
                mapped || absent.contains(&c.signature_alg_id),
                "{:?}",
                ids(*c)
            );
        }
    }

    #[test]
    fn a_verifier_is_refused_only_where_its_cell_is_not_approved() {
        for m in [M3S, M3D, M4S, M4D] {
            assert!(!refused_on(m, None));
            for t in T::ALL {
                let want = matches!(
                    (m, t),
                    (M3S, T::Ed25519) | (M3S, T::MlDsa87) | (M3D, T::MlDsa87)
                );
                assert_eq!(refused_on(m, Some(*t)), want, "{m:?} {t:?}");
            }
        }
    }

    #[test]
    fn fips_is_the_mode_and_not_refused() {
        assert!(!fips_given(M3S, Some(T::Ed25519), true));
        assert!(fips_given(M3D, Some(T::Ed25519), true));
        assert!(fips_given(M4S, Some(T::Ed25519), true));
        assert!(fips_given(M3S, Some(T::EcdsaNistp384Sha384), true));
        assert!(fips_given(M3S, None, true));
        for m in [M3S, M3D, M4S, M4D] {
            assert!(!fips_given(m, Some(T::EcdsaNistp384Sha384), false));
            assert!(!fips_given(m, None, false));
        }
    }

    #[test]
    fn the_chain_list_drops_only_what_the_module_refuses_in_order() {
        let ids = |vs: &[&dyn SignatureVerificationAlgorithm]| {
            vs.iter()
                .map(|a| (a.public_key_alg_id(), a.signature_alg_id()))
                .collect::<Vec<_>>()
        };
        let all: Vec<_> = COMMON_ALL
            .iter()
            .map(|v| (v.public_key_alg_id, v.signature_alg_id))
            .collect();
        for m in [M3D, M4S, M4D] {
            assert_eq!(ids(&chain(m, COMMON_ALL)), all, "{m:?}");
        }
        let mut without = all.clone();
        without.retain(|id| *id != (alg_id::ED25519, alg_id::ED25519));
        assert_eq!(without.len(), all.len() - 1);
        assert_eq!(ids(&chain(M3S, COMMON_ALL)), without);
    }

    #[test]
    fn the_mapping_carries_the_inventory_schemes_in_rustls_order() {
        let codepoints: Vec<u16> = COMMON_MAPPING
            .iter()
            .map(|(s, _)| u16::from_be_bytes(s.to_array()))
            .collect();
        assert_eq!(
            codepoints,
            [
                0x0503, 0x0403, 0x0603, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401
            ]
        );
    }

    #[test]
    fn an_ecdsa_signature_verifies_and_a_flipped_one_or_a_bad_point_prefix_does_not() {
        let k = crate::test_support::key_pair(crypto_profile::SignatureAlgorithm::EcdsaP256Sha256)
            .unwrap();
        let pk = k.public_key().to_vec();
        let sig = k.sign(b"m").unwrap();
        assert!(ECDSA_P256_SHA256.verify_signature(&pk, b"m", &sig).is_ok());
        let mut flipped = sig.clone();
        if let Some(b) = flipped.last_mut() {
            *b ^= 1;
        }
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&pk, b"m", &flipped)
                .is_err()
        );
        let mut bad = pk.clone();
        bad[0] = 0x05;
        assert!(
            ECDSA_P256_SHA256
                .verify_signature(&bad, b"m", &sig)
                .is_err()
        );
    }
}
