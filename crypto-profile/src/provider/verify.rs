// Ported from rustls-webpki 0.103.16 (src/aws_lc_rs_algs.rs), Copyright 2015 Brian Smith, ISC
// license, and rustls 0.23.46 (src/crypto/aws_lc_rs/mod.rs), Copyright (c) 2016 Joseph
// Birr-Pixton, MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::signature;
use rustls::SignatureScheme;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

#[derive(Debug)]
pub(crate) struct Verifier {
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
        super::assembly::fips()
    }
}

pub(crate) static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

pub(crate) static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

pub(crate) static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P256_SHA512_ASN1,
};

pub(crate) static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

pub(crate) static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

pub(crate) static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P384_SHA512_ASN1,
};

pub(crate) static ECDSA_P521_SHA256: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P521_SHA256_ASN1,
};

pub(crate) static ECDSA_P521_SHA384: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P521_SHA384_ASN1,
};

pub(crate) static ECDSA_P521_SHA512: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ECDSA_P521,
    signature_alg_id: alg_id::ECDSA_SHA512,
    verification_alg: &signature::ECDSA_P521_SHA512_ASN1,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA256: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA384: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

pub(crate) static RSA_PKCS1_2048_8192_SHA512: &dyn SignatureVerificationAlgorithm = &Verifier {
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

pub(crate) static RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: RSA_PKCS1_SHA256_ABSENT_PARAMS,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
    };

pub(crate) static RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: RSA_PKCS1_SHA384_ABSENT_PARAMS,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
    };

pub(crate) static RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: RSA_PKCS1_SHA512_ABSENT_PARAMS,
        verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
    };

pub(crate) static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA256,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
    };

pub(crate) static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA384,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
    };

pub(crate) static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: &dyn SignatureVerificationAlgorithm =
    &Verifier {
        public_key_alg_id: alg_id::RSA_ENCRYPTION,
        signature_alg_id: alg_id::RSA_PSS_SHA512,
        verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
    };

pub(crate) static ED25519: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    verification_alg: &signature::ED25519,
};

pub(crate) static COMMON_ALL: &[&dyn SignatureVerificationAlgorithm] = &[
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
            assert!(alg.fips());
        }
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
        let k = crate::signature::KeyPair::generate(
            crypto_profile::SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();
        let pk = k.public_key();
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
