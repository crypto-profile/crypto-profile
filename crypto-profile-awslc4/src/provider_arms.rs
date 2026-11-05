// Ported from rustls 0.23.46 (src/crypto/aws_lc_rs/sign.rs lines 322-448), Copyright (c) 2016
// Joseph Birr-Pixton, used under the MIT license. See LICENSE-THIRD-PARTY.
use crate::provider::verify::Verifier;
use aws_lc_rs::signature::{self, KeyPair as _, PqdsaKeyPair};
use rustls::pki_types::{
    PrivatePkcs8KeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, alg_id,
};
use rustls::sign::{Signer, SigningKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

static ML_DSA_44: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ML_DSA_44,
    signature_alg_id: alg_id::ML_DSA_44,
    verification_alg: &signature::ML_DSA_44,
};
static ML_DSA_65: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ML_DSA_65,
    signature_alg_id: alg_id::ML_DSA_65,
    verification_alg: &signature::ML_DSA_65,
};
static ML_DSA_87: &dyn SignatureVerificationAlgorithm = &Verifier {
    public_key_alg_id: alg_id::ML_DSA_87,
    signature_alg_id: alg_id::ML_DSA_87,
    verification_alg: &signature::ML_DSA_87,
};

const SCHEME: SignatureScheme = SignatureScheme::ML_DSA_87;

pub(crate) static PQDSA_ALL: &[&dyn SignatureVerificationAlgorithm] =
    &[ML_DSA_44, ML_DSA_65, ML_DSA_87];
pub(crate) static PQDSA_MAPPING: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] =
    &[(SignatureScheme::ML_DSA_87, &[ML_DSA_87])];

pub(crate) fn load_pqdsa(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Option<Arc<dyn SigningKey>> {
    PqdsaSigningKey::from_pkcs8(pkcs8).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
}

struct PqdsaSigningKey {
    inner: Arc<PqdsaKeyPair>,
}

impl PqdsaSigningKey {
    fn from_pkcs8(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Option<Self> {
        crate::backend_body::signature::ml_dsa_87_key(pkcs8.secret_pkcs8_der())
            .ok()
            .map(|key| Self {
                inner: Arc::new(crate::backend_arms::MlDsaKey::into_pair(key)),
            })
    }
}

impl SigningKey for PqdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if !offered.contains(&SCHEME) {
            return None;
        }

        Some(Box::new(PqdsaSigner {
            key: self.inner.clone(),
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &alg_id::ML_DSA_87,
            self.inner.public_key(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0)
    }
}

impl Debug for PqdsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqdsaSigningKey")
            .field("scheme", &SCHEME)
            .finish_non_exhaustive()
    }
}

struct PqdsaSigner {
    key: Arc<PqdsaKeyPair>,
}

impl Signer for PqdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let expected_sig_len = self.key.algorithm().signature_len();
        let mut sig = vec![0; expected_sig_len];
        let actual_sig_len = self
            .key
            .sign(message, &mut sig)
            .map_err(|_| Error::General("signing failed".into()))?;

        if actual_sig_len != expected_sig_len {
            return Err(Error::General("unexpected signature length".into()));
        }

        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

impl Debug for PqdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqdsaSigner")
            .field("scheme", &SCHEME)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::PqdsaSigningAlgorithm;

    fn pkcs8(alg: &'static PqdsaSigningAlgorithm) -> PrivatePkcs8KeyDer<'static> {
        PrivatePkcs8KeyDer::from(
            PqdsaKeyPair::generate(alg)
                .unwrap()
                .to_pkcs8v1()
                .unwrap()
                .as_ref()
                .to_vec(),
        )
    }

    #[test]
    fn an_ml_dsa_87_key_loads_and_signs_only_with_its_own_scheme() {
        let der = pkcs8(&signature::ML_DSA_87_SIGNING);
        let pair = PqdsaKeyPair::from_pkcs8(&signature::ML_DSA_87_SIGNING, der.secret_pkcs8_der())
            .unwrap();
        let key = load_pqdsa(&der).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::Unknown(0));
        assert_eq!(
            key.public_key(),
            Some(public_key_to_spki(&alg_id::ML_DSA_87, pair.public_key()))
        );
        assert_eq!(
            format!("{key:?}"),
            "PqdsaSigningKey { scheme: ML_DSA_87, .. }"
        );
        assert!(
            key.choose_scheme(&[SignatureScheme::ML_DSA_44, SignatureScheme::ML_DSA_65])
                .is_none()
        );
        let signer = key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ML_DSA_87,
            ])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ML_DSA_87);
        assert_eq!(
            format!("{signer:?}"),
            "PqdsaSigner { scheme: ML_DSA_87, .. }"
        );
        let sig = signer.sign(b"message").unwrap();
        assert!(
            signature::UnparsedPublicKey::new(&signature::ML_DSA_87, pair.public_key().as_ref())
                .verify(b"message", &sig)
                .is_ok()
        );
    }

    #[test]
    fn an_ml_dsa_44_or_65_key_is_not_loaded() {
        for alg in [&signature::ML_DSA_44_SIGNING, &signature::ML_DSA_65_SIGNING] {
            assert!(load_pqdsa(&pkcs8(alg)).is_none());
        }
    }

    #[test]
    fn a_key_that_is_not_ml_dsa_is_not_loaded() {
        let k = crate::test_support::key_pair(crypto_profile::SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap();
        assert!(
            load_pqdsa(&PrivatePkcs8KeyDer::from(
                k.to_pkcs8_der().unwrap().to_vec()
            ))
            .is_none()
        );
        assert!(load_pqdsa(&PrivatePkcs8KeyDer::from(b"x".to_vec())).is_none());
    }

    #[test]
    fn the_ml_dsa_verifiers_carry_their_identifiers_and_only_ml_dsa_87_is_mapped() {
        let ids =
            |a: &dyn SignatureVerificationAlgorithm| (a.public_key_alg_id(), a.signature_alg_id());
        assert_eq!(
            PQDSA_ALL.iter().map(|a| ids(*a)).collect::<Vec<_>>(),
            [
                (alg_id::ML_DSA_44, alg_id::ML_DSA_44),
                (alg_id::ML_DSA_65, alg_id::ML_DSA_65),
                (alg_id::ML_DSA_87, alg_id::ML_DSA_87),
            ]
        );
        assert_eq!(PQDSA_MAPPING.len(), 1);
        let (scheme, algs) = PQDSA_MAPPING[0];
        assert_eq!(scheme, SignatureScheme::ML_DSA_87);
        assert_eq!(
            algs.iter().map(|a| ids(*a)).collect::<Vec<_>>(),
            [(alg_id::ML_DSA_87, alg_id::ML_DSA_87)]
        );
    }

    #[test]
    fn an_ml_dsa_87_signature_verifies_and_a_flipped_one_does_not() {
        let k = crate::test_support::key_pair(crypto_profile::SignatureAlgorithm::MlDsa87).unwrap();
        let pk = k.public_key();
        let sig = k.sign(b"m").unwrap();
        assert!(ML_DSA_87.verify_signature(pk, b"m", &sig).is_ok());
        let mut flipped = sig.clone();
        if let Some(b) = flipped.last_mut() {
            *b ^= 1;
        }
        assert!(ML_DSA_87.verify_signature(pk, b"m", &flipped).is_err());
    }
}
