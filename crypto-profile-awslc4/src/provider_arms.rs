// Ported from rustls 0.23.46 (src/crypto/aws_lc_rs/sign.rs lines 322-448), Copyright (c) 2016
// Joseph Birr-Pixton, used under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::signature::{self, KeyPair as _, PqdsaKeyPair, PqdsaSigningAlgorithm};
use rustls::pki_types::{AlgorithmIdentifier, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, alg_id};
use rustls::sign::{Signer, SigningKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) fn load_pqdsa(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Option<Arc<dyn SigningKey>> {
    PqdsaSigningKey::from_pkcs8(pkcs8).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
}

struct PqdsaSigningKey {
    kind: PqdsaKeyKind,
    inner: Arc<PqdsaKeyPair>,
}

impl PqdsaSigningKey {
    fn from_pkcs8(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Option<Self> {
        PqdsaKeyKind::iter().find_map(|kind| {
            PqdsaKeyPair::from_pkcs8(kind.to_alg(), pkcs8.secret_pkcs8_der())
                .ok()
                .map(|key_pair| Self {
                    kind,
                    inner: Arc::new(key_pair),
                })
        })
    }
}

impl SigningKey for PqdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if !offered.contains(&self.kind.scheme()) {
            return None;
        }

        Some(Box::new(PqdsaSigner {
            key: self.inner.clone(),
            kind: self.kind,
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &self.kind.alg_id(),
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
            .field("scheme", &self.kind.scheme())
            .finish_non_exhaustive()
    }
}

struct PqdsaSigner {
    key: Arc<PqdsaKeyPair>,
    kind: PqdsaKeyKind,
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
        self.kind.scheme()
    }
}

impl Debug for PqdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqdsaSigner")
            .field("scheme", &self.kind.scheme())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum PqdsaKeyKind {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl PqdsaKeyKind {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87].into_iter()
    }

    fn to_alg(self) -> &'static PqdsaSigningAlgorithm {
        match self {
            Self::MlDsa44 => &signature::ML_DSA_44_SIGNING,
            Self::MlDsa65 => &signature::ML_DSA_65_SIGNING,
            Self::MlDsa87 => &signature::ML_DSA_87_SIGNING,
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
        }
    }

    fn alg_id(&self) -> AlgorithmIdentifier {
        match self {
            Self::MlDsa44 => alg_id::ML_DSA_44,
            Self::MlDsa65 => alg_id::ML_DSA_65,
            Self::MlDsa87 => alg_id::ML_DSA_87,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn every_ml_dsa_parameter_set_loads_and_signs_only_with_its_own_scheme() {
        let kinds = [
            (
                &signature::ML_DSA_44_SIGNING,
                &signature::ML_DSA_44,
                SignatureScheme::ML_DSA_44,
                alg_id::ML_DSA_44,
                "ML_DSA_44",
            ),
            (
                &signature::ML_DSA_65_SIGNING,
                &signature::ML_DSA_65,
                SignatureScheme::ML_DSA_65,
                alg_id::ML_DSA_65,
                "ML_DSA_65",
            ),
            (
                &signature::ML_DSA_87_SIGNING,
                &signature::ML_DSA_87,
                SignatureScheme::ML_DSA_87,
                alg_id::ML_DSA_87,
                "ML_DSA_87",
            ),
        ];
        for (signing, verify, scheme, spki, name) in kinds {
            let der = pkcs8(signing);
            let pair = PqdsaKeyPair::from_pkcs8(signing, der.secret_pkcs8_der()).unwrap();
            let key = load_pqdsa(&der).unwrap();
            assert_eq!(key.algorithm(), SignatureAlgorithm::Unknown(0));
            assert_eq!(
                key.public_key(),
                Some(public_key_to_spki(&spki, pair.public_key()))
            );
            assert_eq!(
                format!("{key:?}"),
                format!("PqdsaSigningKey {{ scheme: {name}, .. }}")
            );
            let others: Vec<SignatureScheme> =
                kinds.iter().map(|k| k.2).filter(|s| *s != scheme).collect();
            assert!(key.choose_scheme(&others).is_none(), "{name}");
            let signer = key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384, scheme])
                .unwrap();
            assert_eq!(signer.scheme(), scheme);
            assert_eq!(
                format!("{signer:?}"),
                format!("PqdsaSigner {{ scheme: {name}, .. }}")
            );
            let sig = signer.sign(b"message").unwrap();
            assert!(
                signature::UnparsedPublicKey::new(verify, pair.public_key().as_ref())
                    .verify(b"message", &sig)
                    .is_ok(),
                "{name}"
            );
        }
    }

    #[test]
    fn a_key_that_is_not_ml_dsa_is_not_loaded() {
        let k = crate::signature::KeyPair::generate(
            crypto_profile::SignatureAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();
        assert!(load_pqdsa(&PrivatePkcs8KeyDer::from(k.pkcs8_der().to_vec())).is_none());
        assert!(load_pqdsa(&PrivatePkcs8KeyDer::from(b"x".to_vec())).is_none());
    }
}
