// Ported from rustls 0.23.46 (src/crypto/aws_lc_rs/sign.rs), Copyright (c) 2016 Joseph
// Birr-Pixton, used under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use rustls::pki_types::{
    AlgorithmIdentifier, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer, alg_id,
};
use rustls::sign::{Signer, SigningKey, public_key_to_spki};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

pub(crate) fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(rsa) = RsaSigningKey::new(der) {
        return Ok(Arc::new(rsa));
    }

    if let Ok(ecdsa) = any_ecdsa_type(der) {
        return Ok(ecdsa);
    }

    if let PrivateKeyDer::Pkcs8(pkcs8) = der {
        if let Ok(eddsa) = any_eddsa_type(pkcs8) {
            return Ok(eddsa);
        }

        if let Some(pqdsa) = super::backend::load_pqdsa(pkcs8) {
            return Ok(pqdsa);
        }
    }

    Err(Error::General(
        "failed to parse private key as RSA, ECDSA, or EdDSA".into(),
    ))
}

fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    if let Ok(ecdsa_p256) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        alg_id::ECDSA_P256,
    ) {
        return Ok(Arc::new(ecdsa_p256));
    }

    if let Ok(ecdsa_p384) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        alg_id::ECDSA_P384,
    ) {
        return Ok(Arc::new(ecdsa_p384));
    }

    if let Ok(ecdsa_p521) = EcdsaSigningKey::new(
        der,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
        alg_id::ECDSA_P521,
    ) {
        return Ok(Arc::new(ecdsa_p521));
    }

    Err(Error::General(
        "failed to parse ECDSA private key as PKCS#8 or SEC1".into(),
    ))
}

fn any_eddsa_type(der: &PrivatePkcs8KeyDer<'_>) -> Result<Arc<dyn SigningKey>, Error> {
    Ok(Arc::new(Ed25519SigningKey::new(
        der,
        SignatureScheme::ED25519,
    )?))
}

pub(crate) struct RsaSigningKey {
    key: Arc<RsaKeyPair>,
}

static RSA_SCHEMES: [(SignatureScheme, &dyn signature::RsaEncoding); 6] = [
    (SignatureScheme::RSA_PSS_SHA512, &signature::RSA_PSS_SHA512),
    (SignatureScheme::RSA_PSS_SHA384, &signature::RSA_PSS_SHA384),
    (SignatureScheme::RSA_PSS_SHA256, &signature::RSA_PSS_SHA256),
    (
        SignatureScheme::RSA_PKCS1_SHA512,
        &signature::RSA_PKCS1_SHA512,
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA384,
        &signature::RSA_PKCS1_SHA384,
    ),
    (
        SignatureScheme::RSA_PKCS1_SHA256,
        &signature::RSA_PKCS1_SHA256,
    ),
];

impl RsaSigningKey {
    pub(crate) fn new(der: &PrivateKeyDer<'_>) -> Result<Self, Error> {
        let key_pair = match der {
            PrivateKeyDer::Pkcs1(pkcs1) => RsaKeyPair::from_der(pkcs1.secret_pkcs1_der()),
            PrivateKeyDer::Pkcs8(pkcs8) => RsaKeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()),
            _ => {
                return Err(Error::General(
                    "failed to parse RSA private key as either PKCS#1 or PKCS#8".into(),
                ));
            }
        }
        .map_err(|key_rejected| {
            Error::General(format!("failed to parse RSA private key: {key_rejected}"))
        })?;

        Ok(Self {
            key: Arc::new(key_pair),
        })
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        RSA_SCHEMES
            .iter()
            .find(|(s, _)| offered.contains(s))
            .map(|(scheme, encoding)| {
                Box::new(RsaSigner {
                    key: self.key.clone(),
                    scheme: *scheme,
                    encoding: *encoding,
                }) as Box<dyn Signer>
            })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &alg_id::RSA_ENCRYPTION,
            self.key.public_key(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

impl Debug for RsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct RsaSigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    encoding: &'static dyn signature::RsaEncoding,
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0; self.key.public_modulus_len()];

        let rng = SystemRandom::new();
        self.key
            .sign(self.encoding, &rng, message, &mut sig)
            .map(|_| sig)
            .map_err(|_| Error::General("signing failed".to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for RsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

struct EcdsaSigningKey {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
    spki_alg: AlgorithmIdentifier,
}

impl EcdsaSigningKey {
    fn new(
        der: &PrivateKeyDer<'_>,
        scheme: SignatureScheme,
        sigalg: &'static signature::EcdsaSigningAlgorithm,
        spki_alg: AlgorithmIdentifier,
    ) -> Result<Self, ()> {
        let key_pair = match der {
            PrivateKeyDer::Sec1(sec1) => {
                EcdsaKeyPair::from_private_key_der(sigalg, sec1.secret_sec1_der())
                    .map_err(|_| ())?
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                EcdsaKeyPair::from_pkcs8(sigalg, pkcs8.secret_pkcs8_der()).map_err(|_| ())?
            }
            _ => return Err(()),
        };

        Ok(Self {
            key: Arc::new(key_pair),
            scheme,
            spki_alg,
        })
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&self.spki_alg, self.key.public_key()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct EcdsaSigner {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map_err(|_| Error::General("signing failed".into()))
            .map(|sig| sig.as_ref().into())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for EcdsaSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

struct Ed25519SigningKey {
    key: Arc<Ed25519KeyPair>,
    scheme: SignatureScheme,
}

impl Ed25519SigningKey {
    fn new(der: &PrivatePkcs8KeyDer<'_>, scheme: SignatureScheme) -> Result<Self, Error> {
        match Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der()) {
            Ok(key_pair) => Ok(Self {
                key: Arc::new(key_pair),
                scheme,
            }),
            Err(e) => Err(Error::General(format!(
                "failed to parse Ed25519 private key: {e}"
            ))),
        }
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(Ed25519Signer {
                key: self.key.clone(),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ED25519, self.key.public_key()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

struct Ed25519Signer {
    key: Arc<Ed25519KeyPair>,
    scheme: SignatureScheme,
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.sign(message).as_ref().into())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl Debug for Ed25519Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::SignatureAlgorithm as S;

    /// A public RSA key used only by `a_pkcs1_rsa_key_loads`; it protects nothing and must never be used as a real key.
    const TEST_ONLY_RSA_2048_PKCS1: &str = concat!(
        "308204a30201000282010100c8c0ad24bab5ad72320f4471a21a327274a7f674cf25c57243842b1e55e61cfeec2ec445",
        "f02f8988f1abf8436fe7a541749c8be81354c29820d07b4ab7cf208b9e242dcb07fafaf0502f581ae686484fbd0b61a1",
        "98ea4953b534e8f1f214e3ee57739ef402e957309ab9fdc48888d93762fa12625a5b35f71b984a99fe1b8e990ba03c11",
        "9db70c9f4924e7b2e90cb0747ae4887a7338a86f76faa642e482cbe7edfd4d6d287dce0f58db01042b3fb748070141e8",
        "ec98cce278127c2f53c47b77df46efb180d9405caf912d1a80d0f61f6700114e41de659907c3e9795d84b1de54dd2dcb",
        "e68dbd13bdf602ce11591d46e3db31369d793060546639fb164c094d020301000102820100126b64ace53961da83a4ff",
        "f82c7c9a8558411dad610ba0feacc58b39437e1374abbcacc33d584c966a94dca36a0df1e2916dadae93b0d2bbfced74",
        "1535214590af3d62e593ec0a2b3e32e1dd71ffa9d1db26c359fd9052e861cccd7f7ee13e2547be883bf0ffc796b793a4",
        "d396b2cbba0d144f2c840830bee562c746dd8304c5ca2a95aa6a2da3f660e6eaac64352788bcdd8c7ecd09f9f5a264ab",
        "64f33d1e3e2d81d1e0b74ac919ce263fc1ad577796dd451be9a370959da1c50eba7cb55ffa8fc8c2824cce68e1a98792",
        "31925592214baa7f91b500495f5c9029a420dfbcedc780b861e7e9c388f59cb9669c5b51e9b7d882df7d8adf80cc8952",
        "1d89f0189702818100e30d929d021f9e95721f08e9a933eacdffa2b04c5fccbbe1be7cf53d42bbf8ac36ddee68a3370b",
        "753bf7f619846f67cec4a69a7d1c9e015ed680575ba9a60d21041679b944f368ba4a1dc2066bf6072c8449b32de3f144",
        "b271f33e0c1243332c6746679845a29e179fb16c87376b5ed357e974d815c4f8a60d998114e8da2d6702818100e258ba",
        "16648abe7e742d3468ba0b5147ec696a44f52041dbcac5359aab088f1a7d8e788f615490c7c4e2bc047091bb103cabf6",
        "0b1b42ce24fee5c59fc198c74e4d4eb084fefeb61736c6077c88a259151be5a2a008b1e67be29dc01cbb05fc644c76a4",
        "b663061f2c8bcee2b95af15816e742df00a53f9f2fff3a9e5e275baf2b02818055d706cbf7468f04ff1d3e986050f17f",
        "aa1b0ebe0125fd0e2e9f3d7448ab9a2b399f14085954712f84598da03e12845386c359fadcfbdb96c84fc337335f44ed",
        "6b8737c3d48e95d4803ad9e4e5a2213a32554eb995c8dc68fe6db0d28d80fc72d824a4fbcbafdc472027cad92019a6c3",
        "0e2483f941d9b30bcc6e717fbf3ce51702818100bc8aca1fa30a8b998c2ea78c6104d2650601dd5aa991802a94a2677f",
        "79debc4d85aeeab00c9443b1944885f370cd83b407c5fa42d0277ace0861df97aecd13a01ef76044b89ff5902ab9143d",
        "611752fb296cc4656838c0540bb5f9f434b9ccbec38ec4af8496f1daca6ec01f4428eb86d086bc79ae2cebee303d64f3",
        "eaf70d570281803b66f9167ea51b86c89dea07f72e6a4afc5007563650ce55b96abb5db40288d7e707066eb8b403082c",
        "c68ff3085a54137574ee4d89f71260b0eeae9a658e7d4286b6e53aafe6a9403376335b4314fa351967c4fb56906b465b",
        "b61fe84929283d889530b51337a58e9786116426f097fc2ece293781f4ca8683a37c4e62964a3f",
    );

    fn load(a: S) -> (crate::signature::KeyPair, Arc<dyn SigningKey>) {
        let k = crate::signature::KeyPair::generate(a).unwrap();
        let der = PrivateKeyDer::Pkcs8(k.pkcs8_der().to_vec().into());
        let key = any_supported_type(&der).unwrap();
        (k, key)
    }

    fn verifies(
        alg: &'static dyn signature::VerificationAlgorithm,
        public: &[u8],
        sig: &[u8],
    ) -> bool {
        signature::UnparsedPublicKey::new(alg, public)
            .verify(b"message", sig)
            .is_ok()
    }

    #[test]
    fn each_key_type_signs_with_its_scheme_and_reports_its_spki() {
        for (a, scheme, algorithm, spki, verify) in [
            (
                S::EcdsaP256Sha256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureAlgorithm::ECDSA,
                alg_id::ECDSA_P256,
                &signature::ECDSA_P256_SHA256_ASN1 as &'static dyn signature::VerificationAlgorithm,
            ),
            (
                S::EcdsaP384Sha384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureAlgorithm::ECDSA,
                alg_id::ECDSA_P384,
                &signature::ECDSA_P384_SHA384_ASN1,
            ),
            (
                S::EcdsaP521Sha512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureAlgorithm::ECDSA,
                alg_id::ECDSA_P521,
                &signature::ECDSA_P521_SHA512_ASN1,
            ),
            (
                S::Ed25519,
                SignatureScheme::ED25519,
                SignatureAlgorithm::ED25519,
                alg_id::ED25519,
                &signature::ED25519,
            ),
        ] {
            let (k, key) = load(a);
            assert_eq!(key.algorithm(), algorithm, "{a}");
            assert_eq!(
                key.public_key(),
                Some(public_key_to_spki(&spki, k.public_key())),
                "{a}"
            );
            assert!(
                key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                    .is_none(),
                "{a}"
            );
            let signer = key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256, scheme])
                .unwrap();
            assert_eq!(signer.scheme(), scheme);
            assert!(
                verifies(verify, &k.public_key(), &signer.sign(b"message").unwrap()),
                "{a}"
            );
        }
    }

    #[test]
    fn an_rsa_key_signs_with_the_first_scheme_of_rustls_order_that_is_offered() {
        let (k, key) = load(S::Rsa2048Sha384);
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
        assert_eq!(
            key.public_key(),
            Some(public_key_to_spki(&alg_id::RSA_ENCRYPTION, k.public_key()))
        );
        for (offered, want, verify) in [
            (
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                ],
                SignatureScheme::RSA_PSS_SHA384,
                &signature::RSA_PSS_2048_8192_SHA384
                    as &'static dyn signature::VerificationAlgorithm,
            ),
            (
                vec![SignatureScheme::RSA_PKCS1_SHA256],
                SignatureScheme::RSA_PKCS1_SHA256,
                &signature::RSA_PKCS1_2048_8192_SHA256,
            ),
            (
                vec![
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA512,
                ],
                SignatureScheme::RSA_PSS_SHA512,
                &signature::RSA_PSS_2048_8192_SHA512,
            ),
            (
                vec![
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                ],
                SignatureScheme::RSA_PKCS1_SHA512,
                &signature::RSA_PKCS1_2048_8192_SHA512,
            ),
            (
                vec![SignatureScheme::RSA_PKCS1_SHA384],
                SignatureScheme::RSA_PKCS1_SHA384,
                &signature::RSA_PKCS1_2048_8192_SHA384,
            ),
            (
                vec![SignatureScheme::RSA_PSS_SHA256],
                SignatureScheme::RSA_PSS_SHA256,
                &signature::RSA_PSS_2048_8192_SHA256,
            ),
        ] {
            let signer = key.choose_scheme(&offered).unwrap();
            assert_eq!(signer.scheme(), want);
            assert!(
                verifies(verify, &k.public_key(), &signer.sign(b"message").unwrap()),
                "{want:?}"
            );
        }
        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_none()
        );
    }

    #[test]
    fn a_pkcs1_rsa_key_loads() {
        let der = hex::decode(TEST_ONLY_RSA_2048_PKCS1).unwrap();
        let public = signature::RsaKeyPair::from_der(&der)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let key = any_supported_type(&PrivateKeyDer::Pkcs1(der.into())).unwrap();
        assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);
        assert_eq!(
            key.public_key(),
            Some(public_key_to_spki(&alg_id::RSA_ENCRYPTION, &public))
        );
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        assert!(verifies(
            &signature::RSA_PSS_2048_8192_SHA256,
            &public,
            &signer.sign(b"message").unwrap()
        ));
    }

    #[test]
    fn a_sec1_ecdsa_key_loads() {
        use aws_lc_rs::encoding::{AsDer, EcPrivateKeyRfc5915Der};
        let pair =
            signature::EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_ASN1_SIGNING).unwrap();
        let sec1: EcPrivateKeyRfc5915Der<'static> = pair.private_key().as_der().unwrap();
        let key = any_supported_type(&PrivateKeyDer::Sec1(sec1.as_ref().to_vec().into())).unwrap();
        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_some()
        );
    }

    #[test]
    fn garbage_is_refused_with_a_general_error() {
        let err = any_supported_type(&PrivateKeyDer::Pkcs8(b"not a key".to_vec().into())).err();
        assert_eq!(
            err,
            Some(Error::General(
                "failed to parse private key as RSA, ECDSA, or EdDSA".into()
            ))
        );
    }

    #[test]
    fn debug_never_prints_key_material() {
        let (_, rsa) = load(S::Rsa2048Sha384);
        assert_eq!(format!("{rsa:?}"), "RsaSigningKey { algorithm: RSA }");
        assert_eq!(
            format!(
                "{:?}",
                rsa.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                    .unwrap()
            ),
            "RsaSigner { scheme: RSA_PSS_SHA256 }"
        );
        let (_, ec) = load(S::EcdsaP384Sha384);
        assert_eq!(format!("{ec:?}"), "EcdsaSigningKey { algorithm: ECDSA }");
        assert_eq!(
            format!(
                "{:?}",
                ec.choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
                    .unwrap()
            ),
            "EcdsaSigner { scheme: ECDSA_NISTP384_SHA384 }"
        );
        let (_, ed) = load(S::Ed25519);
        assert_eq!(
            format!("{ed:?}"),
            "Ed25519SigningKey { algorithm: ED25519 }"
        );
        assert_eq!(
            format!(
                "{:?}",
                ed.choose_scheme(&[SignatureScheme::ED25519]).unwrap()
            ),
            "Ed25519Signer { scheme: ED25519 }"
        );
    }
}
