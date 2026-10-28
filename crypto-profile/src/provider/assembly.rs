use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SupportedKxGroup,
    WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{PrivateKeyDer, SignatureVerificationAlgorithm};
use rustls::sign::SigningKey;
use std::sync::{Arc, OnceLock};

pub(crate) fn fips() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

#[derive(Debug)]
pub(crate) struct Rng;

impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        use aws_lc_rs::rand::SecureRandom as _;
        aws_lc_rs::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips()
    }
}

#[derive(Debug)]
pub(crate) struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        super::sign::any_supported_type(&zeroize::Zeroizing::new(key_der))
    }

    fn fips(&self) -> bool {
        fips()
    }
}

pub(crate) static RNG: Rng = Rng;
pub(crate) static KEYS: Keys = Keys;

pub(crate) fn group(k: crypto_profile::KxGroup) -> &'static dyn SupportedKxGroup {
    use crypto_profile::KxGroup as K;
    match k {
        K::MlKem1024 => super::kx::MLKEM1024,
        K::Secp384r1MlKem1024 => super::kx::SECP384R1MLKEM1024,
        K::X25519MlKem768 => super::kx::X25519MLKEM768,
        K::Secp256r1MlKem768 => super::kx::SECP256R1MLKEM768,
        K::Secp384r1 => super::kx::SECP384R1,
        K::Secp256r1 => super::kx::SECP256R1,
        K::X25519 => super::kx::X25519,
    }
}

pub(crate) fn suite(c: crypto_profile::CipherSuite) -> rustls::SupportedCipherSuite {
    use crypto_profile::CipherSuite as C;
    match c {
        C::Tls13Aes256GcmSha384 => super::tls13::TLS13_AES_256_GCM_SHA384,
        C::Tls13Aes128GcmSha256 => super::tls13::TLS13_AES_128_GCM_SHA256,
        C::Tls13Chacha20Poly1305Sha256 => super::tls13::TLS13_CHACHA20_POLY1305_SHA256,
        C::Tls12EcdheEcdsaAes256GcmSha384 => super::tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        C::Tls12EcdheEcdsaAes128GcmSha256 => super::tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        C::Tls12EcdheEcdsaChacha20Poly1305Sha256 => {
            super::tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        C::Tls12EcdheRsaAes256GcmSha384 => super::tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        C::Tls12EcdheRsaAes128GcmSha256 => super::tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        C::Tls12EcdheRsaChacha20Poly1305Sha256 => {
            super::tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
    }
}

type Mapping = (
    rustls::SignatureScheme,
    &'static [&'static dyn SignatureVerificationAlgorithm],
);

pub(crate) fn verification() -> WebPkiSupportedAlgorithms {
    static TABLE: OnceLock<(
        Vec<&'static dyn SignatureVerificationAlgorithm>,
        Vec<Mapping>,
    )> = OnceLock::new();
    let (all, mapping) = TABLE.get_or_init(|| {
        (
            [super::verify::COMMON_ALL, super::backend::PQDSA_ALL].concat(),
            [super::verify::COMMON_MAPPING, super::backend::PQDSA_MAPPING].concat(),
        )
    });
    WebPkiSupportedAlgorithms { all, mapping }
}

pub(crate) fn full() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: crypto_profile::CipherSuite::ALL
            .into_iter()
            .map(suite)
            .collect(),
        kx_groups: crypto_profile::KxGroup::ALL
            .into_iter()
            .map(group)
            .collect(),
        signature_verification_algorithms: verification(),
        secure_random: &RNG,
        key_provider: &KEYS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::KxGroup as K;

    #[test]
    fn the_module_is_in_fips_mode_on_this_build() {
        assert!(fips());
    }

    #[test]
    fn every_inventory_group_maps_to_its_registry_codepoint() {
        let table = [
            (K::MlKem1024, 0x0202),
            (K::Secp384r1MlKem1024, 0x11ED),
            (K::X25519MlKem768, 0x11EC),
            (K::Secp256r1MlKem768, 0x11EB),
            (K::Secp384r1, 0x0018),
            (K::Secp256r1, 0x0017),
            (K::X25519, 0x001D),
        ];
        assert_eq!(table.len(), K::ALL.len());
        for (k, cp) in table {
            assert_eq!(u16::from_be_bytes(group(k).name().to_array()), cp, "{k:?}");
        }
    }

    #[test]
    fn every_inventory_suite_maps_to_its_registry_codepoint() {
        use crypto_profile::CipherSuite as C;
        let table = [
            (C::Tls13Aes256GcmSha384, 0x1302),
            (C::Tls13Aes128GcmSha256, 0x1301),
            (C::Tls13Chacha20Poly1305Sha256, 0x1303),
            (C::Tls12EcdheEcdsaAes256GcmSha384, 0xC02C),
            (C::Tls12EcdheEcdsaAes128GcmSha256, 0xC02B),
            (C::Tls12EcdheEcdsaChacha20Poly1305Sha256, 0xCCA9),
            (C::Tls12EcdheRsaAes256GcmSha384, 0xC030),
            (C::Tls12EcdheRsaAes128GcmSha256, 0xC02F),
            (C::Tls12EcdheRsaChacha20Poly1305Sha256, 0xCCA8),
        ];
        assert_eq!(table.len(), C::ALL.len());
        for (c, cp) in table {
            assert_eq!(u16::from_be_bytes(suite(c).suite().to_array()), cp, "{c:?}");
        }
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn the_random_source_fills_and_two_fills_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        RNG.fill(&mut a).unwrap();
        RNG.fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
        assert!(RNG.fips());
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn the_key_provider_loads_through_any_supported_type() {
        let k = crate::signature::KeyPair::generate(
            crypto_profile::SignatureAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();
        let key = KEYS
            .load_private_key(PrivateKeyDer::Pkcs8(k.pkcs8_der().to_vec().into()))
            .unwrap();
        assert!(
            key.choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
                .is_some()
        );
        assert!(
            KEYS.load_private_key(PrivateKeyDer::Pkcs8(b"x".to_vec().into()))
                .is_err()
        );
        assert!(KEYS.fips());
    }

    fn ids(algs: &[&dyn SignatureVerificationAlgorithm]) -> Vec<(AlgId, AlgId)> {
        algs.iter()
            .map(|a| (a.public_key_alg_id(), a.signature_alg_id()))
            .collect()
    }

    type AlgId = rustls::pki_types::AlgorithmIdentifier;

    #[test]
    fn verification_is_the_common_tables_then_the_backends() {
        let v = verification();
        assert_eq!(
            ids(v.all),
            [
                ids(super::super::verify::COMMON_ALL),
                ids(super::super::backend::PQDSA_ALL)
            ]
            .concat()
        );
        let mapped = |m: &[Mapping]| {
            m.iter()
                .map(|(s, algs)| (*s, ids(algs)))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            mapped(v.mapping),
            [
                mapped(super::super::verify::COMMON_MAPPING),
                mapped(super::super::backend::PQDSA_MAPPING)
            ]
            .concat()
        );
    }

    #[test]
    fn the_full_provider_carries_every_suite_and_group_in_order() {
        use crypto_profile::CipherSuite as C;
        let p = full();
        assert_eq!(
            p.cipher_suites
                .iter()
                .map(|s| u16::from_be_bytes(s.suite().to_array()))
                .collect::<Vec<_>>(),
            C::ALL.map(|c| u16::from_be_bytes(suite(c).suite().to_array()))
        );
        assert_eq!(
            p.kx_groups
                .iter()
                .map(|g| u16::from_be_bytes(g.name().to_array()))
                .collect::<Vec<_>>(),
            K::ALL.map(|k| u16::from_be_bytes(group(k).name().to_array()))
        );
        assert_eq!(
            ids(p.signature_verification_algorithms.all),
            ids(verification().all)
        );
        assert!(std::ptr::addr_eq(p.secure_random, &RNG));
        assert!(std::ptr::addr_eq(p.key_provider, &KEYS));
        assert!(!p.fips());
    }
}
