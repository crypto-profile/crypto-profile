use rustls::crypto::SupportedKxGroup;

pub(crate) fn fips() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

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
}
