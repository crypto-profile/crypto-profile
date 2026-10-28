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
}
