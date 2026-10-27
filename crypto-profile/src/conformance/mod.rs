//! Shared conformance data and helpers for `crypto-profile` backends.

#[doc(hidden)]
pub use hex as __hex;

/// Known-answer data every backend's conformance run checks.
pub mod vectors {
    /// The sealed-box known-answer vectors, produced by an independent implementation.
    pub mod sealbox {
        /// The domain the known-answer blob was sealed under.
        pub const DOMAIN: &[u8] = b"maknae-seal-v1";
        /// The plaintext of the known-answer blob.
        pub const PLAINTEXT: &[u8] = b"maknae-seal known-answer plaintext";
        /// The recipient's P-384 private key as PKCS#8 DER, hex-encoded.
        pub const PRIVATE_KEY_PKCS8_HEX: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111a16403620004386e767ea5cb716c9cd620ff7342129c892a6fccefe612140c80bff59e943468019dda16e5079b0c1d9001d23a624b6dd088d0c3826394194787403e8a7d07e5e22f7e9c0b8e80fa1faff5d28b4bb597b267f0b87023ca61fc8454bddefd2e0e";
        /// The known-answer sealed blob, hex-encoded.
        pub const BLOB_HEX: &str = "01044f2bda7fd2105f8467e21f45223ad58863ffa4c084832d9f6c64ffc47fdd519727ab53cb71f9c40de24b64acde61f02fc7dce130b612fa5dbcac94573a2354fd005d8e9caefdc5fde48304474708bbd82f77e1fd2c630bea236f6f8dccc1678e000102030405060708090a0b9e5112a45c454d89052a69d413fb8bab9027d5b1ee8f724947f1375c31bf4f0cca4de10984b9e6f2057ce1ec13c1185fb116";
        /// AES-256-GCM output (ciphertext and tag), hex-encoded, under the key derived from a fixed
        /// shared secret of 48 bytes of `0x33` and the known-answer ephemeral key.
        pub const FIXED_SHARED_CT_HEX: &str = "0b97a82530c1e3b734c40e1d1bd3021ecd6c502e16d304d333ccdfdf7e0f35672a70c0815ce1d2c6c5ad3ab9c8968987c6c3";
        /// The nonce of [`FIXED_SHARED_CT_HEX`].
        pub const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        /// The additional authenticated data of the known-answer blob.
        pub fn aad() -> Vec<u8> {
            let mut out = b"maknae-seal-aad-v1".to_vec();
            for field in [
                "c-1",
                "openai",
                "gpt-5.6-luna",
                "maknae-kv/data/maknae/users/alice/openai/personal",
                "api_key",
            ] {
                out.extend_from_slice(&(field.len() as u16).to_be_bytes());
                out.extend_from_slice(field.as_bytes());
            }
            out
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::sealbox_wire::{MIN_BLOB_LEN, NONCE_LEN, VERSION};

            #[test]
            fn the_vectors_are_well_formed() {
                let blob = crate::conformance::__hex::decode(BLOB_HEX).unwrap();
                assert!(blob.len() >= MIN_BLOB_LEN);
                assert_eq!(blob[0], VERSION);
                assert_eq!(NONCE.len(), NONCE_LEN);
                assert_eq!(
                    &blob[1 + crate::sealbox_wire::EPHEMERAL_KEY_LEN
                        ..crate::sealbox_wire::HEADER_LEN],
                    &NONCE
                );
                assert_eq!(blob.len(), crate::sealbox_wire::sealed_len(PLAINTEXT.len()));
                assert_eq!(
                    crate::conformance::__hex::decode(PRIVATE_KEY_PKCS8_HEX)
                        .unwrap()
                        .len(),
                    185
                );
                assert_eq!(
                    crate::conformance::__hex::decode(FIXED_SHARED_CT_HEX)
                        .unwrap()
                        .len(),
                    PLAINTEXT.len() + 16
                );
            }

            #[test]
            fn the_aad_is_length_prefixed_fields() {
                let aad = aad();
                assert!(aad.starts_with(b"maknae-seal-aad-v1\x00\x03c-1\x00\x06openai"));
                assert!(aad.ends_with(b"\x00\x07api_key"));
            }
        }
    }
}
