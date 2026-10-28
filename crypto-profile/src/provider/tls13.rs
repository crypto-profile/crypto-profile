// Ported from rustls 0.23.46 (src/crypto/aws_lc_rs/tls13.rs), Copyright (c) 2016 Joseph
// Birr-Pixton, used under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::{aead, hkdf, hmac};
use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion,
    SupportedCipherSuite, Tls13CipherSuite,
};

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
        aead_alg: &ChachaAead,
        quic: None,
    });

pub(crate) static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
        aead_alg: &GcmAead {
            alg: &aead::AES_256_GCM,
            secrets: |key, iv| ConnectionTrafficSecrets::Aes256Gcm { key, iv },
        },
        quic: None,
    });

pub(crate) static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
        aead_alg: &GcmAead {
            alg: &aead::AES_128_GCM,
            secrets: |key, iv| ConnectionTrafficSecrets::Aes128Gcm { key, iv },
        },
        quic: None,
    });

pub(crate) fn chacha_key(key: &[u8]) -> Option<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .ok()
        .map(aead::LessSafeKey::new)
}

pub(crate) fn unpredictable(output: &mut [u8]) {
    let _ = aws_lc_rs::rand::fill(output);
}

pub(crate) struct Unusable;

impl MessageEncrypter for Unusable {
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

impl MessageDecrypter for Unusable {
    fn decrypt<'a>(
        &mut self,
        _: InboundOpaqueMessage<'a>,
        _: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

struct ChachaAead;

impl Tls13AeadAlgorithm for ChachaAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match chacha_key(key.as_ref()) {
            Some(enc_key) => Box::new(AeadMessageEncrypter { enc_key, iv }),
            None => Box::new(Unusable),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match chacha_key(key.as_ref()) {
            Some(dec_key) => Box::new(AeadMessageDecrypter { dec_key, iv }),
            None => Box::new(Unusable),
        }
    }

    fn key_len(&self) -> usize {
        aead::CHACHA20_POLY1305.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> bool {
        false
    }
}

struct GcmAead {
    alg: &'static aead::Algorithm,
    secrets: fn(AeadKey, Iv) -> ConnectionTrafficSecrets,
}

impl Tls13AeadAlgorithm for GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        match aead::TlsRecordSealingKey::new(self.alg, aead::TlsProtocolId::TLS13, key.as_ref()) {
            Ok(enc_key) => Box::new(GcmMessageEncrypter { enc_key, iv }),
            Err(_) => Box::new(Unusable),
        }
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        match aead::TlsRecordOpeningKey::new(self.alg, aead::TlsProtocolId::TLS13, key.as_ref()) {
            Ok(dec_key) => Box::new(GcmMessageDecrypter { dec_key, iv }),
            Err(_) => Box::new(Unusable),
        }
    }

    fn key_len(&self) -> usize {
        self.alg.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok((self.secrets)(key, iv))
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }
}

struct AeadMessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
}

struct AeadMessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for AeadMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

impl MessageDecrypter for AeadMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

struct GcmMessageEncrypter {
    enc_key: aead::TlsRecordSealingKey,
    iv: Iv,
}

impl MessageEncrypter for GcmMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }
}

struct GcmMessageDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
    iv: Iv,
}

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

struct AwsLcHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for AwsLcHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> rustls::crypto::hmac::Tag {
        rustls::crypto::hmac::Tag::new(
            hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref(),
        )
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }
}

struct AwsLcHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for AwsLcHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        if self.expand_slice(info, output).is_err() {
            unpredictable(output);
        }
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;

    fn suite(s: &SupportedCipherSuite) -> &'static Tls13CipherSuite {
        match s {
            SupportedCipherSuite::Tls13(t) => t,
            SupportedCipherSuite::Tls12(_) => panic!("a TLS 1.2 suite"),
        }
    }

    pub(crate) fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn seal(enc: &mut dyn MessageEncrypter, plain: &[u8], seq: u64) -> Vec<u8> {
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(plain),
        };
        enc.encrypt(msg, seq).unwrap().payload.as_ref().to_vec()
    }

    pub(crate) fn open(
        dec: &mut dyn MessageDecrypter,
        mut record: Vec<u8>,
        seq: u64,
    ) -> Result<Vec<u8>, Error> {
        let msg = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut record,
        );
        dec.decrypt(msg, seq).map(|m| m.payload.to_vec())
    }

    #[test]
    fn the_suites_carry_rustls_constants() {
        let all = [
            &TLS13_AES_256_GCM_SHA384,
            &TLS13_AES_128_GCM_SHA256,
            &TLS13_CHACHA20_POLY1305_SHA256,
        ];
        let cps: Vec<u16> = all
            .iter()
            .map(|s| u16::from_be_bytes(s.suite().to_array()))
            .collect();
        assert_eq!(cps, [0x1302, 0x1301, 0x1303]);
        let limits: Vec<u64> = all
            .iter()
            .map(|s| suite(s).common.confidentiality_limit)
            .collect();
        assert_eq!(limits, [16_777_216, 16_777_216, u64::MAX]);
        let keys: Vec<usize> = all.iter().map(|s| suite(s).aead_alg.key_len()).collect();
        assert_eq!(keys, [32, 16, 32]);
        let fips: Vec<bool> = all.iter().map(|s| s.fips()).collect();
        assert_eq!(fips, [true, true, false]);
        assert!(all.iter().all(|s| suite(s).hkdf_provider.fips()));
        assert!(all.iter().all(|s| suite(s).quic.is_none()));
        let hashes: Vec<usize> = all
            .iter()
            .map(|s| suite(s).common.hash_provider.output_len())
            .collect();
        assert_eq!(hashes, [48, 32, 32]);
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let h = suite(&TLS13_AES_128_GCM_SHA256).hkdf_provider;
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let want =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let mut okm = [0u8; 42];
        h.extract_from_secret(Some(&salt), &[0x0b; 22])
            .expand_slice(&[info.as_slice()], &mut okm)
            .unwrap();
        assert_eq!(hx(&okm), want);
        let prk = OkmBlock::new(&unhex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        ));
        let mut again = [0u8; 42];
        h.expander_for_okm(&prk)
            .expand_slice(&[&info[..4], &info[4..]], &mut again)
            .unwrap();
        assert_eq!(hx(&again), want);
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert!(
            h.expander_for_okm(&prk)
                .expand_slice(&[info.as_slice()], &mut too_long)
                .is_err()
        );
    }

    #[test]
    fn a_zero_ikm_extract_expands_to_the_reference_block() {
        for (s, len, want) in [
            (
                &TLS13_AES_128_GCM_SHA256,
                32,
                "37b8c973bded0783b649c2129de3a70e45466f037ca585c101f4869c09d51dee",
            ),
            (
                &TLS13_AES_256_GCM_SHA384,
                48,
                "d6a7c8febf6fd37ca64f2d7e05158ee91a960dcc406176e7a31dcc2a9cd1030d3c1b9a882696440419a34d847489fe06",
            ),
        ] {
            let h = suite(s).hkdf_provider;
            let zero = vec![0u8; len];
            for e in [
                h.extract_from_zero_ikm(None),
                h.extract_from_zero_ikm(Some(&zero)),
                h.extract_from_secret(None, &zero),
            ] {
                assert_eq!(e.hash_len(), len);
                assert_eq!(hx(e.expand_block(&[b"x".as_slice()]).as_ref()), want);
            }
        }
    }

    #[test]
    fn hmac_sign_matches_rfc_4231_test_case_2() {
        for (s, want) in [
            (
                &TLS13_AES_128_GCM_SHA256,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &TLS13_AES_256_GCM_SHA384,
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            ),
        ] {
            let tag = suite(s)
                .hkdf_provider
                .hmac_sign(&OkmBlock::new(b"Jefe"), b"what do ya want for nothing?");
            assert_eq!(hx(tag.as_ref()), want);
        }
    }

    #[test]
    fn unpredictable_fills_differently_each_time() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        unpredictable(&mut a);
        unpredictable(&mut b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn a_record_round_trips_and_a_changed_record_or_sequence_is_refused() {
        for s in [&TLS13_AES_256_GCM_SHA384, &TLS13_CHACHA20_POLY1305_SHA256] {
            let alg = suite(s).aead_alg;
            let (key, iv) = ([7u8; 32], [9u8; 12]);
            let mut enc = alg.encrypter(AeadKey::from(key), Iv::new(iv));
            let mut dec = alg.decrypter(AeadKey::from(key), Iv::new(iv));
            assert_eq!(enc.encrypted_payload_len(10), 10 + 1 + 16);
            let record = seal(enc.as_mut(), b"0123456789", 5);
            assert_eq!(record.len(), 27);
            assert_eq!(
                open(dec.as_mut(), record.clone(), 5),
                Ok(b"0123456789".to_vec())
            );
            assert_eq!(
                open(dec.as_mut(), record.clone(), 6),
                Err(Error::DecryptError)
            );
            let mut flipped = record;
            flipped[0] ^= 1;
            assert_eq!(open(dec.as_mut(), flipped, 5), Err(Error::DecryptError));
            assert_eq!(open(dec.as_mut(), vec![0; 15], 5), Err(Error::DecryptError));
        }
    }

    #[test]
    fn a_tag_only_record_reaches_the_inner_plaintext_check() {
        for (s, alg) in [
            (&TLS13_AES_256_GCM_SHA384, &aead::AES_256_GCM),
            (&TLS13_CHACHA20_POLY1305_SHA256, &aead::CHACHA20_POLY1305),
        ] {
            let key = [7u8; 32];
            let sealer = aead::LessSafeKey::new(aead::UnboundKey::new(alg, &key).unwrap());
            let nonce = Nonce::new(&Iv::new([9; 12]), 3).0;
            let mut record = Vec::new();
            sealer
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(make_tls13_aad(16)),
                    &mut record,
                )
                .unwrap();
            assert_eq!(record.len(), 16);
            let mut dec = suite(s)
                .aead_alg
                .decrypter(AeadKey::from(key), Iv::new([9; 12]));
            assert_eq!(
                open(dec.as_mut(), record, 3),
                Err(Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::IllegalTlsInnerPlaintext
                ))
            );
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_gives_a_record_layer_that_refuses() {
        let alg = suite(&TLS13_AES_128_GCM_SHA256).aead_alg;
        let mut enc = alg.encrypter(AeadKey::from([0u8; 32]), Iv::new([0; 12]));
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(b"x"),
        };
        assert_eq!(enc.encrypt(msg, 0).err(), Some(Error::EncryptError));
        assert_eq!(enc.encrypted_payload_len(3), 3);
        let mut dec = alg.decrypter(AeadKey::from([0u8; 32]), Iv::new([0; 12]));
        assert_eq!(open(dec.as_mut(), vec![0; 32], 0), Err(Error::DecryptError));
        assert!(chacha_key(&[0; 16]).is_none());
        assert!(chacha_key(&[0; 32]).is_some());
    }

    #[test]
    fn extract_keys_names_the_algorithm() {
        let k = || AeadKey::from([1u8; 32]);
        let iv = || Iv::new([2; 12]);
        assert!(matches!(
            suite(&TLS13_AES_256_GCM_SHA384)
                .aead_alg
                .extract_keys(k(), iv()),
            Ok(ConnectionTrafficSecrets::Aes256Gcm { .. })
        ));
        assert!(matches!(
            suite(&TLS13_AES_128_GCM_SHA256)
                .aead_alg
                .extract_keys(k(), iv()),
            Ok(ConnectionTrafficSecrets::Aes128Gcm { .. })
        ));
        assert!(matches!(
            suite(&TLS13_CHACHA20_POLY1305_SHA256)
                .aead_alg
                .extract_keys(k(), iv()),
            Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { .. })
        ));
    }
}
