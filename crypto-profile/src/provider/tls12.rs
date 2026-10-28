// Ported from rustls 0.23.46 (src/crypto/aws_lc_rs/tls12.rs), Copyright (c) 2016 Joseph
// Birr-Pixton, used under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::{aead, tls_prf};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, NONCE_LEN, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
    PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::crypto::tls12::Prf;
use rustls::crypto::{ActiveKeyExchange, CipherSuiteCommon, KeyExchangeAlgorithm};
use rustls::version::TLS12;
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, Error, SignatureScheme, SupportedCipherSuite,
    Tls12CipherSuite,
};

const MAX_FRAGMENT_LEN: usize = 16_384;

pub(crate) static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &ChaCha20Poly1305,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    });

pub(crate) static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &ChaCha20Poly1305,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    });

pub(crate) static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES128_GCM,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    });

pub(crate) static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        aead_alg: &AES256_GCM,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    });

pub(crate) static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &super::hash::SHA256,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES128_GCM,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    });

pub(crate) static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
            confidentiality_limit: 1 << 24,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        aead_alg: &AES256_GCM,
        prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    });

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

static AES128_GCM: GcmAlgorithm = GcmAlgorithm {
    alg: &aead::AES_128_GCM,
    secrets: |key, iv| ConnectionTrafficSecrets::Aes128Gcm { key, iv },
};
static AES256_GCM: GcmAlgorithm = GcmAlgorithm {
    alg: &aead::AES_256_GCM,
    secrets: |key, iv| ConnectionTrafficSecrets::Aes256Gcm { key, iv },
};

struct GcmAlgorithm {
    alg: &'static aead::Algorithm,
    secrets: fn(AeadKey, Iv) -> ConnectionTrafficSecrets,
}

impl Tls12AeadAlgorithm for GcmAlgorithm {
    fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let (Ok(dec_key), Ok(dec_salt)) = (
            aead::TlsRecordOpeningKey::new(self.alg, aead::TlsProtocolId::TLS12, dec_key.as_ref()),
            <[u8; 4]>::try_from(dec_iv),
        ) else {
            return Box::new(super::tls13::Unusable);
        };
        Box::new(GcmMessageDecrypter { dec_key, dec_salt })
    }

    fn encrypter(
        &self,
        enc_key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        // TLS13: nonce = fixed IV XOR sequence number (RFC 8446 §5.3, as RFC 7905 §2 does for TLS 1.2 ChaCha), not a plain counter.
        let (Ok(enc_key), Some(iv)) = (
            aead::TlsRecordSealingKey::new(self.alg, aead::TlsProtocolId::TLS13, enc_key.as_ref()),
            gcm_iv(write_iv, explicit),
        ) else {
            return Box::new(super::tls13::Unusable);
        };
        Box::new(GcmMessageEncrypter { enc_key, iv })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.alg.key_len(),
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        gcm_iv(write_iv, explicit)
            .map(|iv| (self.secrets)(key, iv))
            .ok_or(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }
}

struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn decrypter(&self, dec_key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let (Some(dec_key), Some(dec_offset)) =
            (super::tls13::chacha_key(dec_key.as_ref()), chacha_iv(iv))
        else {
            return Box::new(super::tls13::Unusable);
        };
        Box::new(ChaCha20Poly1305MessageDecrypter {
            dec_key,
            dec_offset,
        })
    }

    fn encrypter(&self, enc_key: AeadKey, enc_iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let (Some(enc_key), Some(enc_offset)) = (
            super::tls13::chacha_key(enc_key.as_ref()),
            chacha_iv(enc_iv),
        ) else {
            return Box::new(super::tls13::Unusable);
        };
        Box::new(ChaCha20Poly1305MessageEncrypter {
            enc_key,
            enc_offset,
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        chacha_iv(iv)
            .map(|iv| ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
            .ok_or(UnsupportedOperationError)
    }

    fn fips(&self) -> bool {
        false
    }
}

struct GcmMessageEncrypter {
    enc_key: aead::TlsRecordSealingKey,
    iv: Iv,
}

struct GcmMessageDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
    dec_salt: [u8; 4],
}

const GCM_EXPLICIT_NONCE_LEN: usize = 8;
const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

impl MessageDecrypter for GcmMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &msg.payload;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.dec_salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            aead::Nonce::assume_unique_for_key(nonce)
        };

        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - GCM_OVERHEAD,
        ));

        let payload = &mut msg.payload;
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, &mut payload[GCM_EXPLICIT_NONCE_LEN..])
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        Ok(
            msg.into_plain_message_range(
                GCM_EXPLICIT_NONCE_LEN..GCM_EXPLICIT_NONCE_LEN + plain_len,
            ),
        )
    }
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
        let aad = aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));
        payload.extend_from_slice(&nonce.as_ref()[4..]);
        payload.extend_from_chunks(&msg.payload);

        self.enc_key
            .seal_in_place_separate_tag(nonce, aad, &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..])
            .map(|tag| payload.extend_from_slice(tag.as_ref()))
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + self.enc_key.algorithm().tag_len()
    }
}

struct ChaCha20Poly1305MessageEncrypter {
    enc_key: aead::LessSafeKey,
    enc_offset: Iv,
}

struct ChaCha20Poly1305MessageDecrypter {
    dec_key: aead::LessSafeKey,
    dec_offset: Iv,
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

impl MessageDecrypter for ChaCha20Poly1305MessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &msg.payload;

        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.dec_offset, seq).0);
        let aad = aead::Aad::from(make_tls12_aad(
            seq,
            msg.typ,
            msg.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        ));

        let payload = &mut msg.payload;
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        if plain_len > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(msg.into_plain_message())
    }
}

impl MessageEncrypter for ChaCha20Poly1305MessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.enc_offset, seq).0);
        let aad = aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));
        payload.extend_from_chunks(&msg.payload);

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + self.enc_key.algorithm().tag_len()
    }
}

fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Option<Iv> {
    let salt = <[u8; 4]>::try_from(write_iv).ok()?;
    let explicit = <[u8; 8]>::try_from(explicit).ok()?;
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(&salt);
    iv[4..].copy_from_slice(&explicit);
    Some(Iv::new(iv))
}

fn chacha_iv(iv: &[u8]) -> Option<Iv> {
    <[u8; NONCE_LEN]>::try_from(iv).ok().map(Iv::new)
}

struct Tls12Prf(&'static tls_prf::Algorithm);

fn prf(
    alg: &'static tls_prf::Algorithm,
    output: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<(), Error> {
    let derived = tls_prf::Secret::new(alg, secret)
        .and_then(|s| s.derive(label, seed, output.len()))
        .map_err(|_| Error::General("the TLS PRF refused its input".into()))?;
    output.copy_from_slice(derived.as_ref());
    Ok(())
}

impl Prf for Tls12Prf {
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        if prf(self.0, output, secret, label, seed).is_err() {
            super::tls13::unpredictable(output);
        }
    }

    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        prf(
            self.0,
            output,
            kx.complete_for_tls_version(peer_pub_key, &TLS12)?
                .secret_bytes(),
            label,
            seed,
        )
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tls13::tests::{hx, open, seal, unhex};
    use super::*;
    use rustls::PeerMisbehaved;

    fn suite(s: &SupportedCipherSuite) -> &'static Tls12CipherSuite {
        match s {
            SupportedCipherSuite::Tls12(t) => t,
            SupportedCipherSuite::Tls13(_) => panic!("a TLS 1.3 suite"),
        }
    }

    const ALL: [&SupportedCipherSuite; 6] = [
        &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    #[test]
    fn the_suites_carry_rustls_constants() {
        let cp = |x: [u8; 2]| u16::from_be_bytes(x);
        assert_eq!(
            ALL.map(|s| cp(s.suite().to_array())),
            [0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8]
        );
        assert_eq!(
            ALL.map(|s| suite(s).common.confidentiality_limit),
            [
                16_777_216,
                16_777_216,
                u64::MAX,
                16_777_216,
                16_777_216,
                u64::MAX
            ]
        );
        assert_eq!(
            ALL.map(|s| s.fips()),
            [true, true, false, true, true, false]
        );
        assert!(ALL.iter().all(|s| suite(s).prf_provider.fips()));
        assert_eq!(
            ALL.map(|s| suite(s).common.hash_provider.output_len()),
            [48, 32, 32, 48, 32, 32]
        );
        assert!(
            ALL.iter()
                .all(|s| suite(s).kx == KeyExchangeAlgorithm::ECDHE)
        );
        let schemes = |s: &SupportedCipherSuite| {
            suite(s)
                .sign
                .iter()
                .map(|x| cp(x.to_array()))
                .collect::<Vec<_>>()
        };
        assert_eq!(schemes(ALL[0]), [0x0807, 0x0603, 0x0503, 0x0403]);
        assert_eq!(
            schemes(ALL[3]),
            [0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401]
        );
        let shape = |s: &SupportedCipherSuite| {
            let k = suite(s).aead_alg.key_block_shape();
            (k.enc_key_len, k.fixed_iv_len, k.explicit_nonce_len)
        };
        assert_eq!(
            [ALL[0], ALL[1], ALL[2]].map(shape),
            [(32, 4, 8), (16, 4, 8), (32, 12, 0)]
        );
    }

    #[test]
    fn the_prf_matches_the_published_p_sha256_and_p_sha384_vectors() {
        for (s, secret, seed, want) in [
            (
                ALL[1],
                "9bbe436ba940f017b17652849a71db35",
                "a0ba9f936cda311827a6f796ffd5198c",
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af",
            ),
            (
                ALL[0],
                "b80b733d6ceefcdc71566ea48e5567df",
                "cd665cf6a8447dd6ff8b27555edb7465",
                "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0",
            ),
        ] {
            let mut out = [0u8; 48];
            suite(s)
                .prf_provider
                .for_secret(&mut out, &unhex(secret), b"test label", &unhex(seed));
            assert_eq!(hx(&out), want);
        }
    }

    #[test]
    fn a_refused_prf_input_leaves_unpredictable_output() {
        let prf = suite(ALL[0]).prf_provider;
        let (mut a, mut b) = ([0u8; 48], [0u8; 48]);
        prf.for_secret(&mut a, &[], b"label", b"seed");
        prf.for_secret(&mut b, &[], b"label", b"seed");
        assert_ne!(a, [0u8; 48]);
        assert_ne!(a, b);
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn the_master_secret_is_the_prf_of_the_ecdhe_secret_and_a_bad_share_is_refused() {
        let prf = suite(ALL[0]).prf_provider;
        let ours = super::super::kx::SECP384R1.start().unwrap();
        let peer = super::super::kx::SECP384R1
            .start_and_complete(ours.pub_key())
            .unwrap();
        let mut want = [0u8; 48];
        prf.for_secret(
            &mut want,
            peer.secret.secret_bytes(),
            b"master secret",
            b"seed",
        );
        let mut got = [0u8; 48];
        prf.for_key_exchange(&mut got, ours, &peer.pub_key, b"master secret", b"seed")
            .unwrap();
        assert_eq!(got, want);
        let bad = super::super::kx::SECP384R1.start().unwrap();
        assert_eq!(
            prf.for_key_exchange(&mut got, bad, &[0x03; 49], b"master secret", b"seed")
                .err(),
            Some(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        );
    }

    #[test]
    fn gcm_puts_the_explicit_nonce_first_and_bounds_the_fragment() {
        let alg = suite(ALL[0]).aead_alg;
        let mut enc = alg.encrypter(AeadKey::from([7u8; 32]), &[1, 2, 3, 4], &[5; 8]);
        let mut dec = alg.decrypter(AeadKey::from([7u8; 32]), &[1, 2, 3, 4]);
        assert_eq!(enc.encrypted_payload_len(10), 10 + 8 + 16);
        let r0 = seal(enc.as_mut(), b"0123456789", 0);
        assert_eq!((&r0[..8], r0.len()), (&[5u8; 8][..], 34));
        let r1 = seal(enc.as_mut(), b"0123456789", 1);
        assert_eq!(&r1[..8], &[5, 5, 5, 5, 5, 5, 5, 4]);
        assert_eq!(open(dec.as_mut(), r1, 1), Ok(b"0123456789".to_vec()));
        assert_eq!(open(dec.as_mut(), r0.clone(), 1), Err(Error::DecryptError));
        assert_eq!(open(dec.as_mut(), vec![0; 23], 0), Err(Error::DecryptError));
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), b"", 2), 2),
            Ok(vec![])
        );
        let full = vec![0x61; 16_384];
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), &full, 3), 3),
            Ok(full)
        );
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), &[0x61; 16_385], 4), 4),
            Err(Error::PeerSentOversizedRecord)
        );
    }

    #[test]
    fn chacha_round_trips_and_bounds_the_fragment() {
        let alg = suite(ALL[2]).aead_alg;
        let mut enc = alg.encrypter(AeadKey::from([7u8; 32]), &[9; 12], &[]);
        let mut dec = alg.decrypter(AeadKey::from([7u8; 32]), &[9; 12]);
        assert_eq!(enc.encrypted_payload_len(10), 26);
        let r = seal(enc.as_mut(), b"0123456789", 4);
        assert_eq!(open(dec.as_mut(), r.clone(), 4), Ok(b"0123456789".to_vec()));
        assert_eq!(open(dec.as_mut(), r, 5), Err(Error::DecryptError));
        assert_eq!(open(dec.as_mut(), vec![0; 15], 4), Err(Error::DecryptError));
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), b"", 8), 8),
            Ok(vec![])
        );
        let full = vec![0x61; 16_384];
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), &full, 6), 6),
            Ok(full)
        );
        assert_eq!(
            open(dec.as_mut(), seal(enc.as_mut(), &[0x61; 16_385], 7), 7),
            Err(Error::PeerSentOversizedRecord)
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_refuses_and_extract_keys_names_the_algorithm() {
        let aes128 = suite(ALL[1]).aead_alg;
        let enc = aes128.encrypter(AeadKey::from([0u8; 32]), &[0; 4], &[0; 8]);
        assert_eq!(enc.encrypted_payload_len(3), 3);
        let mut dec = aes128.decrypter(AeadKey::from([0u8; 32]), &[0; 4]);
        assert_eq!(open(dec.as_mut(), vec![0; 40], 0), Err(Error::DecryptError));
        let x = |s: &SupportedCipherSuite, iv: &[u8], ex: &[u8]| {
            suite(s)
                .aead_alg
                .extract_keys(AeadKey::from([1u8; 32]), iv, ex)
        };
        assert!(matches!(
            x(ALL[0], &[0; 4], &[0; 8]),
            Ok(ConnectionTrafficSecrets::Aes256Gcm { .. })
        ));
        assert!(matches!(
            x(ALL[1], &[0; 4], &[0; 8]),
            Ok(ConnectionTrafficSecrets::Aes128Gcm { .. })
        ));
        assert!(matches!(
            x(ALL[2], &[0; 12], &[]),
            Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { .. })
        ));
    }

    #[test]
    fn an_iv_or_explicit_nonce_of_the_wrong_length_refuses() {
        let k = || AeadKey::from([7u8; 32]);
        let gcm = suite(ALL[0]).aead_alg;
        assert_eq!(
            gcm.encrypter(k(), &[1, 2, 3], &[5; 8])
                .encrypted_payload_len(3),
            3
        );
        assert_eq!(
            gcm.encrypter(k(), &[1, 2, 3, 4], &[5; 7])
                .encrypted_payload_len(3),
            3
        );
        assert_eq!(
            open(gcm.decrypter(k(), &[1, 2, 3]).as_mut(), vec![0; 40], 0),
            Err(Error::DecryptError)
        );
        assert!(gcm.extract_keys(k(), &[0; 3], &[0; 8]).is_err());
        assert!(gcm.extract_keys(k(), &[0; 4], &[0; 7]).is_err());
        let chacha = suite(ALL[2]).aead_alg;
        assert_eq!(
            chacha
                .encrypter(k(), &[9; 11], &[])
                .encrypted_payload_len(3),
            3
        );
        assert_eq!(
            open(chacha.decrypter(k(), &[9; 11]).as_mut(), vec![0; 40], 0),
            Err(Error::DecryptError)
        );
        assert!(chacha.extract_keys(k(), &[0; 11], &[]).is_err());
    }
}
