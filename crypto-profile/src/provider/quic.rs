// Ported from rustls 0.23.46 (src/crypto/ring/quic.rs, included by src/crypto/aws_lc_rs/mod.rs;
// the algorithms from src/crypto/aws_lc_rs/tls13.rs), Copyright (c) 2016 Joseph Birr-Pixton, used
// under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::aead;
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;

pub(crate) static AES_128_GCM: KeyBuilder = KeyBuilder {
    packet_alg: &aead::AES_128_GCM,
    header_alg: &aead::quic::AES_128,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
    approved: true,
};

pub(crate) static AES_256_GCM: KeyBuilder = KeyBuilder {
    packet_alg: &aead::AES_256_GCM,
    header_alg: &aead::quic::AES_256,
    confidentiality_limit: 1 << 23,
    integrity_limit: 1 << 52,
    approved: true,
};

pub(crate) static CHACHA20_POLY1305: KeyBuilder = KeyBuilder {
    packet_alg: &aead::CHACHA20_POLY1305,
    header_alg: &aead::quic::CHACHA20,
    confidentiality_limit: u64::MAX,
    integrity_limit: 1 << 36,
    approved: false,
};

pub(crate) struct KeyBuilder {
    packet_alg: &'static aead::Algorithm,
    header_alg: &'static aead::quic::Algorithm,
    confidentiality_limit: u64,
    integrity_limit: u64,
    approved: bool,
}

impl quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            key: aead::UnboundKey::new(self.packet_alg, key.as_ref())
                .ok()
                .map(aead::LessSafeKey::new),
            alg: self.packet_alg,
            iv,
            confidentiality_limit: self.confidentiality_limit,
            integrity_limit: self.integrity_limit,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey {
            key: aead::quic::HeaderProtectionKey::new(self.header_alg, key.as_ref()).ok(),
            alg: self.header_alg,
        })
    }

    fn aead_key_len(&self) -> usize {
        self.packet_alg.key_len()
    }

    fn fips(&self) -> bool {
        self.approved && super::assembly::fips()
    }
}

struct HeaderProtectionKey {
    key: Option<aead::quic::HeaderProtectionKey>,
    alg: &'static aead::quic::Algorithm,
}

impl HeaderProtectionKey {
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let [first_mask, pn_mask @ ..] = self
            .key
            .as_ref()
            .ok_or(Error::General("unusable header protection key".into()))?
            .new_mask(sample)
            .map_err(|_| Error::General("sample of invalid length".into()))?;
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        let bits = match *first & 0x80 == 0x80 {
            true => 0x0f,
            false => 0x1f,
        };
        let first_plain = match masked {
            true => *first ^ (first_mask & bits),
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(&pn_mask).take(pn_len) {
            *dst ^= m;
        }
        Ok(())
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        self.alg.sample_len()
    }
}

struct PacketKey {
    key: Option<aead::LessSafeKey>,
    alg: &'static aead::Algorithm,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl PacketKey {
    fn seal(&self, nonce: Nonce, header: &[u8], payload: &mut [u8]) -> Result<quic::Tag, Error> {
        let tag = self
            .key
            .as_ref()
            .ok_or(Error::EncryptError)?
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce.0),
                aead::Aad::from(header),
                payload,
            )
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn open<'a>(
        &self,
        nonce: Nonce,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain = self
            .key
            .as_ref()
            .ok_or(Error::DecryptError)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce.0),
                aead::Aad::from(header),
                payload,
            )
            .map_err(|_| Error::DecryptError)?;
        Ok(plain)
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.seal(Nonce::new(&self.iv, packet_number), header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.seal(
            Nonce::for_path(path_id, &self.iv, packet_number),
            header,
            payload,
        )
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.open(Nonce::new(&self.iv, packet_number), header, payload)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.open(
            Nonce::for_path(path_id, &self.iv, packet_number),
            header,
            payload,
        )
    }

    fn tag_len(&self) -> usize {
        self.alg.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

#[cfg(test)]
mod tests {
    use super::super::tls13::tests::{hx, unhex};
    use super::super::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use crate::tls::{Policy, client_builder, server_builder};
    use crate::{
        CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
        TlsVersion as V,
    };
    use rustls::crypto::cipher::{AeadKey, Iv};
    use rustls::crypto::tls13::OkmBlock;
    use rustls::quic::{Algorithm, DirectionalKeys, KeyChange, Keys, PacketKeySet, Version};
    use rustls::{Side, SupportedCipherSuite, Tls13CipherSuite};
    use std::sync::Arc;

    /// RFC 9001 Appendix A: the client-chosen Destination Connection ID.
    const DCID: &str = "8394c8f03e515708";
    /// RFC 9001 Section 5.2: the QUIC v1 initial salt.
    const INITIAL_SALT_V1: &str = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

    /// RFC 9001 Appendix A.2: the client Initial's CRYPTO frame, before its PADDING.
    const A2_FRAME: &str = concat!(
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba",
        "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
        "0d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000",
        "75300901100f088394c8f03e51570806048000ffff",
    );

    /// RFC 9001 Appendix A.2: the resulting protected client Initial packet.
    const A2_PACKET: &str = concat!(
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
        "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
        "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
        "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
        "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
        "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
        "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
        "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
        "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
        "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
        "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
        "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
        "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
        "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
        "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
        "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
        "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
        "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
        "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
        "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
        "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
        "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
        "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
        "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
        "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
        "e221af44860018ab0856972e194cd934",
    );

    /// RFC 9001 Appendix A.3: the server Initial's payload.
    const A3_PAYLOAD: &str = concat!(
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739",
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94",
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00",
        "020304",
    );

    /// RFC 9001 Appendix A.3: the final protected server Initial packet.
    const A3_PACKET: &str = concat!(
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3",
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4",
        "2158407dd074ee",
    );

    fn tls13(s: &SupportedCipherSuite) -> &'static Tls13CipherSuite {
        match s {
            SupportedCipherSuite::Tls13(t) => t,
            SupportedCipherSuite::Tls12(_) => panic!("a TLS 1.2 suite"),
        }
    }

    fn quic_of(s: &SupportedCipherSuite) -> &'static dyn Algorithm {
        tls13(s).quic.unwrap()
    }

    fn initial(s: &SupportedCipherSuite, side: Side) -> Keys {
        tls13(s)
            .quic_suite()
            .unwrap()
            .keys(&unhex(DCID), side, Version::V1)
    }

    fn expand(s: &SupportedCipherSuite, secret: &[u8], label: &str, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        tls13(s)
            .hkdf_provider
            .expander_for_okm(&OkmBlock::new(secret))
            .expand_slice(&[unhex(label).as_slice()], &mut out)
            .unwrap();
        out
    }

    fn label(len: u16, name: &str) -> String {
        let mut l = len.to_be_bytes().to_vec();
        let full = format!("tls13 {name}");
        l.push(full.len() as u8);
        l.extend(full.as_bytes());
        l.push(0);
        hx(&l)
    }

    #[test]
    fn the_suites_carry_rustls_quic_algorithms() {
        let all = [
            &TLS13_AES_256_GCM_SHA384,
            &TLS13_AES_128_GCM_SHA256,
            &TLS13_CHACHA20_POLY1305_SHA256,
        ];
        assert!(all.iter().all(|s| tls13(s).quic_suite().is_some()));
        let key_lens: Vec<usize> = all.iter().map(|s| quic_of(s).aead_key_len()).collect();
        assert_eq!(key_lens, [32, 16, 32]);
        let fips: Vec<bool> = all.iter().map(|s| quic_of(s).fips()).collect();
        assert_eq!(fips, [true, true, false]);
        let packets: Vec<_> = all
            .iter()
            .map(|s| quic_of(s).packet_key(AeadKey::from([1; 32]), Iv::new([2; 12])))
            .collect();
        let limits: Vec<(u64, u64, usize)> = packets
            .iter()
            .map(|p| (p.confidentiality_limit(), p.integrity_limit(), p.tag_len()))
            .collect();
        assert_eq!(
            limits,
            [
                (8_388_608, 4_503_599_627_370_496, 16),
                (8_388_608, 4_503_599_627_370_496, 16),
                (u64::MAX, 68_719_476_736, 16),
            ]
        );
        let samples: Vec<usize> = all
            .iter()
            .map(|s| {
                quic_of(s)
                    .header_protection_key(AeadKey::from([3; 32]))
                    .sample_len()
            })
            .collect();
        assert_eq!(samples, [16, 16, 16]);
    }

    #[test]
    fn rfc_9001_a1_labels_and_initial_keys() {
        assert_eq!(
            label(32, "client in"),
            "00200f746c73313320636c69656e7420696e00"
        );
        assert_eq!(
            label(32, "server in"),
            "00200f746c7331332073657276657220696e00"
        );
        assert_eq!(
            label(16, "quic key"),
            "00100e746c7331332071756963206b657900"
        );
        assert_eq!(label(12, "quic iv"), "000c0d746c733133207175696320697600");
        assert_eq!(label(16, "quic hp"), "00100d746c733133207175696320687000");
        let s = &TLS13_AES_128_GCM_SHA256;
        let mut secret = [0u8; 32];
        tls13(s)
            .hkdf_provider
            .extract_from_secret(Some(&unhex(INITIAL_SALT_V1)), &unhex(DCID))
            .expand_slice(&[unhex(&label(32, "client in")).as_slice()], &mut secret)
            .unwrap();
        assert_eq!(
            hx(&secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let mut server = [0u8; 32];
        tls13(s)
            .hkdf_provider
            .extract_from_secret(Some(&unhex(INITIAL_SALT_V1)), &unhex(DCID))
            .expand_slice(&[unhex(&label(32, "server in")).as_slice()], &mut server)
            .unwrap();
        assert_eq!(
            hx(&server),
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
        );
        for (secret, key, iv, hp) in [
            (
                secret,
                "1f369613dd76d5467730efcbe3b1a22d",
                "fa044b2f42a3fd3b46fb255c",
                "9f50449e04a0e810283a1e9933adedd2",
            ),
            (
                server,
                "cf3a5331653c364c88f0f379b6067e37",
                "0ac1493ca1905853b0bba03e",
                "c206b8d9b9f0f37644430b490eeaa314",
            ),
        ] {
            assert_eq!(hx(&expand(s, &secret, &label(16, "quic key"), 16)), key);
            assert_eq!(hx(&expand(s, &secret, &label(12, "quic iv"), 12)), iv);
            assert_eq!(hx(&expand(s, &secret, &label(16, "quic hp"), 16)), hp);
        }
    }

    #[test]
    fn rfc_9001_a2_client_initial_packet() {
        let client = initial(&TLS13_AES_128_GCM_SHA256, Side::Client);
        let mut header = unhex("c300000001088394c8f03e5157080000449e00000002");
        let mut payload = unhex(A2_FRAME);
        payload.resize(1162, 0);
        let plain = payload.clone();
        let tag = client
            .local
            .packet
            .encrypt_in_place(2, &header, &mut payload)
            .unwrap();
        assert_eq!(hx(&payload[..16]), "d1b1c98dd7689fb8ec11d242b123dc9b");
        let (first, rest) = header.split_at_mut(1);
        client
            .local
            .header
            .encrypt_in_place(&payload[..16], &mut first[0], &mut rest[17..21])
            .unwrap();
        assert_eq!(hx(&header), "c000000001088394c8f03e5157080000449e7b9aec34");
        let mut packet = header.clone();
        packet.extend(&payload);
        packet.extend(tag.as_ref());
        assert_eq!(hx(&packet), A2_PACKET);

        let server = initial(&TLS13_AES_128_GCM_SHA256, Side::Server);
        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest[17..].split_at_mut(4);
        server
            .remote
            .header
            .decrypt_in_place(&body[..16], &mut first[0], pn)
            .unwrap();
        assert_eq!(
            hx(&packet[..22]),
            "c300000001088394c8f03e5157080000449e00000002"
        );
        let (header, body) = packet.split_at_mut(22);
        let opened = server
            .remote
            .packet
            .decrypt_in_place(2, header, body)
            .unwrap();
        assert_eq!(opened, plain.as_slice());
    }

    #[test]
    fn rfc_9001_a3_server_initial_packet() {
        let server = initial(&TLS13_AES_128_GCM_SHA256, Side::Server);
        let mut header = unhex("c1000000010008f067a5502a4262b50040750001");
        let mut payload = unhex(A3_PAYLOAD);
        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &header, &mut payload)
            .unwrap();
        assert_eq!(hx(&payload[2..18]), "2cd0991cd25b0aac406a5816b6394100");
        let (first, rest) = header.split_at_mut(1);
        server
            .local
            .header
            .encrypt_in_place(&payload[2..18], &mut first[0], &mut rest[17..19])
            .unwrap();
        assert_eq!(hx(&header), "cf000000010008f067a5502a4262b5004075c0d9");
        let mut packet = header;
        packet.extend(&payload);
        packet.extend(tag.as_ref());
        assert_eq!(hx(&packet), A3_PACKET);

        let client = initial(&TLS13_AES_128_GCM_SHA256, Side::Client);
        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest[17..].split_at_mut(2);
        client
            .remote
            .header
            .decrypt_in_place(&body[2..18], &mut first[0], pn)
            .unwrap();
        assert_eq!(
            hx(&packet[..20]),
            "c1000000010008f067a5502a4262b50040750001"
        );
        let (header, body) = packet.split_at_mut(20);
        let opened = client
            .remote
            .packet
            .decrypt_in_place(1, header, body)
            .unwrap();
        assert_eq!(hx(opened), A3_PAYLOAD);
    }

    #[test]
    fn rfc_9001_a5_chacha20_short_header_packet() {
        let s = &TLS13_CHACHA20_POLY1305_SHA256;
        let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let key = expand(s, &secret, &label(32, "quic key"), 32);
        let iv = expand(s, &secret, &label(12, "quic iv"), 12);
        let hp = expand(s, &secret, &label(32, "quic hp"), 32);
        assert_eq!(
            hx(&key),
            "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"
        );
        assert_eq!(hx(&iv), "e0459b3474bdd0e44a41c144");
        assert_eq!(
            hx(&hp),
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
        );
        let packet_key = quic_of(s).packet_key(
            AeadKey::from(<[u8; 32]>::try_from(key).unwrap()),
            Iv::new(<[u8; 12]>::try_from(iv).unwrap()),
        );
        let header_key =
            quic_of(s).header_protection_key(AeadKey::from(<[u8; 32]>::try_from(hp).unwrap()));

        let mut packet = unhex("4200bff401");
        let (header, payload) = packet.split_at_mut(4);
        let tag = packet_key
            .encrypt_in_place(654_360_564, header, payload)
            .unwrap();
        packet.extend(tag.as_ref());
        assert_eq!(hx(&packet[4..]), "655e5cd55c41f69080575d7999c25a5bfb");
        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest.split_at_mut(3);
        header_key
            .encrypt_in_place(&body[1..17], &mut first[0], pn)
            .unwrap();
        assert_eq!(hx(&packet), "4cfe4189655e5cd55c41f69080575d7999c25a5bfb");

        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest.split_at_mut(3);
        header_key
            .decrypt_in_place(&body[1..17], &mut first[0], pn)
            .unwrap();
        assert_eq!(hx(&packet[..4]), "4200bff4");
        let (header, body) = packet.split_at_mut(4);
        let opened = packet_key
            .decrypt_in_place(654_360_564, header, body)
            .unwrap();
        assert_eq!(opened, [0x01]);
    }

    #[test]
    fn header_protection_masks_four_or_five_bits_and_only_the_encoded_packet_number() {
        let hp = [5u8; 32];
        let raw =
            aws_lc_rs::aead::quic::HeaderProtectionKey::new(&aws_lc_rs::aead::quic::CHACHA20, &hp)
                .unwrap();
        let (sample, mask) = (0u8..=255)
            .map(|i| [i; 16])
            .map(|s| (s, raw.new_mask(&s).unwrap()))
            .find(|(_, m)| m[0] & 0x10 == 0x10)
            .unwrap();
        let key = quic_of(&TLS13_CHACHA20_POLY1305_SHA256).header_protection_key(AeadKey::from(hp));
        for (first, bits) in [(0xc1u8, 0x0fu8), (0x41, 0x1f)] {
            let (mut f, mut pn) = (first, [0u8; 4]);
            key.encrypt_in_place(&sample, &mut f, &mut pn).unwrap();
            assert_eq!(f, first ^ (mask[0] & bits), "{first:#04x}");
            assert_eq!(pn, [mask[1], mask[2], 0, 0], "{first:#04x}");
            key.decrypt_in_place(&sample, &mut f, &mut pn).unwrap();
            assert_eq!((f, pn), (first, [0; 4]), "{first:#04x}");
        }
    }

    #[test]
    fn header_protection_refuses_a_bad_sample_a_long_packet_number_or_a_bad_key() {
        let key = quic_of(&TLS13_AES_128_GCM_SHA256);
        let hp = initial(&TLS13_AES_128_GCM_SHA256, Side::Client)
            .local
            .header;
        let (mut first, mut pn) = (0xc3u8, [0u8; 5]);
        assert_eq!(
            hp.encrypt_in_place(&[0; 16], &mut first, &mut pn),
            Err(rustls::Error::General("packet number too long".into()))
        );
        assert_eq!((first, pn), (0xc3, [0; 5]));
        assert_eq!(
            hp.decrypt_in_place(&[0; 15], &mut first, &mut pn[..4]),
            Err(rustls::Error::General("sample of invalid length".into()))
        );
        assert!(
            hp.encrypt_in_place(&[0; 16], &mut first, &mut pn[..4])
                .is_ok()
        );
        let unusable = key.header_protection_key(AeadKey::from([0; 32]));
        assert_eq!(unusable.sample_len(), 16);
        assert_eq!(
            unusable.encrypt_in_place(&[0; 16], &mut first, &mut pn[..4]),
            Err(rustls::Error::General(
                "unusable header protection key".into()
            ))
        );
    }

    #[test]
    fn a_packet_key_of_the_wrong_length_refuses_and_a_changed_packet_is_refused() {
        let alg = quic_of(&TLS13_AES_128_GCM_SHA256);
        let unusable = alg.packet_key(AeadKey::from([0; 32]), Iv::new([0; 12]));
        assert_eq!(unusable.tag_len(), 16);
        assert_eq!(
            unusable.encrypt_in_place(0, b"h", &mut [0; 4]).err(),
            Some(rustls::Error::EncryptError)
        );
        assert_eq!(
            unusable.decrypt_in_place(0, b"h", &mut [0; 20]).err(),
            Some(rustls::Error::DecryptError)
        );
        let keys = initial(&TLS13_AES_128_GCM_SHA256, Side::Client);
        let peer = initial(&TLS13_AES_128_GCM_SHA256, Side::Server);
        let mut body = b"payload".to_vec();
        let tag = keys
            .local
            .packet
            .encrypt_in_place(7, b"h", &mut body)
            .unwrap();
        body.extend(tag.as_ref());
        let mut wrong_pn = body.clone();
        assert_eq!(
            peer.remote
                .packet
                .decrypt_in_place(8, b"h", &mut wrong_pn)
                .err(),
            Some(rustls::Error::DecryptError)
        );
        let mut wrong_header = body.clone();
        assert_eq!(
            peer.remote
                .packet
                .decrypt_in_place(7, b"x", &mut wrong_header)
                .err(),
            Some(rustls::Error::DecryptError)
        );
        assert_eq!(
            peer.remote
                .packet
                .decrypt_in_place(7, b"h", &mut body)
                .unwrap(),
            b"payload"
        );
    }

    #[test]
    fn a_path_nonce_is_the_packet_nonce_on_path_zero_and_differs_on_another_path() {
        for s in [&TLS13_AES_256_GCM_SHA384, &TLS13_CHACHA20_POLY1305_SHA256] {
            let keys = initial(s, Side::Client);
            let peer = initial(s, Side::Server);
            let seal = |path: Option<u32>| {
                let mut body = b"multipath".to_vec();
                let tag = match path {
                    Some(id) => keys
                        .local
                        .packet
                        .encrypt_in_place_for_path(id, 9, b"h", &mut body),
                    None => keys.local.packet.encrypt_in_place(9, b"h", &mut body),
                }
                .unwrap();
                body.extend(tag.as_ref());
                body
            };
            assert_eq!(seal(Some(0)), seal(None));
            let mut on_path_2 = seal(Some(2));
            assert_ne!(on_path_2, seal(None));
            assert_eq!(
                peer.remote
                    .packet
                    .decrypt_in_place(9, b"h", &mut on_path_2.clone())
                    .err(),
                Some(rustls::Error::DecryptError)
            );
            assert_eq!(
                peer.remote
                    .packet
                    .decrypt_in_place_for_path(3, 9, b"h", &mut on_path_2.clone())
                    .err(),
                Some(rustls::Error::DecryptError)
            );
            assert_eq!(
                peer.remote
                    .packet
                    .decrypt_in_place_for_path(2, 9, b"h", &mut on_path_2)
                    .unwrap(),
                b"multipath"
            );
        }
    }

    fn policy(versions: &[V], suite: C) -> Policy {
        Policy {
            versions: versions.to_vec(),
            cipher_suites: vec![suite],
            kx_groups: vec![K::Secp384r1MlKem1024, K::Secp384r1],
            signature_schemes: T::ALL
                .into_iter()
                .filter(|s| {
                    crate::capability(crate::MODULE, crate::Algorithm::Scheme(*s)).available
                })
                .collect(),
        }
    }

    fn configs(p: &Policy) -> (rustls::ClientConfig, rustls::ServerConfig) {
        let pki = crate::test_support::pki(S::EcdsaP384Sha384, S::EcdsaP384Sha384).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(pki.key.pkcs8_der().to_vec().into());
        let mut server = server_builder(p)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(pki.chain, key)
            .unwrap();
        server.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = client_builder(p)
            .unwrap()
            .with_root_certificates(pki.roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        (client, server)
    }

    fn step(
        from: &mut rustls::quic::Connection,
        to: &mut rustls::quic::Connection,
    ) -> Option<KeyChange> {
        let mut buf = Vec::new();
        let change = loop {
            let before = buf.len();
            if let Some(change) = from.write_hs(&mut buf) {
                break Some(change);
            }
            if buf.len() == before {
                break None;
            }
        };
        to.read_hs(&buf).unwrap();
        change
    }

    fn one_rtt(changes: Vec<KeyChange>) -> (DirectionalKeys, DirectionalKeys, PacketKeySet) {
        let mut handshakes = 0;
        let mut found = None;
        for c in changes {
            match c {
                KeyChange::Handshake { .. } => handshakes += 1,
                KeyChange::OneRtt { keys, mut next } => {
                    found = Some((keys.local, keys.remote, next.next_packet_keys()))
                }
            }
        }
        assert_eq!(handshakes, 1);
        found.unwrap()
    }

    fn crosses(from: &DirectionalKeys, to: &DirectionalKeys) {
        let mut packet = b"\x41\x00\x00\x00one-rtt application data".to_vec();
        let (header, body) = packet.split_at_mut(4);
        let tag = from.packet.encrypt_in_place(5, header, body).unwrap();
        packet.extend(tag.as_ref());
        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest.split_at_mut(3);
        from.header
            .encrypt_in_place(&body[1..17], &mut first[0], pn)
            .unwrap();
        assert_ne!(&packet[..4], b"\x41\x00\x00\x00");
        let (first, rest) = packet.split_at_mut(1);
        let (pn, body) = rest.split_at_mut(3);
        to.header
            .decrypt_in_place(&body[1..17], &mut first[0], pn)
            .unwrap();
        let (header, body) = packet.split_at_mut(4);
        assert_eq!(header, b"\x41\x00\x00\x00");
        assert_eq!(
            to.packet.decrypt_in_place(5, header, body).unwrap(),
            b"one-rtt application data"
        );
    }

    #[test]
    fn a_quic_handshake_completes_on_each_tls13_suite_and_its_keys_interoperate() {
        for suite in [
            C::Tls13Aes256GcmSha384,
            C::Tls13Aes128GcmSha256,
            C::Tls13Chacha20Poly1305Sha256,
        ] {
            let (client_cfg, server_cfg) = configs(&policy(&[V::Tls13], suite));
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut client: rustls::quic::Connection = rustls::quic::ClientConnection::new(
                Arc::new(client_cfg),
                Version::V1,
                name,
                b"client transport parameters".to_vec(),
            )
            .unwrap()
            .into();
            let mut server: rustls::quic::Connection = rustls::quic::ServerConnection::new(
                Arc::new(server_cfg),
                Version::V1,
                b"server transport parameters".to_vec(),
            )
            .unwrap()
            .into();
            let (mut client_changes, mut server_changes) = (Vec::new(), Vec::new());
            for _ in 0..8 {
                client_changes.extend(step(&mut client, &mut server));
                server_changes.extend(step(&mut server, &mut client));
            }
            assert!(
                !client.is_handshaking() && !server.is_handshaking(),
                "{suite:?}"
            );
            assert_eq!(
                client
                    .negotiated_cipher_suite()
                    .map(|s| s.suite().to_array()),
                Some(suite.iana().to_be_bytes())
            );
            assert_eq!(
                client
                    .negotiated_key_exchange_group()
                    .map(|g| g.name().to_array()),
                Some([0x11, 0xed])
            );
            assert_eq!(
                client.quic_transport_parameters(),
                Some(&b"server transport parameters"[..])
            );
            assert_eq!(
                server.quic_transport_parameters(),
                Some(&b"client transport parameters"[..])
            );
            let (client_local, client_remote, client_next) = one_rtt(client_changes);
            let (server_local, server_remote, server_next) = one_rtt(server_changes);
            crosses(&client_local, &server_remote);
            crosses(&server_local, &client_remote);
            let mut body = b"after a key update".to_vec();
            let tag = client_next
                .local
                .encrypt_in_place(1, b"h", &mut body)
                .unwrap();
            body.extend(tag.as_ref());
            assert_eq!(
                server_next
                    .remote
                    .decrypt_in_place(1, b"h", &mut body)
                    .unwrap(),
                b"after a key update"
            );
        }
    }

    #[test]
    fn a_quic_connection_needs_a_policy_that_admits_tls13() {
        let (client_cfg, server_cfg) =
            configs(&policy(&[V::Tls12], C::Tls12EcdheEcdsaAes256GcmSha384));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let refused = rustls::Error::General("TLS 1.3 support is required for QUIC".into());
        assert_eq!(
            rustls::quic::ClientConnection::new(Arc::new(client_cfg), Version::V1, name, vec![])
                .err(),
            Some(refused.clone())
        );
        assert_eq!(
            rustls::quic::ServerConnection::new(Arc::new(server_cfg), Version::V1, vec![]).err(),
            Some(refused)
        );
    }
}
