// Ported from rustls 0.23.46 (src/crypto/ring/kx.rs; src/crypto/aws_lc_rs/mod.rs ring_shim;
// src/crypto/aws_lc_rs/pq/{mod,mlkem,hybrid}.rs), Copyright (c) 2016 Joseph Birr-Pixton, used
// under the MIT license. See LICENSE-THIRD-PARTY.
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::{agreement, kem};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, GetRandomFailed, SharedSecret, SupportedKxGroup,
};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use std::fmt;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
const X25519_LEN: usize = 32;
const SECP256R1_LEN: usize = 65;
const SECP384R1_LEN: usize = 97;
const MLKEM768_ENCAP_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM1024_ENCAP_LEN: usize = 1568;
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;

pub(crate) struct Ecdh {
    name: NamedGroup,
    agreement_algorithm: &'static agreement::Algorithm,
    fips_allowed: bool,
    pub_key_validator: fn(&[u8]) -> bool,
}

impl SupportedKxGroup for Ecdh {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let rng = SystemRandom::new();
        let priv_key = agreement::EphemeralPrivateKey::generate(self.agreement_algorithm, &rng)
            .map_err(|_| GetRandomFailed)?;

        let pub_key = priv_key.compute_public_key().map_err(|_| GetRandomFailed)?;

        Ok(Box::new(EcdhActive {
            name: self.name,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key,
            pub_key_validator: self.pub_key_validator,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn fips(&self) -> bool {
        self.fips_allowed && super::assembly::fips()
    }
}

impl fmt::Debug for Ecdh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

pub(crate) static X25519: &dyn SupportedKxGroup = &Ecdh {
    name: NamedGroup::X25519,
    agreement_algorithm: &agreement::X25519,
    fips_allowed: false,
    pub_key_validator: |point: &[u8]| point.len() == 32,
};

pub(crate) static SECP256R1: &dyn SupportedKxGroup = &Ecdh {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};

pub(crate) static SECP384R1: &dyn SupportedKxGroup = &Ecdh {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};

fn uncompressed_point(point: &[u8]) -> bool {
    matches!(point.first(), Some(0x04))
}

struct EcdhActive {
    name: NamedGroup,
    agreement_algorithm: &'static agreement::Algorithm,
    priv_key: agreement::EphemeralPrivateKey,
    pub_key: agreement::PublicKey,
    pub_key_validator: fn(&[u8]) -> bool,
}

impl ActiveKeyExchange for EcdhActive {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if !(self.pub_key_validator)(peer) {
            return Err(INVALID_KEY_SHARE);
        }
        let peer_key = agreement::UnparsedPublicKey::new(self.agreement_algorithm, peer);
        agreement::agree_ephemeral(self.priv_key, peer_key, (), |secret| {
            Ok(SharedSecret::from(secret))
        })
        .map_err(|()| INVALID_KEY_SHARE)
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}

#[derive(Debug)]
pub(crate) struct MlKem {
    alg: &'static kem::Algorithm<kem::AlgorithmId>,
    group: NamedGroup,
}

impl SupportedKxGroup for MlKem {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let decaps_key = kem::DecapsulationKey::generate(self.alg)
            .map_err(|_| Error::General("key generation failed".into()))?;

        let pub_key_bytes = decaps_key
            .encapsulation_key()
            .and_then(|encaps_key| encaps_key.key_bytes())
            .map_err(|_| Error::General("encaps failed".into()))?;

        Ok(Box::new(MlKemActive {
            decaps_key: Box::new(decaps_key),
            encaps_key_bytes: Vec::from(pub_key_bytes.as_ref()),
            group: self.group,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encaps_key =
            kem::EncapsulationKey::new(self.alg, client_share).map_err(|_| INVALID_KEY_SHARE)?;

        let (ciphertext, shared_secret) =
            encaps_key.encapsulate().map_err(|_| INVALID_KEY_SHARE)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: Vec::from(ciphertext.as_ref()),
            secret: SharedSecret::from(shared_secret.as_ref()),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn fips(&self) -> bool {
        super::assembly::fips()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct MlKemActive {
    decaps_key: Box<kem::DecapsulationKey<kem::AlgorithmId>>,
    encaps_key_bytes: Vec<u8>,
    group: NamedGroup,
}

impl ActiveKeyExchange for MlKemActive {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let shared_secret = self
            .decaps_key
            .decapsulate(peer_pub_key.into())
            .map_err(|_| INVALID_KEY_SHARE)?;

        Ok(SharedSecret::from(shared_secret.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encaps_key_bytes
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

static MLKEM768: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_768,
    group: NamedGroup::MLKEM768,
};

pub(crate) static MLKEM1024: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_1024,
    group: NamedGroup::MLKEM1024,
};

#[derive(Debug)]
pub(crate) struct Hybrid {
    classical: &'static dyn SupportedKxGroup,
    post_quantum: &'static dyn SupportedKxGroup,
    name: NamedGroup,
    layout: Layout,
}

impl SupportedKxGroup for Hybrid {
    #[expect(clippy::disallowed_methods)]
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let post_quantum = self.post_quantum.start()?;

        let combined_pub_key = self
            .layout
            .concat(post_quantum.pub_key(), classical.pub_key());

        Ok(Box::new(ActiveHybrid {
            classical,
            post_quantum,
            name: self.name,
            layout: self.layout,
            combined_pub_key,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (post_quantum_share, classical_share) = self
            .layout
            .split_received_client_share(client_share)
            .ok_or(INVALID_KEY_SHARE)?;

        let cl = self.classical.start_and_complete(classical_share)?;
        let pq = self.post_quantum.start_and_complete(post_quantum_share)?;

        let combined_pub_key = self.layout.concat(&pq.pub_key, &cl.pub_key);
        let secret = self
            .layout
            .concat(pq.secret.secret_bytes(), cl.secret.secret_bytes());

        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: combined_pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn fips(&self) -> bool {
        match self.layout.post_quantum_first {
            true => self.post_quantum.fips(),
            false => self.classical.fips(),
        }
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    name: NamedGroup,
    layout: Layout,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let (post_quantum_share, classical_share) = self
            .layout
            .split_received_server_share(peer_pub_key)
            .ok_or(INVALID_KEY_SHARE)?;

        let cl = self.classical.complete(classical_share)?;
        let pq = self.post_quantum.complete(post_quantum_share)?;

        let secret = self.layout.concat(pq.secret_bytes(), cl.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    classical_share_len: usize,
    post_quantum_client_share_len: usize,
    post_quantum_server_share_len: usize,
    post_quantum_first: bool,
}

impl Layout {
    fn split_received_client_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_client_share_len)
    }

    fn split_received_server_share<'a>(&self, share: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        self.split(share, self.post_quantum_server_share_len)
    }

    fn split<'a>(
        &self,
        share: &'a [u8],
        post_quantum_share_len: usize,
    ) -> Option<(&'a [u8], &'a [u8])> {
        if share.len() != self.classical_share_len + post_quantum_share_len {
            return None;
        }

        Some(match self.post_quantum_first {
            true => {
                let (first_share, second_share) = share.split_at(post_quantum_share_len);
                (first_share, second_share)
            }
            false => {
                let (first_share, second_share) = share.split_at(self.classical_share_len);
                (second_share, first_share)
            }
        })
    }

    fn concat(&self, post_quantum: &[u8], classical: &[u8]) -> Vec<u8> {
        match self.post_quantum_first {
            true => [post_quantum, classical].concat(),
            false => [classical, post_quantum].concat(),
        }
    }
}

pub(crate) static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

pub(crate) static SECP256R1MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: Layout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

pub(crate) static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &Hybrid {
    classical: SECP384R1,
    post_quantum: MLKEM1024,
    name: NamedGroup::Unknown(0x11ED),
    layout: Layout {
        classical_share_len: SECP384R1_LEN,
        post_quantum_client_share_len: MLKEM1024_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM1024_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(g: NamedGroup) -> u16 {
        u16::from_be_bytes(g.to_array())
    }

    #[test]
    fn every_group_names_its_registry_codepoint_and_has_no_ffdhe_group() {
        for (g, want) in [
            (X25519, 0x001D),
            (SECP256R1, 0x0017),
            (SECP384R1, 0x0018),
            (MLKEM1024, 0x0202),
            (X25519MLKEM768, 0x11EC),
            (SECP256R1MLKEM768, 0x11EB),
            (SECP384R1MLKEM1024, 0x11ED),
        ] {
            assert_eq!(cp(g.name()), want);
            assert!(g.ffdhe_group().is_none(), "{want:#06x}");
        }
        assert_eq!(SECP384R1MLKEM1024.name(), NamedGroup::Unknown(0x11ED));
    }

    #[test]
    fn fips_follows_rustls_classification() {
        assert!(aws_lc_rs::try_fips_mode().is_ok());
        let want = [
            (X25519, false),
            (SECP256R1, true),
            (SECP384R1, true),
            (MLKEM1024, true),
            (X25519MLKEM768, true),
            (SECP256R1MLKEM768, true),
            (SECP384R1MLKEM1024, true),
        ];
        for (g, fips) in want {
            assert_eq!(g.fips(), fips, "{:?}", g.name());
        }
    }

    #[test]
    fn post_quantum_groups_are_tls13_only_and_ecdh_is_not() {
        for g in [
            MLKEM1024,
            X25519MLKEM768,
            SECP256R1MLKEM768,
            SECP384R1MLKEM1024,
        ] {
            assert!(g.usable_for_version(ProtocolVersion::TLSv1_3));
            assert!(!g.usable_for_version(ProtocolVersion::TLSv1_2));
        }
        for g in [X25519, SECP256R1, SECP384R1] {
            assert!(g.usable_for_version(ProtocolVersion::TLSv1_2));
        }
    }

    #[test]
    fn ecdh_debug_is_the_group_name() {
        assert_eq!(format!("{X25519:?}"), "X25519");
        assert_eq!(format!("{SECP384R1:?}"), "secp384r1");
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn secp384r1mlkem1024_client_share_is_the_p384_point_then_the_encapsulation_key() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        let share = client.pub_key().to_vec();
        assert_eq!(share.len(), 97 + 1568);
        assert_eq!(share[0], 0x04);
        assert_eq!(
            client.hybrid_component(),
            Some((NamedGroup::secp384r1, &share[..97]))
        );
        let ecdh = SECP384R1.start_and_complete(&share[..97]).unwrap();
        let kem = MLKEM1024.start_and_complete(&share[97..]).unwrap();
        let server_share = [ecdh.pub_key.as_slice(), kem.pub_key.as_slice()].concat();
        let secret = client.complete(&server_share).unwrap();
        assert_eq!(secret.secret_bytes().len(), 48 + 32);
        assert_eq!(
            secret.secret_bytes(),
            [ecdh.secret.secret_bytes(), kem.secret.secret_bytes()].concat()
        );
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn secp384r1mlkem1024_server_share_and_secret_put_p384_first() {
        let ecdh = SECP384R1.start().unwrap();
        let kem = MLKEM1024.start().unwrap();
        let client_share = [ecdh.pub_key(), kem.pub_key()].concat();
        assert_eq!(client_share.len(), 1665);
        let done = SECP384R1MLKEM1024
            .start_and_complete(&client_share)
            .unwrap();
        assert_eq!(cp(done.group), 0x11ED);
        assert_eq!(done.pub_key.len(), 97 + 1568);
        assert_eq!(done.pub_key[0], 0x04);
        let want = [
            ecdh.complete(&done.pub_key[..97])
                .unwrap()
                .secret_bytes()
                .to_vec(),
            kem.complete(&done.pub_key[97..])
                .unwrap()
                .secret_bytes()
                .to_vec(),
        ]
        .concat();
        assert_eq!(done.secret.secret_bytes(), want.as_slice());
        assert_eq!(want.len(), 80);
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn the_other_hybrids_keep_their_layouts() {
        let x = X25519MLKEM768.start().unwrap();
        assert_eq!(x.pub_key().len(), 1184 + 32);
        assert_eq!(
            x.hybrid_component(),
            Some((NamedGroup::X25519, &x.pub_key()[1184..]))
        );
        let p = SECP256R1MLKEM768.start().unwrap();
        assert_eq!(p.pub_key().len(), 65 + 1184);
        assert_eq!(
            p.hybrid_component(),
            Some((NamedGroup::secp256r1, &p.pub_key()[..65]))
        );
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn the_classical_component_completes_alone() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        let (_, share) = client.hybrid_component().unwrap();
        let server = SECP384R1.start_and_complete(share).unwrap();
        let secret = client.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn a_secp384r1mlkem1024_share_of_the_wrong_length_is_refused() {
        for len in [1664, 1666] {
            assert_eq!(
                SECP384R1MLKEM1024.start_and_complete(&vec![4; len]).err(),
                Some(INVALID_KEY_SHARE)
            );
            let client = SECP384R1MLKEM1024.start().unwrap();
            assert_eq!(
                client.complete(&vec![4; len]).err(),
                Some(INVALID_KEY_SHARE)
            );
        }
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn a_hybrid_with_a_bad_classical_point_is_refused() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        let mut share = client.pub_key().to_vec();
        share[0] = 0x03;
        assert_eq!(
            SECP384R1MLKEM1024.start_and_complete(&share).err(),
            Some(INVALID_KEY_SHARE)
        );
        assert_eq!(
            X25519.start().unwrap().complete(&[9; 31]).err(),
            Some(INVALID_KEY_SHARE)
        );
        assert_eq!(
            MLKEM1024.start().unwrap().complete(&[0; 1567]).err(),
            Some(INVALID_KEY_SHARE)
        );
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn a_compressed_p384_point_is_refused() {
        let peer = SECP384R1.start().unwrap();
        let point = peer.pub_key();
        let mut compressed = vec![0x02 | (point[96] & 1)];
        compressed.extend_from_slice(&point[1..49]);
        assert_eq!(compressed.len(), 49);
        let probe =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P384, &SystemRandom::new())
                .unwrap();
        let decoded = agreement::agree_ephemeral(
            probe,
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P384, &compressed),
            (),
            |_| Ok(()),
        );
        assert_eq!(decoded, Ok(()));
        assert_eq!(
            SECP384R1.start().unwrap().complete(&compressed).err(),
            Some(INVALID_KEY_SHARE)
        );
        assert_eq!(
            SECP384R1.start_and_complete(&compressed).err(),
            Some(INVALID_KEY_SHARE)
        );
    }
}
