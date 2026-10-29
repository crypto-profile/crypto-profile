#![allow(missing_docs)]
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, KeyPair as _};
use crypto_profile_awslc4::rustls;
use crypto_profile_awslc4::test_support::{Pki, drive, pki, recording};
use crypto_profile_awslc4::tls::{
    Policy, client_builder, crypto_provider, server_builder, server_cert_verifier_builder,
};
use crypto_profile_awslc4::{
    CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
    TlsVersion as V,
};
use rustls::crypto::aws_lc_rs::{cipher_suite as rs, kx_group as rk};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::pki_types::{PrivateKeyDer, SignatureVerificationAlgorithm};
use rustls::quic::{DirectionalKeys, Version};
use rustls::{
    ClientConfig, HandshakeKind, ServerConfig, Side, SignatureScheme, SupportedCipherSuite,
};
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Option<SignatureScheme>>>;

#[derive(Debug)]
struct Case {
    version: V,
    suite: C,
    group: K,
    scheme: T,
    key: S,
    wire: [u16; 4],
    reference: (
        SupportedCipherSuite,
        &'static dyn SupportedKxGroup,
        SignatureScheme,
    ),
}

fn e(x: impl std::fmt::Display) -> String {
    x.to_string()
}

#[expect(clippy::disallowed_methods)]
fn stock() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

fn reference(c: &Case) -> CryptoProvider {
    let base = stock();
    let rows: Vec<_> = base
        .signature_verification_algorithms
        .mapping
        .iter()
        .copied()
        .filter(|(s, _)| *s == c.reference.2)
        .collect();
    CryptoProvider {
        cipher_suites: vec![c.reference.0],
        kx_groups: vec![c.reference.1],
        signature_verification_algorithms: WebPkiSupportedAlgorithms {
            all: base.signature_verification_algorithms.all,
            mapping: Box::leak(rows.into_boxed_slice()),
        },
        ..base
    }
}

fn policy(c: &Case) -> Policy {
    Policy {
        peer_certificate_rule: None,
        versions: vec![c.version],
        cipher_suites: vec![c.suite],
        kx_groups: vec![c.group],
        signature_schemes: vec![c.scheme],
    }
}

fn version(v: V) -> &'static rustls::SupportedProtocolVersion {
    match v {
        V::Tls12 => &rustls::version::TLS12,
        V::Tls13 => &rustls::version::TLS13,
    }
}

fn key_der(p: &Pki) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(p.key.pkcs8_der().to_vec().into())
}

#[expect(clippy::disallowed_methods)]
fn reference_server(c: &Case, p: &Pki) -> Result<ServerConfig, String> {
    ServerConfig::builder_with_provider(Arc::new(reference(c)))
        .with_protocol_versions(&[version(c.version)])
        .map_err(e)?
        .with_no_client_auth()
        .with_single_cert(p.chain.clone(), key_der(p))
        .map_err(e)
}

#[expect(clippy::disallowed_methods)]
fn reference_client(c: &Case, p: &Pki) -> Result<(ClientConfig, Seen), String> {
    let provider = Arc::new(reference(c));
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(p.roots.clone()),
        provider.clone(),
    )
    .build()
    .map_err(e)?;
    let (verifier, seen) = recording(inner);
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version(c.version)])
        .map_err(e)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok((cfg, seen))
}

fn ours_to_reference(c: &Case, p: &Pki) -> Result<([u16; 4], HandshakeKind), String> {
    let inner = server_cert_verifier_builder(Arc::new(p.roots.clone()), &policy(c))
        .map_err(e)?
        .build()
        .map_err(e)?;
    let (verifier, seen) = recording(inner);
    let client = client_builder(&policy(c))
        .map_err(e)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    drive(client, reference_server(c, p)?, &seen)
}

fn reference_to_ours(c: &Case, p: &Pki) -> Result<([u16; 4], HandshakeKind), String> {
    let (client, seen) = reference_client(c, p)?;
    let server = server_builder(&policy(c))
        .map_err(e)?
        .with_no_client_auth()
        .with_single_cert(p.chain.clone(), key_der(p))
        .map_err(e)?;
    drive(client, server, &seen)
}

fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    let p384 = (K::Secp384r1, 0x0018, rk::SECP384R1);
    for (group, cp, rg) in [
        (K::MlKem1024, 0x0202, rk::MLKEM1024),
        (K::X25519MlKem768, 0x11EC, rk::X25519MLKEM768),
        (K::Secp256r1MlKem768, 0x11EB, rk::SECP256R1MLKEM768),
        p384,
        (K::Secp256r1, 0x0017, rk::SECP256R1),
        (K::X25519, 0x001D, rk::X25519),
    ] {
        v.push(Case {
            version: V::Tls13,
            suite: C::Tls13Aes256GcmSha384,
            group,
            scheme: T::EcdsaNistp384Sha384,
            key: S::EcdsaP384Sha384,
            wire: [0x0304, 0x1302, cp, 0x0503],
            reference: (
                rs::TLS13_AES_256_GCM_SHA384,
                rg,
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
        });
    }
    let ecdsa = (
        S::EcdsaP384Sha384,
        T::EcdsaNistp384Sha384,
        0x0503,
        SignatureScheme::ECDSA_NISTP384_SHA384,
    );
    let rsa = (
        S::Rsa2048Sha384,
        T::RsaPssSha512,
        0x0806,
        SignatureScheme::RSA_PSS_SHA512,
    );
    for (version, vcp, suite, cp, rsuite, (key, scheme, scp, rscheme)) in [
        (
            V::Tls13,
            0x0304,
            C::Tls13Aes256GcmSha384,
            0x1302,
            rs::TLS13_AES_256_GCM_SHA384,
            ecdsa,
        ),
        (
            V::Tls13,
            0x0304,
            C::Tls13Aes128GcmSha256,
            0x1301,
            rs::TLS13_AES_128_GCM_SHA256,
            ecdsa,
        ),
        (
            V::Tls13,
            0x0304,
            C::Tls13Chacha20Poly1305Sha256,
            0x1303,
            rs::TLS13_CHACHA20_POLY1305_SHA256,
            ecdsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheEcdsaAes256GcmSha384,
            0xC02C,
            rs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ecdsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheEcdsaAes128GcmSha256,
            0xC02B,
            rs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ecdsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheEcdsaChacha20Poly1305Sha256,
            0xCCA9,
            rs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ecdsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheRsaAes256GcmSha384,
            0xC030,
            rs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheRsaAes128GcmSha256,
            0xC02F,
            rs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rsa,
        ),
        (
            V::Tls12,
            0x0303,
            C::Tls12EcdheRsaChacha20Poly1305Sha256,
            0xCCA8,
            rs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            rsa,
        ),
    ] {
        v.push(Case {
            version,
            suite,
            group: p384.0,
            scheme,
            key,
            wire: [vcp, cp, 0x0018, scp],
            reference: (rsuite, p384.2, rscheme),
        });
    }
    let t13 = (
        V::Tls13,
        0x0304,
        C::Tls13Aes256GcmSha384,
        0x1302,
        rs::TLS13_AES_256_GCM_SHA384,
    );
    let t12 = (
        V::Tls12,
        0x0303,
        C::Tls12EcdheRsaAes256GcmSha384,
        0xC030,
        rs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    );
    for (scheme, scp, rscheme, key, (version, vcp, suite, cp, rsuite)) in [
        (
            T::EcdsaNistp256Sha256,
            0x0403,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            S::EcdsaP256Sha256,
            t13,
        ),
        (
            T::EcdsaNistp384Sha384,
            0x0503,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            S::EcdsaP384Sha384,
            t13,
        ),
        (
            T::EcdsaNistp521Sha512,
            0x0603,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            S::EcdsaP521Sha512,
            t13,
        ),
        (
            T::Ed25519,
            0x0807,
            SignatureScheme::ED25519,
            S::Ed25519,
            t13,
        ),
        (
            T::RsaPssSha256,
            0x0804,
            SignatureScheme::RSA_PSS_SHA256,
            S::Rsa2048Sha384,
            t13,
        ),
        (
            T::RsaPssSha384,
            0x0805,
            SignatureScheme::RSA_PSS_SHA384,
            S::Rsa2048Sha384,
            t13,
        ),
        (
            T::RsaPssSha512,
            0x0806,
            SignatureScheme::RSA_PSS_SHA512,
            S::Rsa2048Sha384,
            t13,
        ),
        (
            T::RsaPkcs1Sha256,
            0x0401,
            SignatureScheme::RSA_PKCS1_SHA256,
            S::Rsa2048Sha384,
            t12,
        ),
        (
            T::RsaPkcs1Sha384,
            0x0501,
            SignatureScheme::RSA_PKCS1_SHA384,
            S::Rsa2048Sha384,
            t12,
        ),
        (
            T::RsaPkcs1Sha512,
            0x0601,
            SignatureScheme::RSA_PKCS1_SHA512,
            S::Rsa2048Sha384,
            t12,
        ),
        (
            T::MlDsa87,
            0x0906,
            SignatureScheme::ML_DSA_87,
            S::MlDsa87,
            t13,
        ),
    ] {
        v.push(Case {
            version,
            suite,
            group: p384.0,
            scheme,
            key,
            wire: [vcp, cp, 0x0018, scp],
            reference: (rsuite, p384.2, rscheme),
        });
    }
    v
}

#[test]
fn every_shared_group_suite_and_scheme_interoperates_both_ways() {
    let cases = cases();
    assert_eq!(cases.len(), 6 + 9 + 11);
    for c in &cases {
        let p = pki(S::EcdsaP384Sha384, c.key).unwrap();
        assert_eq!(
            ours_to_reference(c, &p),
            Ok((c.wire, HandshakeKind::Full)),
            "ours -> reference {c:?}"
        );
        assert_eq!(
            reference_to_ours(c, &p),
            Ok((c.wire, HandshakeKind::Full)),
            "reference -> ours {c:?}"
        );
    }
}

#[test]
fn every_shared_component_classifies_fips_as_the_reference() {
    for c in &cases() {
        let ours = crypto_provider(&policy(c)).unwrap();
        assert_eq!(ours.cipher_suites[0].fips(), c.reference.0.fips(), "{c:?}");
        assert_eq!(ours.kx_groups[0].fips(), c.reference.1.fips(), "{c:?}");
    }
    let mine = crypto_provider(&Policy {
        peer_certificate_rule: None,
        versions: vec![V::Tls13],
        cipher_suites: vec![C::Tls13Aes256GcmSha384],
        kx_groups: vec![K::Secp384r1MlKem1024],
        signature_schemes: vec![T::EcdsaNistp384Sha384],
    })
    .unwrap();
    assert_eq!(mine.kx_groups[0].fips(), rk::SECP384R1.fips());
    assert_eq!(
        (mine.secure_random.fips(), mine.key_provider.fips()),
        (stock().secure_random.fips(), stock().key_provider.fips())
    );
}

fn quic_fingerprint(k: &DirectionalKeys) -> Result<Vec<u8>, rustls::Error> {
    let mut packet = b"\xc3\x00\x00\x00\x01quic differential payload".to_vec();
    let (header, body) = packet.split_at_mut(5);
    let tag = k.packet.encrypt_in_place(7, header, body)?;
    packet.extend(tag.as_ref());
    let (first, rest) = packet.split_at_mut(1);
    let (pn, body) = rest.split_at_mut(4);
    k.header.encrypt_in_place(&body[..16], &mut first[0], pn)?;
    let mut path = b"multipath".to_vec();
    let tag = k.packet.encrypt_in_place_for_path(3, 7, b"h", &mut path)?;
    packet.extend(path);
    packet.extend(tag.as_ref());
    for n in [
        k.packet.confidentiality_limit(),
        k.packet.integrity_limit(),
        k.packet.tag_len() as u64,
        k.header.sample_len() as u64,
    ] {
        packet.extend(n.to_be_bytes());
    }
    Ok(packet)
}

#[test]
fn every_quic_suite_derives_the_keys_of_the_reference() {
    for (suite, reference) in [
        (C::Tls13Aes256GcmSha384, rs::TLS13_AES_256_GCM_SHA384),
        (C::Tls13Aes128GcmSha256, rs::TLS13_AES_128_GCM_SHA256),
        (
            C::Tls13Chacha20Poly1305Sha256,
            rs::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ] {
        let provider = crypto_provider(&Policy {
            peer_certificate_rule: None,
            versions: vec![V::Tls13],
            cipher_suites: vec![suite],
            kx_groups: vec![K::Secp384r1],
            signature_schemes: vec![T::EcdsaNistp384Sha384],
        })
        .unwrap();
        let ours = provider.cipher_suites[0]
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let theirs = reference.tls13().unwrap().quic_suite().unwrap();
        assert_eq!(
            ours.quic.fips(),
            theirs.quic.fips() && suite != C::Tls13Chacha20Poly1305Sha256,
            "{suite:?}"
        );
        assert_eq!(
            ours.quic.aead_key_len(),
            theirs.quic.aead_key_len(),
            "{suite:?}"
        );
        for version in [Version::V1, Version::V2] {
            for side in [Side::Client, Side::Server] {
                let (o, t) = (
                    ours.keys(b"connection id", side, version),
                    theirs.keys(b"connection id", side, version),
                );
                assert_eq!(
                    quic_fingerprint(&o.local).unwrap(),
                    quic_fingerprint(&t.local).unwrap(),
                    "{suite:?}"
                );
                assert_eq!(
                    quic_fingerprint(&o.remote).unwrap(),
                    quic_fingerprint(&t.remote).unwrap(),
                    "{suite:?}"
                );
            }
        }
    }
}

fn every_scheme() -> Policy {
    Policy {
        peer_certificate_rule: None,
        versions: vec![V::Tls13],
        cipher_suites: vec![C::Tls13Aes256GcmSha384],
        kx_groups: vec![K::Secp384r1],
        signature_schemes: T::ALL.to_vec(),
    }
}

#[test]
fn the_verification_tables_match_the_reference() {
    let ours = crypto_provider(&every_scheme())
        .unwrap()
        .signature_verification_algorithms;
    let theirs = stock().signature_verification_algorithms;
    let ids = |x: &[&dyn SignatureVerificationAlgorithm]| {
        x.iter()
            .map(|a| (a.public_key_alg_id(), a.signature_alg_id()))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(ours.all), ids(theirs.all));
    assert_eq!(ours.mapping.len(), 11);
    for (scheme, algs) in ours.mapping {
        let (_, want) = theirs.mapping.iter().find(|(s, _)| s == scheme).unwrap();
        assert_eq!(ids(algs), ids(want), "{scheme:?}");
    }
    assert_eq!(ours.fips(), theirs.fips());
}

const MSG: &[u8] = b"m";

type Signed = (Vec<u8>, Vec<u8>);

#[test]
fn every_verifier_accepts_and_refuses_as_the_reference() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn ecdsa(alg: &'static signature::EcdsaSigningAlgorithm) -> (Vec<u8>, Vec<u8>) {
        let k = signature::EcdsaKeyPair::generate(alg).unwrap();
        (
            k.public_key().as_ref().to_vec(),
            k.sign(&SystemRandom::new(), MSG).unwrap().as_ref().to_vec(),
        )
    }

    fn rsa(
        k: &signature::RsaKeyPair,
        encoding: &'static dyn signature::RsaEncoding,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut sig = vec![0; k.public_modulus_len()];
        k.sign(encoding, &SystemRandom::new(), MSG, &mut sig)
            .unwrap();
        (k.public_key().as_ref().to_vec(), sig)
    }

    fn ml_dsa(alg: &'static signature::PqdsaSigningAlgorithm) -> (Vec<u8>, Vec<u8>) {
        let k = signature::PqdsaKeyPair::generate(alg).unwrap();
        let mut sig = vec![0; alg.signature_len()];
        let len = k.sign(MSG, &mut sig).unwrap();
        sig.truncate(len);
        (k.public_key().as_ref().to_vec(), sig)
    }

    use webpki::aws_lc_rs as w;
    let fixed = |pk: &str, sig: &str| (unhex(pk), unhex(sig));
    let rsa_key = signature::RsaKeyPair::from_pkcs8(
        crypto_profile_awslc4::signature::KeyPair::generate(S::Rsa2048Sha384)
            .unwrap()
            .pkcs8_der(),
    )
    .unwrap();
    let ed = signature::Ed25519KeyPair::generate().unwrap();
    let rows: Vec<(&'static dyn SignatureVerificationAlgorithm, Signed)> = vec![
        (
            w::ECDSA_P256_SHA256,
            ecdsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING),
        ),
        (
            w::ECDSA_P256_SHA384,
            fixed(
                "040830952e09e8818559d7f8333806150d73013fb9a8cbfaafa59f939a2bcf1429e3b1dcb15a4cb3286e3906d4d6903aa39c8cbcfb2bee36adb3c71205056c4139",
                "3045022100a82baacfff74106f46413e86204feb6ee68c1d9aad1a90a337faa43c6def913f02204f0924eaada6c199d7587405a267421df4720ab302f8c022f04b38a8a3a6a2fb",
            ),
        ),
        (
            w::ECDSA_P256_SHA512,
            fixed(
                "0436c51ead31e96daa81094ebdd255d17ea243896de3408edf967417215b759f88798e957f72f92556a7e309329d5774f6d0709d8ff94d30bfc3bbd36df1d40544",
                "30460221009826fa37d5217e778bc8da7589485540a789b3f4604b9fb4273b667e2402eb3d022100ade4349c33459c20cd127cbdc0fc1058da5af16f943a3e1ea379d5db7ff008e6",
            ),
        ),
        (
            w::ECDSA_P384_SHA256,
            fixed(
                "04d410c862d0dd566ff1bdf8134bdb9bf01d3b29b0565b17c1ccbb5904295e86fb7b399b9150736cafb85bb9de9dea863c5d589c9866fa98a0b6aa52925d9ac9a18c02f19c86a27b5c1115592130ec2f3d569be2c130f3e78fae39f9aa2eb64b2f",
                "3066023100ea8b2954877c152c6bc28df2ae2bab66e50a795e98291edc9aa29c3de12e9effcd7cf96efe871396cdf5379320d048b0023100fc5f17e886d453ff1ecb9d858207cb0ff4be6f668268f56773c15d7758777f1836b37a91b5a731e9a839bc7bc76152d3",
            ),
        ),
        (
            w::ECDSA_P384_SHA384,
            ecdsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING),
        ),
        (
            w::ECDSA_P384_SHA512,
            fixed(
                "0486c630e2ce3fe9a5ae1aa8be376a202924b8e2e8050132b8ab1fbdde426361f9296a4404a2b34e835bb0c92f2f6b53d64a6e1e7991dbade5d3882b799968d02306f4bb3e2cc88be0dd68b62faece2e1f0267465a2383a6387fa9991d695100b9",
                "3065023058ef1cb3af09c2fa6c27c57337485c54a7d491c79c8e9ed96ae82f69fcb79f96f022569a816306423852fccd77cd618d0231008b0a49bd91f87ebcd0c215f37e5eca4ee04cc9ba493ba36277f56d36df5d437c8fdd25238ed1b590997373da1659d41f",
            ),
        ),
        (
            w::ECDSA_P521_SHA256,
            ecdsa(&signature::ECDSA_P521_SHA256_ASN1_SIGNING),
        ),
        (
            w::ECDSA_P521_SHA384,
            ecdsa(&signature::ECDSA_P521_SHA384_ASN1_SIGNING),
        ),
        (
            w::ECDSA_P521_SHA512,
            ecdsa(&signature::ECDSA_P521_SHA512_ASN1_SIGNING),
        ),
        (
            w::ED25519,
            (
                ed.public_key().as_ref().to_vec(),
                ed.sign(MSG).as_ref().to_vec(),
            ),
        ),
        (
            w::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            rsa(&rsa_key, &signature::RSA_PSS_SHA256),
        ),
        (
            w::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            rsa(&rsa_key, &signature::RSA_PSS_SHA384),
        ),
        (
            w::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            rsa(&rsa_key, &signature::RSA_PSS_SHA512),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA256,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA256),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA384,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA384),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA512,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA512),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA256),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA384),
        ),
        (
            w::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
            rsa(&rsa_key, &signature::RSA_PKCS1_SHA512),
        ),
        (w::ML_DSA_44, ml_dsa(&signature::ML_DSA_44_SIGNING)),
        (w::ML_DSA_65, ml_dsa(&signature::ML_DSA_65_SIGNING)),
        (w::ML_DSA_87, ml_dsa(&signature::ML_DSA_87_SIGNING)),
    ];
    let ours = crypto_provider(&every_scheme())
        .unwrap()
        .signature_verification_algorithms
        .all;
    assert_eq!(rows.len(), ours.len());
    for (theirs, (pk, sig)) in &rows {
        let id = (theirs.public_key_alg_id(), theirs.signature_alg_id());
        let mine: Vec<_> = ours
            .iter()
            .filter(|a| (a.public_key_alg_id(), a.signature_alg_id()) == id)
            .collect();
        assert_eq!(mine.len(), 1, "{id:?}");
        let mut flipped = sig.clone();
        if let Some(b) = flipped.last_mut() {
            *b ^= 1;
        }
        assert!(
            mine[0].verify_signature(pk, MSG, sig).is_ok(),
            "ours refused {id:?}"
        );
        assert!(
            theirs.verify_signature(pk, MSG, sig).is_ok(),
            "the reference refused {id:?}"
        );
        assert!(
            mine[0].verify_signature(pk, MSG, &flipped).is_err(),
            "ours accepted a flipped {id:?}"
        );
        assert!(
            theirs.verify_signature(pk, MSG, &flipped).is_err(),
            "the reference accepted a flipped {id:?}"
        );
    }
}
