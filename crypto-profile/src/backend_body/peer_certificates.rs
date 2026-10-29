//! Bounded decoding and profile admission of peer certificate public keys.
use crate::{PeerCertificateViolation, PeerKey, Profile, TlsError};
use rustls::pki_types::CertificateDer;

use crate::{MlDsaParameterSet, PeerCurve, RsaSizeRule, peer_certificate_rule};
use PeerCertificateViolation::Malformed;

struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    fn byte(&mut self) -> Result<u8, PeerCertificateViolation> {
        let (&byte, rest) = self.0.split_first().ok_or(Malformed)?;
        self.0 = rest;
        Ok(byte)
    }

    fn value(&mut self, tag: u8) -> Result<&'a [u8], PeerCertificateViolation> {
        if self.byte()? != tag {
            return Err(Malformed);
        }
        let first = self.byte()?;
        let len = if first < 128 {
            usize::from(first)
        } else {
            let count = first & 0x7f;
            if !(1..=2).contains(&count) {
                return Err(Malformed);
            }
            let leading = self.byte()?;
            if leading == 0 {
                return Err(Malformed);
            }
            let len = if count == 2 {
                usize::from(leading) * 256 + usize::from(self.byte()?)
            } else {
                usize::from(leading)
            };
            if len < 128 {
                return Err(Malformed);
            }
            len
        };
        let (value, rest) = self.0.split_at_checked(len).ok_or(Malformed)?;
        self.0 = rest;
        Ok(value)
    }

    fn end(self) -> Result<(), PeerCertificateViolation> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    fn oid(&mut self) -> Result<&'a [u8], PeerCertificateViolation> {
        let value = self.value(6)?;
        if value.is_empty() {
            return Err(Malformed);
        }
        let mut start = true;
        for byte in value {
            if start && *byte == 0x80 {
                return Err(Malformed);
            }
            start = byte & 0x80 == 0;
        }
        if !start {
            return Err(Malformed);
        }
        Ok(value)
    }
}

fn sequence(der: &[u8]) -> Result<Der<'_>, PeerCertificateViolation> {
    let mut outer = Der(der);
    let inner = outer.value(0x30)?;
    outer.end()?;
    Ok(Der(inner))
}

fn positive_integer<'a>(der: &mut Der<'a>) -> Result<&'a [u8], PeerCertificateViolation> {
    let value = der.value(2)?;
    let (&first, rest) = value.split_first().ok_or(Malformed)?;
    if first & 0x80 != 0 {
        return Err(Malformed);
    }
    if first == 0 {
        if rest.first().is_none_or(|b| b & 0x80 == 0) {
            return Err(Malformed);
        }
        Ok(rest)
    } else {
        Ok(value)
    }
}

/// Decodes a complete DER SubjectPublicKeyInfo into a bounded key descriptor.
///
/// Input is limited to 16384 bytes. Structural checks do not replace the verifier's
/// cryptographic key and point validation. Unsupported OIDs become `PeerKey::Unknown`.
pub fn parse_spki(der: &[u8]) -> Result<PeerKey, PeerCertificateViolation> {
    if der.len() > 16384 {
        return Err(Malformed);
    }
    let mut spki = sequence(der)?;
    let mut algorithm = Der(spki.value(0x30)?);
    let oid = algorithm.oid()?;
    let params = algorithm.0;
    let bit_string = spki.value(3)?;
    spki.end()?;
    let (&unused, key) = bit_string.split_first().ok_or(Malformed)?;
    if unused != 0 || key.is_empty() {
        return Err(Malformed);
    }
    match oid {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1] => {
            if !params.is_empty() && params != [5, 0] {
                return Err(Malformed);
            }
            let mut rsa = sequence(key)?;
            let modulus = positive_integer(&mut rsa)?;
            positive_integer(&mut rsa)?;
            rsa.end()?;
            let bits = modulus.len() * 8 - modulus[0].leading_zeros() as usize;
            Ok(PeerKey::Rsa(u16::try_from(bits).map_err(|_| Malformed)?))
        }
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1] => {
            let curve = algorithm.oid()?;
            algorithm.end()?;
            let (curve, len) = match curve {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7] => (PeerCurve::P256, 65),
                [0x2b, 0x81, 4, 0, 0x22] => (PeerCurve::P384, 97),
                [0x2b, 0x81, 4, 0, 0x23] => (PeerCurve::P521, 133),
                _ => return Ok(PeerKey::Unknown),
            };
            if key.len() != len || key[0] != 4 {
                return Err(Malformed);
            }
            Ok(PeerKey::Ec(curve))
        }
        [0x2b, 0x65, 0x70] => {
            algorithm.end()?;
            if key.len() != 32 {
                return Err(Malformed);
            }
            Ok(PeerKey::Ed25519)
        }
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, set @ 0x11..=0x13] => {
            algorithm.end()?;
            let (set, len) = match set {
                0x11 => (MlDsaParameterSet::MlDsa44, 1312),
                0x12 => (MlDsaParameterSet::MlDsa65, 1952),
                _ => (MlDsaParameterSet::MlDsa87, 2592),
            };
            if key.len() != len {
                return Err(Malformed);
            }
            Ok(PeerKey::MlDsa(set))
        }
        _ => {
            if let Some(&tag) = params.first() {
                algorithm.value(tag)?;
            }
            algorithm.end()?;
            Ok(PeerKey::Unknown)
        }
    }
}

fn leaf_key(cert: &CertificateDer<'_>) -> Result<PeerKey, PeerCertificateViolation> {
    if cert.len() > 65535 {
        return Err(Malformed);
    }
    let mut certificate = sequence(cert.as_ref())?;
    let mut tbs = Der(certificate.value(0x30)?);
    certificate.value(0x30)?;
    let signature = certificate.value(3)?;
    if signature.first() != Some(&0) {
        return Err(Malformed);
    }
    certificate.end()?;
    if tbs.0.first() == Some(&0xa0) {
        let mut version = Der(tbs.value(0xa0)?);
        if !matches!(version.value(2)?, [1] | [2]) {
            return Err(Malformed);
        }
        version.end()?;
    }
    tbs.value(2)?;
    for _ in 0..4 {
        tbs.value(0x30)?;
    }
    let spki = tbs.0;
    tbs.value(0x30)?;
    let spki = &spki[..spki.len() - tbs.0.len()];
    for tag in [0x81, 0x82, 0xa3] {
        if tbs.0.first() == Some(&tag) {
            tbs.value(tag)?;
        }
    }
    tbs.end()?;
    parse_spki(spki)
}

/// Checks the actual leaf SPKI against the profile's certificate key rule.
///
/// RSA admission also respects the verifier's 8192-bit implementation ceiling.
/// Baseline certificate validation remains the caller's responsibility.
#[allow(
    dead_code,
    reason = "Strict peer verifier integration is a separate task."
)]
pub fn check_leaf(profile: Profile, cert: &CertificateDer<'_>) -> Result<(), TlsError> {
    let check = || {
        let key = leaf_key(cert)?;
        let rule = &peer_certificate_rule(profile).leaf_keys;
        let allowed = match key {
            PeerKey::Ec(curve) => rule.ec_curves.contains(&curve),
            PeerKey::Rsa(bits) => {
                bits <= 8192
                    && (!rule.rsa_even_bits || bits % 2 == 0)
                    && match rule.rsa {
                        Some(RsaSizeRule::Minimum(min)) => bits >= min,
                        Some(RsaSizeRule::Exact(sizes)) => sizes.contains(&bits),
                        None => false,
                    }
            }
            PeerKey::Ed25519 => rule.ed25519,
            PeerKey::MlDsa(set) => rule.ml_dsa.contains(&set),
            PeerKey::Unknown => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(PeerCertificateViolation::LeafKey(key))
        }
    };
    check().map_err(|violation| TlsError::PeerCertificate { profile, violation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlDsaParameterSet::*;

    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
    const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
    const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
    const P384: &[u8] = &[0x2b, 0x81, 4, 0, 0x22];
    const P521: &[u8] = &[0x2b, 0x81, 4, 0, 0x23];
    const ED: &[u8] = &[0x2b, 0x65, 0x70];
    const ML44: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x11];
    const ML65: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12];
    const ML87: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x13];

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            let bytes = body.len().to_be_bytes();
            let significant = &bytes[bytes.iter().position(|b| *b != 0).unwrap()..];
            out.push(0x80 | significant.len() as u8);
            out.extend_from_slice(significant);
        }
        out.extend_from_slice(body);
        out
    }

    fn spki(oid: &[u8], params: &[u8], key: &[u8]) -> Vec<u8> {
        let alg = tlv(0x30, &[tlv(6, oid), params.to_vec()].concat());
        tlv(0x30, &[alg, tlv(3, &[&[0][..], key].concat())].concat())
    }

    fn rsa_integer(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        spki(
            RSA,
            &[5, 0],
            &tlv(0x30, &[tlv(2, modulus), tlv(2, exponent)].concat()),
        )
    }

    fn rsa(bits: u16) -> Vec<u8> {
        let mut n = vec![0; usize::from(bits).div_ceil(8)];
        n[0] = 1 << ((bits - 1) % 8);
        let last = n.len() - 1;
        n[last] |= 1;
        if n[0] & 0x80 != 0 {
            n.insert(0, 0);
        }
        rsa_integer(&n, &[1, 0, 1])
    }

    fn ec(curve: &[u8], size: usize) -> Vec<u8> {
        let mut point = vec![1; size];
        point[0] = 4;
        spki(EC, &tlv(6, curve), &point)
    }

    fn certificate(key: &[u8], version: bool) -> CertificateDer<'static> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(tlv(0xa0, &[2, 1, 2]));
        }
        tbs.extend([2, 1, 1]);
        for _ in 0..4 {
            tbs.extend([0x30, 0]);
        }
        tbs.extend_from_slice(key);
        CertificateDer::from(tlv(
            0x30,
            &[tlv(0x30, &tbs), tlv(0x30, &[]), tlv(3, &[0, 1])].concat(),
        ))
    }

    #[test]
    fn supported_families_and_significant_rsa_bits() {
        for bits in [
            1, 7, 8, 9, 2047, 2048, 2049, 2999, 3000, 3071, 3072, 4096, 8192, 8193,
        ] {
            assert_eq!(parse_spki(&rsa(bits)), Ok(PeerKey::Rsa(bits)), "{bits}");
        }
        for (oid, size, key) in [
            (P256, 65, PeerKey::Ec(crate::PeerCurve::P256)),
            (P384, 97, PeerKey::Ec(crate::PeerCurve::P384)),
            (P521, 133, PeerKey::Ec(crate::PeerCurve::P521)),
        ] {
            assert_eq!(parse_spki(&ec(oid, size)), Ok(key));
        }
        for (oid, size, key) in [
            (ED, 32, PeerKey::Ed25519),
            (ML44, 1312, PeerKey::MlDsa(MlDsa44)),
            (ML65, 1952, PeerKey::MlDsa(MlDsa65)),
            (ML87, 2592, PeerKey::MlDsa(MlDsa87)),
        ] {
            assert_eq!(parse_spki(&spki(oid, &[], &vec![1; size])), Ok(key));
        }
        let absent = spki(RSA, &[], &tlv(0x30, &[2, 1, 1, 2, 1, 3]));
        assert_eq!(parse_spki(&absent), Ok(PeerKey::Rsa(1)));
    }

    #[test]
    fn unsupported_oids_are_bounded_unknown_descriptors() {
        for der in [
            spki(&[0x2a, 3], &[], &[1]),
            ec(&[0x2a, 3], 65),
            spki(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 10],
                &tlv(0x30, &[]),
                &[1],
            ),
        ] {
            assert_eq!(parse_spki(&der), Ok(PeerKey::Unknown));
        }
    }

    #[test]
    fn malformed_keys_fail_closed() {
        let mut cases = vec![
            vec![],
            vec![0x30, 0x80, 0, 0],
            vec![0x30, 0x81, 0],
            vec![0x30, 0x82, 0, 0x80],
            vec![0x30, 0xff],
            vec![0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            spki(EC, &[], &[4; 65]),
            spki(EC, &[5, 0], &[4; 65]),
            spki(RSA, &tlv(6, ED), &[1]),
            rsa_integer(&[], &[3]),
            rsa_integer(&[0], &[3]),
            rsa_integer(&[0x80], &[3]),
            rsa_integer(&[0, 1], &[3]),
            rsa_integer(&[0, 0x80], &[0]),
            rsa_integer(&[1], &[]),
            rsa_integer(&[1], &[0x80]),
            rsa_integer(&[1], &[0, 1]),
            spki(RSA, &[5, 0], &tlv(0x30, &[2, 1, 1, 2, 1, 3, 0])),
            spki(RSA, &[5, 1, 0], &[1]),
            spki(ED, &[5, 0], &[1; 32]),
            spki(ED, &[], &[1; 31]),
            spki(ED, &[], &[1; 33]),
            spki(ML44, &[5, 0], &vec![1; 1312]),
            spki(ML65, &[], &vec![1; 1312]),
            spki(ML87, &[], &vec![1; 1952]),
            spki(&[], &[], &[1]),
            spki(&[0x2a, 0x80, 0], &[], &[1]),
            spki(&[0x2a, 0x81], &[], &[1]),
            ec(P256, 64),
            ec(P384, 98),
            ec(P521, 132),
            spki(EC, &tlv(6, P256), &[2; 65]),
            spki(&[0x2a, 3], &[5, 0, 5, 0], &[1]),
            vec![0; 16385],
        ];
        let valid = ec(P384, 97);
        for end in 0..valid.len() {
            cases.push(valid[..end].to_vec());
        }
        cases.push([valid.clone(), vec![0]].concat());
        let mut unused_bits = spki(ED, &[], &[1; 32]);
        let offset = unused_bits.len() - 33;
        unused_bits[offset] = 1;
        cases.push(unused_bits);
        for der in cases {
            assert_eq!(
                parse_spki(&der),
                Err(PeerCertificateViolation::Malformed),
                "{der:?}"
            );
        }
    }

    #[test]
    fn literal_leaf_rule_matrix() {
        use Profile::*;
        let profiles = [
            Unrestricted,
            Preferred,
            Cnsa2,
            Cnsa1,
            Bsi,
            Fips1403,
            Fips1402,
        ];
        let mut cases = vec![
            (
                ec(P256, 65),
                PeerKey::Ec(crate::PeerCurve::P256),
                [true, true, false, false, true, true, true],
            ),
            (
                ec(P384, 97),
                PeerKey::Ec(crate::PeerCurve::P384),
                [true, true, false, true, true, true, true],
            ),
            (
                ec(P521, 133),
                PeerKey::Ec(crate::PeerCurve::P521),
                [true, true, false, false, true, true, true],
            ),
            (
                spki(ED, &[], &[1; 32]),
                PeerKey::Ed25519,
                [true, false, false, false, false, true, false],
            ),
            (
                spki(ML44, &[], &vec![1; 1312]),
                PeerKey::MlDsa(MlDsa44),
                [false; 7],
            ),
            (
                spki(ML65, &[], &vec![1; 1952]),
                PeerKey::MlDsa(MlDsa65),
                [false, true, false, false, false, false, false],
            ),
            (
                spki(ML87, &[], &vec![1; 2592]),
                PeerKey::MlDsa(MlDsa87),
                [true, true, true, false, false, true, false],
            ),
            (spki(&[0x2a, 3], &[], &[1]), PeerKey::Unknown, [false; 7]),
        ];
        for (bits, expected) in [
            (2047, [false; 7]),
            (2048, [true, false, false, false, false, true, true]),
            (2049, [true, false, false, false, false, false, true]),
            (2999, [true, false, false, false, false, false, true]),
            (3000, [true, false, false, false, true, true, true]),
            (3071, [true, false, false, false, true, false, true]),
            (3072, [true, true, false, true, true, true, true]),
            (3073, [true, true, false, false, true, false, true]),
            (4096, [true, true, false, true, true, true, true]),
            (8192, [true, true, false, false, true, true, true]),
            (8193, [false; 7]),
        ] {
            cases.push((rsa(bits), PeerKey::Rsa(bits), expected));
        }
        for (spki, key, allowed) in cases {
            for (profile, allowed) in profiles.into_iter().zip(allowed) {
                for version in [false, true] {
                    let expected = if allowed {
                        Ok(())
                    } else {
                        Err(TlsError::PeerCertificate {
                            profile,
                            violation: PeerCertificateViolation::LeafKey(key),
                        })
                    };
                    assert_eq!(
                        check_leaf(profile, &certificate(&spki, version)),
                        expected,
                        "{profile:?} {key:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn certificate_spki_is_not_the_outer_signature() {
        for algorithm in [
            crate::SignatureAlgorithm::EcdsaP256Sha256,
            crate::SignatureAlgorithm::EcdsaP384Sha384,
            crate::SignatureAlgorithm::Ed25519,
        ] {
            let pki = super::super::test_support::pki(
                crate::SignatureAlgorithm::EcdsaP384Sha384,
                algorithm,
            )
            .unwrap();
            assert_eq!(check_leaf(Profile::Unrestricted, &pki.chain[0]), Ok(()));
        }
    }

    #[test]
    fn malformed_certificates_fail_closed_without_panics() {
        let valid = certificate(&ec(P384, 97), true);
        let expected = Err(TlsError::PeerCertificate {
            profile: Profile::Cnsa1,
            violation: PeerCertificateViolation::Malformed,
        });
        for end in 0..valid.len() {
            assert_eq!(
                check_leaf(Profile::Cnsa1, &CertificateDer::from(&valid[..end])),
                expected
            );
        }
        assert_eq!(
            check_leaf(
                Profile::Cnsa1,
                &CertificateDer::from([valid.as_ref(), &[0]].concat())
            ),
            expected
        );
        assert_eq!(
            check_leaf(Profile::Cnsa1, &certificate(&[], false)),
            expected
        );
    }
    #[test]
    fn nested_certificate_fields_and_optional_order_are_checked() {
        let key = ec(P384, 97);
        let mut tbs = vec![2, 1, 1];
        for _ in 0..4 {
            tbs.extend([0x30, 0]);
        }
        tbs.extend(&key);
        let wrap = |body: &[u8], alg: &[u8], sig: &[u8]| {
            CertificateDer::from(tlv(
                0x30,
                &[tlv(0x30, body), alg.to_vec(), tlv(3, sig)].concat(),
            ))
        };
        let check = |cert: CertificateDer<'_>| check_leaf(Profile::Cnsa1, &cert);
        let bad = Err(TlsError::PeerCertificate {
            profile: Profile::Cnsa1,
            violation: PeerCertificateViolation::Malformed,
        });
        assert_eq!(check(wrap(&tbs, &[0x30, 0], &[0, 1])), Ok(()));
        assert_eq!(check(wrap(&tbs, &[0x30, 0], &[])), bad);
        assert_eq!(check(wrap(&tbs, &[0x30, 0], &[1, 1])), bad);
        assert_eq!(check(wrap(&tbs, &[0x31, 0], &[0, 1])), bad);
        for end in 0..tbs.len() {
            assert_eq!(check(wrap(&tbs[..end], &[0x30, 0], &[0, 1])), bad);
        }
        for version in [
            vec![],
            vec![2, 0],
            vec![2, 1, 0],
            vec![2, 1, 3],
            vec![2, 1, 2, 0],
        ] {
            let body = [tlv(0xa0, &version), tbs.clone()].concat();
            assert_eq!(check(wrap(&body, &[0x30, 0], &[0, 1])), bad);
        }
        let v2 = [tlv(0xa0, &[2, 1, 1]), tbs.clone()].concat();
        assert_eq!(check(wrap(&v2, &[0x30, 0], &[0, 1])), Ok(()));
        let optional = [
            tlv(0x81, &[0, 1]),
            tlv(0x82, &[0, 1]),
            tlv(0xa3, &[0x30, 0]),
        ]
        .concat();
        assert_eq!(
            check(wrap(&[tbs.clone(), optional].concat(), &[0x30, 0], &[0, 1])),
            Ok(())
        );
        for tail in [
            vec![0],
            vec![0x81, 0, 0x81, 0],
            vec![0xa3, 0, 0x82, 0],
            vec![0x82, 9],
        ] {
            assert_eq!(
                check(wrap(&[tbs.clone(), tail].concat(), &[0x30, 0], &[0, 1])),
                bad
            );
        }
        let huge = CertificateDer::from(vec![0; 65536]);
        assert_eq!(check(huge), bad);
        let malformed_key = certificate(&spki(ED, &[], &[1]), false);
        assert_eq!(check(malformed_key), bad);
        let extra_outer = CertificateDer::from(tlv(
            0x30,
            &[tlv(0x30, &tbs), vec![0x30, 0, 3, 1, 0, 0]].concat(),
        ));
        assert_eq!(check(extra_outer), bad);
    }

    #[test]
    fn der_length_and_integer_boundaries() {
        for len in [127, 128, 255, 256, 16300] {
            assert_eq!(
                parse_spki(&spki(&[0x2a, 3], &[], &vec![1; len])),
                Ok(PeerKey::Unknown)
            );
        }
        for der in [
            vec![0x31, 0],
            vec![0x30],
            vec![0x30, 0x81],
            vec![0x30, 0x82, 1],
            vec![0x30, 0x81, 0x7f],
            vec![0x30, 0x82, 0, 0x80],
            vec![0x30, 0x82, 1, 0],
            tlv(0x30, &[0x30, 0, 3, 1, 0]),
            tlv(0x30, &[tlv(0x30, &tlv(6, ED)), vec![3, 0]].concat()),
            spki(RSA, &[5, 0], &tlv(0x30, &[2, 1, 1])),
            spki(RSA, &[5, 0], &tlv(0x30, &[2, 1, 1, 3, 1, 3])),
            rsa_integer(&[1], &[0, 0x80]),
        ] {
            if der == rsa_integer(&[1], &[0, 0x80]) {
                assert_eq!(parse_spki(&der), Ok(PeerKey::Rsa(1)));
            } else {
                assert_eq!(parse_spki(&der), Err(PeerCertificateViolation::Malformed));
            }
        }
        assert_eq!(
            parse_spki(&rsa_integer(&vec![1; 8193], &[3])),
            Err(PeerCertificateViolation::Malformed)
        );
        for (oid, len) in [(ML44, 1312), (ML65, 1952), (ML87, 2592)] {
            for size in [0, len - 1, len + 1] {
                assert_eq!(
                    parse_spki(&spki(oid, &[], &vec![1; size])),
                    Err(PeerCertificateViolation::Malformed)
                );
            }
        }
        for params in [vec![5], vec![5, 1], tlv(6, &[0x2a])] {
            let der = spki(&[0x2a, 3], &params, &[1]);
            if params == tlv(6, &[0x2a]) {
                assert_eq!(parse_spki(&der), Ok(PeerKey::Unknown));
            } else {
                assert_eq!(parse_spki(&der), Err(PeerCertificateViolation::Malformed));
            }
        }
    }
    #[test]
    fn bounded_inputs_include_the_exact_limit() {
        let der = spki(&[0x2a, 3], &[], &vec![1; 16369]);
        assert_eq!(der.len(), 16384);
        assert_eq!(parse_spki(&der), Ok(PeerKey::Unknown));
        let too_large = spki(&[0x2a, 3], &[], &vec![1; 16370]);
        assert_eq!(
            parse_spki(&too_large),
            Err(PeerCertificateViolation::Malformed)
        );
        let base = certificate(&ec(P384, 97), false);
        let mut outer = sequence(base.as_ref()).unwrap();
        let mut tbs = outer.value(0x30).unwrap().to_vec();
        let padding = tlv(0xa3, &vec![0; 65386]);
        tbs.extend(padding);
        let cert = CertificateDer::from(tlv(
            0x30,
            &[tlv(0x30, &tbs), vec![0x30, 0, 3, 2, 0, 1]].concat(),
        ));
        assert_eq!(cert.len(), 65535);
        assert_eq!(check_leaf(Profile::Cnsa1, &cert), Ok(()));
    }
    #[test]
    fn indefinite_length_cannot_masquerade_as_a_short_length() {
        let valid = spki(&[0x2a, 3], &[], &[1; 119]);
        assert_eq!(&valid[..3], &[0x30, 0x81, 0x80]);
        let indefinite = [&[0x30, 0x80][..], &valid[3..]].concat();
        assert_eq!(
            parse_spki(&indefinite),
            Err(PeerCertificateViolation::Malformed)
        );
    }
}
