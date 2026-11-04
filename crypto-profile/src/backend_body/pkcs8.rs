//! Strict DER for the private keys the crate imports (decision 0011): RFC 5958 §2
//! OneAsymmetricKey, and the structure each key type carries inside it.

// X.690 §8.1.2: the identifier's first octet and the bytes after the identifier. A tag number
// above 30, and only such a number, takes the high-tag-number form, in minimal base-128 octets.
fn identifier(der: &[u8]) -> Option<(u8, &[u8])> {
    let (&first, rest) = der.split_first()?;
    if first & 0x1f != 0x1f {
        return Some((first, rest));
    }
    let end = rest.iter().position(|octet| octet & 0x80 == 0)?;
    let minimal = match &rest[..=end] {
        [only] => *only > 30,
        [leading, ..] => *leading != 0x80,
        [] => false,
    };
    minimal.then_some((first, &rest[end + 1..]))
}

// One DER element with a minimal definite length of at most two bytes: its identifier's first
// octet, its value and the bytes after it.
pub(crate) fn split_tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, after) = identifier(der)?;
    let (header, len) = match after {
        [n @ 0..=0x7f, ..] => (1, usize::from(*n)),
        [0x81, n @ 0x80..=0xff, ..] => (2, usize::from(*n)),
        [0x82, hi @ 0x01..=0xff, lo, ..] => (3, usize::from(u16::from_be_bytes([*hi, *lo]))),
        _ => return None,
    };
    let (value, rest) = after[header..].split_at_checked(len)?;
    Some((tag, value, rest))
}

fn optional(tag: u8, der: &[u8]) -> (Option<&[u8]>, &[u8]) {
    match split_tlv(der) {
        Some((t, value, rest)) if t == tag => (Some(value), rest),
        _ => (None, der),
    }
}

// X.690 §11.6: `next` does not precede `prev`, compared as octet strings with the shorter padded
// at its end with 0-octets.
fn not_after(prev: &[u8], next: &[u8]) -> bool {
    let padded = |s: &[u8]| {
        (0..prev.len().max(next.len()))
            .map(|i| s.get(i).copied().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    padded(prev) <= padded(next)
}

// The elements of a SET OF in `der`, each passing `element(tag, value)`, in ascending order of their
// encodings (X.690 §11.6).
fn set_of(mut der: &[u8], element: impl Fn(u8, &[u8]) -> bool) -> bool {
    let mut previous: Option<&[u8]> = None;
    for _ in 0..=der.len() {
        if der.is_empty() {
            return true;
        }
        let Some((tag, value, rest)) = split_tlv(der) else {
            return false;
        };
        let whole = &der[..der.len() - rest.len()];
        if !element(tag, value) || !previous.is_none_or(|p| not_after(p, whole)) {
            return false;
        }
        previous = Some(whole);
        der = rest;
    }
    false
}

// RFC 5958 §2 Attributes, IMPLICIT: Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET },
// a SET OF Attribute whose attrValues is a SET OF ANY.
fn are_attributes(der: &[u8]) -> bool {
    set_of(der, |tag, attribute| {
        let Some((0x06, [_, ..], values)) = split_tlv(attribute) else {
            return false;
        };
        tag == 0x30
            && matches!(split_tlv(values), Some((0x31, set, [])) if set_of(set, |_, _| true))
    })
}

/// RFC 5958 §2, DER: the privateKey contents, and the publicKey bits if it carries one, of one
/// OneAsymmetricKey spanning `der` whose privateKeyAlgorithm is byte for byte `algorithm`. Then
/// come optional `[0]` attributes and, only where `public_key` allows it, a `[1]` publicKey with no
/// unused bits; the version is v2 exactly when `[1]` is present, and nothing follows.
fn one_asymmetric_key<'a>(
    der: &'a [u8],
    algorithm: &[u8],
    public_key: bool,
) -> Option<(&'a [u8], Option<&'a [u8]>)> {
    let Some((0x30, body, [])) = split_tlv(der) else {
        return None;
    };
    let (v2, rest) = match body {
        [0x02, 0x01, 0x00, rest @ ..] => (false, rest),
        [0x02, 0x01, 0x01, rest @ ..] if public_key => (true, rest),
        _ => return None,
    };
    let rest = rest.strip_prefix(algorithm)?;
    let Some((0x04, private_key, rest)) = split_tlv(rest) else {
        return None;
    };
    let (attributes, rest) = optional(0xa0, rest);
    let (carried, rest) = optional(0x81, rest);
    if !rest.is_empty() || !attributes.is_none_or(are_attributes) || carried.is_some() != v2 {
        return None;
    }
    match carried {
        None => Some((private_key, None)),
        Some([0x00, bits @ ..]) => Some((private_key, Some(bits))),
        Some(_) => None,
    }
}

/// The first octet of an uncompressed SEC 1 point (SEC 1 §2.3.3).
pub(crate) const UNCOMPRESSED: u8 = 0x04;

/// A NIST curve's RFC 5480 §2.1.1 AlgorithmIdentifier, id-ecPublicKey with its namedCurve, and its
/// private scalar and uncompressed point lengths (RFC 5915 §3, SEC 1 §2.3.3).
pub(crate) struct EcCurve {
    algorithm: &'static [u8],
    pub(crate) scalar_len: usize,
    point_len: usize,
}

const ALGORITHM_HEADER: usize = 11;

impl EcCurve {
    fn named_curve(&self) -> &'static [u8] {
        &self.algorithm[ALGORITHM_HEADER..]
    }
}

pub(crate) const P256: EcCurve = EcCurve {
    algorithm: &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ],
    scalar_len: 32,
    point_len: 65,
};

pub(crate) const P384: EcCurve = EcCurve {
    algorithm: &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x22,
    ],
    scalar_len: 48,
    point_len: 97,
};

pub(crate) const P521: EcCurve = EcCurve {
    algorithm: &[
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x23,
    ],
    scalar_len: 66,
    point_len: 133,
};

/// The publicKey point an EC private key carries, if any, once `der` is an RFC 5958 §2
/// PrivateKeyInfo, version v1, whose privateKeyAlgorithm is `c`'s and whose privateKey is one RFC
/// 5915 §3 ECPrivateKey on `c`; or, where `bare` allows it, that ECPrivateKey alone, with its
/// parameters.
pub(crate) fn ec<'a>(c: &EcCurve, der: &'a [u8], bare: bool) -> Option<Option<&'a [u8]>> {
    if let Some((private_key, _)) = one_asymmetric_key(der, c.algorithm, false) {
        let Some((0x30, body, [])) = split_tlv(private_key) else {
            return None;
        };
        return ec_private_key(c, body, false);
    }
    match split_tlv(der) {
        Some((0x30, body, [])) if bare => ec_private_key(c, body, true),
        _ => None,
    }
}

// RFC 5915 §3 (EXPLICIT TAGS). §3 requires parameters; inside a PrivateKeyInfo, §1 a) puts the
// curve in privateKeyAlgorithm.
fn ec_private_key<'a>(c: &EcCurve, body: &'a [u8], bare: bool) -> Option<Option<&'a [u8]>> {
    let rest = body.strip_prefix(&[0x02, 0x01, 0x01])?;
    let Some((0x04, scalar, rest)) = split_tlv(rest) else {
        return None;
    };
    let (parameters, rest) = optional(0xa0, rest);
    let (public_key, rest) = optional(0xa1, rest);
    let curve = match parameters {
        Some(named_curve) => named_curve == c.named_curve(),
        None => !bare,
    };
    if scalar.len() != c.scalar_len || !curve || !rest.is_empty() {
        return None;
    }
    match public_key.map(split_tlv) {
        None => Some(None),
        // RFC 5480 §2.2: an uncompressed point, the crate's only public-key form.
        Some(Some((0x03, [0x00, point @ ..], [])))
            if point.len() == c.point_len && point.first() == Some(&UNCOMPRESSED) =>
        {
            Some(Some(point))
        }
        Some(_) => None,
    }
}

// RFC 8410 §3: id-Ed25519, parameters absent.
const ED25519_ALGORITHM: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// The publicKey an Ed25519 private key carries, if any, once `der` is an RFC 5958 §2
/// OneAsymmetricKey with RFC 8410 §3's id-Ed25519 and no parameters, its privateKey the 32-byte
/// CurvePrivateKey (RFC 8410 §7, RFC 8032 §5.1.5), version v1, or v2 with a 32-byte publicKey.
pub(crate) fn ed25519(der: &[u8]) -> Option<Option<&[u8]>> {
    let (private_key, public_key) = one_asymmetric_key(der, ED25519_ALGORITHM, true)?;
    match (split_tlv(private_key)?, public_key) {
        ((0x04, seed, []), None) if seed.len() == 32 => Some(None),
        ((0x04, seed, []), Some(key)) if seed.len() == 32 && key.len() == 32 => Some(Some(key)),
        _ => None,
    }
}

// RFC 3279 §2.3.1, RFC 8017 A.1: rsaEncryption, parameters NULL.
const RSA_ALGORITHM: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

// RFC 8017 §3.2: a positive INTEGER, DER-minimal (X.690 §8.3.2): its contents and what follows.
fn positive(der: &[u8]) -> Option<(&[u8], &[u8])> {
    match split_tlv(der)? {
        (0x02, value @ ([0x01..=0x7f, ..] | [0x00, 0x80..=0xff, ..]), rest) => Some((value, rest)),
        _ => None,
    }
}

/// Whether `der` is an RFC 5958 §2 PrivateKeyInfo, version v1, with rsaEncryption and NULL
/// parameters, whose privateKey is one RFC 8017 A.1.2 RSAPrivateKey: version 0 (two primes), then
/// eight positive, minimal INTEGERs and nothing after them, the modulus of exactly `bits` bits and
/// the public exponent 65537.
pub(crate) fn rsa(der: &[u8], bits: usize) -> bool {
    let Some((private_key, _)) = one_asymmetric_key(der, RSA_ALGORITHM, false) else {
        return false;
    };
    let Some((0x30, body, [])) = split_tlv(private_key) else {
        return false;
    };
    let Some(rest) = body.strip_prefix(&[0x02, 0x01, 0x00]) else {
        return false;
    };
    let mut rest = rest;
    let mut values = Vec::with_capacity(8);
    for _ in 0..8 {
        let Some((value, next)) = positive(rest) else {
            return false;
        };
        values.push(value);
        rest = next;
    }
    let n = values[0];
    rest.is_empty()
        && n.first() == Some(&0)
        && n.len() == 1 + bits / 8
        && values[1] == [0x01, 0x00, 0x01]
}

// RFC 9881 §2: id-ml-dsa-87, parameters absent.
const ML_DSA_87_ALGORITHM: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];

const ML_DSA_87_EXPANDED_KEY: usize = 4896;
const ML_DSA_87_PUBLIC_KEY: usize = 2592;

/// What a private key carries besides the key, each of which must be the imported key's own: the
/// publicKey, and for ML-DSA-87 the expandedKey of RFC 9881 §6's `both` form.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Carried<'a> {
    pub(crate) public_key: Option<&'a [u8]>,
    pub(crate) expanded_key: Option<&'a [u8]>,
}

/// What an ML-DSA-87 private key carries, once `der` is an RFC 5958 §2 OneAsymmetricKey with RFC
/// 9881 §2's id-ml-dsa-87 and no parameters, its privateKey one RFC 9881 §6 ML-DSA-87-PrivateKey:
/// the 32-byte seed, or both the seed and the 4,896-byte expandedKey. The expandedKey form alone is
/// refused: the module cannot export such a key again. Version v1, or v2 with a 2,592-byte
/// publicKey.
pub(crate) fn ml_dsa_87(der: &[u8]) -> Option<Carried<'_>> {
    let (private_key, public_key) = one_asymmetric_key(der, ML_DSA_87_ALGORITHM, true)?;
    let expanded_key = match split_tlv(private_key)? {
        (0x80, seed, []) if seed.len() == 32 => None,
        (0x30, both, []) => match split_tlv(both)? {
            (0x04, seed, expanded) if seed.len() == 32 => match split_tlv(expanded)? {
                (0x04, key, []) if key.len() == ML_DSA_87_EXPANDED_KEY => Some(key),
                _ => return None,
            },
            _ => return None,
        },
        _ => return None,
    };
    match public_key {
        Some(key) if key.len() != ML_DSA_87_PUBLIC_KEY => None,
        _ => Some(Carried {
            public_key,
            expanded_key,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_minimally_encoded_sequence_spanning_the_input_is_whole() {
        let with = |head: &[u8], n: usize| [head, &vec![0; n][..]].concat();
        let is_one_sequence = |der: &[u8]| matches!(split_tlv(der), Some((0x30, _, [])));
        for (whole, header) in [
            (with(&[0x30, 0x03], 3), 2),
            (with(&[0x30, 0x81, 0x80], 0x80), 3),
            (with(&[0x30, 0x82, 0x01, 0x01], 0x101), 4),
        ] {
            let empty: &[u8] = &[];
            assert_eq!(
                split_tlv(&whole),
                Some((0x30, &whole[header..], empty)),
                "{:02x?}",
                &whole[..4]
            );
        }
        for bad in [
            Vec::new(),
            vec![0x30],
            with(&[0x30, 0x03], 2),
            with(&[0x30, 0x03], 4),
            with(&[0x31, 0x03], 3),
            with(&[0x30, 0x80], 2),
            with(&[0x30, 0x81, 0x7f], 0x7f),
            with(&[0x30, 0x81, 0x80], 0x81),
            with(&[0x30, 0x82, 0x00, 0xff], 0xff),
            with(&[0x30, 0x82, 0x01, 0x01], 0x100),
            with(&[0x30, 0x83, 0x00, 0x01, 0x00], 0x100),
        ] {
            assert!(!is_one_sequence(&bad), "{bad:02x?}");
        }
    }

    #[test]
    fn a_tag_number_above_30_alone_takes_the_minimal_high_tag_number_form() {
        let empty: &[u8] = &[];
        for (der, first) in [
            (&[0x1f, 0x1f, 0x01, 0x00][..], 0x1f),
            (&[0x9f, 0x28, 0x01, 0x00], 0x9f),
            (&[0xbf, 0x81, 0x00, 0x01, 0x00], 0xbf),
            (&[0x1f, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x01, 0x00], 0x1f),
            (&[0x1f, 0x90, 0x80, 0x80, 0x80, 0x00, 0x01, 0x00], 0x1f),
            (
                &[0x1f, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00, 0x01, 0x00],
                0x1f,
            ),
        ] {
            assert_eq!(
                split_tlv(der),
                Some((first, &[0x00][..], empty)),
                "{der:02x?}"
            );
        }
        for bad in [
            &[0x1f, 0x01, 0x00][..],
            &[0x1f, 0x1e, 0x01, 0x00],
            &[0x1f, 0x80, 0x1f, 0x01, 0x00],
            &[0x1f],
            &[0x1f, 0x81],
            &[0x1f, 0x81, 0x80],
        ] {
            assert_eq!(split_tlv(bad), None, "{bad:02x?}");
        }
    }

    #[test]
    fn set_of_elements_are_compared_as_octet_strings_padded_with_zeros() {
        assert!(not_after(&[1, 2], &[1, 3]));
        assert!(not_after(&[1, 2], &[1, 2]));
        assert!(not_after(&[1, 2], &[1, 2, 1]));
        assert!(not_after(&[1, 2], &[1, 2, 0]));
        assert!(not_after(&[1, 2, 0], &[1, 2]));
        assert!(!not_after(&[1, 3], &[1, 2]));
        assert!(!not_after(&[1, 2, 1], &[1, 2]));
        assert!(!not_after(&[1, 3], &[1, 2, 9]));
        assert!(!not_after(&[2], &[1, 9, 9]));
        assert!(not_after(&[1, 9, 9], &[2]));
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let n = u16::try_from(value.len()).unwrap();
        let [hi, lo] = n.to_be_bytes();
        let len = match n {
            0..=0x7f => vec![lo],
            0x80..=0xff => vec![0x81, lo],
            _ => vec![0x82, hi, lo],
        };
        [&[tag][..], &len, value].concat()
    }

    fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &fields.concat())
    }

    fn attribute(last: u8) -> Vec<u8> {
        sequence(&[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, last],
            ),
            tlv(0x31, &[]),
        ])
    }

    const V1: [u8; 3] = [0x02, 0x01, 0x00];
    const V2: [u8; 3] = [0x02, 0x01, 0x01];
    const NULL: [u8; 2] = [0x05, 0x00];

    fn key(version: &[u8], algorithm: &[u8], private_key: &[u8], after: &[Vec<u8>]) -> Vec<u8> {
        let fields = [
            vec![version.to_vec(), algorithm.to_vec(), tlv(0x04, private_key)],
            after.to_vec(),
        ]
        .concat();
        sequence(&fields)
    }

    fn bits(key: &[u8]) -> Vec<u8> {
        tlv(0x81, &[&[0][..], key].concat())
    }

    // Every OneAsymmetricKey framing the validators share, around a well-formed privateKey `inner`
    // and, where the type defines one, a publicKey `public`.
    fn framings(
        algorithm: &[u8],
        inner: &[u8],
        public: Option<&[u8]>,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let attributes = tlv(0xa0, &[attribute(0x14), attribute(0x15)].concat());
        let mut bad = vec![
            (
                "trailing byte",
                [key(&V1, algorithm, inner, &[]), vec![0]].concat(),
            ),
            (
                "two keys",
                [
                    key(&V1, algorithm, inner, &[]),
                    key(&V1, algorithm, inner, &[]),
                ]
                .concat(),
            ),
            ("v2 without [1]", key(&V2, algorithm, inner, &[])),
            ("version 2", key(&[0x02, 0x01, 0x02], algorithm, inner, &[])),
            (
                "version 0 in two bytes",
                key(&[0x02, 0x02, 0x00, 0x00], algorithm, inner, &[]),
            ),
            (
                "attributes out of order",
                key(
                    &V1,
                    algorithm,
                    inner,
                    &[tlv(0xa0, &[attribute(0x15), attribute(0x14)].concat())],
                ),
            ),
            (
                "attributes as an explicit SET",
                key(&V1, algorithm, inner, &[tlv(0x31, &attribute(0x14))]),
            ),
            (
                "an undefined field",
                key(&V1, algorithm, inner, &[NULL.to_vec()]),
            ),
            (
                "two [0]",
                key(
                    &V1,
                    algorithm,
                    inner,
                    &[attributes.clone(), attributes.clone()],
                ),
            ),
            (
                "unknown [2]",
                key(&V1, algorithm, inner, &[tlv(0xa2, &NULL)]),
            ),
            (
                "privateKey not an OCTET STRING",
                sequence(&[V1.to_vec(), algorithm.to_vec(), tlv(0x30, inner)]),
            ),
            (
                "another algorithm",
                key(
                    &V1,
                    &sequence(&[tlv(0x06, &[0x2b, 0x65, 0x6e])]),
                    inner,
                    &[],
                ),
            ),
            (
                "the algorithm with NULL appended",
                key(
                    &V1,
                    &tlv(0x30, &[&algorithm[2..], &NULL[..]].concat()),
                    inner,
                    &[],
                ),
            ),
            ("BER outer length", {
                let good = key(&V1, algorithm, inner, &[]);
                let (_, body, _) = split_tlv(&good).unwrap();
                let n = u32::try_from(body.len()).unwrap().to_be_bytes();
                [&[0x30, 0x84][..], &n, body].concat()
            }),
        ];
        match public {
            Some(public) => {
                bad.push(("v1 with [1]", key(&V1, algorithm, inner, &[bits(public)])));
                bad.push((
                    "[1] with unused bits",
                    key(
                        &V2,
                        algorithm,
                        inner,
                        &[tlv(0x81, &[&[1][..], public].concat())],
                    ),
                ));
                bad.push((
                    "[1] constructed",
                    key(
                        &V2,
                        algorithm,
                        inner,
                        &[tlv(0xa1, &tlv(0x03, &[&[0][..], public].concat()))],
                    ),
                ));
                bad.push((
                    "[1] before [0]",
                    key(&V2, algorithm, inner, &[bits(public), attributes.clone()]),
                ));
                bad.push((
                    "[1] one byte short",
                    key(&V2, algorithm, inner, &[bits(&public[1..])]),
                ));
                bad.push((
                    "[1] one byte long",
                    key(&V2, algorithm, inner, &[bits(&[public, &[0]].concat())]),
                ));
                bad.push((
                    "two [1]",
                    key(&V2, algorithm, inner, &[bits(public), bits(public)]),
                ));
            }
            None => bad.push(("v2 with [1]", key(&V2, algorithm, inner, &[bits(&[7; 32])]))),
        }
        bad
    }

    #[test]
    fn every_validator_takes_v1_attributes_and_refuses_what_rfc_5958_does_not_define() {
        let ec_inner = sequence(&[V2.to_vec(), tlv(0x04, &[7; 48])]);
        let rsa_inner = rsa_private_key(2048, &[0x01, 0x00, 0x01]);
        let ed_inner = tlv(0x04, &[9; 32]);
        let ml_inner = tlv(0x80, &[5; 32]);
        let attributes = tlv(0xa0, &[attribute(0x14), attribute(0x15)].concat());
        type Case<'a> = (
            &'a str,
            &'a [u8],
            &'a [u8],
            Option<Vec<u8>>,
            fn(&[u8]) -> bool,
        );
        let cases: [Case<'_>; 4] = [
            ("ec", P384.algorithm, &ec_inner, None, |d| {
                ec(&P384, d, false).is_some()
            }),
            ("rsa", RSA_ALGORITHM, &rsa_inner, None, |d| rsa(d, 2048)),
            (
                "ed25519",
                ED25519_ALGORITHM,
                &ed_inner,
                Some(vec![3; 32]),
                |d| ed25519(d).is_some(),
            ),
            (
                "ml-dsa-87",
                ML_DSA_87_ALGORITHM,
                &ml_inner,
                Some(vec![4; 2592]),
                |d| ml_dsa_87(d).is_some(),
            ),
        ];
        for (name, algorithm, inner, public, check) in cases {
            assert!(check(&key(&V1, algorithm, inner, &[])), "{name}");
            assert!(
                check(&key(
                    &V1,
                    algorithm,
                    inner,
                    std::slice::from_ref(&attributes)
                )),
                "{name}"
            );
            assert!(
                check(&key(&V1, algorithm, inner, &[tlv(0xa0, &[])])),
                "{name}"
            );
            if let Some(public) = &public {
                assert!(
                    check(&key(&V2, algorithm, inner, &[bits(public)])),
                    "{name}"
                );
                assert!(
                    check(&key(
                        &V2,
                        algorithm,
                        inner,
                        &[attributes.clone(), bits(public)]
                    )),
                    "{name}"
                );
            }
            for (why, der) in framings(algorithm, inner, public.as_deref()) {
                assert!(!check(&der), "{name}: {why} {der:02x?}");
            }
        }
    }

    #[test]
    fn an_ed25519_key_is_a_32_byte_curve_private_key_with_its_32_byte_public_key() {
        let public = [3; 32];
        assert_eq!(
            ed25519(&key(&V1, ED25519_ALGORITHM, &tlv(0x04, &[9; 32]), &[])),
            Some(None)
        );
        assert_eq!(
            ed25519(&key(
                &V2,
                ED25519_ALGORITHM,
                &tlv(0x04, &[9; 32]),
                &[bits(&public)]
            )),
            Some(Some(&public[..]))
        );
        for (why, inner) in [
            ("31 bytes", tlv(0x04, &[9; 31])),
            ("33 bytes", tlv(0x04, &[9; 33])),
            ("not wrapped", vec![9; 32]),
            ("wrapped twice", tlv(0x04, &tlv(0x04, &[9; 32]))),
            ("a byte after", [tlv(0x04, &[9; 32]), vec![0]].concat()),
            ("a BIT STRING", tlv(0x03, &[9; 32])),
        ] {
            assert_eq!(
                ed25519(&key(&V1, ED25519_ALGORITHM, &inner, &[])),
                None,
                "{why}"
            );
        }
        let null = sequence(&[tlv(0x06, &[0x2b, 0x65, 0x70]), NULL.to_vec()]);
        assert_eq!(ed25519(&key(&V1, &null, &tlv(0x04, &[9; 32]), &[])), None);
    }

    fn integer(magnitude: &[u8]) -> Vec<u8> {
        if magnitude[0] & 0x80 == 0 {
            tlv(0x02, magnitude)
        } else {
            tlv(0x02, &[&[0][..], magnitude].concat())
        }
    }

    fn rsa_private_key(bits: usize, e: &[u8]) -> Vec<u8> {
        let mut n = vec![0xc5; bits / 8];
        n[bits / 8 - 1] = 0x01;
        let half = vec![0xd3; bits / 16];
        sequence(&[
            V1.to_vec(),
            integer(&n),
            integer(e),
            integer(&n),
            integer(&half),
            integer(&half),
            integer(&half),
            integer(&half),
            integer(&half),
        ])
    }

    #[test]
    fn an_rsa_key_is_version_0_then_eight_positive_minimal_integers() {
        let pki = |inner: &[u8]| key(&V1, RSA_ALGORITHM, inner, &[]);
        for bits in [2048, 3072, 4096] {
            assert!(rsa(&pki(&rsa_private_key(bits, &[0x01, 0x00, 0x01])), bits));
        }
        let good = rsa_private_key(2048, &[0x01, 0x00, 0x01]);
        let (_, body, _) = split_tlv(&good).unwrap();
        let mut fields = Vec::new();
        let mut rest = body;
        while let Some((tag, value, next)) = split_tlv(rest).filter(|_| fields.len() < 16) {
            fields.push(tlv(tag, value));
            rest = next;
        }
        assert_eq!(fields.len(), 9);
        let with = |at: usize, field: Vec<u8>| {
            let mut f = fields.clone();
            f[at] = field;
            sequence(&f)
        };
        let mut wider = vec![0xc5; 257];
        wider[0] = 0x01;
        let zero = tlv(0x02, &[0]);
        for (why, inner) in [
            ("version 1, multi-prime", with(0, vec![0x02, 0x01, 0x01])),
            (
                "version 0 in two bytes",
                with(0, vec![0x02, 0x02, 0x00, 0x00]),
            ),
            ("2,049 bits", with(1, integer(&wider))),
            ("2,040 bits", with(1, integer(&[0xc5; 255]))),
            (
                "2,047 bits",
                with(1, tlv(0x02, &[&[0x7f][..], &[0xc5; 255]].concat())),
            ),
            ("e = 3", with(2, integer(&[3]))),
            ("e = 65539", with(2, integer(&[0x01, 0x00, 0x03]))),
            (
                "e with a leading zero",
                with(2, tlv(0x02, &[0x00, 0x01, 0x00, 0x01])),
            ),
            ("e zero (stripped)", with(2, zero.clone())),
            ("d zero", with(3, zero.clone())),
            ("p zero", with(4, zero.clone())),
            ("q zero", with(5, zero.clone())),
            ("dP zero", with(6, zero.clone())),
            ("dQ zero", with(7, zero.clone())),
            ("qInv zero", with(8, zero.clone())),
            ("qInv negative", with(8, tlv(0x02, &[0x80, 0x01]))),
            ("qInv non-minimal", with(8, tlv(0x02, &[0x00, 0x01]))),
            ("qInv empty", with(8, tlv(0x02, &[]))),
            ("qInv an OCTET STRING", with(8, tlv(0x04, &[0x01]))),
            ("eight integers", sequence(&fields[..8])),
            (
                "ten integers",
                sequence(&[&fields[..], &[integer(&[1])]].concat()),
            ),
            (
                "otherPrimeInfos",
                sequence(
                    &[
                        &fields[..],
                        &[sequence(&[sequence(&[
                            integer(&[3]),
                            integer(&[3]),
                            integer(&[3]),
                        ])])],
                    ]
                    .concat(),
                ),
            ),
            ("a byte after", [good.clone(), vec![0]].concat()),
            ("not a SEQUENCE", tlv(0x31, body)),
        ] {
            assert!(!rsa(&pki(&inner), 2048), "{why}");
        }
        assert!(!rsa(&pki(&good), 3072));
        let absent = sequence(&[RSA_ALGORITHM[2..13].to_vec()]);
        assert!(
            !rsa(&key(&V1, &absent, &good, &[]), 2048),
            "parameters absent"
        );
        let pss = sequence(&[tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
        )]);
        assert!(!rsa(&key(&V1, &pss, &good, &[]), 2048), "id-RSASSA-PSS");
    }

    #[test]
    fn positive_takes_minimal_positive_integers_only() {
        for value in [
            &[0x01][..],
            &[0x7f],
            &[0x00, 0x80],
            &[0x00, 0xff, 0x00],
            &[0x01, 0x00],
        ] {
            let der = [tlv(0x02, value), vec![0xee]].concat();
            assert_eq!(positive(&der), Some((value, &[0xee][..])), "{value:02x?}");
        }
        for value in [&[][..], &[0x00], &[0x00, 0x7f], &[0x80], &[0xff, 0x01]] {
            assert_eq!(positive(&tlv(0x02, value)), None, "{value:02x?}");
        }
        assert_eq!(positive(&tlv(0x04, &[0x01])), None);
    }

    #[test]
    fn an_ml_dsa_87_key_is_the_seed_or_both_forms_with_nothing_after() {
        let pki = |inner: &[u8], after: &[Vec<u8>]| {
            let version = if after.is_empty() { &V1 } else { &V2 };
            key(version, ML_DSA_87_ALGORITHM, inner, after)
        };
        let seed = tlv(0x80, &[5; 32]);
        let expanded = tlv(0x04, &[6; 4896]);
        let both = sequence(&[tlv(0x04, &[5; 32]), expanded.clone()]);
        let public = vec![4; 2592];
        let carried = |public_key, expanded_key| {
            Some(Carried {
                public_key,
                expanded_key,
            })
        };
        let expanded_key = Some(&[6; 4896][..]);
        assert_eq!(ml_dsa_87(&pki(&seed, &[])), carried(None, None));
        assert_eq!(ml_dsa_87(&pki(&both, &[])), carried(None, expanded_key));
        assert_eq!(
            ml_dsa_87(&pki(&seed, &[bits(&public)])),
            carried(Some(&public[..]), None)
        );
        assert_eq!(
            ml_dsa_87(&pki(&both, &[bits(&public)])),
            carried(Some(&public[..]), expanded_key)
        );
        for (why, inner) in [
            ("expandedKey alone", expanded.clone()),
            ("seed then 05 00", [seed.clone(), NULL.to_vec()].concat()),
            ("both then 05 00", [both.clone(), NULL.to_vec()].concat()),
            ("seed of 31 bytes", tlv(0x80, &[5; 31])),
            ("seed of 33 bytes", tlv(0x80, &[5; 33])),
            ("seed as an OCTET STRING", tlv(0x04, &[5; 32])),
            ("seed constructed", tlv(0xa0, &tlv(0x04, &[5; 32]))),
            (
                "both, expandedKey one byte short",
                sequence(&[tlv(0x04, &[5; 32]), tlv(0x04, &[6; 4895])]),
            ),
            (
                "both, expandedKey one byte long",
                sequence(&[tlv(0x04, &[5; 32]), tlv(0x04, &[6; 4897])]),
            ),
            (
                "both, seed of 31 bytes",
                sequence(&[tlv(0x04, &[5; 31]), expanded.clone()]),
            ),
            (
                "both, seed tagged [0]",
                sequence(&[tlv(0x80, &[5; 32]), expanded.clone()]),
            ),
            (
                "both, expandedKey first",
                sequence(&[expanded.clone(), tlv(0x04, &[5; 32])]),
            ),
            (
                "both, a field after",
                sequence(&[tlv(0x04, &[5; 32]), expanded.clone(), NULL.to_vec()]),
            ),
            ("both, seed only", sequence(&[tlv(0x04, &[5; 32])])),
            ("empty", vec![]),
        ] {
            assert_eq!(ml_dsa_87(&pki(&inner, &[])), None, "{why}");
            assert_eq!(ml_dsa_87(&pki(&inner, &[bits(&public)])), None, "{why}, v2");
        }
        let with_params = sequence(&[tlv(0x06, &ML_DSA_87_ALGORITHM[4..]), NULL.to_vec()]);
        assert_eq!(ml_dsa_87(&key(&V1, &with_params, &seed, &[])), None);
    }

    #[test]
    fn the_ec_algorithm_identifiers_name_their_curves() {
        for (c, oid) in [
            (
                &P256,
                &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..],
            ),
            (&P384, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
            (&P521, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        ] {
            assert_eq!(c.named_curve(), oid);
            assert_eq!(
                c.algorithm,
                sequence(&[
                    tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                    oid.to_vec()
                ])
            );
            assert_eq!(c.point_len, 2 * c.scalar_len + 1);
        }
    }
}
