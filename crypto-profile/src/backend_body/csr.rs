//! Certificate signing requests for a TLS certificate key.
use crate::tls::CertificateKey;
use crate::{CryptoError, CsrError};
use std::net::IpAddr;

/// An extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtendedKeyUsage {
    /// TLS server authentication.
    ServerAuth,
    /// TLS client authentication.
    ClientAuth,
}

/// A key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyUsage {
    /// Digital signature.
    DigitalSignature,
    /// Key encipherment.
    KeyEncipherment,
    /// Key agreement.
    KeyAgreement,
}

/// What a request asks for. An empty value leaves that part out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CsrParams {
    /// The subject common name.
    pub common_name: Option<String>,
    /// The subject organization.
    pub organization: Option<String>,
    /// The subject organizational unit.
    pub organizational_unit: Option<String>,
    /// DNS subject alternative names.
    pub dns_names: Vec<String>,
    /// IP subject alternative names.
    pub ip_addresses: Vec<IpAddr>,
    /// URI subject alternative names.
    pub uris: Vec<String>,
    /// Extended key usages.
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    /// Key usages.
    pub key_usage: Vec<KeyUsage>,
}

/// A PEM PKCS#10 request for `key`, signed by it. The profile admitted `key` when it was made
/// (`tls::CertificateKey::generate`), so the request is for a key of the profile's TLS key list;
/// keep the key to request again for it. Refuses the request's names and parameters
/// (`CryptoError::Csr`).
pub fn generate_csr(key: &CertificateKey, p: &CsrParams) -> Result<String, CryptoError> {
    let name = |_| CryptoError::Csr(CsrError::InvalidName);
    let signing = |_| CryptoError::Csr(CsrError::Signing);
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|_| CryptoError::Csr(CsrError::InvalidParams))?;
    let mut dn = rcgen::DistinguishedName::new();
    if let Some(v) = &p.common_name {
        dn.push(rcgen::DnType::CommonName, v.as_str());
    }
    if let Some(v) = &p.organization {
        dn.push(rcgen::DnType::OrganizationName, v.as_str());
    }
    if let Some(v) = &p.organizational_unit {
        dn.push(rcgen::DnType::OrganizationalUnitName, v.as_str());
    }
    params.distinguished_name = dn;
    let mut sans = Vec::new();
    for d in &p.dns_names {
        sans.push(rcgen::SanType::DnsName(
            d.as_str().try_into().map_err(name)?,
        ));
    }
    for ip in &p.ip_addresses {
        sans.push(rcgen::SanType::IpAddress(*ip));
    }
    for u in &p.uris {
        sans.push(rcgen::SanType::URI(u.as_str().try_into().map_err(name)?));
    }
    params.subject_alt_names = sans;
    params.extended_key_usages = p
        .extended_key_usage
        .iter()
        .map(|e| match e {
            ExtendedKeyUsage::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsage::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        })
        .collect();
    params.key_usages = p
        .key_usage
        .iter()
        .map(|k| match k {
            KeyUsage::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
            KeyUsage::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
            KeyUsage::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
        })
        .collect();
    params
        .serialize_request(key.key_pair())
        .map_err(signing)?
        .pem()
        .map_err(signing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_profile::SignatureAlgorithm as S;
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::prelude::FromDer;

    fn der(pem_text: &str) -> Vec<u8> {
        let p = pem::parse(pem_text).unwrap();
        assert_eq!(p.tag(), "CERTIFICATE REQUEST");
        p.contents().to_vec()
    }

    fn assert_request_for(key: &CertificateKey, pem_text: &str) {
        let a = key.algorithm();
        let der = der(pem_text);
        let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
        let info = &csr.certification_request_info;
        assert_eq!(
            info.subject_pki.subject_public_key.data.as_ref(),
            key.public_key(),
            "{a}"
        );
        assert_eq!(
            csr.signature_algorithm.algorithm.to_id_string(),
            a.signature_oid(),
            "{a}"
        );
        let params = match info.subject_pki.algorithm.parameters.as_ref() {
            None => crate::signature::SpkiParams::Absent,
            Some(p) if p.header.tag() == x509_parser::der_parser::asn1_rs::Tag::Null => {
                crate::signature::SpkiParams::Null
            }
            Some(p) => match p.as_oid() {
                Ok(oid) => crate::signature::SpkiParams::NamedCurve(oid.to_id_string()),
                Err(_) => crate::signature::SpkiParams::Other,
            },
        };
        assert!(
            crate::signature::matches_spki(
                a,
                &info.subject_pki.algorithm.algorithm.to_id_string(),
                &params,
                key.public_key().len(),
                info.subject_pki.subject_public_key.unused_bits
            ),
            "{a}"
        );
        let oracle = super::super::backend::csr_oracle(a).unwrap();
        assert!(
            oracle
                .verify_signature(
                    key.public_key(),
                    info.raw,
                    csr.signature_value.data.as_ref()
                )
                .is_ok(),
            "{a}: the backend oracle refuses our CSR signature"
        );
    }

    fn unrestricted() -> crate::Resolved {
        crate::resolve(crate::Profile::Unrestricted, crate::Options::default()).unwrap()
    }

    fn key(a: S) -> CertificateKey {
        CertificateKey::generate(&unrestricted(), a).unwrap()
    }

    #[test]
    fn every_algorithm_signs_a_request_for_its_own_key() {
        let params = CsrParams {
            common_name: Some("svc.example.test".into()),
            dns_names: vec!["svc.example.test".into()],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            key_usage: vec![KeyUsage::DigitalSignature],
            ..Default::default()
        };
        let r = unrestricted();
        for &a in S::ALL {
            if !r.keys.contains(&a) {
                assert_eq!(
                    CertificateKey::generate(&r, a).err(),
                    Some(CryptoError::KeyNotInProfile {
                        profile: crate::Profile::Unrestricted,
                        algorithm: a
                    })
                );
                assert!(super::super::backend::csr_oracle(a).is_err());
                continue;
            }
            let key = CertificateKey::generate(&r, a).unwrap();
            assert_request_for(&key, &generate_csr(&key, &params).unwrap());
        }
    }

    #[test]
    fn every_profile_tls_key_is_requested_bound_presented_and_reimported() {
        let client = unrestricted().tls;
        let mut seen = 0;
        for &p in crate::Profile::ALL {
            let r = match crate::resolve(p, crate::Options::default()) {
                Ok(r) => r,
                Err(e) => {
                    assert_eq!(
                        (p, crate::MODULE.line),
                        (crate::Profile::Cnsa2, crate::ModuleLine::AwsLcFips3),
                        "{e:?}"
                    );
                    continue;
                }
            };
            for &a in &r.keys {
                let key = CertificateKey::generate(&r, a).unwrap();
                assert_request_for(&key, &generate_csr(&key, &CsrParams::default()).unwrap());
                let again =
                    CertificateKey::from_pkcs8_der(&r, a, &key.to_pkcs8_der().unwrap()).unwrap();
                assert_eq!(again.public_key(), key.public_key(), "{p} {a}");
                let pki = crate::test_support::issue(S::EcdsaP384Sha384, again).unwrap();
                assert!(r.certified_key(pki.chain, &pki.key).is_ok(), "{p} {a}");
                let n = crate::test_support::handshake_certified(&client, &r, a)
                    .unwrap_or_else(|e| panic!("{p} {a}: {e}"));
                assert!(r.tls.signature_schemes.contains(&n.scheme), "{p} {a}");
                seen += 1;
            }
        }
        assert!(seen > 0);
    }

    #[test]
    fn an_rsa_pss_key_in_a_reassigned_list_is_refused_at_signing() {
        let mut r = unrestricted();
        r.keys.push(S::Rsa2048Sha384Pss);
        let key = CertificateKey::generate(&r, S::Rsa2048Sha384Pss).unwrap();
        assert_eq!(
            generate_csr(&key, &CsrParams::default()).err(),
            Some(CryptoError::Csr(CsrError::Signing))
        );
    }

    #[test]
    fn every_field_reaches_the_request() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        let params = CsrParams {
            common_name: Some("cn.example.test".into()),
            organization: Some("Example Org".into()),
            organizational_unit: Some("Example Unit".into()),
            dns_names: vec!["dns.example.test".into()],
            ip_addresses: vec!["192.0.2.7".parse().unwrap()],
            uris: vec!["spiffe://example.test/x".into()],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
            key_usage: vec![
                KeyUsage::DigitalSignature,
                KeyUsage::KeyEncipherment,
                KeyUsage::KeyAgreement,
            ],
        };
        let pem_text = generate_csr(&key(S::Rsa2048Sha384), &params).unwrap();
        let der = der(&pem_text);
        let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
        let subject = csr.certification_request_info.subject.to_string();
        for want in ["CN=cn.example.test", "O=Example Org", "OU=Example Unit"] {
            assert!(subject.contains(want), "{subject}");
        }
        let exts: Vec<_> = csr.requested_extensions().into_iter().flatten().collect();
        let san: Vec<String> = exts
            .iter()
            .filter_map(|e| match e {
                ParsedExtension::SubjectAlternativeName(s) => Some(
                    s.general_names
                        .iter()
                        .map(|g| match g {
                            GeneralName::DNSName(d) => format!("dns:{d}"),
                            GeneralName::IPAddress(ip) => format!("ip:{ip:?}"),
                            GeneralName::URI(u) => format!("uri:{u}"),
                            other => format!("other:{other:?}"),
                        })
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            san,
            [
                "dns:dns.example.test",
                "ip:[192, 0, 2, 7]",
                "uri:spiffe://example.test/x"
            ]
        );
        let eku = exts.iter().find_map(|e| match e {
            ParsedExtension::ExtendedKeyUsage(k) => Some((k.server_auth, k.client_auth)),
            _ => None,
        });
        assert_eq!(eku, Some((true, true)));
        let ku = exts.iter().find_map(|e| match e {
            ParsedExtension::KeyUsage(k) => Some((
                k.digital_signature(),
                k.key_encipherment(),
                k.key_agreement(),
            )),
            _ => None,
        });
        assert_eq!(ku, Some((true, true, true)));
    }

    #[test]
    fn a_uri_only_request_has_an_empty_subject_and_one_san() {
        let params = CsrParams {
            uris: vec!["spiffe://example.test/plane/kernel".into()],
            ..Default::default()
        };
        let pem_text = generate_csr(&key(S::EcdsaP384Sha384), &params).unwrap();
        let der = der(&pem_text);
        let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
        assert_eq!(csr.certification_request_info.subject.iter().count(), 0);
        let sans: usize = csr
            .requested_extensions()
            .into_iter()
            .flatten()
            .filter_map(|e| match e {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(s) => {
                    Some(s.general_names.len())
                }
                _ => None,
            })
            .sum();
        assert_eq!(sans, 1);
    }

    #[test]
    fn a_non_ascii_name_is_refused_with_its_cause() {
        let params = CsrParams {
            dns_names: vec!["é.example".into()],
            ..Default::default()
        };
        assert_eq!(
            generate_csr(&key(S::EcdsaP384Sha384), &params).err(),
            Some(CryptoError::Csr(CsrError::InvalidName))
        );
        let params = CsrParams {
            uris: vec!["https://é.example/".into()],
            ..Default::default()
        };
        assert_eq!(
            generate_csr(&key(S::EcdsaP384Sha384), &params).err(),
            Some(CryptoError::Csr(CsrError::InvalidName))
        );
    }
}
