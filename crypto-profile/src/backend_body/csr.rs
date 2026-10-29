//! Certificate signing requests for a fresh key.
use crate::signature::KeyPair;
use crate::{CryptoError, CsrError, SignatureAlgorithm};
use std::net::IpAddr;

/// An extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    /// TLS server authentication.
    ServerAuth,
    /// TLS client authentication.
    ClientAuth,
}

/// A key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A new key of algorithm `a` and a PEM PKCS#10 request for it, signed by that key.
pub fn generate_csr(
    a: SignatureAlgorithm,
    p: &CsrParams,
) -> Result<(KeyPair, String), CryptoError> {
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
    let key = KeyPair::generate(a)?;
    let csr = params
        .serialize_request(&key)
        .map_err(signing)?
        .pem()
        .map_err(signing)?;
    Ok((key, csr))
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

    #[test]
    fn every_algorithm_signs_a_request_for_its_own_key() {
        let params = CsrParams {
            common_name: Some("svc.example.test".into()),
            dns_names: vec!["svc.example.test".into()],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
            key_usage: vec![KeyUsage::DigitalSignature],
            ..Default::default()
        };
        for a in S::ALL {
            if !crate::capability(crate::MODULE, crate::Algorithm::Signature(a)).available {
                assert_eq!(
                    generate_csr(a, &params).err(),
                    Some(CryptoError::Unavailable(crate::Algorithm::Signature(a)))
                );
                assert!(super::super::backend::csr_oracle(a).is_err());
                continue;
            }
            let (key, pem_text) = generate_csr(a, &params).unwrap();
            assert_eq!(key.algorithm(), a);
            let der = der(&pem_text);
            let (_, csr) = X509CertificationRequest::from_der(&der).unwrap();
            let info = &csr.certification_request_info;
            assert_eq!(
                info.subject_pki.subject_public_key.data.as_ref(),
                key.public_key().as_slice(),
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
                        &key.public_key(),
                        info.raw,
                        csr.signature_value.data.as_ref()
                    )
                    .is_ok(),
                "{a}: the backend oracle refuses our CSR signature"
            );
        }
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
        let (_, pem_text) = generate_csr(S::Rsa2048Sha384, &params).unwrap();
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
        let (_, pem_text) = generate_csr(S::EcdsaP384Sha384, &params).unwrap();
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
            generate_csr(S::EcdsaP384Sha384, &params).err(),
            Some(CryptoError::Csr(CsrError::InvalidName))
        );
        let params = CsrParams {
            uris: vec!["https://é.example/".into()],
            ..Default::default()
        };
        assert_eq!(
            generate_csr(S::EcdsaP384Sha384, &params).err(),
            Some(CryptoError::Csr(CsrError::InvalidName))
        );
    }
}
