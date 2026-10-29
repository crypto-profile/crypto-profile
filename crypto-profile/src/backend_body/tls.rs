// Error mapping adapted from rustls 0.23.46, Copyright (c) 2016 Joseph Birr-Pixton,
// MIT license. See LICENSE-THIRD-PARTY.
//! TLS configuration from a [`Policy`]: which versions, cipher suites, key-exchange groups and
//! handshake signature schemes a provider carries, in preference order.
use crate::{
    Algorithm, CipherSuite as C, CryptoError, Family, KxGroup as K, TlsError,
    TlsSignatureScheme as T, TlsVersion as V, ensure,
};
use rustls::crypto::{CryptoProvider, KeyProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// What a TLS configuration may use: versions, suites and groups in preference order, and a set
/// of signature schemes. No list may name an entry twice.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Policy {
    /// Protocol versions.
    pub versions: Vec<V>,
    /// Cipher suites; a suite whose version is not in `versions` is not offered.
    pub cipher_suites: Vec<C>,
    /// Key-exchange groups.
    pub kx_groups: Vec<K>,
    /// Handshake signature schemes: those this side accepts from its peer, and those a key loaded
    /// through this policy's provider signs with. Certificate-chain signature algorithms are not
    /// restricted. A provider carries them in [`TlsSignatureScheme::preference`](T::preference) order,
    /// the order every profile lists them in, whatever order they are given in.
    pub signature_schemes: Vec<T>,
    /// Canonical peer-certificate restrictions; hand-written policies default to none.
    pub peer_certificate_rule: Option<crypto_profile::PeerCertificateRuleId>,
}

pub(crate) use crate::provider::assembly::group as rustls_group;
pub(crate) use crate::provider::assembly::suite as rustls_suite;

fn rustls_scheme(t: T) -> rustls::SignatureScheme {
    use rustls::SignatureScheme as R;
    match t {
        T::EcdsaNistp256Sha256 => R::ECDSA_NISTP256_SHA256,
        T::EcdsaNistp384Sha384 => R::ECDSA_NISTP384_SHA384,
        T::EcdsaNistp521Sha512 => R::ECDSA_NISTP521_SHA512,
        T::Ed25519 => R::ED25519,
        T::RsaPssSha256 => R::RSA_PSS_SHA256,
        T::RsaPssSha384 => R::RSA_PSS_SHA384,
        T::RsaPssSha512 => R::RSA_PSS_SHA512,
        T::RsaPkcs1Sha256 => R::RSA_PKCS1_SHA256,
        T::RsaPkcs1Sha384 => R::RSA_PKCS1_SHA384,
        T::RsaPkcs1Sha512 => R::RSA_PKCS1_SHA512,
        T::MlDsa87 => R::ML_DSA_87,
    }
}

fn rustls_version(v: V) -> &'static rustls::SupportedProtocolVersion {
    match v {
        V::Tls12 => &rustls::version::TLS12,
        V::Tls13 => &rustls::version::TLS13,
    }
}

fn base_provider() -> CryptoProvider {
    crate::provider::assembly::full()
}

type SchemeMapping = (
    rustls::SignatureScheme,
    &'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
);

fn select_schemes(
    base: &[SchemeMapping],
    schemes: &[T],
) -> Result<Vec<SchemeMapping>, CryptoError> {
    schemes
        .iter()
        .map(|t| {
            base.iter()
                .find(|(s, _)| *s == rustls_scheme(*t))
                .copied()
                .ok_or(CryptoError::Unavailable(Algorithm::Scheme(*t)))
        })
        .collect()
}

#[derive(Debug)]
struct PolicyKey {
    inner: Arc<dyn SigningKey>,
    schemes: &'static [rustls::SignatureScheme],
}

impl SigningKey for PolicyKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        let allowed: Vec<_> = offered
            .iter()
            .copied()
            .filter(|s| self.schemes.contains(s))
            .collect();
        self.inner.choose_scheme(&allowed)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[derive(Debug)]
struct PolicyKeyProvider {
    base: &'static dyn KeyProvider,
    schemes: &'static [rustls::SignatureScheme],
}

impl KeyProvider for PolicyKeyProvider {
    #[expect(clippy::disallowed_methods)]
    fn load_private_key(
        &self,
        der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        Ok(Arc::new(PolicyKey {
            inner: self.base.load_private_key(der)?,
            schemes: self.schemes,
        }))
    }

    fn fips(&self) -> bool {
        self.base.fips()
    }
}

struct SchemeSet {
    bits: u16,
    ordered: Vec<T>,
}

fn scheme_set(schemes: &[T]) -> Result<SchemeSet, CryptoError> {
    let mut bits = 0u16;
    for t in schemes {
        let bit = 1u16 << t.preference();
        if bits & bit != 0 {
            return Err(CryptoError::PolicyDuplicate(Algorithm::Scheme(*t)));
        }
        bits |= bit;
    }
    let mut ordered = schemes.to_vec();
    ordered.sort_by_key(|t| t.preference());
    Ok(SchemeSet { bits, ordered })
}

#[derive(Clone, Copy)]
struct Tables {
    verification: &'static WebPkiSupportedAlgorithms,
    keys: &'static PolicyKeyProvider,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct TableKey {
    scheme_bits: u16,
    rule: Option<crypto_profile::PeerCertificateRuleId>,
}

static TABLES: OnceLock<Mutex<HashMap<TableKey, Tables>>> = OnceLock::new();
static STRICT_TABLES: OnceLock<Mutex<HashMap<TableKey, Tables>>> = OnceLock::new();

fn tables_for_rule(
    set: &SchemeSet,
    rule: Option<crypto_profile::PeerCertificateRuleId>,
) -> Result<Tables, CryptoError> {
    let cache = match rule {
        None => &TABLES,
        Some(_) => &STRICT_TABLES,
    };
    let mut cache = cache
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    cached_tables(
        &mut cache,
        TableKey {
            scheme_bits: set.bits,
            rule,
        },
        set,
    )
}

#[cfg(test)]
fn tables(set: &SchemeSet) -> Result<Tables, CryptoError> {
    tables_for_rule(set, None)
}

fn cached_tables(
    cache: &mut HashMap<TableKey, Tables>,
    key: TableKey,
    set: &SchemeSet,
) -> Result<Tables, CryptoError> {
    if set.ordered.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::SignatureScheme));
    }
    if let Some(t) = cache.get(&key).copied() {
        return Ok(t);
    }
    let base = base_provider();
    let verify = base.signature_verification_algorithms;
    let mapping = select_schemes(verify.mapping, &set.ordered)?;
    let t = Tables {
        verification: Box::leak(Box::new(WebPkiSupportedAlgorithms {
            all: verify.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        })),
        keys: Box::leak(Box::new(PolicyKeyProvider {
            base: base.key_provider,
            schemes: Box::leak(set.ordered.iter().map(|t| rustls_scheme(*t)).collect()),
        })),
    };
    cache.insert(key, t);
    Ok(t)
}

fn no_duplicate<X: Copy + PartialEq>(
    xs: &[X],
    algorithm: fn(X) -> Algorithm,
) -> Result<(), CryptoError> {
    for (i, x) in xs.iter().enumerate() {
        if xs[..i].contains(x) {
            return Err(CryptoError::PolicyDuplicate(algorithm(*x)));
        }
    }
    Ok(())
}

fn validate(
    p: &Policy,
    available: impl Fn(Algorithm) -> Result<(), CryptoError>,
) -> Result<SchemeSet, CryptoError> {
    if p.versions.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::Version));
    }
    if p.kx_groups.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::KxGroup));
    }
    if p.signature_schemes.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::SignatureScheme));
    }
    no_duplicate(&p.versions, Algorithm::Protocol)?;
    no_duplicate(&p.cipher_suites, Algorithm::Cipher)?;
    no_duplicate(&p.kx_groups, Algorithm::Kx)?;
    let schemes = scheme_set(&p.signature_schemes)?;
    for v in &p.versions {
        available(Algorithm::Protocol(*v))?;
    }
    for c in &p.cipher_suites {
        available(Algorithm::Cipher(*c))?;
    }
    for k in &p.kx_groups {
        available(Algorithm::Kx(*k))?;
    }
    for t in &p.signature_schemes {
        available(Algorithm::Scheme(*t))?;
    }
    Ok(schemes)
}

/// A provider carrying exactly `p`. It refuses, in this order: an empty version, group or scheme
/// list; a duplicate entry in any list, naming the first one found in versions, suites, groups,
/// then schemes; an unavailable algorithm; and a suite list left empty once suites of unlisted
/// versions are dropped; then, for each listed version in policy order, a version with no suite,
/// no group usable at it, or no scheme a suite at it can sign with, checked in that order
/// (`PolicyVersionUnusable`). A key loaded through its key provider signs only with a scheme in
/// `p.signature_schemes`.
pub fn crypto_provider(p: &Policy) -> Result<CryptoProvider, CryptoError> {
    let schemes = validate(p, ensure)?;
    let suites: Vec<_> = p
        .cipher_suites
        .iter()
        .filter(|c| p.versions.contains(&c.version()))
        .map(|c| rustls_suite(*c))
        .collect();
    if suites.is_empty() {
        return Err(CryptoError::PolicyEmpty(Family::CipherSuite));
    }
    for v in &p.versions {
        let refuse = |family| CryptoError::PolicyVersionUnusable {
            version: *v,
            family,
        };
        let at_v: Vec<C> = p
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| c.version() == *v)
            .collect();
        if at_v.is_empty() {
            return Err(refuse(Family::CipherSuite));
        }
        if !p.kx_groups.iter().any(|k| k.usable_in(*v)) {
            return Err(refuse(Family::KxGroup));
        }
        if !p
            .signature_schemes
            .iter()
            .any(|t| at_v.iter().any(|c| c.signs_with(*t)))
        {
            return Err(refuse(Family::SignatureScheme));
        }
    }
    let tables = tables_for_rule(&schemes, p.peer_certificate_rule)?;
    Ok(CryptoProvider {
        cipher_suites: suites,
        kx_groups: p.kx_groups.iter().map(|k| rustls_group(*k)).collect(),
        signature_verification_algorithms: *tables.verification,
        key_provider: tables.keys,
        ..base_provider()
    })
}

fn versions(p: &Policy) -> Vec<&'static rustls::SupportedProtocolVersion> {
    p.versions.iter().map(|v| rustls_version(*v)).collect()
}

/// A client configuration builder on `p`.
#[expect(clippy::disallowed_methods)]
pub fn client_builder(
    p: &Policy,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, CryptoError> {
    if p.peer_certificate_rule.is_some() {
        return Err(CryptoError::Tls(TlsError::StrictBuilderRequired {
            entry_point: "strict_client_builder",
        }));
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
        .with_protocol_versions(&versions(p))
        .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))
}

/// A server configuration builder on `p`.
#[expect(clippy::disallowed_methods)]
pub fn server_builder(
    p: &Policy,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>, CryptoError> {
    if p.peer_certificate_rule.is_some() {
        return Err(CryptoError::Tls(TlsError::StrictBuilderRequired {
            entry_point: "strict_server_builder",
        }));
    }
    rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
        .with_protocol_versions(&versions(p))
        .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))
}

/// Installs a provider for `p` as the process default; refuses if one is already installed.
pub fn install_default(p: &Policy) -> Result<(), CryptoError> {
    crypto_provider(p)?
        .install_default()
        .map_err(|_| CryptoError::Tls(TlsError::DefaultProviderInstalled))
}

/// Refuses a provider that does not carry exactly `p`'s suites and groups in order and its
/// schemes in [`TlsSignatureScheme::preference`](T::preference) order, or whose key provider is not the one
/// `crypto_provider(p)` carries.
pub fn assert_provider_matches(provider: &CryptoProvider, p: &Policy) -> Result<(), CryptoError> {
    let want = crypto_provider(p)?;
    let suites = |x: &CryptoProvider| {
        x.cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect::<Vec<_>>()
    };
    let groups = |x: &CryptoProvider| x.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>();
    let schemes = |x: &CryptoProvider| {
        x.signature_verification_algorithms
            .mapping
            .iter()
            .map(|(s, _)| *s)
            .collect::<Vec<_>>()
    };
    if suites(provider) == suites(&want)
        && groups(provider) == groups(&want)
        && schemes(provider) == schemes(&want)
        && std::ptr::addr_eq(provider.key_provider, want.key_provider)
    {
        Ok(())
    } else {
        Err(CryptoError::PolicyDrift)
    }
}

/// Loads a private key into a signing key that signs only with a scheme in
/// `p.signature_schemes`. The key's algorithm is not checked against any profile;
/// `Resolved::certified_key` checks it.
#[expect(clippy::disallowed_methods)]
pub fn load_private_key(
    p: &Policy,
    der: PrivateKeyDer<'static>,
) -> Result<Arc<dyn SigningKey>, CryptoError> {
    crypto_provider(p)?
        .key_provider
        .load_private_key(der)
        .map_err(|_| CryptoError::Tls(TlsError::PrivateKey))
}

use crate::{PeerCertificateRuleId, PeerVerifierIdentity};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

#[derive(Debug, Clone)]
struct VerifierConfig {
    roots: Arc<rustls::RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    depth: webpki::RevocationCheckDepth,
    unknown: webpki::UnknownStatusPolicy,
    expiration: webpki::ExpirationPolicy,
    algorithms: WebPkiSupportedAlgorithms,
    identity: PeerVerifierIdentity,
}

impl VerifierConfig {
    fn new(roots: Arc<rustls::RootCertStore>, p: &Policy) -> Result<Self, CryptoError> {
        let provider = crypto_provider(p)?;
        Ok(Self {
            roots,
            crls: Vec::new(),
            depth: webpki::RevocationCheckDepth::Chain,
            unknown: webpki::UnknownStatusPolicy::Deny,
            expiration: webpki::ExpirationPolicy::Ignore,
            algorithms: provider.signature_verification_algorithms,
            identity: identity(p)?,
        })
    }

    fn build(self) -> Result<ProfileVerifier, rustls::server::VerifierBuilderError> {
        use rustls::server::VerifierBuilderError;
        if self.roots.is_empty() {
            return Err(VerifierBuilderError::NoRootAnchors);
        }
        let crls = self
            .crls
            .iter()
            .map(|der| {
                webpki::OwnedCertRevocationList::from_der(der.as_ref())
                    .map(Into::into)
                    .map_err(|e| VerifierBuilderError::InvalidCrl(crl_error(e)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProfileVerifier { config: self, crls })
    }
}

#[derive(Debug)]
struct ProfileVerifier {
    config: VerifierConfig,
    crls: Vec<webpki::CertRevocationList<'static>>,
}

fn identity(p: &Policy) -> Result<PeerVerifierIdentity, CryptoError> {
    Ok(PeerVerifierIdentity::Owned {
        rule: p.peer_certificate_rule,
        handshake_schemes: scheme_set(&p.signature_schemes)?.bits,
    })
}

fn compatible(p: &Policy, actual: PeerVerifierIdentity) -> Result<(), CryptoError> {
    let expected = identity(p)?;
    if p.peer_certificate_rule.is_none() || expected != actual {
        return Err(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
            expected,
            actual,
        }));
    }
    Ok(())
}

fn rule_profile(rule: PeerCertificateRuleId) -> crate::Profile {
    use crate::Profile as P;
    match rule {
        PeerCertificateRuleId::Unrestricted => P::Unrestricted,
        PeerCertificateRuleId::Preferred => P::Preferred,
        PeerCertificateRuleId::Cnsa2 => P::Cnsa2,
        PeerCertificateRuleId::Cnsa1 => P::Cnsa1,
        PeerCertificateRuleId::Bsi => P::Bsi,
        PeerCertificateRuleId::Fips1403 => P::Fips1403,
        PeerCertificateRuleId::Fips1402 => P::Fips1402,
    }
}

fn certificate_error(error: impl std::error::Error + Send + Sync + 'static) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(error),
    )))
}

impl ProfileVerifier {
    fn verify(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: webpki::KeyUsage,
        name: Option<&ServerName<'_>>,
    ) -> Result<(), rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(leaf).map_err(pki_error)?;
        let crls: Vec<_> = self.crls.iter().collect();
        let revocation = webpki::RevocationOptionsBuilder::new(&crls)
            .ok()
            .map(|builder| {
                builder
                    .with_depth(self.config.depth)
                    .with_status_policy(self.config.unknown)
                    .with_expiration_policy(self.config.expiration)
                    .build()
            });
        let path = cert
            .verify_for_usage(
                self.config.algorithms.all,
                &self.config.roots.roots,
                intermediates,
                now,
                usage,
                revocation,
                None,
            )
            .map_err(pki_error)?;
        if let Some(name) = name {
            cert.verify_is_valid_for_subject_name(name)
                .map_err(pki_error)?;
        }
        match self.config.identity {
            PeerVerifierIdentity::Owned {
                rule: Some(rule), ..
            } => {
                super::peer_certificates::check_verified_path(rule_profile(rule), &path)
                    .map_err(certificate_error)?;
            }
            PeerVerifierIdentity::Owned { rule: None, .. } | PeerVerifierIdentity::Opaque => {}
        }
        Ok(())
    }
}

/// An owned server-certificate verifier bound to its rule and handshake schemes.
#[derive(Debug)]
pub struct ServerVerifierHandle {
    verifier: ProfileServerVerifier,
}

#[derive(Debug)]
struct ProfileServerVerifier(ProfileVerifier);

impl ServerCertVerifier for ServerVerifierHandle {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verifier
            .verify_server_cert(leaf, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

impl ServerCertVerifier for ProfileServerVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.0.verify(
            leaf,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            Some(name),
        )?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.config.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.config.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.config.algorithms.supported_schemes()
    }
}

/// An owned client-certificate verifier bound to its rule and handshake schemes.
#[derive(Debug)]
pub struct ClientVerifierHandle {
    verifier: ProfileClientVerifier,
}

#[derive(Debug)]
struct ProfileClientVerifier {
    common: ProfileVerifier,
    hints: Vec<rustls::DistinguishedName>,
    mandatory: bool,
}

impl ClientVerifierHandle {
    /// The canonical handshake signature schemes this verifier accepts.
    pub fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

impl ClientCertVerifier for ClientVerifierHandle {
    fn client_auth_mandatory(&self) -> bool {
        self.verifier.client_auth_mandatory()
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.verifier.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verifier.verify_client_cert(leaf, intermediates, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

impl ClientCertVerifier for ProfileClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.hints
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.common.verify(
            leaf,
            intermediates,
            now,
            webpki::KeyUsage::client_auth(),
            None,
        )?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.common.config.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.common.config.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.common.config.algorithms.supported_schemes()
    }
}

/// A server-certificate verifier builder preserving baseline revocation configuration.
#[derive(Debug, Clone)]
pub struct ServerVerifierBuilder {
    config: VerifierConfig,
}

impl ServerVerifierBuilder {
    /// Appends certificate revocation lists.
    pub fn with_crls(
        mut self,
        crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>,
    ) -> Self {
        self.config.crls.extend(crls);
        self
    }
    /// Checks only the leaf's revocation status.
    pub fn only_check_end_entity_revocation(mut self) -> Self {
        self.config.depth = webpki::RevocationCheckDepth::EndEntity;
        self
    }
    /// Allows unknown revocation status.
    pub fn allow_unknown_revocation_status(mut self) -> Self {
        self.config.unknown = webpki::UnknownStatusPolicy::Allow;
        self
    }
    /// Enforces CRL expiration.
    pub fn enforce_revocation_expiration(mut self) -> Self {
        self.config.expiration = webpki::ExpirationPolicy::Enforce;
        self
    }
    /// Builds an owned verifier, refusing empty roots or invalid CRLs.
    pub fn build(self) -> Result<Arc<ServerVerifierHandle>, rustls::server::VerifierBuilderError> {
        Ok(Arc::new(ServerVerifierHandle {
            verifier: ProfileServerVerifier(self.config.build()?),
        }))
    }
}

/// A client-certificate verifier builder preserving hints, authentication and revocation modes.
#[derive(Debug, Clone)]
pub struct ClientVerifierBuilder {
    config: VerifierConfig,
    hints: Vec<rustls::DistinguishedName>,
    mandatory: bool,
}

impl ClientVerifierBuilder {
    /// Appends certificate revocation lists.
    pub fn with_crls(
        mut self,
        crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>,
    ) -> Self {
        self.config.crls.extend(crls);
        self
    }
    /// Checks only the leaf's revocation status.
    pub fn only_check_end_entity_revocation(mut self) -> Self {
        self.config.depth = webpki::RevocationCheckDepth::EndEntity;
        self
    }
    /// Allows unknown revocation status.
    pub fn allow_unknown_revocation_status(mut self) -> Self {
        self.config.unknown = webpki::UnknownStatusPolicy::Allow;
        self
    }
    /// Enforces CRL expiration.
    pub fn enforce_revocation_expiration(mut self) -> Self {
        self.config.expiration = webpki::ExpirationPolicy::Enforce;
        self
    }
    /// Clears the advertised CA subjects.
    pub fn clear_root_hint_subjects(mut self) -> Self {
        self.hints.clear();
        self
    }
    /// Appends advertised CA subjects.
    pub fn add_root_hint_subjects(
        mut self,
        hints: impl IntoIterator<Item = rustls::DistinguishedName>,
    ) -> Self {
        self.hints.extend(hints);
        self
    }
    /// Offers client authentication but permits clients without a certificate.
    pub fn allow_unauthenticated(mut self) -> Self {
        self.mandatory = false;
        self
    }
    /// Builds an owned verifier, refusing empty roots or invalid CRLs.
    pub fn build(self) -> Result<Arc<ClientVerifierHandle>, rustls::server::VerifierBuilderError> {
        Ok(Arc::new(ClientVerifierHandle {
            verifier: ProfileClientVerifier {
                common: self.config.build()?,
                hints: self.hints,
                mandatory: self.mandatory,
            },
        }))
    }
}

/// Builds a client-certificate verifier with `p`'s canonical identity.
pub fn client_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
    p: &Policy,
) -> Result<ClientVerifierBuilder, CryptoError> {
    Ok(ClientVerifierBuilder {
        hints: roots.subjects(),
        config: VerifierConfig::new(roots, p)?,
        mandatory: true,
    })
}

/// Builds a server-certificate verifier with `p`'s canonical identity.
pub fn server_cert_verifier_builder(
    roots: Arc<rustls::RootCertStore>,
    p: &Policy,
) -> Result<ServerVerifierBuilder, CryptoError> {
    Ok(ServerVerifierBuilder {
        config: VerifierConfig::new(roots, p)?,
    })
}

/// Input to strict client completion. Opaque verifiers are rejection-only.
#[derive(Debug)]
pub enum ServerVerifierInput {
    /// A crate-owned verifier.
    Owned(Arc<ServerVerifierHandle>),
    /// A verifier without an established policy identity.
    Opaque(Arc<dyn ServerCertVerifier>),
}
impl From<Arc<ServerVerifierHandle>> for ServerVerifierInput {
    fn from(value: Arc<ServerVerifierHandle>) -> Self {
        Self::Owned(value)
    }
}
impl From<Arc<dyn ServerCertVerifier>> for ServerVerifierInput {
    fn from(value: Arc<dyn ServerCertVerifier>) -> Self {
        Self::Opaque(value)
    }
}
impl From<Arc<rustls::client::WebPkiServerVerifier>> for ServerVerifierInput {
    fn from(value: Arc<rustls::client::WebPkiServerVerifier>) -> Self {
        Self::Opaque(value)
    }
}

/// Input to strict server completion. Opaque verifiers are rejection-only.
#[derive(Debug)]
pub enum ClientVerifierInput {
    /// A crate-owned verifier.
    Owned(Arc<ClientVerifierHandle>),
    /// A verifier without an established policy identity.
    Opaque(Arc<dyn ClientCertVerifier>),
}
impl From<Arc<ClientVerifierHandle>> for ClientVerifierInput {
    fn from(value: Arc<ClientVerifierHandle>) -> Self {
        Self::Owned(value)
    }
}
impl From<Arc<dyn ClientCertVerifier>> for ClientVerifierInput {
    fn from(value: Arc<dyn ClientCertVerifier>) -> Self {
        Self::Opaque(value)
    }
}

/// Completes a client builder with an owned verifier matching both rule and scheme set.
///
/// Direct-rustls bypass: callers configuring rustls directly bypass crate enforcement.
#[expect(clippy::disallowed_methods)]
pub fn strict_client_builder(
    p: &Policy,
    verifier: impl Into<ServerVerifierInput>,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>, CryptoError>
{
    let verifier = match verifier.into() {
        ServerVerifierInput::Owned(handle) => {
            compatible(p, handle.verifier.0.config.identity)?;
            handle
        }
        ServerVerifierInput::Opaque(_) => {
            return Err(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
                expected: identity(p)?,
                actual: PeerVerifierIdentity::Opaque,
            }));
        }
    };
    Ok(
        rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
            .with_protocol_versions(&versions(p))
            .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))?
            .dangerous()
            .with_custom_certificate_verifier(verifier),
    )
}

/// Completes a server builder with an owned verifier matching both rule and scheme set.
///
/// Direct-rustls bypass: callers configuring rustls directly bypass crate enforcement.
#[expect(clippy::disallowed_methods)]
pub fn strict_server_builder(
    p: &Policy,
    verifier: impl Into<ClientVerifierInput>,
) -> Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>, CryptoError>
{
    let verifier = match verifier.into() {
        ClientVerifierInput::Owned(handle) => {
            compatible(p, handle.verifier.common.config.identity)?;
            handle
        }
        ClientVerifierInput::Opaque(_) => {
            return Err(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
                expected: identity(p)?,
                actual: PeerVerifierIdentity::Opaque,
            }));
        }
    };
    Ok(
        rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider(p)?))
            .with_protocol_versions(&versions(p))
            .map_err(|_| CryptoError::Tls(TlsError::ProtocolVersions))?
            .with_client_cert_verifier(verifier),
    )
}

fn crl_error(e: webpki::Error) -> rustls::CertRevocationListError {
    use rustls::{CertRevocationListError, OtherError};
    use webpki::Error::*;
    match e {
        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature,
        #[allow(deprecated)]
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm
        }
        UnsupportedCrlSignatureAlgorithmContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
        }
        UnsupportedSignatureAlgorithmForPublicKeyContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
        }
        InvalidCrlNumber => CertRevocationListError::InvalidCrlNumber,
        InvalidSerialNumber => CertRevocationListError::InvalidRevokedCertSerialNumber,
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl,
        MalformedExtensions | BadDer | BadDerTime => CertRevocationListError::ParseError,
        UnsupportedCriticalExtension => CertRevocationListError::UnsupportedCriticalExtension,
        UnsupportedCrlVersion => CertRevocationListError::UnsupportedCrlVersion,
        UnsupportedDeltaCrl => CertRevocationListError::UnsupportedDeltaCrl,
        UnsupportedIndirectCrl => CertRevocationListError::UnsupportedIndirectCrl,
        UnsupportedRevocationReason => CertRevocationListError::UnsupportedRevocationReason,

        _ => CertRevocationListError::Other(OtherError(Arc::new(e))),
    }
}

fn eku(values: impl Iterator<Item = usize>) -> rustls::ExtendedKeyPurpose {
    let values: Vec<_> = values.collect();
    match values.as_slice() {
        [1, 3, 6, 1, 5, 5, 7, 3, 1] => rustls::ExtendedKeyPurpose::ServerAuth,
        [1, 3, 6, 1, 5, 5, 7, 3, 2] => rustls::ExtendedKeyPurpose::ClientAuth,
        _ => rustls::ExtendedKeyPurpose::Other(values),
    }
}

fn pki_error(error: webpki::Error) -> rustls::Error {
    use rustls::{CertRevocationListError, CertificateError, OtherError};
    use webpki::Error::*;
    use webpki::InvalidNameContext;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName(InvalidNameContext {
            expected,
            presented,
        }) => CertificateError::NotValidForNameContext {
            expected,
            presented,
        }
        .into(),
        CertRevoked => CertificateError::Revoked.into(),
        UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            CertificateError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedSignatureAlgorithmContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedSignatureAlgorithmForPublicKeyContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        InvalidCrlSignatureForPublicKey => CertRevocationListError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedCrlSignatureAlgorithm | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedCrlSignatureAlgorithmContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedCrlSignatureAlgorithmForPublicKeyContext(cx) => {
            CertRevocationListError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }

        #[allow(deprecated)]
        RequiredEkuNotFound => CertificateError::InvalidPurpose.into(),
        RequiredEkuNotFoundContext(webpki::RequiredEkuNotFoundContext { required, present }) => {
            CertificateError::InvalidPurposeContext {
                required: eku(required.oid_values()),
                presented: present
                    .into_iter()
                    .map(|purpose| eku(purpose.into_iter()))
                    .collect(),
            }
            .into()
        }

        _ => CertificateError::Other(OtherError(Arc::new(error))).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Negotiated, handshake};
    use crate::{
        CipherSuite as C, KxGroup as K, SignatureAlgorithm as S, TlsSignatureScheme as T,
        TlsVersion as V,
    };
    use rustls::client::danger::ServerCertVerifier;
    use std::sync::Arc;

    fn available_schemes() -> Vec<T> {
        T::ALL
            .into_iter()
            .filter(|s| crate::capability(crate::MODULE, Algorithm::Scheme(*s)).available)
            .collect()
    }

    fn policy(versions: &[V], suites: &[C], kx: &[K], schemes: &[T]) -> Policy {
        Policy {
            peer_certificate_rule: None,
            versions: versions.to_vec(),
            cipher_suites: suites.to_vec(),
            kx_groups: kx.to_vec(),
            signature_schemes: schemes
                .iter()
                .copied()
                .filter(|s| crate::capability(crate::MODULE, Algorithm::Scheme(*s)).available)
                .collect(),
        }
    }

    fn one13(k: K) -> Policy {
        policy(&[V::Tls13], &[C::Tls13Aes256GcmSha384], &[k], &T::ALL)
    }

    fn cp(bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }

    #[test]
    fn peer_certificates_old_builders_require_strict_completion() {
        for profile in crate::Profile::ALL {
            let resolved = crate::resolve(
                profile,
                crate::Options {
                    peer_certificates_match_profile: true,
                    ..Default::default()
                },
            );
            let Ok(resolved) = resolved else {
                assert_eq!(profile, crate::Profile::Cnsa2);
                continue;
            };
            assert_eq!(
                client_builder(&resolved.tls).err(),
                Some(CryptoError::Tls(TlsError::StrictBuilderRequired {
                    entry_point: "strict_client_builder"
                }))
            );
            assert_eq!(
                server_builder(&resolved.tls).err(),
                Some(CryptoError::Tls(TlsError::StrictBuilderRequired {
                    entry_point: "strict_server_builder"
                }))
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn peer_certificates_baseline_error_categories_are_preserved() {
        use rustls::pki_types::UnixTime;
        use rustls::{CertRevocationListError as R, CertificateError as E};
        use webpki::Error as W;
        let time = UnixTime::since_unix_epoch(std::time::Duration::from_secs(10));
        let bound = UnixTime::since_unix_epoch(std::time::Duration::from_secs(20));
        for (input, expected) in [
            (W::BadDer, E::BadEncoding),
            (W::BadDerTime, E::BadEncoding),
            (
                W::TrailingData(webpki::DerTypeId::Certificate),
                E::BadEncoding,
            ),
            (
                W::CertNotValidYet {
                    time,
                    not_before: bound,
                },
                E::NotValidYetContext {
                    time,
                    not_before: bound,
                },
            ),
            (
                W::CertExpired {
                    time,
                    not_after: bound,
                },
                E::ExpiredContext {
                    time,
                    not_after: bound,
                },
            ),
            (W::InvalidCertValidity, E::Expired),
            (W::UnknownIssuer, E::UnknownIssuer),
            (W::CertRevoked, E::Revoked),
            (W::UnknownRevocationStatus, E::UnknownRevocationStatus),
            (
                W::CrlExpired {
                    time,
                    next_update: bound,
                },
                E::ExpiredRevocationListContext {
                    time,
                    next_update: bound,
                },
            ),
            (W::InvalidSignatureForPublicKey, E::BadSignature),
            (
                W::UnsupportedSignatureAlgorithm,
                E::UnsupportedSignatureAlgorithm,
            ),
            (
                W::UnsupportedSignatureAlgorithmForPublicKey,
                E::UnsupportedSignatureAlgorithm,
            ),
            (W::RequiredEkuNotFound, E::InvalidPurpose),
        ] {
            assert_eq!(
                pki_error(input),
                rustls::Error::InvalidCertificate(expected)
            );
        }
        for (input, expected) in [
            (W::InvalidCrlSignatureForPublicKey, R::BadSignature),
            (
                W::UnsupportedCrlSignatureAlgorithm,
                R::UnsupportedSignatureAlgorithm,
            ),
            (
                W::UnsupportedCrlSignatureAlgorithmForPublicKey,
                R::UnsupportedSignatureAlgorithm,
            ),
            (W::InvalidCrlNumber, R::InvalidCrlNumber),
            (W::InvalidSerialNumber, R::InvalidRevokedCertSerialNumber),
            (W::IssuerNotCrlSigner, R::IssuerInvalidForCrl),
            (W::MalformedExtensions, R::ParseError),
            (W::BadDer, R::ParseError),
            (W::BadDerTime, R::ParseError),
            (
                W::UnsupportedCriticalExtension,
                R::UnsupportedCriticalExtension,
            ),
            (W::UnsupportedCrlVersion, R::UnsupportedCrlVersion),
            (W::UnsupportedDeltaCrl, R::UnsupportedDeltaCrl),
            (W::UnsupportedIndirectCrl, R::UnsupportedIndirectCrl),
            (
                W::UnsupportedRevocationReason,
                R::UnsupportedRevocationReason,
            ),
        ] {
            assert_eq!(crl_error(input), expected);
        }
        for (input, expected) in [
            (W::InvalidCrlSignatureForPublicKey, R::BadSignature),
            (
                W::UnsupportedCrlSignatureAlgorithm,
                R::UnsupportedSignatureAlgorithm,
            ),
            (
                W::UnsupportedCrlSignatureAlgorithmForPublicKey,
                R::UnsupportedSignatureAlgorithm,
            ),
            (W::IssuerNotCrlSigner, R::IssuerInvalidForCrl),
        ] {
            assert_eq!(
                pki_error(input),
                rustls::Error::InvalidCertRevocationList(expected)
            );
        }
        let signature_context = webpki::UnsupportedSignatureAlgorithmContext {
            signature_algorithm_id: vec![1, 2],
            supported_algorithms: vec![],
        };
        let key_context = webpki::UnsupportedSignatureAlgorithmForPublicKeyContext {
            signature_algorithm_id: vec![3, 4],
            public_key_algorithm_id: vec![5, 6],
        };
        assert_eq!(
            pki_error(W::UnsupportedSignatureAlgorithmContext(
                signature_context.clone()
            )),
            E::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: vec![1, 2],
                supported_algorithms: vec![]
            }
            .into()
        );
        assert_eq!(
            pki_error(W::UnsupportedSignatureAlgorithmForPublicKeyContext(
                key_context.clone()
            )),
            E::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: vec![3, 4],
                public_key_algorithm_id: vec![5, 6]
            }
            .into()
        );
        let crl_signature_expected = R::UnsupportedSignatureAlgorithmContext {
            signature_algorithm_id: vec![1, 2],
            supported_algorithms: vec![],
        };
        let crl_key_expected = R::UnsupportedSignatureAlgorithmForPublicKeyContext {
            signature_algorithm_id: vec![3, 4],
            public_key_algorithm_id: vec![5, 6],
        };
        assert_eq!(
            crl_error(W::UnsupportedCrlSignatureAlgorithmContext(
                signature_context.clone()
            )),
            crl_signature_expected
        );
        assert_eq!(
            crl_error(W::UnsupportedSignatureAlgorithmForPublicKeyContext(
                key_context.clone()
            )),
            crl_key_expected
        );
        assert_eq!(
            pki_error(W::UnsupportedCrlSignatureAlgorithmContext(
                signature_context
            )),
            rustls::Error::InvalidCertRevocationList(crl_signature_expected)
        );
        assert_eq!(
            pki_error(W::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(
                key_context
            )),
            rustls::Error::InvalidCertRevocationList(crl_key_expected)
        );
        let expected_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        assert_eq!(
            pki_error(W::CertNotValidForName(webpki::InvalidNameContext {
                expected: expected_name.clone(),
                presented: vec!["other.invalid".into()]
            })),
            E::NotValidForNameContext {
                expected: expected_name,
                presented: vec!["other.invalid".into()]
            }
            .into()
        );
        assert_eq!(
            pki_error(W::RequiredEkuNotFoundContext(
                webpki::RequiredEkuNotFoundContext {
                    required: webpki::KeyUsage::server_auth(),
                    present: vec![vec![1, 3, 6, 1, 5, 5, 7, 3, 2], vec![1, 2, 3]],
                }
            )),
            E::InvalidPurposeContext {
                required: rustls::ExtendedKeyPurpose::ServerAuth,
                presented: vec![
                    rustls::ExtendedKeyPurpose::ClientAuth,
                    rustls::ExtendedKeyPurpose::Other(vec![1, 2, 3])
                ]
            }
            .into()
        );
        let rustls::Error::InvalidCertificate(E::Other(rustls::OtherError(cause))) =
            pki_error(W::PathLenConstraintViolated)
        else {
            panic!("lost baseline cause");
        };
        assert_eq!(
            cause.downcast_ref::<W>(),
            Some(&W::PathLenConstraintViolated)
        );
        let R::Other(rustls::OtherError(cause)) = crl_error(W::UnknownIssuer) else {
            panic!("lost CRL cause");
        };
        assert_eq!(cause.downcast_ref::<W>(), Some(&W::UnknownIssuer));
    }

    struct Sha256<'a>(&'a crate::signature::KeyPair);
    impl rcgen::PublicKeyData for Sha256<'_> {
        fn der_bytes(&self) -> &[u8] {
            rcgen::PublicKeyData::der_bytes(self.0)
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_RSA_SHA256
        }
    }
    impl rcgen::SigningKey for Sha256<'_> {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            let key = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(self.0.pkcs8_der()).unwrap();
            let mut sig = vec![0; key.public_modulus_len()];
            key.sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                msg,
                &mut sig,
            )
            .unwrap();
            Ok(sig)
        }
    }

    #[test]
    fn peer_certificates_forbidden_intermediate_edges() {
        use crate::{
            CertificateSignature as CS, HashAlgorithm as H, PeerCertificateViolation as V, Profile,
        };
        use rcgen::{CertificateParams, Issuer};
        use rustls::server::danger::ClientCertVerifier;
        for (algorithm, sha256, violation) in [
            (
                S::Rsa2048Sha384,
                false,
                V::IssuerKey(crate::PeerKey::Rsa(2048)),
            ),
            (
                S::Rsa3072Sha384,
                true,
                V::ChainSignature(CS::RsaPkcs1(H::Sha256)),
            ),
        ] {
            let root_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let root = params.self_signed(&root_key).unwrap();
            let root_issuer = Issuer::new(params.clone(), &root_key);
            let intermediate_key = crate::signature::KeyPair::generate(algorithm).unwrap();
            let intermediate = params.signed_by(&intermediate_key, &root_issuer).unwrap();
            let sha256_key = Sha256(&intermediate_key);
            let signing_key: &dyn rcgen::SigningKey = if sha256 {
                &sha256_key
            } else {
                &intermediate_key
            };
            let issuer = Issuer::new(params, signing_key);
            let leaf_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
            let leaf = CertificateParams::new(vec!["localhost".into()])
                .unwrap()
                .signed_by(&leaf_key, &issuer)
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(root.der().clone()).unwrap();
            let roots = Arc::new(roots);
            let chain = [intermediate.der().clone()];
            for rule in [None, Some(PeerCertificateRuleId::Cnsa1)] {
                let policy = Policy {
                    peer_certificate_rule: rule,
                    ..one13(K::Secp384r1)
                };
                let server = server_cert_verifier_builder(roots.clone(), &policy)
                    .unwrap()
                    .build()
                    .unwrap();
                let client = client_cert_verifier_builder(roots.clone(), &policy)
                    .unwrap()
                    .build()
                    .unwrap();
                for result in [
                    server
                        .verify_server_cert(
                            leaf.der(),
                            &chain,
                            &ServerName::try_from("localhost").unwrap(),
                            &[],
                            UnixTime::now(),
                        )
                        .map(|_| ()),
                    client
                        .verify_client_cert(leaf.der(), &chain, UnixTime::now())
                        .map(|_| ()),
                ] {
                    if rule.is_none() {
                        result.unwrap();
                    } else {
                        let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                            rustls::OtherError(cause),
                        )) = result.unwrap_err()
                        else {
                            panic!("missing intermediate-edge refusal")
                        };
                        assert_eq!(
                            cause.downcast_ref::<TlsError>(),
                            Some(&TlsError::PeerCertificate {
                                profile: Profile::Cnsa1,
                                violation
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn peer_certificates_selected_path_ignores_unused_alternatives() {
        use crate::{
            CertificateSignature, HashAlgorithm, PeerCertificateViolation, PeerCurve, Profile,
        };
        use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer};
        use rustls::server::danger::ClientCertVerifier;
        let ca_params = |name: &str| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, name);
            params
        };
        let good_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let bad_key = crate::signature::KeyPair::generate(S::EcdsaP256Sha256).unwrap();
        let good_params = ca_params("good root");
        let bad_params = ca_params("bad root");
        let good_root = good_params.self_signed(&good_key).unwrap();
        let bad_root = bad_params.self_signed(&bad_key).unwrap();
        let good_issuer = Issuer::new(good_params, &good_key);
        let bad_issuer = Issuer::new(bad_params, &bad_key);
        let intermediate_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let intermediate_params = ca_params("shared intermediate");
        let good = intermediate_params
            .signed_by(&intermediate_key, &good_issuer)
            .unwrap();
        let bad = intermediate_params
            .signed_by(&intermediate_key, &bad_issuer)
            .unwrap();
        let issuer = Issuer::new(intermediate_params, &intermediate_key);
        let crls: Vec<_> = [&good_issuer, &bad_issuer, &issuer]
            .into_iter()
            .map(|issuer| {
                rcgen::CertificateRevocationListParams {
                    this_update: rcgen::date_time_ymd(2020, 1, 1),
                    next_update: rcgen::date_time_ymd(2040, 1, 1),
                    crl_number: rcgen::SerialNumber::from(1),
                    issuing_distribution_point: None,
                    revoked_certs: vec![],
                    key_identifier_method: rcgen::KeyIdMethod::Sha256,
                }
                .signed_by(issuer)
                .unwrap()
                .der()
                .clone()
            })
            .collect();
        let parsed_crls: Vec<_> = crls
            .iter()
            .map(|crl| {
                webpki::CertRevocationList::from(
                    webpki::BorrowedCertRevocationList::from_der(crl.as_ref()).unwrap(),
                )
            })
            .collect();
        let crl_refs: Vec<_> = parsed_crls.iter().collect();
        let revocation = webpki::RevocationOptionsBuilder::new(&crl_refs)
            .unwrap()
            .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
            .build();
        let leaf_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let leaf = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(good_root.der().clone()).unwrap();
        roots.add(bad_root.der().clone()).unwrap();
        let policy = Policy {
            peer_certificate_rule: Some(PeerCertificateRuleId::Cnsa1),
            ..one13(K::Secp384r1)
        };
        let roots = Arc::new(roots);
        for usage in [
            webpki::KeyUsage::server_auth(),
            webpki::KeyUsage::client_auth(),
        ] {
            for bad_first in [false, true] {
                let chain = if bad_first {
                    vec![bad.der().clone(), good.der().clone()]
                } else {
                    vec![good.der().clone(), bad.der().clone()]
                };
                let cert = webpki::EndEntityCert::try_from(leaf.der()).unwrap();
                let path = cert
                    .verify_for_usage(
                        base_provider().signature_verification_algorithms.all,
                        &roots.roots,
                        &chain,
                        UnixTime::now(),
                        usage,
                        Some(revocation),
                        None,
                    )
                    .unwrap();
                let selected: Vec<_> = path
                    .intermediate_certificates()
                    .map(|cert| cert.der())
                    .collect();
                assert_eq!(selected, vec![chain[0].clone()]);
                let selected_root = if bad_first {
                    bad_root.der()
                } else {
                    good_root.der()
                };
                assert_eq!(
                    path.anchor().subject_public_key_info,
                    webpki::anchor_from_trusted_cert(selected_root)
                        .unwrap()
                        .subject_public_key_info
                );
                for rule in [None, policy.peer_certificate_rule] {
                    let policy = Policy {
                        peer_certificate_rule: rule,
                        ..policy.clone()
                    };
                    let server = server_cert_verifier_builder(roots.clone(), &policy)
                        .unwrap()
                        .with_crls(crls.clone())
                        .enforce_revocation_expiration()
                        .build()
                        .unwrap();
                    let client = client_cert_verifier_builder(roots.clone(), &policy)
                        .unwrap()
                        .with_crls(crls.clone())
                        .enforce_revocation_expiration()
                        .build()
                        .unwrap();
                    for result in [
                        server
                            .verify_server_cert(
                                leaf.der(),
                                &chain,
                                &ServerName::try_from("localhost").unwrap(),
                                &[],
                                UnixTime::now(),
                            )
                            .map(|_| ()),
                        client
                            .verify_client_cert(leaf.der(), &chain, UnixTime::now())
                            .map(|_| ()),
                    ] {
                        if bad_first && rule.is_some() {
                            let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                                rustls::OtherError(cause),
                            )) = result.unwrap_err()
                            else {
                                panic!("missing selected-path refusal")
                            };
                            assert_eq!(
                                cause.downcast_ref::<TlsError>(),
                                Some(&TlsError::PeerCertificate {
                                    profile: Profile::Cnsa1,
                                    violation: PeerCertificateViolation::ChainSignature(
                                        CertificateSignature::Ecdsa(
                                            PeerCurve::P256,
                                            HashAlgorithm::Sha256
                                        )
                                    )
                                })
                            );
                        } else {
                            result.unwrap();
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn peer_certificates_sha256_crls_stay_baseline_with_strict_sha384_paths() {
        use rcgen::{CertificateParams, CertificateRevocationListParams, SerialNumber};
        use rustls::server::danger::ClientCertVerifier;
        let key = crate::signature::KeyPair::generate(S::Rsa3072Sha384).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = params.self_signed(&Sha256(&key)).unwrap();
        let issuer = rcgen::Issuer::new(params.clone(), &key);
        let sha256 = Sha256(&key);
        let crl_issuer = rcgen::Issuer::new(params, &sha256);
        let leaf_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.serial_number = Some(SerialNumber::from(42));
        let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        let roots = Arc::new(roots);
        let strict = Policy {
            peer_certificate_rule: Some(PeerCertificateRuleId::Cnsa1),
            ..one13(K::Secp384r1)
        };
        for revoked in [false, true] {
            let crl = CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2020, 1, 1),
                next_update: rcgen::date_time_ymd(2040, 1, 1),
                crl_number: SerialNumber::from(1),
                issuing_distribution_point: None,
                revoked_certs: if revoked {
                    vec![rcgen::RevokedCertParams {
                        serial_number: SerialNumber::from(42),
                        revocation_time: rcgen::date_time_ymd(2020, 1, 1),
                        reason_code: None,
                        invalidity_date: None,
                    }]
                } else {
                    vec![]
                },
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(&crl_issuer)
            .unwrap()
            .der()
            .clone();
            let server = server_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .with_crls([crl.clone()])
                .enforce_revocation_expiration()
                .build()
                .unwrap();
            let client = client_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .with_crls([crl])
                .enforce_revocation_expiration()
                .build()
                .unwrap();
            for result in [
                server
                    .verify_server_cert(
                        leaf.der(),
                        &[],
                        &ServerName::try_from("localhost").unwrap(),
                        &[],
                        UnixTime::now(),
                    )
                    .map(|_| ()),
                client
                    .verify_client_cert(leaf.der(), &[], UnixTime::now())
                    .map(|_| ()),
            ] {
                if revoked {
                    assert_eq!(
                        result,
                        Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::Revoked
                        ))
                    );
                } else {
                    result.unwrap();
                }
            }
            assert!(strict_client_builder(&strict, server).is_ok());
            assert!(strict_server_builder(&strict, client).is_ok());
        }
    }

    #[test]
    fn peer_certificates_selected_path_chain_refusals() {
        use crate::{
            CertificateSignature as CS, HashAlgorithm as H, PeerCertificateViolation as E,
            PeerCurve as EC, Profile,
        };
        use rustls::server::danger::ClientCertVerifier;
        for (ca, violation) in [
            (
                S::EcdsaP256Sha256,
                E::ChainSignature(CS::Ecdsa(EC::P256, H::Sha256)),
            ),
            (S::Rsa2048Sha384, E::IssuerKey(crate::PeerKey::Rsa(2048))),
        ] {
            let pki = crate::test_support::pki(ca, S::EcdsaP384Sha384).unwrap();
            for rule in [None, Some(PeerCertificateRuleId::Cnsa1)] {
                let policy = Policy {
                    peer_certificate_rule: rule,
                    ..one13(K::Secp384r1)
                };
                let roots = Arc::new(pki.roots.clone());
                let server = server_cert_verifier_builder(roots.clone(), &policy)
                    .unwrap()
                    .build()
                    .unwrap();
                let client = client_cert_verifier_builder(roots, &policy)
                    .unwrap()
                    .build()
                    .unwrap();
                for result in [
                    server
                        .verify_server_cert(
                            &pki.chain[0],
                            &pki.chain[1..],
                            &ServerName::try_from("localhost").unwrap(),
                            &[],
                            UnixTime::now(),
                        )
                        .map(|_| ()),
                    client
                        .verify_client_cert(&pki.chain[0], &pki.chain[1..], UnixTime::now())
                        .map(|_| ()),
                ] {
                    if rule.is_none() {
                        result.unwrap();
                    } else {
                        let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                            rustls::OtherError(cause),
                        )) = result.unwrap_err()
                        else {
                            panic!("missing typed chain cause")
                        };
                        assert_eq!(
                            cause.downcast_ref::<TlsError>(),
                            Some(&TlsError::PeerCertificate {
                                profile: Profile::Cnsa1,
                                violation
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn peer_certificates_revocation_modes_survive_owned_completion() {
        use rcgen::{CertificateParams, CertificateRevocationListParams, SerialNumber};
        use rustls::pki_types::{ServerName, UnixTime};
        use rustls::server::danger::ClientCertVerifier;
        let ca_key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(params, &ca_key);
        let key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        leaf_params.serial_number = Some(SerialNumber::from(42));
        let leaf = leaf_params.signed_by(&key, &issuer).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let roots = Arc::new(roots);
        let strict = Policy {
            peer_certificate_rule: Some(crate::PeerCertificateRuleId::Cnsa1),
            ..one13(K::Secp384r1)
        };
        let crl = |revoked: bool| {
            CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2000, 1, 1),
                next_update: rcgen::date_time_ymd(2001, 1, 1),
                crl_number: SerialNumber::from(1),
                issuing_distribution_point: None,
                revoked_certs: if revoked {
                    vec![rcgen::RevokedCertParams {
                        serial_number: SerialNumber::from(42),
                        revocation_time: rcgen::date_time_ymd(2000, 1, 1),
                        reason_code: None,
                        invalidity_date: None,
                    }]
                } else {
                    vec![]
                },
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            }
            .signed_by(&issuer)
            .unwrap()
            .der()
            .clone()
        };
        let name = ServerName::try_from("localhost").unwrap();
        for revoked in [false, true] {
            for enforce_expiration in [false, true] {
                let mut server = server_cert_verifier_builder(roots.clone(), &strict)
                    .unwrap()
                    .with_crls([crl(revoked)])
                    .only_check_end_entity_revocation();
                let mut client = client_cert_verifier_builder(roots.clone(), &strict)
                    .unwrap()
                    .with_crls([crl(revoked)])
                    .only_check_end_entity_revocation();
                if enforce_expiration {
                    server = server.enforce_revocation_expiration();
                    client = client.enforce_revocation_expiration();
                }
                let server = server.build().unwrap();
                let client = client.build().unwrap();
                let results = [
                    server
                        .verify_server_cert(leaf.der(), &[], &name, &[], UnixTime::now())
                        .map(|_| ()),
                    client
                        .verify_client_cert(leaf.der(), &[], UnixTime::now())
                        .map(|_| ()),
                ];
                for result in results {
                    if enforce_expiration {
                        assert!(matches!(
                            result,
                            Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::ExpiredRevocationListContext { .. }
                            ))
                        ));
                    } else if revoked {
                        assert!(matches!(
                            result,
                            Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::Revoked
                            ))
                        ));
                    } else {
                        result.unwrap();
                    }
                }
                assert!(strict_client_builder(&strict, server).is_ok());
                assert!(strict_server_builder(&strict, client).is_ok());
            }
        }
        let unrelated = crate::test_support::pki(S::EcdsaP384Sha384, S::EcdsaP384Sha384).unwrap();
        let mut mixed_roots = roots.as_ref().clone();
        mixed_roots.add(unrelated.ca.clone()).unwrap();
        let mixed_roots = Arc::new(mixed_roots);
        for allow_unknown in [false, true] {
            let mut server = server_cert_verifier_builder(mixed_roots.clone(), &strict)
                .unwrap()
                .with_crls([crl(false)]);
            let mut client = client_cert_verifier_builder(mixed_roots.clone(), &strict)
                .unwrap()
                .with_crls([crl(false)]);
            if allow_unknown {
                server = server.allow_unknown_revocation_status();
                client = client.allow_unknown_revocation_status();
            }
            let server = server.build().unwrap();
            let client = client.build().unwrap();
            for result in [
                server
                    .verify_server_cert(&unrelated.chain[0], &[], &name, &[], UnixTime::now())
                    .map(|_| ()),
                client
                    .verify_client_cert(&unrelated.chain[0], &[], UnixTime::now())
                    .map(|_| ()),
            ] {
                if allow_unknown {
                    result.unwrap();
                } else {
                    assert!(matches!(
                        result,
                        Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::UnknownRevocationStatus
                        ))
                    ));
                }
            }
        }
        for roots in [Arc::new(rustls::RootCertStore::empty()), roots] {
            let server = server_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .with_crls([CertificateRevocationListDer::from(vec![0xff])])
                .build();
            let client = client_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .with_crls([CertificateRevocationListDer::from(vec![0xff])])
                .build();
            if roots.is_empty() {
                assert!(matches!(
                    server,
                    Err(rustls::server::VerifierBuilderError::NoRootAnchors)
                ));
                assert!(matches!(
                    client,
                    Err(rustls::server::VerifierBuilderError::NoRootAnchors)
                ));
            } else {
                assert!(matches!(
                    server,
                    Err(rustls::server::VerifierBuilderError::InvalidCrl(_))
                ));
                assert!(matches!(
                    client,
                    Err(rustls::server::VerifierBuilderError::InvalidCrl(_))
                ));
            }
        }
    }

    fn peer_certificate_handshake(
        strict: &Policy,
        server_checks_client: bool,
        peer_key: S,
    ) -> Result<(), (bool, rustls::Error)> {
        peer_certificate_chain_handshake(strict, server_checks_client, S::EcdsaP384Sha384, peer_key)
    }

    fn peer_certificate_chain_handshake(
        strict: &Policy,
        server_checks_client: bool,
        peer_ca: S,
        peer_key: S,
    ) -> Result<(), (bool, rustls::Error)> {
        let server_pki = crate::test_support::pki(
            if server_checks_client {
                S::EcdsaP384Sha384
            } else {
                peer_ca
            },
            if server_checks_client {
                S::EcdsaP384Sha384
            } else {
                peer_key
            },
        )
        .unwrap();
        let client_pki = crate::test_support::pki(
            if server_checks_client {
                peer_ca
            } else {
                S::EcdsaP384Sha384
            },
            if server_checks_client {
                peer_key
            } else {
                S::EcdsaP384Sha384
            },
        )
        .unwrap();
        let off = Policy {
            peer_certificate_rule: None,
            ..one13(K::Secp384r1)
        };
        let off = Policy {
            versions: strict.versions.clone(),
            cipher_suites: C::ALL.to_vec(),
            ..off
        };
        let server_roots = Arc::new(server_pki.roots.clone());
        let client_roots = Arc::new(client_pki.roots.clone());
        let client_builder = if server_checks_client {
            client_builder(&off)
                .unwrap()
                .with_root_certificates(server_pki.roots.clone())
        } else {
            strict_client_builder(
                strict,
                server_cert_verifier_builder(server_roots, strict)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
        };
        let client_config = client_builder
            .with_client_auth_cert(
                client_pki.chain,
                PrivateKeyDer::Pkcs8(client_pki.key.pkcs8_der().to_vec().into()),
            )
            .unwrap();
        let server_builder = if server_checks_client {
            strict_server_builder(
                strict,
                client_cert_verifier_builder(client_roots, strict)
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .unwrap()
        } else {
            server_builder(&off).unwrap().with_no_client_auth()
        };
        let server_config = server_builder
            .with_single_cert(
                server_pki.chain,
                PrivateKeyDer::Pkcs8(server_pki.key.pkcs8_der().to_vec().into()),
            )
            .unwrap();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        while client.is_handshaking() || server.is_handshaking() {
            let mut to_server = Vec::new();
            client.write_tls(&mut to_server).unwrap();
            let mut bytes = to_server.as_slice();
            while !bytes.is_empty() {
                assert_ne!(server.read_tls(&mut bytes).unwrap(), 0);
                server.process_new_packets().map_err(|e| (true, e))?;
            }
            let mut to_client = Vec::new();
            server.write_tls(&mut to_client).unwrap();
            let mut bytes = to_client.as_slice();
            while !bytes.is_empty() {
                assert_ne!(client.read_tls(&mut bytes).unwrap(), 0);
                client.process_new_packets().map_err(|e| (false, e))?;
            }
            assert!(
                !(to_server.is_empty() && to_client.is_empty()),
                "handshake stalled"
            );
        }
        Ok(())
    }

    #[test]
    fn peer_certificates_strict_completion_enforces_chain_in_both_directions() {
        use crate::{
            CertificateSignature as CS, HashAlgorithm as H, PeerCertificateViolation as E,
            PeerCurve as EC, Profile,
        };
        for version in [V::Tls12, V::Tls13] {
            let strict = Policy {
                peer_certificate_rule: Some(PeerCertificateRuleId::Cnsa1),
                versions: vec![version],
                cipher_suites: C::ALL.to_vec(),
                ..one13(K::Secp384r1)
            };
            for direction in [false, true] {
                for (ca, violation) in [
                    (
                        S::EcdsaP256Sha256,
                        E::ChainSignature(CS::Ecdsa(EC::P256, H::Sha256)),
                    ),
                    (S::Rsa2048Sha384, E::IssuerKey(crate::PeerKey::Rsa(2048))),
                ] {
                    let (detector, error) = peer_certificate_chain_handshake(
                        &strict,
                        direction,
                        ca,
                        S::EcdsaP384Sha384,
                    )
                    .unwrap_err();
                    assert_eq!(detector, direction);
                    let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                        rustls::OtherError(cause),
                    )) = error
                    else {
                        panic!("missing typed path error")
                    };
                    assert_eq!(
                        cause.downcast_ref::<TlsError>(),
                        Some(&TlsError::PeerCertificate {
                            profile: Profile::Cnsa1,
                            violation
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn peer_certificates_strict_completion_enforces_both_handshake_directions() {
        for version in [V::Tls12, V::Tls13] {
            for server_checks_client in [false, true] {
                for key in [S::EcdsaP384Sha384, S::Rsa2048Sha384] {
                    let mut resolved = crate::resolve(
                        crate::Profile::Cnsa1,
                        crate::Options {
                            peer_certificates_match_profile: true,
                            ..Default::default()
                        },
                    )
                    .unwrap()
                    .tls;
                    resolved.versions = vec![version];
                    let result = peer_certificate_handshake(&resolved, server_checks_client, key);
                    if key == S::EcdsaP384Sha384 {
                        result.unwrap();
                    } else {
                        let (detected_at_server, error) = result.unwrap_err();
                        assert_eq!(detected_at_server, server_checks_client);
                        let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                            rustls::OtherError(cause),
                        )) = error
                        else {
                            panic!("missing typed handshake cause");
                        };
                        assert_eq!(
                            cause.downcast_ref::<TlsError>(),
                            Some(&TlsError::PeerCertificate {
                                profile: crate::Profile::Cnsa1,
                                violation: crate::PeerCertificateViolation::LeafKey(
                                    crate::PeerKey::Rsa(2048)
                                ),
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[expect(clippy::disallowed_methods)]
    fn peer_certificates_owned_verifiers_bind_rules_and_scheme_sets() {
        use crate::{PeerCertificateRuleId as R, PeerVerifierIdentity as I};
        let pki = crate::test_support::pki(S::EcdsaP384Sha384, S::EcdsaP384Sha384).unwrap();
        let roots = Arc::new(pki.roots);
        let mut strict = one13(K::Secp384r1);
        strict.peer_certificate_rule = Some(R::Cnsa1);
        let identity = |p: &Policy| I::Owned {
            rule: p.peer_certificate_rule,
            handshake_schemes: scheme_set(&p.signature_schemes).unwrap().bits,
        };
        let refuse = |completion: &Policy, built: &Policy| {
            let expected = Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
                expected: identity(completion),
                actual: identity(built),
            }));
            let server = server_cert_verifier_builder(roots.clone(), built)
                .unwrap()
                .build()
                .unwrap();
            let client = client_cert_verifier_builder(roots.clone(), built)
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(strict_client_builder(completion, server).err(), expected);
            assert_eq!(strict_server_builder(completion, client).err(), expected);
        };
        let off = Policy {
            peer_certificate_rule: None,
            ..strict.clone()
        };
        let other = Policy {
            peer_certificate_rule: Some(R::Preferred),
            ..strict.clone()
        };
        let narrow = Policy {
            signature_schemes: vec![T::RsaPssSha384],
            ..strict.clone()
        };
        refuse(&strict, &off);
        refuse(&strict, &other);
        refuse(&strict, &narrow);
        refuse(&narrow, &strict);
        refuse(&off, &off);
        let resolved_off = crate::resolve(crate::Profile::Cnsa1, crate::Options::default())
            .unwrap()
            .tls;
        refuse(&resolved_off, &resolved_off);
        assert!(client_builder(&off).is_ok());
        assert!(server_builder(&off).is_ok());
        assert!(client_builder(&resolved_off).is_ok());
        assert!(server_builder(&resolved_off).is_ok());
        refuse(&off, &strict);
        let mut permuted = strict.clone();
        permuted.signature_schemes.reverse();
        let server = server_cert_verifier_builder(roots.clone(), &permuted)
            .unwrap()
            .build()
            .unwrap();
        let client = client_cert_verifier_builder(roots.clone(), &permuted)
            .unwrap()
            .build()
            .unwrap();
        assert!(strict_client_builder(&strict, server).is_ok());
        assert!(strict_server_builder(&strict, client).is_ok());
        let opaque_server = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.clone(),
            Arc::new(crypto_provider(&off).unwrap()),
        )
        .build()
        .unwrap();
        let opaque_client = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots,
            Arc::new(crypto_provider(&off).unwrap()),
        )
        .build()
        .unwrap();
        let expected = Some(CryptoError::Tls(TlsError::IncompatiblePeerVerifier {
            expected: identity(&strict),
            actual: I::Opaque,
        }));
        assert_eq!(
            strict_client_builder(&strict, opaque_server).err(),
            expected
        );
        assert_eq!(
            strict_server_builder(&strict, opaque_client).err(),
            expected
        );
    }

    #[test]
    fn peer_certificates_owned_adapters_preserve_baseline_and_typed_leaf_causes() {
        use crate::{
            PeerCertificateRuleId as R, PeerCertificateViolation as E, PeerCurve, PeerKey,
        };
        use rustls::pki_types::{ServerName, UnixTime};
        use rustls::server::danger::ClientCertVerifier;
        let now = UnixTime::now();
        for (key, expected_key) in [
            (S::EcdsaP256Sha256, Some(PeerKey::Ec(PeerCurve::P256))),
            (S::Rsa2048Sha384, Some(PeerKey::Rsa(2048))),
            (S::EcdsaP384Sha384, None),
        ] {
            let pki = crate::test_support::pki(S::EcdsaP384Sha384, key).unwrap();
            let roots = Arc::new(pki.roots.clone());
            let strict = Policy {
                peer_certificate_rule: Some(R::Cnsa1),
                ..one13(K::Secp384r1)
            };
            let server = server_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .build()
                .unwrap();
            let client = client_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .build()
                .unwrap();
            let name = ServerName::try_from("localhost").unwrap();
            let server_result =
                server.verify_server_cert(&pki.chain[0], &pki.chain[1..], &name, &[], now);
            let client_result = client.verify_client_cert(&pki.chain[0], &pki.chain[1..], now);
            let cause = |error| {
                let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(cause),
                )) = error
                else {
                    panic!("missing typed certificate cause");
                };
                *cause.downcast_ref::<TlsError>().unwrap()
            };
            if let Some(key) = expected_key {
                let expected = TlsError::PeerCertificate {
                    profile: crate::Profile::Cnsa1,
                    violation: E::LeafKey(key),
                };
                assert_eq!(cause(server_result.unwrap_err()), expected);
                assert_eq!(cause(client_result.unwrap_err()), expected);
            } else {
                assert!(server_result.is_ok());
                assert!(client_result.is_ok());
            }
            let off = Policy {
                peer_certificate_rule: None,
                ..strict.clone()
            };
            let baseline = server_cert_verifier_builder(roots.clone(), &off)
                .unwrap()
                .build()
                .unwrap();
            assert!(
                baseline
                    .verify_server_cert(&pki.chain[0], &pki.chain[1..], &name, &[], now)
                    .is_ok()
            );
            use rustls::internal::msgs::codec::{Codec, Reader};
            let invalid_signature =
                rustls::DigitallySignedStruct::read(&mut Reader::init(&[0x05, 0x03, 0, 1, 0]))
                    .unwrap();
            for result in [
                server.verify_tls12_signature(b"message", &pki.chain[0], &invalid_signature),
                server.verify_tls13_signature(b"message", &pki.chain[0], &invalid_signature),
                client.verify_tls12_signature(b"message", &pki.chain[0], &invalid_signature),
                client.verify_tls13_signature(b"message", &pki.chain[0], &invalid_signature),
            ] {
                assert!(result.is_err());
            }
            assert!(!server.requires_raw_public_keys());
            assert!(!client.requires_raw_public_keys());
            assert!(server.root_hint_subjects().is_none());
            assert_eq!(
                client
                    .root_hint_subjects()
                    .iter()
                    .map(|x| x.as_ref())
                    .collect::<Vec<_>>(),
                roots
                    .subjects()
                    .iter()
                    .map(|x| x.as_ref())
                    .collect::<Vec<_>>()
            );
            assert!(client.offer_client_auth());
            assert!(client.client_auth_mandatory());
            let optional = client_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .clear_root_hint_subjects()
                .allow_unauthenticated()
                .build()
                .unwrap();
            assert!(optional.offer_client_auth());
            assert!(!optional.client_auth_mandatory());
            assert!(optional.root_hint_subjects().is_empty());
            let hint = rustls::DistinguishedName::from(vec![0x30, 0]);
            let advertised = client_cert_verifier_builder(roots.clone(), &strict)
                .unwrap()
                .clear_root_hint_subjects()
                .add_root_hint_subjects([hint.clone()])
                .build()
                .unwrap();
            assert_eq!(
                advertised
                    .root_hint_subjects()
                    .iter()
                    .map(|x| x.as_ref())
                    .collect::<Vec<_>>(),
                vec![hint.as_ref()]
            );
            assert!(strict_server_builder(&strict, optional).is_ok());

            let wrong_name = ServerName::try_from("elsewhere.invalid").unwrap();
            assert!(matches!(
                server.verify_server_cert(&pki.chain[0], &pki.chain[1..], &wrong_name, &[], now),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::NotValidForNameContext { .. }
                ))
            ));
        }
    }

    #[test]
    fn a_hybrid_offer_completes_on_its_classical_component() {
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1MlKem1024, K::Secp384r1],
            &T::ALL,
        );
        let n = handshake(&client, &one13(K::Secp384r1), S::EcdsaP384Sha384).unwrap();
        assert_eq!(n.kx.iana(), 0x0018);
        assert_eq!(n.kind, rustls::HandshakeKind::Full);
    }

    #[test]
    fn a_retry_into_secp384r1mlkem1024_completes() {
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1, K::Secp384r1MlKem1024],
            &T::ALL,
        );
        let n = handshake(&client, &one13(K::Secp384r1MlKem1024), S::EcdsaP384Sha384).unwrap();
        assert_eq!(n.kx.iana(), 0x11ED);
        assert_eq!(n.kind, rustls::HandshakeKind::FullWithHelloRetryRequest);
    }

    #[test]
    fn every_mapping_carries_its_registry_codepoint() {
        for c in C::ALL {
            assert_eq!(cp(rustls_suite(c).suite().to_array()), c.iana(), "{c:?}");
        }
        for k in K::ALL {
            assert_eq!(cp(rustls_group(k).name().to_array()), k.iana(), "{k:?}");
        }
        for t in T::ALL {
            assert_eq!(cp(rustls_scheme(t).to_array()), t.iana(), "{t:?}");
        }
        for v in V::ALL {
            assert_eq!(cp(rustls_version(v).version.to_array()), v.iana(), "{v:?}");
        }
    }

    #[test]
    fn a_scheme_missing_from_the_base_mapping_is_refused() {
        let base = base_provider().signature_verification_algorithms.mapping;
        let names = |m: &[SchemeMapping]| m.iter().map(|(s, _)| *s).collect::<Vec<_>>();
        assert_eq!(
            names(&select_schemes(base, &[T::Ed25519, T::EcdsaNistp384Sha384]).unwrap()),
            [
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384
            ]
        );
        let without: Vec<SchemeMapping> = base
            .iter()
            .filter(|(s, _)| *s != rustls::SignatureScheme::ED25519)
            .copied()
            .collect();
        assert_eq!(
            select_schemes(&without, &[T::EcdsaNistp384Sha384, T::Ed25519]).err(),
            Some(CryptoError::Unavailable(Algorithm::Scheme(T::Ed25519)))
        );
    }

    #[test]
    fn a_server_config_with_x25519_is_not_fips() {
        let key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into());
        let fips = server_builder(&one13(K::Secp384r1))
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der.clone_key())
            .unwrap();
        assert_eq!(crate::fips::assert_fips_server_config(&fips), Ok(()));
        let x = server_builder(&one13(K::X25519))
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], der)
            .unwrap();
        assert_eq!(
            crate::fips::assert_fips_server_config(&x),
            Err(CryptoError::NotFips)
        );
    }

    #[test]
    fn verifiers_carry_the_policys_schemes_in_the_canonical_order() {
        let key = crate::signature::KeyPair::generate(S::EcdsaP384Sha384).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(params.self_signed(&key).unwrap().der().clone())
            .unwrap();
        let roots = Arc::new(roots);
        let p = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::Ed25519, T::EcdsaNistp384Sha384],
        );
        let want = [T::EcdsaNistp384Sha384.iana(), T::Ed25519.iana()];
        let server_v = server_cert_verifier_builder(roots.clone(), &p)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            server_v
                .supported_verify_schemes()
                .iter()
                .map(|s| cp(s.to_array()))
                .collect::<Vec<_>>(),
            want
        );
        let client_v = client_cert_verifier_builder(roots, &p)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            client_v
                .supported_verify_schemes()
                .iter()
                .map(|s| cp(s.to_array()))
                .collect::<Vec<_>>(),
            want
        );
    }

    #[test]
    fn an_empty_family_is_refused() {
        let p = one13(K::Secp384r1);
        for (fam, q) in [
            (
                Family::Version,
                Policy {
                    versions: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::CipherSuite,
                Policy {
                    cipher_suites: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::KxGroup,
                Policy {
                    kx_groups: vec![],
                    ..p.clone()
                },
            ),
            (
                Family::SignatureScheme,
                Policy {
                    signature_schemes: vec![],
                    ..p.clone()
                },
            ),
        ] {
            assert_eq!(
                crypto_provider(&q).err(),
                Some(CryptoError::PolicyEmpty(fam))
            );
        }
    }

    #[test]
    fn a_suite_without_its_version_is_refused() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls12EcdheRsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::RsaPssSha384],
        );
        assert_eq!(
            crypto_provider(&q).err(),
            Some(CryptoError::PolicyEmpty(Family::CipherSuite))
        );
    }

    #[test]
    fn the_provider_carries_exactly_the_policy_in_order() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384, C::Tls13Aes128GcmSha256],
            &[K::MlKem1024, K::Secp384r1],
            &[T::EcdsaNistp384Sha384, T::Ed25519],
        );
        let p = crypto_provider(&q).unwrap();
        assert_eq!(
            p.cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect::<Vec<_>>(),
            [
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            ]
        );
        assert_eq!(
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            [rustls::NamedGroup::MLKEM1024, rustls::NamedGroup::secp384r1]
        );
        assert_eq!(
            p.signature_verification_algorithms
                .mapping
                .iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>(),
            [
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519
            ]
        );
        assert_eq!(assert_provider_matches(&p, &q), Ok(()));
    }

    #[test]
    fn drift_in_any_one_family_is_refused() {
        let q = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384],
        );
        let p = crypto_provider(&q).unwrap();
        for other in [
            Policy {
                cipher_suites: vec![C::Tls13Aes128GcmSha256],
                ..q.clone()
            },
            Policy {
                kx_groups: vec![K::Secp256r1],
                ..q.clone()
            },
            Policy {
                signature_schemes: vec![T::Ed25519],
                ..q.clone()
            },
        ] {
            assert_eq!(
                assert_provider_matches(&p, &other),
                Err(CryptoError::PolicyDrift),
                "{other:?}"
            );
        }
    }

    #[test]
    fn an_approved_only_policy_is_fips_and_x25519_or_chacha_is_not() {
        let fips = one13(K::Secp384r1);
        assert!(crypto_provider(&fips).unwrap().fips());
        assert!(!crypto_provider(&one13(K::X25519)).unwrap().fips());
        let c = Policy {
            cipher_suites: vec![C::Tls13Chacha20Poly1305Sha256],
            ..fips
        };
        assert!(!crypto_provider(&c).unwrap().fips());
    }

    #[test]
    fn a_policy_with_x25519_is_not_fips() {
        let cfg = client_builder(&one13(K::X25519))
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert_eq!(
            crate::fips::assert_fips_client_config(&cfg),
            Err(CryptoError::NotFips)
        );
    }

    #[test]
    fn tls12_fips_config_requires_ems() {
        let p = policy(
            &[V::Tls12],
            &[C::Tls12EcdheEcdsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384],
        );
        let cfg = client_builder(&p)
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(cfg.require_ems);
        assert_eq!(crate::fips::assert_fips_client_config(&cfg), Ok(()));
    }

    #[test]
    fn each_group_is_the_one_negotiated() {
        for k in K::ALL {
            let n = handshake(&one13(k), &one13(k), S::EcdsaP384Sha384)
                .unwrap_or_else(|e| panic!("{k:?}: {e}"));
            assert_eq!(
                n,
                Negotiated {
                    version: V::Tls13,
                    suite: C::Tls13Aes256GcmSha384,
                    kx: k,
                    scheme: T::EcdsaNistp384Sha384,
                    kind: rustls::HandshakeKind::Full,
                }
            );
        }
    }

    #[test]
    fn each_suite_is_the_one_negotiated() {
        for s in C::ALL {
            let key = match s {
                C::Tls12EcdheRsaAes256GcmSha384
                | C::Tls12EcdheRsaAes128GcmSha256
                | C::Tls12EcdheRsaChacha20Poly1305Sha256 => S::Rsa2048Sha384,
                C::Tls13Aes256GcmSha384
                | C::Tls13Aes128GcmSha256
                | C::Tls13Chacha20Poly1305Sha256
                | C::Tls12EcdheEcdsaAes256GcmSha384
                | C::Tls12EcdheEcdsaAes128GcmSha256
                | C::Tls12EcdheEcdsaChacha20Poly1305Sha256 => S::EcdsaP384Sha384,
            };
            let p = policy(&[s.version()], &[s], &[K::Secp384r1], &T::ALL);
            let n = handshake(&p, &p, key).unwrap_or_else(|e| panic!("{s:?}: {e}"));
            let scheme = match key {
                S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => T::RsaPssSha512,
                S::MlDsa87
                | S::EcdsaP256Sha256
                | S::EcdsaP384Sha384
                | S::EcdsaP521Sha384
                | S::EcdsaP521Sha512
                | S::Ed25519 => key.tls_scheme(),
            };
            assert_eq!(
                n,
                Negotiated {
                    version: s.version(),
                    suite: s,
                    kx: K::Secp384r1,
                    scheme,
                    kind: rustls::HandshakeKind::Full,
                },
                "{s:?}"
            );
        }
    }

    #[test]
    fn every_key_algorithm_authenticates_a_tls13_server() {
        for a in S::ALL {
            if !crate::capability(crate::MODULE, Algorithm::Signature(a)).available {
                assert_eq!(
                    crate::signature::KeyPair::generate(a).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(a)))
                );
                continue;
            }
            let n = handshake(&one13(K::Secp384r1), &one13(K::Secp384r1), a)
                .unwrap_or_else(|e| panic!("{a}: {e}"));
            let full_offer = match a {
                S::Rsa2048Sha384 | S::Rsa3072Sha384 | S::Rsa4096Sha384 => T::RsaPssSha512,
                S::MlDsa87
                | S::EcdsaP256Sha256
                | S::EcdsaP384Sha384
                | S::EcdsaP521Sha384
                | S::EcdsaP521Sha512
                | S::Ed25519 => a.tls_scheme(),
            };
            assert_eq!(n.scheme, full_offer, "{a}");
        }
    }

    #[test]
    fn a_one_scheme_offer_gets_that_scheme() {
        let rsa = [T::RsaPssSha256, T::RsaPssSha384, T::RsaPssSha512];
        let cases = S::ALL
            .into_iter()
            .map(|a| (a, a.tls_scheme()))
            .chain(rsa.into_iter().map(|t| (S::Rsa2048Sha384, t)));
        for (a, t) in cases {
            if !crate::capability(crate::MODULE, Algorithm::Signature(a)).available {
                assert_eq!(
                    crate::signature::KeyPair::generate(a).err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(a)))
                );
                continue;
            }
            let client = policy(
                &[V::Tls13],
                &[C::Tls13Aes256GcmSha384],
                &[K::Secp384r1],
                &[t],
            );
            let n = handshake(&client, &one13(K::Secp384r1), a)
                .unwrap_or_else(|e| panic!("{a} {t:?}: {e}"));
            assert_eq!(n.scheme, t, "{a}");
        }
    }

    #[test]
    fn a_policy_mismatch_fails_the_handshake() {
        let server = one13(K::Secp384r1);
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes128GcmSha256],
            &[K::Secp384r1],
            &T::ALL,
        );
        assert_eq!(
            handshake(&client, &server, S::EcdsaP384Sha384),
            Err("peer is incompatible: NoCipherSuitesInCommon".to_string())
        );
        let client = policy(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::Ed25519],
        );
        assert_eq!(
            handshake(&client, &server, S::EcdsaP384Sha384),
            Err("peer is incompatible: NoSignatureSchemesInCommon".to_string())
        );
    }

    fn chosen(p: &Policy, a: S, offered: &[T]) -> Option<u16> {
        let key = crate::signature::KeyPair::generate(a).unwrap();
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.pkcs8_der().to_vec().into());
        let offered: Vec<_> = offered.iter().map(|t| rustls_scheme(*t)).collect();
        load_private_key(p, der)
            .unwrap()
            .choose_scheme(&offered)
            .map(|s| cp(s.scheme().to_array()))
    }

    #[test]
    fn a_loaded_key_signs_only_with_a_scheme_the_policy_lists() {
        let rsa = |schemes: &[T]| {
            policy(
                &[V::Tls13],
                &[C::Tls13Aes256GcmSha384],
                &[K::Secp384r1],
                schemes,
            )
        };
        let offer = [T::RsaPssSha512, T::RsaPssSha384, T::RsaPssSha256];
        let a = S::Rsa3072Sha384;
        assert_eq!(chosen(&rsa(&T::ALL), a, &offer), Some(0x0806));
        assert_eq!(chosen(&rsa(&[T::RsaPssSha384]), a, &offer), Some(0x0805));
        assert_eq!(
            chosen(&rsa(&[T::RsaPssSha256, T::RsaPssSha384]), a, &offer),
            Some(0x0805)
        );
        let pkcs1_tls12 = policy(
            &[V::Tls12],
            &[C::Tls12EcdheRsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::RsaPkcs1Sha384],
        );
        assert_eq!(chosen(&pkcs1_tls12, a, &offer), None);
        assert_eq!(
            crypto_provider(&rsa(&[T::RsaPkcs1Sha384])).err(),
            Some(CryptoError::PolicyVersionUnusable {
                version: V::Tls13,
                family: Family::SignatureScheme
            })
        );
        if crate::capability(crate::MODULE, Algorithm::Scheme(T::MlDsa87)).available {
            assert_eq!(
                chosen(&rsa(&[T::MlDsa87]), S::EcdsaP384Sha384, &T::ALL),
                None
            );
        } else {
            let mut unavailable = rsa(&[T::Ed25519]);
            unavailable.signature_schemes = vec![T::MlDsa87];
            assert_eq!(
                crypto_provider(&unavailable).err(),
                Some(CryptoError::Unavailable(Algorithm::Scheme(T::MlDsa87)))
            );
        }
    }

    fn lit(versions: &[V], suites: &[C], kx: &[K], schemes: &[T]) -> Policy {
        Policy {
            peer_certificate_rule: None,
            versions: versions.to_vec(),
            cipher_suites: suites.to_vec(),
            kx_groups: kx.to_vec(),
            signature_schemes: schemes.to_vec(),
        }
    }

    fn unusable(version: V, family: Family) -> Option<CryptoError> {
        Some(CryptoError::PolicyVersionUnusable { version, family })
    }

    fn ml_dsa() -> bool {
        crate::capability(crate::MODULE, Algorithm::Scheme(T::MlDsa87)).available
    }

    const BOTH_SUITES: [C; 2] = [C::Tls13Aes256GcmSha384, C::Tls12EcdheEcdsaAes256GcmSha384];

    #[test]
    fn tls12_with_only_post_quantum_groups_is_refused() {
        for k in [
            K::MlKem1024,
            K::Secp384r1MlKem1024,
            K::X25519MlKem768,
            K::Secp256r1MlKem768,
        ] {
            assert!(
                crate::capability(crate::MODULE, Algorithm::Kx(k)).available,
                "{k:?}"
            );
            let q = lit(
                &[V::Tls12, V::Tls13],
                &BOTH_SUITES,
                &[k],
                &[T::EcdsaNistp384Sha384],
            );
            assert_eq!(
                crypto_provider(&q).err(),
                unusable(V::Tls12, Family::KxGroup),
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_listed_version_without_a_suite_is_refused() {
        let q = lit(
            &[V::Tls12, V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384],
        );
        assert_eq!(
            crypto_provider(&q).err(),
            unusable(V::Tls12, Family::CipherSuite)
        );
    }

    #[test]
    fn tls13_with_only_pkcs1_schemes_is_refused() {
        let q = lit(
            &[V::Tls13],
            &[C::Tls13Aes256GcmSha384],
            &[K::Secp384r1],
            &[T::RsaPkcs1Sha256, T::RsaPkcs1Sha384, T::RsaPkcs1Sha512],
        );
        assert_eq!(
            crypto_provider(&q).err(),
            unusable(V::Tls13, Family::SignatureScheme)
        );
    }

    #[test]
    fn tls12_with_only_ml_dsa_is_refused() {
        let q = lit(
            &[V::Tls12],
            &[C::Tls12EcdheEcdsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::MlDsa87],
        );
        let want = if ml_dsa() {
            unusable(V::Tls12, Family::SignatureScheme)
        } else {
            Some(CryptoError::Unavailable(Algorithm::Scheme(T::MlDsa87)))
        };
        assert_eq!(crypto_provider(&q).err(), want);
    }

    #[test]
    fn tls12_suites_that_cannot_sign_with_any_listed_scheme_are_refused() {
        let ecdsa_suites_rsa_schemes = lit(
            &[V::Tls12],
            &[C::Tls12EcdheEcdsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::RsaPssSha384, T::RsaPkcs1Sha384],
        );
        assert_eq!(
            crypto_provider(&ecdsa_suites_rsa_schemes).err(),
            unusable(V::Tls12, Family::SignatureScheme)
        );
        let rsa_suites_ecdsa_schemes = lit(
            &[V::Tls12],
            &[C::Tls12EcdheRsaAes256GcmSha384],
            &[K::Secp384r1],
            &[T::EcdsaNistp384Sha384, T::Ed25519],
        );
        assert_eq!(
            crypto_provider(&rsa_suites_ecdsa_schemes).err(),
            unusable(V::Tls12, Family::SignatureScheme)
        );
    }

    #[test]
    fn versions_are_checked_in_policy_order() {
        let a = lit(
            &[V::Tls13, V::Tls12],
            &BOTH_SUITES,
            &[K::MlKem1024],
            &[T::RsaPkcs1Sha256],
        );
        assert_eq!(
            crypto_provider(&a).err(),
            unusable(V::Tls13, Family::SignatureScheme)
        );
        let b = lit(
            &[V::Tls12, V::Tls13],
            &BOTH_SUITES,
            &[K::MlKem1024],
            &[T::RsaPkcs1Sha256],
        );
        assert_eq!(
            crypto_provider(&b).err(),
            unusable(V::Tls12, Family::KxGroup)
        );
    }

    #[test]
    fn groups_are_checked_before_schemes() {
        let q = lit(
            &[V::Tls12],
            &[C::Tls12EcdheEcdsaAes256GcmSha384],
            &[K::MlKem1024],
            &[T::RsaPkcs1Sha256],
        );
        assert_eq!(
            crypto_provider(&q).err(),
            unusable(V::Tls12, Family::KxGroup)
        );
    }

    #[test]
    fn kx_usability_matches_the_provider() {
        for k in [
            K::MlKem1024,
            K::Secp384r1MlKem1024,
            K::X25519MlKem768,
            K::Secp256r1MlKem768,
            K::Secp384r1,
            K::Secp256r1,
            K::X25519,
        ] {
            for (v, wire) in [
                (V::Tls12, rustls::ProtocolVersion::TLSv1_2),
                (V::Tls13, rustls::ProtocolVersion::TLSv1_3),
            ] {
                assert_eq!(
                    k.usable_in(v),
                    rustls_group(k).usable_for_version(wire),
                    "{k:?} {v:?}"
                );
            }
        }
    }

    #[test]
    fn suite_signing_matches_the_provider() {
        for c in C::ALL {
            for t in T::ALL {
                let provider = match rustls_suite(c) {
                    rustls::SupportedCipherSuite::Tls12(s) => s.sign.contains(&rustls_scheme(t)),
                    rustls::SupportedCipherSuite::Tls13(_) => t.usable_in(V::Tls13),
                };
                assert_eq!(c.signs_with(t), provider, "{c:?} {t:?}");
            }
        }
    }

    #[derive(Debug)]
    struct NotFips;

    impl KeyProvider for NotFips {
        fn load_private_key(
            &self,
            _: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
            Err(rustls::Error::General("not used".to_string()))
        }
    }

    fn keys(schemes: &[T]) -> &'static PolicyKeyProvider {
        tables(&scheme_set(schemes).unwrap()).unwrap().keys
    }

    #[test]
    fn the_key_provider_is_fips_exactly_when_its_base_is() {
        let wrap = |base: &'static dyn KeyProvider| PolicyKeyProvider { base, schemes: &[] };
        assert!(!wrap(&NotFips).fips());
        assert!(wrap(base_provider().key_provider).fips());
        assert!(keys(&available_schemes()).fips());
    }

    #[test]
    fn a_provider_with_another_key_provider_is_drift() {
        let p = one13(K::Secp384r1);
        let stock = CryptoProvider {
            key_provider: base_provider().key_provider,
            ..crypto_provider(&p).unwrap()
        };
        assert_eq!(
            assert_provider_matches(&stock, &p),
            Err(CryptoError::PolicyDrift)
        );
        let other = CryptoProvider {
            key_provider: keys(&[T::Ed25519]),
            ..crypto_provider(&p).unwrap()
        };
        assert_eq!(
            assert_provider_matches(&other, &p),
            Err(CryptoError::PolicyDrift)
        );
    }

    fn subsets() -> impl Iterator<Item = Vec<T>> {
        (1u16..1 << available_schemes().len()).map(|m| {
            available_schemes()
                .into_iter()
                .enumerate()
                .filter(|(i, _)| m & (1 << i) != 0)
                .map(|(_, t)| t)
                .collect()
        })
    }

    fn with_schemes(schemes: Vec<T>) -> Policy {
        Policy {
            signature_schemes: schemes,
            ..one13(K::Secp384r1)
        }
    }

    #[test]
    fn the_first_duplicate_in_any_list_is_refused_in_family_order() {
        let p = one13(K::Secp384r1);
        let versions = Policy {
            versions: vec![V::Tls13, V::Tls12, V::Tls13],
            cipher_suites: vec![C::Tls13Aes256GcmSha384, C::Tls13Aes256GcmSha384],
            ..p.clone()
        };
        let suites = Policy {
            cipher_suites: vec![
                C::Tls13Aes256GcmSha384,
                C::Tls13Aes128GcmSha256,
                C::Tls13Aes128GcmSha256,
                C::Tls13Aes256GcmSha384,
            ],
            kx_groups: vec![K::Secp384r1, K::Secp384r1],
            ..p.clone()
        };
        let groups = Policy {
            kx_groups: vec![K::MlKem1024, K::Secp384r1, K::MlKem1024],
            signature_schemes: vec![T::Ed25519, T::Ed25519],
            ..p.clone()
        };
        for (q, a) in [
            (versions, Algorithm::Protocol(V::Tls13)),
            (suites, Algorithm::Cipher(C::Tls13Aes128GcmSha256)),
            (groups, Algorithm::Kx(K::MlKem1024)),
        ] {
            assert_eq!(
                crypto_provider(&q).err(),
                Some(CryptoError::PolicyDuplicate(a)),
                "{q:?}"
            );
        }
    }

    #[test]
    fn a_duplicate_is_refused_before_an_unavailable_algorithm() {
        let p = one13(K::Secp384r1);
        let none = |a: Algorithm| Err(CryptoError::Unavailable(a));
        for (q, a) in [
            (
                Policy {
                    versions: vec![V::Tls13, V::Tls13],
                    ..p.clone()
                },
                Algorithm::Protocol(V::Tls13),
            ),
            (
                Policy {
                    cipher_suites: vec![C::Tls13Aes256GcmSha384; 2],
                    ..p.clone()
                },
                Algorithm::Cipher(C::Tls13Aes256GcmSha384),
            ),
            (
                Policy {
                    kx_groups: vec![K::Secp384r1; 2],
                    ..p.clone()
                },
                Algorithm::Kx(K::Secp384r1),
            ),
            (
                Policy {
                    signature_schemes: vec![T::MlDsa87; 2],
                    ..p.clone()
                },
                Algorithm::Scheme(T::MlDsa87),
            ),
        ] {
            assert_eq!(
                validate(&q, none).err(),
                Some(CryptoError::PolicyDuplicate(a)),
                "{q:?}"
            );
        }
        assert_eq!(
            validate(&p, none).err(),
            Some(CryptoError::Unavailable(Algorithm::Protocol(V::Tls13)))
        );
    }

    #[test]
    fn a_duplicate_scheme_is_refused_where_the_policy_enters() {
        let roots = Arc::new(rustls::RootCertStore::empty());
        let dup = with_schemes(vec![T::Ed25519, T::EcdsaNistp384Sha384, T::Ed25519]);
        let want = Some(CryptoError::PolicyDuplicate(Algorithm::Scheme(T::Ed25519)));
        assert_eq!(crypto_provider(&dup).err(), want);
        assert_eq!(client_builder(&dup).err(), want);
        assert_eq!(server_builder(&dup).err(), want);
        assert_eq!(
            server_cert_verifier_builder(roots.clone(), &dup).err(),
            want
        );
        assert_eq!(client_cert_verifier_builder(roots, &dup).err(), want);
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(b"not a key".to_vec().into());
        assert_eq!(load_private_key(&dup, der).err(), want);
    }

    #[test]
    fn a_permuted_policy_builds_the_same_provider() {
        let q = with_schemes(vec![T::Ed25519, T::RsaPssSha384, T::EcdsaNistp384Sha384]);
        let r = with_schemes(vec![T::RsaPssSha384, T::EcdsaNistp384Sha384, T::Ed25519]);
        assert_eq!(
            assert_provider_matches(&crypto_provider(&q).unwrap(), &r),
            Ok(())
        );
    }

    #[test]
    fn strict_cache_is_bounded_and_keeps_baseline_algorithms() {
        use PeerCertificateRuleId::*;
        let mut cache = HashMap::new();
        for schemes in subsets() {
            let set = scheme_set(&schemes).unwrap();
            let mut reverse = schemes.clone();
            reverse.reverse();
            for rule in [
                Unrestricted,
                Preferred,
                Cnsa2,
                Cnsa1,
                Bsi,
                Fips1403,
                Fips1402,
            ] {
                let key = TableKey {
                    scheme_bits: set.bits,
                    rule: Some(rule),
                };
                let first = cached_tables(&mut cache, key, &set).unwrap();
                let again = cached_tables(&mut cache, key, &scheme_set(&reverse).unwrap()).unwrap();
                assert!(std::ptr::eq(first.verification, again.verification));
                let baseline = base_provider().signature_verification_algorithms;
                assert!(std::ptr::eq(first.verification.all, baseline.all));
                assert_eq!(
                    first
                        .verification
                        .mapping
                        .iter()
                        .map(|(s, _)| *s)
                        .collect::<Vec<_>>(),
                    set.ordered
                        .iter()
                        .map(|s| rustls_scheme(*s))
                        .collect::<Vec<_>>()
                );
            }
        }
        let expected = if available_schemes().len() == 11 {
            14329
        } else {
            7161
        };
        assert_eq!(cache.len(), expected);
        let set = scheme_set(&[T::RsaPssSha384]).unwrap();
        let a = cached_tables(
            &mut cache,
            TableKey {
                scheme_bits: set.bits,
                rule: Some(Cnsa1),
            },
            &set,
        )
        .unwrap();
        let b = cached_tables(
            &mut cache,
            TableKey {
                scheme_bits: set.bits,
                rule: Some(Preferred),
            },
            &set,
        )
        .unwrap();
        assert!(!std::ptr::eq(a.verification, b.verification));
        let empty = scheme_set(&[]).unwrap();
        assert!(
            cached_tables(
                &mut cache,
                TableKey {
                    scheme_bits: 0,
                    rule: Some(Cnsa1)
                },
                &empty
            )
            .is_err()
        );
        assert_eq!(cache.len(), expected);
        let on = Policy {
            peer_certificate_rule: Some(Cnsa1),
            ..one13(K::Secp384r1)
        };
        let off = Policy {
            peer_certificate_rule: None,
            ..on.clone()
        };
        let on_provider = crypto_provider(&on).unwrap();
        let off_provider = crypto_provider(&off).unwrap();
        assert!(std::ptr::eq(
            on_provider.signature_verification_algorithms.all,
            off_provider.signature_verification_algorithms.all
        ));
        assert!(!std::ptr::addr_eq(
            on_provider.key_provider,
            off_provider.key_provider
        ));
    }

    #[test]
    fn retained_cache_state_is_bounded_by_the_distinct_scheme_sets() {
        let mut cache = HashMap::new();
        for s in subsets() {
            let set = scheme_set(&s).unwrap();
            cached_tables(
                &mut cache,
                TableKey {
                    scheme_bits: set.bits,
                    rule: None,
                },
                &set,
            )
            .unwrap();
        }
        let sets = (1 << available_schemes().len()) - 1;
        assert_eq!(cache.len(), sets);
        for s in subsets() {
            let mut rev = s.clone();
            rev.reverse();
            let mut rot = s.clone();
            rot.rotate_left(1);
            let set = scheme_set(&rev).unwrap();
            cached_tables(
                &mut cache,
                TableKey {
                    scheme_bits: set.bits,
                    rule: None,
                },
                &set,
            )
            .unwrap();
            let set = scheme_set(&rot).unwrap();
            cached_tables(
                &mut cache,
                TableKey {
                    scheme_bits: set.bits,
                    rule: None,
                },
                &set,
            )
            .unwrap();
            let set = scheme_set(&s.clone()).unwrap();
            cached_tables(
                &mut cache,
                TableKey {
                    scheme_bits: set.bits,
                    rule: None,
                },
                &set,
            )
            .unwrap();
            let mut dup = s.clone();
            dup.push(s[0]);
            assert_eq!(
                crypto_provider(&with_schemes(dup)).err(),
                Some(CryptoError::PolicyDuplicate(Algorithm::Scheme(s[0])))
            );
        }
        assert_eq!(cache.len(), sets);
    }

    #[test]
    fn load_private_key_refuses_garbage() {
        let der = rustls::pki_types::PrivateKeyDer::Pkcs8(b"not a key".to_vec().into());
        assert_eq!(
            load_private_key(&one13(K::Secp384r1), der).err(),
            Some(CryptoError::Tls(TlsError::PrivateKey))
        );
    }

    #[test]
    fn an_ml_dsa_44_or_65_key_loads_but_no_policy_signs_with_it() {
        for (fixture, scheme) in [
            (
                super::super::backend::MlDsa::fixture44(),
                rustls::SignatureScheme::ML_DSA_44,
            ),
            (
                super::super::backend::MlDsa::fixture65(),
                rustls::SignatureScheme::ML_DSA_65,
            ),
        ] {
            assert_eq!(
                fixture.is_some(),
                crate::capability(crate::MODULE, Algorithm::Signature(S::MlDsa87)).available
            );
            let Some(pkcs8) = fixture else {
                assert_eq!(
                    super::super::backend::MlDsa::generate().err(),
                    Some(CryptoError::Unavailable(Algorithm::Signature(S::MlDsa87)))
                );
                continue;
            };
            let der = PrivateKeyDer::Pkcs8(pkcs8.to_vec().into());
            let key = load_private_key(&one13(K::Secp384r1), der).unwrap();
            assert!(
                key.choose_scheme(&[scheme, rustls::SignatureScheme::ML_DSA_87])
                    .is_none(),
                "{scheme:?}"
            );
        }
    }

    #[test]
    fn the_base_provider_draws_randomness_and_loads_keys_through_the_crates_own_provider() {
        let base = base_provider();
        assert_eq!(format!("{:?}", base.secure_random), "Rng");
        assert_eq!(format!("{:?}", base.key_provider), "Keys");
    }
}
