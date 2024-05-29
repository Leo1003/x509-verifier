use const_oid::{db::rfc5280::*, ObjectIdentifier};
use std::{borrow::Borrow, collections::HashSet};
use x509_cert::{
    ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages},
    Certificate,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateKeyUsage(Option<KeyUsage>);

impl CertificateKeyUsage {
    pub(crate) fn new(key_usage: Option<KeyUsage>) -> Self {
        Self(key_usage)
    }

    /// Returns whether the key usage extension is present.
    pub fn is_key_usage_present(&self) -> bool {
        self.0.is_some()
    }

    /// Returns whether the certificate has specific key usage.
    pub fn key_usage_has(&self, usage: KeyUsages) -> bool {
        self.0.map(|ku| ku.0.contains(usage)).unwrap_or(false)
    }

    /// Returns whether the certificate has the `digitalSignature` usage.
    pub fn has_digital_signature(&self) -> bool {
        self.key_usage_has(KeyUsages::DigitalSignature)
    }

    /// Returns whether the certificate has the `nonRepudiation` usage.
    pub fn has_non_repudiation(&self) -> bool {
        self.key_usage_has(KeyUsages::NonRepudiation)
    }

    /// Returns whether the certificate has the `contentCommitment` usage.
    ///
    /// X.509 has renamed `nonRepudiation` to `contentCommitment`.
    /// This is an alias for `has_non_repudiation`.
    pub fn has_content_commitment(&self) -> bool {
        self.has_non_repudiation()
    }

    /// Returns whether the certificate has the `keyEncipherment` usage.
    pub fn has_key_encipherment(&self) -> bool {
        self.key_usage_has(KeyUsages::KeyEncipherment)
    }

    /// Returns whether the certificate has the `dataEncipherment` usage.
    pub fn has_data_encipherment(&self) -> bool {
        self.key_usage_has(KeyUsages::DataEncipherment)
    }

    /// Returns whether the certificate has the `keyAgreement` usage.
    pub fn has_key_agreement(&self) -> bool {
        self.key_usage_has(KeyUsages::KeyAgreement)
    }

    /// Returns whether the certificate has the `keyCertSign` usage.
    pub fn has_key_cert_sign(&self) -> bool {
        self.key_usage_has(KeyUsages::KeyCertSign)
    }

    /// Returns whether the certificate has the `cRLSign` usage.
    pub fn has_crl_sign(&self) -> bool {
        self.key_usage_has(KeyUsages::CRLSign)
    }

    /// Returns whether the certificate has the `encipherOnly` usage.
    pub fn has_encipher_only(&self) -> bool {
        self.key_usage_has(KeyUsages::EncipherOnly)
    }

    /// Returns whether the certificate has the `decipherOnly` usage.
    pub fn has_decipher_only(&self) -> bool {
        self.key_usage_has(KeyUsages::DecipherOnly)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateExtendedKeyUsage(Option<HashSet<ObjectIdentifier>>);

impl CertificateExtendedKeyUsage {
    pub(crate) fn new(ext_usage: Option<ExtendedKeyUsage>) -> Self {
        Self(ext_usage.map(|ext| ext.0.into_iter().collect()))
    }

    /// Returns whether the extended key usage extension is present.
    pub fn is_ext_key_usage_present(&self) -> bool {
        self.0.is_some()
    }

    /// Returns whether the certificate has the specific usage.
    pub fn ext_usage_has(&self, oid: &ObjectIdentifier) -> bool {
        self.0
            .as_ref()
            .map(|ext| ext.contains(oid))
            .unwrap_or(false)
    }

    /// Returns whether the certificate has the `anyExtendedKeyUsage` usage.
    pub fn has_any_ext_key_usage(&self) -> bool {
        self.ext_usage_has(&ANY_EXTENDED_KEY_USAGE)
    }

    /// Returns whether the certificate has the `id-kp-serverAuth` usage.
    pub fn has_server_auth(&self) -> bool {
        self.ext_usage_has(&ID_KP_SERVER_AUTH)
    }

    /// Returns whether the certificate has the `id-kp-clientAuth` usage.
    pub fn has_client_auth(&self) -> bool {
        self.ext_usage_has(&ID_KP_CLIENT_AUTH)
    }

    /// Returns whether the certificate has the `id-kp-codeSigning` usage.
    pub fn has_code_signing(&self) -> bool {
        self.ext_usage_has(&ID_KP_CODE_SIGNING)
    }

    /// Returns whether the certificate has the `id-kp-emailProtection` usage.
    pub fn has_email_protection(&self) -> bool {
        self.ext_usage_has(&ID_KP_EMAIL_PROTECTION)
    }

    /// Returns whether the certificate has the `id-kp-timeStamping` usage.
    pub fn has_time_stamping(&self) -> bool {
        self.ext_usage_has(&ID_KP_TIME_STAMPING)
    }

    /// Returns whether the certificate has the `id-kp-OCSPSigning` usage.
    pub fn has_ocsp_signing(&self) -> bool {
        self.ext_usage_has(&ID_KP_OCSP_SIGNING)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateKeyUsages {
    ku: CertificateKeyUsage,
    eku: CertificateExtendedKeyUsage,
}

impl CertificateKeyUsages {
    pub(crate) fn new(key_usage: Option<KeyUsage>, ext_usage: Option<ExtendedKeyUsage>) -> Self {
        Self {
            ku: CertificateKeyUsage::new(key_usage),
            eku: CertificateExtendedKeyUsage::new(ext_usage),
        }
    }

    pub fn key_usage(&self) -> &CertificateKeyUsage {
        &self.ku
    }

    pub fn extended_key_usage(&self) -> &CertificateExtendedKeyUsage {
        &self.eku
    }
}

impl Borrow<CertificateKeyUsage> for CertificateKeyUsages {
    fn borrow(&self) -> &CertificateKeyUsage {
        &self.ku
    }
}

impl Borrow<CertificateExtendedKeyUsage> for CertificateKeyUsages {
    fn borrow(&self) -> &CertificateExtendedKeyUsage {
        &self.eku
    }
}

impl TryFrom<&Certificate> for CertificateKeyUsages {
    type Error = der::Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        Ok(Self::new(
            cert.tbs_certificate.get()?.map(|e| e.1),
            cert.tbs_certificate.get()?.map(|e| e.1),
        ))
    }
}

impl TryFrom<Certificate> for CertificateKeyUsages {
    type Error = der::Error;

    fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
        Self::try_from(&cert)
    }
}

impl From<(KeyUsage, ExtendedKeyUsage)> for CertificateKeyUsages {
    fn from((key_usage, ext_usage): (KeyUsage, ExtendedKeyUsage)) -> Self {
        Self::new(Some(key_usage), Some(ext_usage))
    }
}
