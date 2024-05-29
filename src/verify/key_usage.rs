use crate::{
    traits::KeyUsagesVerifier,
    types::{CertificateExtendedKeyUsage, CertificateKeyUsage, CertificateKeyUsages},
};
use std::{fmt::Formatter, sync::Arc};
use std::{
    fmt::{Debug, Result as FmtResult},
    ptr::addr_of,
};
use x509_cert::Certificate;

#[derive(Clone, Debug)]
pub struct ServerProfile {
    inner: GenericKeyUsageVerifier,
}

impl Default for ServerProfile {
    fn default() -> Self {
        Self::new(KeyUsageVerifierOptions::default().allow_any_key_usage())
    }
}

impl ServerProfile {
    pub fn new(options: KeyUsageVerifierOptions) -> Self {
        Self {
            inner: GenericKeyUsageVerifier {
                options,
                ku_checker: Arc::new(Self::verify_ku),
                eku_checker: Arc::new(Self::verify_eku),
            },
        }
    }

    pub fn strict_mode() -> Self {
        Self::new(
            KeyUsageVerifierOptions::default()
                .require_key_usage_extension()
                .require_extended_key_usage_extension(),
        )
    }

    pub fn verify_ku(ku: &CertificateKeyUsage) -> bool {
        ku.has_digital_signature()
    }

    fn verify_eku(eku: &CertificateExtendedKeyUsage) -> bool {
        eku.has_server_auth()
    }
}

impl KeyUsagesVerifier for ServerProfile {
    fn verify_key_usages(&self, cert: &Certificate, key_usages: &CertificateKeyUsages) -> bool {
        self.inner.verify_key_usages(cert, key_usages)
    }
}

#[derive(Clone, Debug)]
pub struct ClientProfile {
    inner: GenericKeyUsageVerifier,
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self::new(KeyUsageVerifierOptions::default().allow_any_key_usage())
    }
}

impl ClientProfile {
    pub fn new(options: KeyUsageVerifierOptions) -> Self {
        Self {
            inner: GenericKeyUsageVerifier {
                options,
                ku_checker: Arc::new(Self::verify_ku),
                eku_checker: Arc::new(Self::verify_eku),
            },
        }
    }

    pub fn strict_mode() -> Self {
        Self::new(
            KeyUsageVerifierOptions::default()
                .require_key_usage_extension()
                .require_extended_key_usage_extension(),
        )
    }

    fn verify_ku(ku: &CertificateKeyUsage) -> bool {
        ku.has_digital_signature()
    }

    fn verify_eku(eku: &CertificateExtendedKeyUsage) -> bool {
        eku.has_client_auth()
    }
}

impl KeyUsagesVerifier for ClientProfile {
    fn verify_key_usages(&self, cert: &Certificate, key_usages: &CertificateKeyUsages) -> bool {
        self.inner.verify_key_usages(cert, key_usages)
    }
}

#[derive(Clone, Debug)]
pub struct CaProfile {
    inner: GenericKeyUsageVerifier,
}

impl Default for CaProfile {
    fn default() -> Self {
        Self::new(
            KeyUsageVerifierOptions::default()
                .require_key_usage_extension()
                .allow_any_key_usage(),
        )
    }
}

impl CaProfile {
    pub fn new(options: KeyUsageVerifierOptions) -> Self {
        Self {
            inner: GenericKeyUsageVerifier {
                options,
                ku_checker: Arc::new(Self::verify_ku),
                eku_checker: Arc::new(Self::verify_eku),
            },
        }
    }

    pub fn strict_mode() -> Self {
        Self::new(KeyUsageVerifierOptions::default().require_key_usage_extension())
    }

    fn verify_ku(ku: &CertificateKeyUsage) -> bool {
        ku.has_key_cert_sign()
    }

    fn verify_eku(_eku: &CertificateExtendedKeyUsage) -> bool {
        true
    }
}

impl KeyUsagesVerifier for CaProfile {
    fn verify_key_usages(&self, cert: &Certificate, key_usages: &CertificateKeyUsages) -> bool {
        self.inner.verify_key_usages(cert, key_usages)
    }
}

#[derive(Clone)]
pub struct GenericKeyUsageVerifier {
    pub options: KeyUsageVerifierOptions,
    pub ku_checker: Arc<dyn Fn(&CertificateKeyUsage) -> bool + Send + Sync>,
    pub eku_checker: Arc<dyn Fn(&CertificateExtendedKeyUsage) -> bool + Send + Sync>,
}

impl Debug for GenericKeyUsageVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("GenericKeyUsageVerifier")
            .field("options", &self.options)
            .field("ku_checker", &addr_of!(*self.ku_checker))
            .field("eku_checker", &addr_of!(*self.eku_checker))
            .finish()
    }
}

impl GenericKeyUsageVerifier {
    fn verify_ku(&self, ku: &CertificateKeyUsage) -> bool {
        match (self.options.ku_required, ku.is_key_usage_present()) {
            // The extension is required but not present.
            (true, false) => false,
            // The extension is not required and not present.
            (false, false) => true,
            _ => (self.ku_checker)(ku),
        }
    }

    fn verify_eku(&self, eku: &CertificateExtendedKeyUsage) -> bool {
        match (self.options.eku_required, eku.is_ext_key_usage_present()) {
            // The extension is required but not present.
            (true, false) => false,
            // The extension is not required and not present.
            (false, false) => true,
            _ => {
                if self.options.allow_any_eku && eku.has_any_ext_key_usage() {
                    true
                } else {
                    (self.eku_checker)(eku)
                }
            }
        }
    }
}

impl KeyUsagesVerifier for GenericKeyUsageVerifier {
    fn verify_key_usages(&self, _cert: &Certificate, key_usages: &CertificateKeyUsages) -> bool {
        self.verify_ku(key_usages.key_usage()) && self.verify_eku(key_usages.extended_key_usage())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyUsageVerifierOptions {
    ku_required: bool,
    eku_required: bool,
    allow_any_eku: bool,
}

impl KeyUsageVerifierOptions {
    pub fn require_key_usage_extension(self) -> Self {
        Self {
            ku_required: true,
            ..self
        }
    }

    pub fn require_extended_key_usage_extension(self) -> Self {
        Self {
            eku_required: true,
            ..self
        }
    }

    pub fn allow_any_key_usage(self) -> Self {
        Self {
            allow_any_eku: true,
            ..self
        }
    }
}
