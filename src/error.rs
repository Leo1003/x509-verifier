use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

pub type PkixResult<T> = Result<T, PkixError>;

#[derive(Clone, Debug)]
pub struct PkixError {
    kind: PkixErrorKind,
    source: Option<Arc<dyn Error + 'static>>,
}

impl PkixError {
    pub fn new<E>(kind: PkixErrorKind, source: Option<E>) -> Self
    where
        E: Error + 'static,
    {
        Self {
            kind,
            source: source.map(|e| Arc::new(e) as Arc<dyn Error + 'static>),
        }
    }

    pub fn kind(&self) -> PkixErrorKind {
        self.kind
    }

    pub(crate) fn merge(&mut self, other: Self) {
        if self.kind.significant() < other.kind.significant() {
            *self = other;
        }
    }
}

impl Display for PkixError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PKIX error: {}", self.kind)
    }
}

impl Error for PkixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
}

impl From<PkixErrorKind> for PkixError {
    fn from(kind: PkixErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl From<der::Error> for PkixError {
    fn from(err: der::Error) -> Self {
        Self::new(PkixErrorKind::DerError, Some(err))
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PkixErrorKind {
    BasicConstraintsViolated,
    NameConstraintsViolated,
    InvalidValidity,
    CertificateExpired,
    CertificateNotYetValid,
    InvalidPublicKey,
    InvalidAlgorithmIdentifier,
    InvalidSubtree,
    InvalidIpAddressConstraints,
    UnsupportedAlgorithm,
    UnknownCriticalExtension,
    KeyUsageViolated,
    BadSignature,
    DerError,
    UnknownIssuer,
}

impl PkixErrorKind {
    pub const fn significant(&self) -> u32 {
        match self {
            // Certificate validity errors
            PkixErrorKind::CertificateNotYetValid => 321,
            PkixErrorKind::CertificateExpired => 320,
            PkixErrorKind::KeyUsageViolated => 311,
            PkixErrorKind::BadSignature => 310,
            PkixErrorKind::BasicConstraintsViolated => 302,
            PkixErrorKind::NameConstraintsViolated => 301,
            PkixErrorKind::UnknownCriticalExtension => 300,
            // Unsupported features of this library
            PkixErrorKind::UnsupportedAlgorithm => 200,
            // Certificate format errors or value not conforming to
            // the RFC 5280 profile
            PkixErrorKind::InvalidAlgorithmIdentifier => 122,
            PkixErrorKind::InvalidValidity => 121,
            PkixErrorKind::InvalidPublicKey => 120,
            PkixErrorKind::InvalidIpAddressConstraints => 112,
            PkixErrorKind::InvalidSubtree => 111,
            PkixErrorKind::DerError => 100,
            // Algorithm errors
            PkixErrorKind::UnknownIssuer => 0,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            PkixErrorKind::BasicConstraintsViolated => "basic constraints violated",
            PkixErrorKind::NameConstraintsViolated => "name constraints violated",
            PkixErrorKind::InvalidValidity => "invalid validity",
            PkixErrorKind::CertificateExpired => "certificate expired",
            PkixErrorKind::CertificateNotYetValid => "certificate not yet valid",
            PkixErrorKind::InvalidPublicKey => "invalid public key",
            PkixErrorKind::InvalidAlgorithmIdentifier => "invalid algorithm identifier",
            PkixErrorKind::InvalidSubtree => "invalid general subtree",
            PkixErrorKind::InvalidIpAddressConstraints => "invalid IP address constraints",
            PkixErrorKind::UnsupportedAlgorithm => "unsupported algorithm",
            PkixErrorKind::UnknownCriticalExtension => "unknown critical extension",
            PkixErrorKind::KeyUsageViolated => "key usage violated",
            PkixErrorKind::BadSignature => "bad signature",
            PkixErrorKind::DerError => "DER error",
            PkixErrorKind::UnknownIssuer => "unknown issuer",
        }
    }
}

impl Display for PkixErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
