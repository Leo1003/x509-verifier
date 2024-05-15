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
    InvalidValidity,
    CertificateExpired,
    CertificateNotYetValid,
    InvalidPublicKey,
    BadSignature,
    DerError,
    Other,
    UnknownIssuer,
}

impl PkixErrorKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PkixErrorKind::BasicConstraintsViolated => "basic constraints violated",
            PkixErrorKind::InvalidValidity => "invalid validity",
            PkixErrorKind::CertificateExpired => "certificate expired",
            PkixErrorKind::CertificateNotYetValid => "certificate not yet valid",
            PkixErrorKind::InvalidPublicKey => "invalid public key",
            PkixErrorKind::BadSignature => "bad signature",
            PkixErrorKind::DerError => "DER error",
            PkixErrorKind::Other => "other error",
            PkixErrorKind::UnknownIssuer => "unknown issuer",
        }
    }
}

impl Display for PkixErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
