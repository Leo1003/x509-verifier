use crate::{
    error::{PkixError, PkixErrorKind},
    traits::AsEntity,
};
use x509_cert::{
    der::{asn1::BitString, Any},
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, NameConstraints},
    name::Name,
    spki::SubjectPublicKeyInfo,
    Certificate, TbsCertificate,
};

/// This struct contains all the needed information required to
/// verify a certificate chain.
///
/// The field design is inspired by [RFC 5914](https://datatracker.ietf.org/doc/html/rfc5914#autoid-3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo<Any, BitString>,
    pub name_constraints: Option<NameConstraints>,
    pub path_len_constraint: Option<u8>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<ExtendedKeyUsage>,
}

impl TryFrom<Certificate> for TrustAnchor {
    type Error = PkixError;

    fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
        Self::try_from(cert.tbs_certificate)
    }
}

impl TryFrom<TbsCertificate> for TrustAnchor {
    type Error = PkixError;

    fn try_from(tbs_certificate: TbsCertificate) -> Result<Self, Self::Error> {
        let name_constraints = tbs_certificate
            .get::<NameConstraints>()?
            .map(|(_critical, ext)| ext);
        let basic_constraints = tbs_certificate
            .get::<BasicConstraints>()?
            .map(|(_critical, ext)| ext)
            .unwrap_or_else(|| BasicConstraints {
                ca: false,
                path_len_constraint: None,
            });
        let key_usage = tbs_certificate
            .get::<KeyUsage>()?
            .map(|(_critical, ext)| ext);
        let extended_key_usage = tbs_certificate
            .get::<ExtendedKeyUsage>()?
            .map(|(_critical, ext)| ext);

        if !basic_constraints.ca {
            return Err(PkixErrorKind::BasicConstraintsViolated.into());
        }

        Ok(Self {
            subject: tbs_certificate.subject,
            subject_public_key_info: tbs_certificate.subject_public_key_info,
            name_constraints,
            path_len_constraint: basic_constraints.path_len_constraint,
            key_usage,
            extended_key_usage,
        })
    }
}

impl AsEntity for TrustAnchor {
    fn subject(&self) -> &Name {
        &self.subject
    }

    fn spki(&self) -> &SubjectPublicKeyInfo<Any, BitString> {
        &self.subject_public_key_info
    }
}
