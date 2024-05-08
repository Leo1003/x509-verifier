use x509_cert::{
    der::{asn1::BitString, Any},
    ext::pkix::NameConstraints,
    name::RdnSequence,
    spki::SubjectPublicKeyInfo,
    Certificate, TbsCertificate,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub subject: RdnSequence,
    pub subject_public_key_info: SubjectPublicKeyInfo<Any, BitString>,
    pub name_constraints: Option<NameConstraints>,
}

impl TryFrom<Certificate> for TrustAnchor {
    type Error = x509_cert::der::Error;

    fn try_from(cert: Certificate) -> Result<Self, Self::Error> {
        Self::try_from(cert.tbs_certificate)
    }
}

impl TryFrom<TbsCertificate> for TrustAnchor {
    type Error = x509_cert::der::Error;

    fn try_from(tbs_certificate: TbsCertificate) -> Result<Self, Self::Error> {
        let name_constraints = tbs_certificate
            .get::<NameConstraints>()?
            .map(|(_critical, ext)| ext);

        Ok(Self {
            subject: tbs_certificate.subject,
            subject_public_key_info: tbs_certificate.subject_public_key_info,
            name_constraints,
        })
    }
}
