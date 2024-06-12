use crate::types::TrustAnchor;
use x509_cert::{name::Name, Certificate};

#[derive(Clone, Debug, Default)]
pub struct CertificatePool {
    trust_anchors: Vec<TrustAnchor>,

    intermediate_certs: Vec<Certificate>,
}

impl CertificatePool {
    pub fn find_trustanchors_by_subject<'s>(
        &'s self,
        name: &'s Name,
    ) -> impl Iterator<Item = &'s TrustAnchor> {
        self.trust_anchors
            .iter()
            .filter(move |ta| &ta.subject == name)
    }

    pub fn find_intermediate_by_subject<'s>(
        &'s self,
        name: &'s Name,
    ) -> impl Iterator<Item = &'s Certificate> {
        self.intermediate_certs
            .iter()
            .filter(move |cert| &cert.tbs_certificate.subject == name)
    }
}

impl Extend<TrustAnchor> for CertificatePool {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = TrustAnchor>,
    {
        self.trust_anchors.extend(iter);
    }
}

impl Extend<Certificate> for CertificatePool {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Certificate>,
    {
        self.intermediate_certs.extend(iter);
    }
}
