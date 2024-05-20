use crate::types::TrustAnchor;
use x509_cert::Certificate;

#[derive(Clone, Debug, Default)]
pub struct CertificatePool {
    pub(crate) trust_anchors: Vec<TrustAnchor>,

    pub(crate) intermediate_certs: Vec<Certificate>,
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
