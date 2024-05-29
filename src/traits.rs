use crate::types::CertificateKeyUsages;
use std::{error::Error, fmt::Debug, future::Future};
use x509_cert::{
    der::{asn1::BitString, Any},
    name::RdnSequence,
    spki::SubjectPublicKeyInfo,
    Certificate,
};

pub trait Request {
    type Response;
}

pub trait SyncAccessor<R: Request>: Debug + Send + Sync {
    type Error: Error + 'static;

    fn retrieve(request: R) -> Result<R::Response, Self::Error>;
}

pub trait AsyncAccessor<R: Request>: Debug + Send + Sync {
    type Error: Error + 'static;

    fn retrieve_async(request: R) -> impl Future<Output = Result<R::Response, Self::Error>> + Send;
}

pub trait KeyUsagesVerifier: Debug + Send + Sync {
    fn verify_key_usages(&self, cert: &Certificate, key_usages: &CertificateKeyUsages) -> bool;
}

pub trait AsEntity {
    fn subject(&self) -> &RdnSequence;

    fn spki(&self) -> &SubjectPublicKeyInfo<Any, BitString>;
}

impl AsEntity for Certificate {
    fn subject(&self) -> &RdnSequence {
        &self.tbs_certificate.subject
    }

    fn spki(&self) -> &SubjectPublicKeyInfo<Any, BitString> {
        &self.tbs_certificate.subject_public_key_info
    }
}

impl AsEntity for (RdnSequence, SubjectPublicKeyInfo<Any, BitString>) {
    fn subject(&self) -> &RdnSequence {
        &self.0
    }

    fn spki(&self) -> &SubjectPublicKeyInfo<Any, BitString> {
        &self.1
    }
}
