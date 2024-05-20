use std::fmt::Debug;
use x509_cert::{
    der::{asn1::BitString, Any},
    name::RdnSequence,
    spki::SubjectPublicKeyInfo,
    Certificate,
};

pub trait CRLFetcher: Debug + Send + Sync {}

pub trait OCSPAccessor: Debug + Send + Sync {}

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
