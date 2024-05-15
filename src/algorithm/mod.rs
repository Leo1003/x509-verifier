use crate::error::PkixResult;
use der::{asn1::BitString, Any};
use p256::pkcs8::SubjectPublicKeyInfo;
use x509_cert::spki::{AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier};

mod ecdsa;
mod identifiers;

pub use ecdsa::{
    EcdsaAlgorithm, ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
};

pub trait VerificationAlgorithm:
    AssociatedAlgorithmIdentifier + SignatureAlgorithmIdentifier
{
    fn verify_signature(
        &self,
        spki: &SubjectPublicKeyInfo<Any, BitString>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()>;
}
