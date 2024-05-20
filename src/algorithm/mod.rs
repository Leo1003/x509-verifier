use crate::error::PkixResult;
use der::{asn1::BitString, Any};
use p256::pkcs8::SubjectPublicKeyInfo;
use x509_cert::spki::{AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier};

mod ecdsa;
mod ed25519;
mod identifiers;
mod rsa;

pub use ecdsa::{
    EcdsaAlgorithm, ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
};
pub use ed25519::{Ed25519Algorithm, ED25519};
pub use rsa::{
    RsaAlgorithm, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256,
    RSA_PSS_SHA384, RSA_PSS_SHA512,
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
