use crate::error::{PkixError, PkixResult};
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};

mod ecdsa;
mod ed25519;
mod identifiers;
mod rsa;

pub use ecdsa::{
    EcdsaAlgorithm, ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384,
    ECDSA_P521_SHA512,
};
pub use ed25519::{Ed25519Algorithm, ED25519};
pub use rsa::{RsaPkcs1Algorithm, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS};

pub trait VerificationAlgorithm {
    fn signature_oid(&self) -> ObjectIdentifier;

    fn publickey_oid(&self) -> ObjectIdentifier;

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()>;
}

fn assert_result<T, E>(a: T, b: T, error: E) -> PkixResult<()>
where
    T: PartialEq,
    E: Into<PkixError>,
{
    if a != b {
        Err(error.into())
    } else {
        Ok(())
    }
}
