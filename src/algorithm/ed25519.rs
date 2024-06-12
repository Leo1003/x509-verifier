use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519Algorithm;

impl Ed25519Algorithm {
    const fn new() -> Self {
        Self
    }
}

impl VerificationAlgorithm for Ed25519Algorithm {
    fn signature_oid(&self) -> ObjectIdentifier {
        ed25519_dalek::pkcs8::ALGORITHM_OID
    }

    fn publickey_oid(&self) -> ObjectIdentifier {
        ed25519_dalek::pkcs8::ALGORITHM_OID
    }

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        assert_result(
            identifiers::decode_algorithm_identifier(algorithm)
                .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithmIdentifier, Some(e)))?,
            identifiers::ALG_ED25519,
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;

        let public_key = VerifyingKey::try_from(spki)
            .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;
        let signature = Signature::from_slice(signature)
            .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;

        public_key
            .verify(data, &signature)
            .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))
    }
}

pub const ED25519: Ed25519Algorithm = Ed25519Algorithm::new();
assert_impl_all!(Ed25519Algorithm: VerificationAlgorithm);
