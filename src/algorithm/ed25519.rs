use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use der::asn1::Null;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};
use x509_cert::spki::{
    AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519Algorithm;

impl Ed25519Algorithm {
    const fn new() -> Self {
        Self
    }
}

impl AssociatedAlgorithmIdentifier for Ed25519Algorithm {
    type Params = Null;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_ED25519;
}

impl SignatureAlgorithmIdentifier for Ed25519Algorithm {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_ED25519;
}

impl VerificationAlgorithm for Ed25519Algorithm {
    fn signature_oid(&self) -> ObjectIdentifier {
        Self::SIGNATURE_ALGORITHM_IDENTIFIER.oid
    }

    fn publickey_oid(&self) -> ObjectIdentifier {
        Self::ALGORITHM_IDENTIFIER.oid
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
                .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithm, Some(e)))?,
            Self::SIGNATURE_ALGORITHM_IDENTIFIER,
            PkixErrorKind::InvalidAlgorithm,
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
