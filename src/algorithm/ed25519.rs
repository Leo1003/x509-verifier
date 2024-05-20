use super::{identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use pkcs8::SubjectPublicKeyInfoRef;
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
    type Params = ();

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_ED25519;
}

impl SignatureAlgorithmIdentifier for Ed25519Algorithm {
    type Params = ();

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_ED25519;
}

impl VerificationAlgorithm for Ed25519Algorithm {
    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
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
