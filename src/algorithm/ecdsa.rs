use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::AnyRef;
use digest::{generic_array::ArrayLength, Digest};
use ecdsa::{
    elliptic_curve::{AffinePoint, CurveArithmetic},
    hazmat::VerifyPrimitive,
    PrimeCurve, Signature, SignatureSize, VerifyingKey,
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use std::marker::PhantomData;
use x509_cert::spki::AlgorithmIdentifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcdsaAlgorithm<D>(PhantomData<D>);

impl<D> EcdsaAlgorithm<D> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl AssociatedOid for EcdsaAlgorithm<Sha256> {
    const OID: ObjectIdentifier = ecdsa::ECDSA_SHA256_OID;
}

impl AssociatedOid for EcdsaAlgorithm<Sha384> {
    const OID: ObjectIdentifier = ecdsa::ECDSA_SHA384_OID;
}

impl AssociatedOid for EcdsaAlgorithm<Sha512> {
    const OID: ObjectIdentifier = ecdsa::ECDSA_SHA512_OID;
}

impl<D> VerificationAlgorithm for EcdsaAlgorithm<D>
where
    Self: AssociatedOid,
    D: Digest,
{
    fn signature_oid(&self) -> ObjectIdentifier {
        Self::OID
    }

    fn publickey_oid(&self) -> ObjectIdentifier {
        ecdsa::elliptic_curve::ALGORITHM_OID
    }

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        let alg: AlgorithmIdentifier<AnyRef<'_>> =
            identifiers::decode_algorithm_identifier(algorithm)
                .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithmIdentifier, Some(e)))?;
        assert_result(
            alg.oid,
            self.signature_oid(),
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;
        assert_result(alg.parameters, None, PkixErrorKind::InvalidAlgorithmIdentifier)?;

        assert_result(
            spki.algorithm.oid,
            self.publickey_oid(),
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;
        match spki.algorithm.parameters_oid() {
            Ok(NistP256::OID) => {
                let key = VerifyingKey::<NistP256>::try_from(spki)
                    .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;
                let sig = Signature::<NistP256>::from_der(signature)
                    .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;
                ecdsa_verify::<NistP256, D>(&key, data, &sig)
            }
            Ok(NistP384::OID) => {
                let key = VerifyingKey::<NistP384>::try_from(spki)
                    .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;
                let sig = Signature::<NistP384>::from_der(signature)
                    .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;
                ecdsa_verify::<NistP384, D>(&key, data, &sig)
            }
            Ok(NistP521::OID) => {
                let key = VerifyingKey::<NistP521>::try_from(spki)
                    .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;
                let sig = Signature::<NistP521>::from_der(signature)
                    .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;
                ecdsa_verify::<NistP521, D>(&key, data, &sig)
            }
            Ok(_) => Err(PkixErrorKind::UnsupportedAlgorithm.into()),
            Err(e) => Err(PkixError::new(PkixErrorKind::InvalidAlgorithmIdentifier, Some(e))),
        }
    }
}

fn ecdsa_verify<C, D>(
    key: &VerifyingKey<C>,
    data: &[u8],
    signature: &Signature<C>,
) -> PkixResult<()>
where
    C: PrimeCurve + CurveArithmetic,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    D: Digest,
{
    let hash = D::digest(data);

    // Using PrehashVerifier instead of DigestVerifier to allow
    // digest algorithms with different output sizes.
    key.verify_prehash(hash.as_slice(), signature)
        .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))
}

pub const ECDSA_SHA256: EcdsaAlgorithm<Sha256> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<Sha256>: VerificationAlgorithm);

pub const ECDSA_SHA384: EcdsaAlgorithm<Sha384> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<Sha384>: VerificationAlgorithm);

pub const ECDSA_SHA512: EcdsaAlgorithm<Sha512> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<Sha512>: VerificationAlgorithm);
