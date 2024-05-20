use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::Null;
use digest::{generic_array::ArrayLength, Digest};
use ecdsa::{
    der::{MaxOverhead, MaxSize, Signature},
    elliptic_curve::{
        point::PointCompression,
        sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
        AffinePoint, CurveArithmetic, FieldBytesSize,
    },
    hazmat::VerifyPrimitive,
    PrimeCurve, SignatureSize, VerifyingKey,
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use std::{marker::PhantomData, ops::Add};
use x509_cert::spki::{
    AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EcdsaAlgorithm<C, D>(PhantomData<C>, PhantomData<D>);

impl<C, D> EcdsaAlgorithm<C, D> {
    const fn new() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<D> AssociatedAlgorithmIdentifier for EcdsaAlgorithm<NistP256, D> {
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_ECDSA_P256;
}
impl<D> AssociatedAlgorithmIdentifier for EcdsaAlgorithm<NistP384, D> {
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_ECDSA_P384;
}
impl<D> AssociatedAlgorithmIdentifier for EcdsaAlgorithm<NistP521, D> {
    type Params = ObjectIdentifier;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_ECDSA_P521;
}

impl<C> SignatureAlgorithmIdentifier for EcdsaAlgorithm<C, Sha256> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_ECDSA_WITH_SHA256;
}
impl<C> SignatureAlgorithmIdentifier for EcdsaAlgorithm<C, Sha384> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_ECDSA_WITH_SHA384;
}
impl<C> SignatureAlgorithmIdentifier for EcdsaAlgorithm<C, Sha512> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_ECDSA_WITH_SHA512;
}

impl<C, D> VerificationAlgorithm for EcdsaAlgorithm<C, D>
where
    Self: AssociatedAlgorithmIdentifier + SignatureAlgorithmIdentifier<Params = Null>,
    C: PrimeCurve + AssociatedOid + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    MaxSize<C>: ArrayLength<u8>,
    FieldBytesSize<C>: ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
    D: Digest,
{
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

        let key = VerifyingKey::<C>::try_from(spki)
            .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;
        let sig = Signature::<C>::from_bytes(signature)
            .map_err(|e| PkixError::new(PkixErrorKind::DerError, Some(e)))?;

        let mut hasher = D::new();
        Digest::update(&mut hasher, data);
        let hash = Digest::finalize(hasher);

        // Using PrehashVerifier instead of DigestVerifier to allow
        // digest algorithms with different output sizes.
        key.verify_prehash(hash.as_slice(), &sig)
            .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;
        Ok(())
    }
}

pub const ECDSA_P256_SHA256: EcdsaAlgorithm<NistP256, Sha256> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<NistP256, Sha256>: VerificationAlgorithm);

pub const ECDSA_P256_SHA384: EcdsaAlgorithm<NistP256, Sha384> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<NistP256, Sha384>: VerificationAlgorithm);

pub const ECDSA_P384_SHA256: EcdsaAlgorithm<NistP384, Sha256> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<NistP384, Sha256>: VerificationAlgorithm);

pub const ECDSA_P384_SHA384: EcdsaAlgorithm<NistP384, Sha384> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<NistP384, Sha384>: VerificationAlgorithm);

pub const ECDSA_P521_SHA512: EcdsaAlgorithm<NistP521, Sha512> = EcdsaAlgorithm::new();
assert_impl_all!(EcdsaAlgorithm<NistP521, Sha512>: VerificationAlgorithm);
