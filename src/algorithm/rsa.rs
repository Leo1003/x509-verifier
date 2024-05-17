use super::{identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use const_oid::AssociatedOid;
use der::{
    asn1::{BitString, Null},
    referenced::OwnedToRef,
    Any,
};
use digest::DynDigest;
use rsa::{
    pkcs1::RsaPssParams, pkcs8::SubjectPublicKeyInfo, traits::SignatureScheme, Pkcs1v15Sign, Pss,
    RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::marker::PhantomData;
use x509_cert::spki::{
    AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RsaAlgorithm<D, S>(PhantomData<D>, PhantomData<S>);

impl<D, S> RsaAlgorithm<D, S> {
    const fn new() -> Self {
        Self(PhantomData, PhantomData)
    }
}

impl<D, S> AssociatedAlgorithmIdentifier for RsaAlgorithm<D, S> {
    type Params = Null;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_RSA_ENCRYPTION;
}

impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha256, Pss> {
    type Params = RsaPssParams<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA256_RSA_SSA_PSS;
}
impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha384, Pss> {
    type Params = RsaPssParams<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA384_RSA_SSA_PSS;
}
impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha512, Pss> {
    type Params = RsaPssParams<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA512_RSA_SSA_PSS;
}
impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha256, Pkcs1v15Sign> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA256_WITH_RSA_ENCRYPTION;
}
impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha384, Pkcs1v15Sign> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA384_WITH_RSA_ENCRYPTION;
}
impl SignatureAlgorithmIdentifier for RsaAlgorithm<Sha512, Pkcs1v15Sign> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA512_WITH_RSA_ENCRYPTION;
}

impl<D> VerificationAlgorithm for RsaAlgorithm<D, Pss>
where
    Self: AssociatedAlgorithmIdentifier + SignatureAlgorithmIdentifier,
    D: 'static + Digest + DynDigest + Send + Sync,
{
    fn verify_signature(
        &self,
        spki: &SubjectPublicKeyInfo<Any, BitString>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        rsa_verify::<D, _>(spki, Pss::new::<D>(), data, signature)
    }
}

impl<D> VerificationAlgorithm for RsaAlgorithm<D, Pkcs1v15Sign>
where
    Self: AssociatedAlgorithmIdentifier + SignatureAlgorithmIdentifier,
    D: Digest + AssociatedOid,
{
    fn verify_signature(
        &self,
        spki: &SubjectPublicKeyInfo<Any, BitString>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        rsa_verify::<D, _>(spki, Pkcs1v15Sign::new::<D>(), data, signature)
    }
}

fn rsa_verify<D, S>(
    spki: &SubjectPublicKeyInfo<Any, BitString>,
    scheme: S,
    data: &[u8],
    signature: &[u8],
) -> PkixResult<()>
where
    S: SignatureScheme,
    D: Digest,
{
    let key = RsaPublicKey::try_from(spki.owned_to_ref())
        .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;

    let mut hasher = D::new();
    Digest::update(&mut hasher, data);
    let hash = Digest::finalize(hasher);

    key.verify(scheme, hash.as_slice(), signature)
        .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;

    Ok(())
}

pub const RSA_PSS_SHA256: RsaAlgorithm<Sha256, Pss> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha256, Pss>: VerificationAlgorithm);

pub const RSA_PSS_SHA384: RsaAlgorithm<Sha384, Pss> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha384, Pss>: VerificationAlgorithm);

pub const RSA_PSS_SHA512: RsaAlgorithm<Sha512, Pss> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha512, Pss>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA256: RsaAlgorithm<Sha256, Pkcs1v15Sign> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha256, Pkcs1v15Sign>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA384: RsaAlgorithm<Sha384, Pkcs1v15Sign> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha384, Pkcs1v15Sign>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA512: RsaAlgorithm<Sha512, Pkcs1v15Sign> = RsaAlgorithm::new();
assert_impl_all!(RsaAlgorithm<Sha512, Pkcs1v15Sign>: VerificationAlgorithm);
