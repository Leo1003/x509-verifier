use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use const_oid::{
    db::rfc5912::{ID_MGF_1, ID_RSASSA_PSS},
    AssociatedOid,
};
use der::AnyRef;
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};
use rsa::{
    pkcs1::RsaPssParams, pkcs1v15::RsaSignatureAssociatedOid, traits::SignatureScheme,
    Pkcs1v15Sign, Pss, RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::marker::PhantomData;
use x509_cert::spki::AlgorithmIdentifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RsaPssAlgorithm;

impl RsaPssAlgorithm {
    const fn new() -> Self {
        Self
    }
}

impl VerificationAlgorithm for RsaPssAlgorithm {
    fn publickey_oid(&self) -> ObjectIdentifier {
        rsa::pkcs1::ALGORITHM_OID
    }

    fn signature_oid(&self) -> ObjectIdentifier {
        ID_RSASSA_PSS
    }

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        let alg: AlgorithmIdentifier<RsaPssParams> =
            identifiers::decode_algorithm_identifier(algorithm)
                .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithmIdentifier, Some(e)))?;
        assert_result(
            alg.oid,
            self.signature_oid(),
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;
        let pss_params = alg.parameters.unwrap_or_default();
        validate_pss_params(&pss_params)?;

        let salt_len = pss_params.salt_len as usize;
        match pss_params.hash.oid {
            <Sha256 as AssociatedOid>::OID => rsa_verify::<Sha256, _>(
                spki,
                Pss::new_with_salt::<Sha256>(salt_len),
                data,
                signature,
            ),
            <Sha384 as AssociatedOid>::OID => rsa_verify::<Sha384, _>(
                spki,
                Pss::new_with_salt::<Sha384>(salt_len),
                data,
                signature,
            ),
            <Sha512 as AssociatedOid>::OID => rsa_verify::<Sha512, _>(
                spki,
                Pss::new_with_salt::<Sha512>(salt_len),
                data,
                signature,
            ),
            _ => Err(PkixErrorKind::UnsupportedAlgorithm.into()),
        }
    }
}

fn validate_pss_params(pss_params: &RsaPssParams) -> PkixResult<()> {
    // The hash algorithm of the mask generation function should match the hash algorithm
    assert_result(
        Some(pss_params.hash),
        pss_params.mask_gen.parameters,
        PkixErrorKind::InvalidAlgorithmIdentifier,
    )?;
    assert_result(
        pss_params.mask_gen.oid,
        ID_MGF_1,
        PkixErrorKind::InvalidAlgorithmIdentifier,
    )?;
    assert_result(
        pss_params.hash.parameters,
        Some(AnyRef::NULL),
        PkixErrorKind::InvalidAlgorithmIdentifier,
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RsaPkcs1Algorithm<D>(PhantomData<D>);

impl<D> RsaPkcs1Algorithm<D> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<D> VerificationAlgorithm for RsaPkcs1Algorithm<D>
where
    D: Digest + AssociatedOid + RsaSignatureAssociatedOid,
{
    fn publickey_oid(&self) -> ObjectIdentifier {
        rsa::pkcs1::ALGORITHM_OID
    }

    fn signature_oid(&self) -> ObjectIdentifier {
        <D as RsaSignatureAssociatedOid>::OID
    }

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        let alg = identifiers::decode_algorithm_identifier(algorithm)
            .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithmIdentifier, Some(e)))?;
        assert_result(
            alg.oid,
            self.signature_oid(),
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;
        assert_result(
            alg.parameters,
            Some(AnyRef::NULL),
            PkixErrorKind::InvalidAlgorithmIdentifier,
        )?;

        rsa_verify::<D, _>(spki, Pkcs1v15Sign::new::<D>(), data, signature)
    }
}

fn rsa_verify<D, S>(
    spki: SubjectPublicKeyInfoRef<'_>,
    scheme: S,
    data: &[u8],
    signature: &[u8],
) -> PkixResult<()>
where
    S: SignatureScheme,
    D: Digest,
{
    let key = RsaPublicKey::try_from(spki)
        .map_err(|e| PkixError::new(PkixErrorKind::InvalidPublicKey, Some(e)))?;

    let mut hasher = D::new();
    Digest::update(&mut hasher, data);
    let hash = Digest::finalize(hasher);

    key.verify(scheme, hash.as_slice(), signature)
        .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))
}

pub const RSA_PSS: RsaPssAlgorithm = RsaPssAlgorithm::new();
assert_impl_all!(RsaPssAlgorithm: VerificationAlgorithm);

pub const RSA_PKCS1_SHA256: RsaPkcs1Algorithm<Sha256> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha256>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA384: RsaPkcs1Algorithm<Sha384> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha384>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA512: RsaPkcs1Algorithm<Sha512> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha512>: VerificationAlgorithm);
