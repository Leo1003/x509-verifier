use super::{assert_result, identifiers, VerificationAlgorithm};
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use const_oid::{
    db::rfc5912::{ID_MGF_1, ID_RSASSA_PSS},
    AssociatedOid,
};
use der::{asn1::Null, AnyRef};
use pkcs8::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use rsa::{pkcs1::RsaPssParams, traits::SignatureScheme, Pkcs1v15Sign, Pss, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::marker::PhantomData;
use x509_cert::spki::{
    AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RsaPssAlgorithm;

impl RsaPssAlgorithm {
    const fn new() -> Self {
        Self
    }
}

impl AssociatedAlgorithmIdentifier for RsaPssAlgorithm {
    type Params = Null;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_RSA_ENCRYPTION;
}

impl VerificationAlgorithm for RsaPssAlgorithm {
    fn publickey_oid(&self) -> pkcs8::ObjectIdentifier {
        Self::ALGORITHM_IDENTIFIER.oid
    }

    fn signature_oid(&self) -> pkcs8::ObjectIdentifier {
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
                .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithm, Some(e)))?;
        assert_result(
            alg.oid,
            self.signature_oid(),
            PkixErrorKind::InvalidAlgorithm,
        )?;
        let pss_params = alg.parameters.unwrap_or_default();
        validate_pss_params(&pss_params)?;

        let salt_len = pss_params.salt_len as usize;
        match pss_params.hash.oid {
            Sha256::OID => rsa_verify::<Sha256, _>(
                spki,
                Pss::new_with_salt::<Sha256>(salt_len),
                data,
                signature,
            ),
            Sha384::OID => rsa_verify::<Sha384, _>(
                spki,
                Pss::new_with_salt::<Sha384>(salt_len),
                data,
                signature,
            ),
            Sha512::OID => rsa_verify::<Sha512, _>(
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
        PkixErrorKind::InvalidAlgorithm,
    )?;
    assert_result(
        pss_params.mask_gen.oid,
        ID_MGF_1,
        PkixErrorKind::InvalidAlgorithm,
    )?;
    assert_result(
        pss_params.hash.parameters,
        Some(AnyRef::NULL),
        PkixErrorKind::InvalidAlgorithm,
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

impl<D> AssociatedAlgorithmIdentifier for RsaPkcs1Algorithm<D> {
    type Params = Null;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = identifiers::ALG_RSA_ENCRYPTION;
}

impl SignatureAlgorithmIdentifier for RsaPkcs1Algorithm<Sha256> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA256_WITH_RSA_ENCRYPTION;
}
impl SignatureAlgorithmIdentifier for RsaPkcs1Algorithm<Sha384> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA384_WITH_RSA_ENCRYPTION;
}
impl SignatureAlgorithmIdentifier for RsaPkcs1Algorithm<Sha512> {
    type Params = Null;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        identifiers::ALG_SHA512_WITH_RSA_ENCRYPTION;
}

impl<D> VerificationAlgorithm for RsaPkcs1Algorithm<D>
where
    Self: AssociatedAlgorithmIdentifier + SignatureAlgorithmIdentifier<Params = Null>,
    D: Digest + AssociatedOid,
{
    fn publickey_oid(&self) -> pkcs8::ObjectIdentifier {
        Self::ALGORITHM_IDENTIFIER.oid
    }

    fn signature_oid(&self) -> pkcs8::ObjectIdentifier {
        Self::SIGNATURE_ALGORITHM_IDENTIFIER.oid
    }

    fn verify_signature(
        &self,
        spki: SubjectPublicKeyInfoRef<'_>,
        algorithm: AlgorithmIdentifierRef<'_>,
        data: &[u8],
        signature: &[u8],
    ) -> PkixResult<()> {
        if identifiers::decode_algorithm_identifier(algorithm)
            .map_err(|e| PkixError::new(PkixErrorKind::InvalidAlgorithm, Some(e)))?
            != Self::SIGNATURE_ALGORITHM_IDENTIFIER
        {
            return Err(PkixErrorKind::InvalidAlgorithm.into());
        }

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
        .map_err(|e| PkixError::new(PkixErrorKind::BadSignature, Some(e)))?;

    Ok(())
}

pub const RSA_PSS: RsaPssAlgorithm = RsaPssAlgorithm::new();
assert_impl_all!(RsaPssAlgorithm: VerificationAlgorithm);

pub const RSA_PKCS1_SHA256: RsaPkcs1Algorithm<Sha256> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha256>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA384: RsaPkcs1Algorithm<Sha384> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha384>: VerificationAlgorithm);

pub const RSA_PKCS1_SHA512: RsaPkcs1Algorithm<Sha512> = RsaPkcs1Algorithm::new();
assert_impl_all!(RsaPkcs1Algorithm<Sha512>: VerificationAlgorithm);
