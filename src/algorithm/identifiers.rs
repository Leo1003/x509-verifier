use const_oid::{
    db::{rfc5912::*, rfc8410::*},
    AssociatedOid, ObjectIdentifier,
};
use der::{asn1::Null, AnyRef, Choice, DecodeValue};
use digest::{typenum::Unsigned, OutputSizeUser};
use pkcs8::AlgorithmIdentifierRef;
use rsa::pkcs1::{RsaPssParams, TrailerField};
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::spki::AlgorithmIdentifier;

pub fn decode_algorithm_identifier<'a, T>(
    algorithm: AlgorithmIdentifierRef<'a>,
) -> der::Result<AlgorithmIdentifier<T>>
where
    T: Choice<'a> + DecodeValue<'a>,
{
    Ok(match algorithm.parameters {
        Some(parameter) => AlgorithmIdentifier {
            oid: algorithm.oid,
            parameters: Some(parameter.decode_as::<T>()?),
        },
        None => AlgorithmIdentifier {
            oid: algorithm.oid,
            parameters: None,
        },
    })
}

const fn pss_params<D>() -> RsaPssParams<'static>
where
    D: AssociatedOid + OutputSizeUser,
{
    RsaPssParams {
        hash: AlgorithmIdentifier {
            oid: D::OID,
            parameters: Some(AnyRef::NULL),
        },
        mask_gen: AlgorithmIdentifier {
            oid: ID_MGF_1,
            parameters: Some(AlgorithmIdentifier {
                oid: D::OID,
                parameters: Some(AnyRef::NULL),
            }),
        },
        salt_len: D::OutputSize::U8,
        trailer_field: TrailerField::BC,
    }
}

// Public key algorithms
pub const ALG_RSA_ENCRYPTION: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: RSA_ENCRYPTION,
    parameters: Some(Null),
};
pub const ALG_ECDSA_P256: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
    oid: ID_EC_PUBLIC_KEY,
    parameters: Some(SECP_256_R_1),
};
pub const ALG_ECDSA_P384: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
    oid: ID_EC_PUBLIC_KEY,
    parameters: Some(SECP_384_R_1),
};
pub const ALG_ECDSA_P521: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
    oid: ID_EC_PUBLIC_KEY,
    parameters: Some(SECP_521_R_1),
};

// Signature algorithms
pub const ALG_SHA256_WITH_RSA_ENCRYPTION: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: SHA_256_WITH_RSA_ENCRYPTION,
    parameters: Some(Null),
};
pub const ALG_SHA384_WITH_RSA_ENCRYPTION: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: SHA_384_WITH_RSA_ENCRYPTION,
    parameters: Some(Null),
};
pub const ALG_SHA512_WITH_RSA_ENCRYPTION: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: SHA_512_WITH_RSA_ENCRYPTION,
    parameters: Some(Null),
};
pub const ALG_SHA256_RSA_SSA_PSS: AlgorithmIdentifier<RsaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(pss_params::<Sha256>()),
};
pub const ALG_SHA384_RSA_SSA_PSS: AlgorithmIdentifier<RsaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(pss_params::<Sha384>()),
};
pub const ALG_SHA512_RSA_SSA_PSS: AlgorithmIdentifier<RsaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(pss_params::<Sha512>()),
};
pub const ALG_ECDSA_WITH_SHA256: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_256,
    parameters: None,
};
pub const ALG_ECDSA_WITH_SHA384: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_384,
    parameters: None,
};
pub const ALG_ECDSA_WITH_SHA512: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_512,
    parameters: None,
};
pub const ALG_ED25519: AlgorithmIdentifier<Null> = AlgorithmIdentifier {
    oid: ID_ED_25519,
    parameters: None,
};
