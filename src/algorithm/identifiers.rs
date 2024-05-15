use const_oid::{
    db::{rfc5912::*, rfc8410::*},
    ObjectIdentifier,
};
use x509_cert::{
    der::{asn1::Null, Sequence},
    spki::AlgorithmIdentifier,
};

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RsassaPssParams {
    #[asn1(default = "Self::default_hash_algorithm")]
    pub hash_algorithm: AlgorithmIdentifier<Null>,
    #[asn1(default = "Self::default_mask_gen_algorithm")]
    pub mask_gen_algorithm: AlgorithmIdentifier<AlgorithmIdentifier<Null>>,
    #[asn1(default = "Self::default_salt_length")]
    pub salt_length: u32,
    #[asn1(default = "Self::default_trailer_field")]
    pub trailer_field: u32,
}

impl RsassaPssParams {
    fn default_hash_algorithm() -> AlgorithmIdentifier<Null> {
        AlgorithmIdentifier {
            oid: ID_SHA_1,
            parameters: Some(Null),
        }
    }

    fn default_mask_gen_algorithm() -> AlgorithmIdentifier<AlgorithmIdentifier<Null>> {
        AlgorithmIdentifier {
            oid: ID_MGF_1,
            parameters: Some(Self::default_hash_algorithm()),
        }
    }

    fn default_salt_length() -> u32 {
        20
    }

    fn default_trailer_field() -> u32 {
        1
    }
}

impl Default for RsassaPssParams {
    fn default() -> Self {
        Self {
            hash_algorithm: Self::default_hash_algorithm(),
            mask_gen_algorithm: Self::default_mask_gen_algorithm(),
            salt_length: Self::default_salt_length(),
            trailer_field: Self::default_trailer_field(),
        }
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
pub const ALG_SHA256_RSA_SSA_PSS: AlgorithmIdentifier<RsassaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(RsassaPssParams {
        hash_algorithm: AlgorithmIdentifier {
            oid: ID_SHA_256,
            parameters: Some(Null),
        },
        mask_gen_algorithm: AlgorithmIdentifier {
            oid: ID_MGF_1,
            parameters: Some(AlgorithmIdentifier {
                oid: ID_SHA_256,
                parameters: Some(Null),
            }),
        },
        salt_length: 32,
        trailer_field: 1,
    }),
};
pub const ALG_SHA384_RSA_SSA_PSS: AlgorithmIdentifier<RsassaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(RsassaPssParams {
        hash_algorithm: AlgorithmIdentifier {
            oid: ID_SHA_384,
            parameters: Some(Null),
        },
        mask_gen_algorithm: AlgorithmIdentifier {
            oid: ID_MGF_1,
            parameters: Some(AlgorithmIdentifier {
                oid: ID_SHA_384,
                parameters: Some(Null),
            }),
        },
        salt_length: 48,
        trailer_field: 1,
    }),
};
pub const ALG_SHA512_RSA_SSA_PSS: AlgorithmIdentifier<RsassaPssParams> = AlgorithmIdentifier {
    oid: ID_RSASSA_PSS,
    parameters: Some(RsassaPssParams {
        hash_algorithm: AlgorithmIdentifier {
            oid: ID_SHA_512,
            parameters: Some(Null),
        },
        mask_gen_algorithm: AlgorithmIdentifier {
            oid: ID_MGF_1,
            parameters: Some(AlgorithmIdentifier {
                oid: ID_SHA_512,
                parameters: Some(Null),
            }),
        },
        salt_length: 64,
        trailer_field: 1,
    }),
};
pub const ALG_ECDSA_WITH_SHA256: AlgorithmIdentifier<()> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_256,
    parameters: None,
};
pub const ALG_ECDSA_WITH_SHA384: AlgorithmIdentifier<()> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_384,
    parameters: None,
};
pub const ALG_ECDSA_WITH_SHA512: AlgorithmIdentifier<()> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_512,
    parameters: None,
};
pub const ALG_ED25519: AlgorithmIdentifier<()> = AlgorithmIdentifier {
    oid: ID_ED_25519,
    parameters: None,
};
