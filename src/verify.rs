use self::{
    key_usage::CaProfile,
    path::{CertificateBuildingPath, CertificatePath, PathLenRequirement},
};
use crate::{
    algorithm::*,
    certpool::CertificatePool,
    error::{PkixError, PkixErrorKind, PkixResult},
    traits::{AsEntity, KeyUsagesVerifier},
    types::CertificateKeyUsages,
};
use const_oid::ObjectIdentifier;
use der::{referenced::OwnedToRef, Encode};
use pkcs8::AssociatedOid;
use time::PrimitiveDateTime;
use x509_cert::{
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    Certificate,
};

pub mod key_usage;
mod options;
mod path;

pub use options::VerifyOptions;

#[rustfmt::skip]
// Currently known extension OIDs,
// remember to update this list after supporting more extensions
const KNOWN_EXTENSION_OIDS: [ObjectIdentifier; 3] = [
    BasicConstraints::OID,
    KeyUsage::OID,
    ExtendedKeyUsage::OID,
];

pub fn verify_cert_chain(
    cert_pool: &CertificatePool,
    certificate: &Certificate,
    options: &VerifyOptions,
    key_usages_verifier: &dyn KeyUsagesVerifier,
) -> PkixResult<()> {
    cert_path_building(
        cert_pool,
        &CertificateBuildingPath::with_end_certificate(certificate),
        options,
        PathLenRequirement::EndEntity,
        key_usages_verifier,
    )
}

fn cert_path_building(
    cert_pool: &CertificatePool,
    cert_path: &CertificateBuildingPath,
    options: &VerifyOptions,
    path_req: PathLenRequirement,
    kus_verifier: &dyn KeyUsagesVerifier,
) -> PkixResult<()> {
    // Check the certificate itself
    check_certificate(cert_path.head(), options, path_req, kus_verifier)?;

    let mut current_error: PkixError = PkixErrorKind::UnknownIssuer.into();
    let issuer = &cert_path.head().tbs_certificate.issuer;

    // Check the possibility to go directly to a trust anchor
    for ta in cert_pool.find_trustanchors_by_subject(issuer) {
        let path = cert_path.complete(ta);

        match cert_path_verifying(&path) {
            Ok(()) => return Ok(()),
            Err(e) => current_error.merge(e),
        }
    }

    // Find next certificates
    for next_cert in cert_pool.find_intermediate_by_subject(issuer) {
        // RFC 4158 Section 5.2 Loop Detection
        if cert_path.find_entity(next_cert).is_some() {
            // Skip the certificate if it would form a loop
            continue;
        }
        let next_path = cert_path.push(next_cert);

        match cert_path_building(
            cert_pool,
            &next_path,
            options,
            path_req + 1,
            &CaProfile::default(),
        ) {
            Ok(()) => return Ok(()),
            Err(e) => current_error.merge(e),
        }
    }

    Err(current_error)
}

fn cert_path_verifying(cert_path: &CertificatePath) -> PkixResult<()> {
    // TODO: Check name constraints

    let mut entity: &dyn AsEntity = cert_path.trust_anchor;
    for cert in cert_path
        .intermediates
        .iter()
        .copied()
        .rev()
        .chain(Some(cert_path.end_certificate))
    {
        verify_signature(cert, entity)?;
        entity = cert;
    }

    Ok(())
}

fn check_certificate(
    cert: &Certificate,
    options: &VerifyOptions,
    path_req: PathLenRequirement,
    kus_verifier: &dyn KeyUsagesVerifier,
) -> PkixResult<()> {
    check_critical_extensions(cert)?;
    check_basic_constraints(cert, path_req)?;
    check_validty(cert, options)?;
    check_kus(cert, kus_verifier)?;

    Ok(())
}

fn check_critical_extensions(cert: &Certificate) -> PkixResult<()> {
    for ext in cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|ext| ext.critical)
    {
        // TODO: Let user add their own known extensions
        if !KNOWN_EXTENSION_OIDS.contains(&ext.extn_id) {
            return Err(PkixErrorKind::UnknownCriticalExtension.into());
        }
    }
    Ok(())
}

fn check_basic_constraints(cert: &Certificate, path_req: PathLenRequirement) -> PkixResult<()> {
    let basic_constraints = cert
        .tbs_certificate
        .get::<BasicConstraints>()?
        .map(|crit_ext| crit_ext.1)
        // If the certificate does not contain a basic constraints extension,
        // treat it as a leaf certificate.
        .unwrap_or(BasicConstraints {
            ca: false,
            path_len_constraint: None,
        });

    match path_req {
        PathLenRequirement::EndEntity => {
            if basic_constraints.ca {
                return Err(PkixErrorKind::BasicConstraintsViolated.into());
            }
        }
        PathLenRequirement::Ca(required_path_len) => {
            if !(basic_constraints.ca
                && basic_constraints
                    .path_len_constraint
                    .map_or(true, |path_len| path_len as usize >= required_path_len))
            {
                return Err(PkixErrorKind::BasicConstraintsViolated.into());
            }
        }
    }
    Ok(())
}

fn check_validty(cert: &Certificate, options: &VerifyOptions) -> PkixResult<()> {
    let not_before =
        PrimitiveDateTime::try_from(cert.tbs_certificate.validity.not_before.to_date_time())?
            .assume_utc();
    let not_after =
        PrimitiveDateTime::try_from(cert.tbs_certificate.validity.not_after.to_date_time())?
            .assume_utc();
    if not_before > not_after {
        return Err(PkixErrorKind::InvalidValidity.into());
    }

    // Since it is common to encounter expired certificates,
    // provide an option to bypass the validity check when debugging/fixing the issues.
    //
    // But the invalid validity check above is always performed
    // since it is the basic requirement of a valid certificate.
    if !options.insecure_bypass_validity_check() {
        let time = options.verify_time();
        if time < not_before {
            return Err(PkixErrorKind::CertificateNotYetValid.into());
        }
        if time > not_after {
            return Err(PkixErrorKind::CertificateExpired.into());
        }
    }

    Ok(())
}

fn check_kus(cert: &Certificate, verifier: &dyn KeyUsagesVerifier) -> PkixResult<()> {
    let kus = CertificateKeyUsages::try_from(cert)?;

    if verifier.verify_key_usages(cert, &kus) {
        Ok(())
    } else {
        Err(PkixErrorKind::KeyUsageViolated.into())
    }
}

fn verify_signature<E>(cert: &Certificate, issuer: &E) -> PkixResult<()>
where
    E: AsEntity + ?Sized,
{
    let algorithms: [&dyn VerificationAlgorithm; 8] = [
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
        &RSA_PSS,
        &ECDSA_SHA256,
        &ECDSA_SHA384,
        &ECDSA_SHA512,
        &ED25519,
    ];

    let mut error = PkixErrorKind::UnsupportedAlgorithm.into();

    for algorithm in algorithms.iter() {
        if algorithm.publickey_oid() == issuer.spki().algorithm.oid
            && algorithm.signature_oid() == cert.signature_algorithm.oid
        {
            let data = cert.tbs_certificate.to_der()?;
            match algorithm.verify_signature(
                issuer.spki().owned_to_ref(),
                cert.signature_algorithm.owned_to_ref(),
                &data,
                cert.signature
                    .as_bytes()
                    .ok_or(PkixErrorKind::BadSignature)?,
            ) {
                Ok(()) => return Ok(()),
                Err(e) => match e.kind() {
                    PkixErrorKind::InvalidAlgorithm | PkixErrorKind::UnsupportedAlgorithm => {
                        error = e
                    }
                    _ => return Err(e),
                },
            }
        }
    }

    Err(error)
}
