use self::{
    key_usage::CaProfile,
    path::{CertificateBuildingPath, CertificatePath, PathLenRequirement},
};
use crate::{
    algorithm::*,
    certpool::CertificatePool,
    error::{PkixErrorKind, PkixResult},
    traits::{AsEntity, KeyUsagesVerifier},
    types::CertificateKeyUsages,
};
use der::{referenced::OwnedToRef, Encode};
use std::time::SystemTime;
use x509_cert::{ext::pkix::BasicConstraints, Certificate};

pub mod key_usage;
mod path;

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub time: SystemTime,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            time: SystemTime::now(),
        }
    }
}

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

    for path in find_paths_to_trustanchor(cert_pool, cert_path)? {
        match cert_path_verifying(&path) {
            Ok(()) => return Ok(()),
            // TODO: Return error
            Err(_) => continue,
        }
    }

    for next_path in find_paths_to_intermediate(cert_pool, cert_path)? {
        match cert_path_building(
            cert_pool,
            &next_path,
            options,
            path_req + 1,
            &CaProfile::default(),
        ) {
            Ok(()) => return Ok(()),
            // TODO: Return error
            Err(_) => continue,
        }
    }

    Err(PkixErrorKind::UnknownIssuer.into())
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
    // TODO: Check no unknown critical extensions

    check_basic_constraints(cert, path_req)?;
    check_validty(cert, options.time)?;
    check_kus(cert, kus_verifier)?;

    Ok(())
}

fn find_paths_to_trustanchor<'a>(
    cert_pool: &'a CertificatePool,
    cert_path: &'a CertificateBuildingPath,
) -> PkixResult<impl Iterator<Item = CertificatePath<'a>>> {
    let issuer = &cert_path.head().tbs_certificate.issuer;

    Ok(cert_pool
        .trust_anchors
        .iter()
        .filter(|ta| ta.subject == *issuer)
        .map(|ta| cert_path.complete(ta)))
}

fn find_paths_to_intermediate<'a>(
    cert_pool: &'a CertificatePool,
    cert_path: &'a CertificateBuildingPath,
) -> PkixResult<impl Iterator<Item = CertificateBuildingPath<'a>>> {
    let issuer = &cert_path.head().tbs_certificate.issuer;

    Ok(cert_pool
        .intermediate_certs
        .iter()
        .filter(|cert| cert.tbs_certificate.subject == *issuer)
        // RFC 4158 Section 5.2 Loop Detection
        .filter(|cert| cert_path.find_entity(*cert).is_none())
        .map(|cert| cert_path.push(cert)))
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

fn check_validty(cert: &Certificate, time: SystemTime) -> PkixResult<()> {
    // Currently, we use SystemTime for checking, but it had its limitations.
    let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
    let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

    if not_before > not_after {
        return Err(PkixErrorKind::InvalidValidity.into());
    }
    if time < not_before {
        return Err(PkixErrorKind::CertificateNotYetValid.into());
    }
    if time > not_after {
        return Err(PkixErrorKind::CertificateExpired.into());
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
