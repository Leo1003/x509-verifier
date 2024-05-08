use std::{
    ops::{Add, Sub},
    time::SystemTime,
};
use x509_cert::{ext::pkix::BasicConstraints, Certificate};

use crate::{
    certpool::CertificatePool,
    error::{PkixErrorKind, PkixResult},
};

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

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum PathLenRequirement {
    #[default]
    EndEntity,
    Ca(usize),
}

impl Add<usize> for PathLenRequirement {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        match self {
            Self::EndEntity => {
                if let Some(l) = rhs.checked_sub(1) {
                    Self::Ca(l)
                } else {
                    Self::EndEntity
                }
            }
            Self::Ca(n) => Self::Ca(n.saturating_add(rhs)),
        }
    }
}

impl Sub<usize> for PathLenRequirement {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            Self::EndEntity => Self::EndEntity,
            Self::Ca(n) => {
                if let Some(l) = n.checked_sub(rhs) {
                    Self::Ca(l)
                } else {
                    Self::EndEntity
                }
            }
        }
    }
}

pub fn verify_cert_chain(
    cert_pool: &CertificatePool,
    certificate: &Certificate,
    options: &VerifyOptions,
) -> PkixResult<()> {
    verify_recursive(
        cert_pool,
        certificate,
        options,
        PathLenRequirement::EndEntity,
    )
}

fn verify_recursive(
    cert_pool: &CertificatePool,
    certificate: &Certificate,
    options: &VerifyOptions,
    path_req: PathLenRequirement,
) -> PkixResult<()> {
    // Check the certificate itself
    check_certificate(certificate, options, path_req)?;

    Ok(())
}

fn check_certificate(
    cert: &Certificate,
    options: &VerifyOptions,
    path_req: PathLenRequirement,
) -> PkixResult<()> {
    // TODO: Check no unknown critical extensions
    // TODO: Check key usage
    // TODO: Check extended key usage

    check_basic_constraints(cert, path_req)?;
    check_validty(cert, options.time)?;

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
