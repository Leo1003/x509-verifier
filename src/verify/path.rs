use crate::{traits::AsEntity, types::TrustAnchor};
use std::ops::{Add, Sub};
use x509_cert::{certificate, Certificate};

#[derive(Clone, Debug)]
pub struct CertificatePath<'a> {
    pub(crate) end_certificate: &'a Certificate,
    pub(crate) intermediates: Vec<&'a Certificate>,
    pub(crate) trust_anchor: &'a TrustAnchor,
}

#[derive(Clone, Debug)]
pub struct CertificateBuildingPath<'a> {
    pub(crate) end_certificate: &'a Certificate,
    pub(crate) intermediates: Vec<&'a Certificate>,
}

impl CertificateBuildingPath<'_> {
    pub fn with_end_certificate(end_certificate: &Certificate) -> CertificateBuildingPath<'_> {
        CertificateBuildingPath {
            end_certificate,
            intermediates: Vec::new(),
        }
    }

    pub fn head(&self) -> &Certificate {
        if let Some(cert) = self.intermediates.last() {
            cert
        } else {
            self.end_certificate
        }
    }

    pub fn find_entity<E>(&self, entity: &E) -> Option<&Certificate>
    where E: AsEntity {
        if self.end_certificate.subject() == entity.subject() && self.end_certificate.spki() == entity.spki() {
            Some(self.end_certificate)
        } else {
            self.intermediates.iter().copied().find(|cert| {
                cert.subject() == entity.subject() && cert.spki() == entity.spki()
            })
        }
    }
}

impl<'a> CertificateBuildingPath<'a> {
    pub fn push(&'a self, certificate: &'a Certificate) -> CertificateBuildingPath<'a> {
        CertificateBuildingPath {
            end_certificate: self.end_certificate,
            intermediates: self
                .intermediates
                .iter()
                .copied()
                .chain(Some(certificate))
                .collect(),
        }
    }

    pub fn complete(&'a self, trust_anchor: &'a TrustAnchor) -> CertificatePath<'a> {
        CertificatePath {
            end_certificate: self.end_certificate,
            intermediates: self.intermediates.clone(),
            trust_anchor,
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
