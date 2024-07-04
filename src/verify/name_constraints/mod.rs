use self::ip_address::IpAddressSubtree;
use crate::error::{PkixError, PkixErrorKind, PkixResult};
use x509_cert::ext::pkix::{constraints::name::GeneralSubtree, name::GeneralName};

mod domain;
mod ip_address;

pub type ParsedSubtrees = Vec<ParsedSubtree>;

#[derive(Clone, Debug)]
pub enum ParsedSubtree {
    IpAddress(IpAddressSubtree),
}

impl ParsedSubtree {
    pub fn match_name(&self, name: &GeneralName) -> PkixResult<SubtreeMatch> {
        match (self, name) {
            (ParsedSubtree::IpAddress(subtree), GeneralName::IpAddress(name)) => {
                subtree.match_name(name)
            }
            _ => Ok(SubtreeMatch::NameFormMismatch),
        }
    }
}

impl TryFrom<GeneralSubtree> for ParsedSubtree {
    type Error = PkixError;

    fn try_from(subtree: GeneralSubtree) -> PkixResult<Self> {
        // RFC 5280 section 4.2.1.10
        //
        // Within this profile, the minimum and maximum fields are not used with
        // any name forms, thus, the minimum MUST be zero, and maximum MUST be
        // absent.
        if !(subtree.minimum == 0 && subtree.maximum.is_none()) {
            return Err(PkixErrorKind::InvalidSubtree.into());
        }

        match subtree.base {
            GeneralName::Rfc822Name(_) => unimplemented!(),
            GeneralName::DnsName(_) => unimplemented!(),
            GeneralName::DirectoryName(_) => unimplemented!(),
            GeneralName::UniformResourceIdentifier(_) => unimplemented!(),
            GeneralName::IpAddress(constraint) => Ok(ParsedSubtree::IpAddress(
                IpAddressSubtree::try_from(constraint)?,
            )),
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubtreeMatch {
    Match = 2,
    Mismatch = 1,
    NameFormMismatch = 0,
}

pub fn subtrees_match(subtrees: &ParsedSubtrees, name: &GeneralName) -> PkixResult<SubtreeMatch> {
    let mut result = SubtreeMatch::NameFormMismatch;
    for subtree in subtrees {
        // The enum implement the Ord trait.
        // And only higher rank result can override the lowerv.
        result = result.max(subtree.match_name(name)?);
    }

    Ok(result)
}
