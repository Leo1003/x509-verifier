use std::net::IpAddr;

use der::asn1::OctetString;
use ipnetwork::IpNetwork;

use crate::error::{PkixError, PkixErrorKind, PkixResult};

use super::SubtreeMatch;

#[derive(Clone, Debug)]
pub struct IpAddressSubtree {
    network: IpNetwork,
}

impl IpAddressSubtree {
    pub fn network(&self) -> IpNetwork {
        self.network
    }

    pub fn match_name(&self, name: &OctetString) -> PkixResult<SubtreeMatch> {
        let name_address_bytes = name.as_bytes();
        let name_address = bytes_to_address(name_address_bytes)?;

        if self.network.contains(name_address) {
            Ok(SubtreeMatch::Match)
        } else {
            Ok(SubtreeMatch::Mismatch)
        }
    }
}

impl TryFrom<OctetString> for IpAddressSubtree {
    type Error = PkixError;

    fn try_from(constraint: OctetString) -> PkixResult<Self> {
        let constraint_bytes = constraint.as_bytes();

        let (constraint_address_bytes, constraint_mask_bytes) =
            constraint_bytes.split_at(constraint_bytes.len() / 2);

        let constraint_address = bytes_to_address(constraint_address_bytes)?;
        let constraint_mask = bytes_to_address(constraint_mask_bytes)?;

        // The constraint_address and constraint_mask should be both IPv4 or both IPv6.
        let constraint_network = IpNetwork::with_netmask(constraint_address, constraint_mask)
            .map_err(|e| PkixError::new(PkixErrorKind::InvalidIpAddressConstraints, Some(e)))?;

        Ok(Self {
            network: constraint_network,
        })
    }
}

pub(crate) fn bytes_to_address(bytes: &[u8]) -> PkixResult<IpAddr> {
    let v4_addr = TryInto::<[u8; 4]>::try_into(bytes).map(IpAddr::from);
    let v6_addr = TryInto::<[u8; 16]>::try_into(bytes).map(IpAddr::from);
    v4_addr
        .or(v6_addr)
        .map_err(|e| PkixError::new(PkixErrorKind::InvalidIpAddressConstraints, Some(e)))
}
