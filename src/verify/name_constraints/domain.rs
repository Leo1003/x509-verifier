use std::{
    fmt::{Display, Formatter},
    ops::{Index, IndexMut},
    slice::SliceIndex,
    str::FromStr,
};

#[derive(Clone, Debug)]
pub struct Domain {
    is_fqdn: bool,
    parts: Vec<Label>,
}

impl Domain {
    pub fn is_fqdn(&self) -> bool {
        self.is_fqdn
    }

    pub fn parts(&self) -> impl Iterator<Item = &Label> {
        self.parts.iter()
    }

    pub fn parts_len(&self) -> usize {
        self.parts.len()
    }

    pub fn is_wildcard(&self) -> bool {
        self.parts
            .iter()
            .last()
            .map_or(false, |part| part.is_wildcard())
    }
}

impl FromStr for Domain {
    type Err = DomainError;

    fn from_str(domain_name: &str) -> Result<Self, Self::Err> {
        let (is_fqdn, s) = if let Some(s) = domain_name.strip_suffix('.') {
            (true, s)
        } else {
            (false, domain_name)
        };
        if s.len() > 253 {
            return Err(DomainError::DomainNameTooLong);
        }

        let parts = s
            .split('.')
            .map(Label::from_str)
            .rev()
            .collect::<Result<Vec<_>, _>>()?;
        // Only the first part can be wildcard
        if parts.iter().rev().skip(1).any(|part| part.is_wildcard()) {
            return Err(DomainError::InvalidWildcardPart);
        }
        Ok(Self { is_fqdn, parts })
    }
}

impl Display for Domain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, part) in self.parts.iter().rev().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", part)?;
        }
        if self.is_fqdn {
            write!(f, ".")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DomainSubtree {
    base: Domain,
    match_type: DomainSubtreeMatchType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainSubtreeMatchType {
    Exact,
    ZeroOrMoreLabels,
    OneOrMoreLabels,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label {
    len: usize,
    buffer: [u8; 63],
}

impl Label {
    fn from_slice(slice: &[u8]) -> Self {
        let mut buffer = [0; 63];
        buffer[..slice.len()].copy_from_slice(slice);
        Self {
            len: slice.len(),
            buffer,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_wildcard(&self) -> bool {
        self.len == 1 && self.buffer[0] == b'*'
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}
impl AsMut<[u8]> for Label {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.len]
    }
}
impl<I> Index<I> for Label
where
    I: SliceIndex<[u8]>,
{
    type Output = <I as SliceIndex<[u8]>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.buffer[..self.len][index]
    }
}
impl<I> IndexMut<I> for Label
where
    I: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: I) -> &mut <I as SliceIndex<[u8]>>::Output {
        &mut self.buffer[..self.len][index]
    }
}

impl PartialEq<str> for Label {
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other.as_bytes()
    }
}
impl PartialEq<[u8]> for Label {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_ref() == other
    }
}

impl FromStr for Label {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let c = s.as_bytes();
        if c.len() > 63 {
            return Err(DomainError::InvalidLabelLength);
        }

        if c == b"*" {
            return Ok(Self::from_slice(c));
        }

        let mut iter = c.iter().copied();
        let Some(first) = iter.next() else {
            return Err(DomainError::InvalidLabelLength);
        };
        if !is_label_letter(first) {
            return Err(DomainError::InvalidCharacter);
        }

        if let Some(last) = iter.next_back() {
            if !is_label_let_dig(last) {
                return Err(DomainError::InvalidCharacter);
            }
        }
        if iter.all(is_label_let_dig_hyp) {
            Ok(Self::from_slice(c))
        } else {
            Err(DomainError::InvalidCharacter)
        }
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.buffer[..self.len].escape_ascii())
    }
}

fn is_label_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

fn is_label_let_dig(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_label_let_dig_hyp(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

#[derive(Clone, Debug, Display, Error)]
pub enum DomainError {
    #[display("Invalid character in domain name")]
    InvalidCharacter,
    #[display("Domain name too long")]
    DomainNameTooLong,
    #[display("Invalid label length")]
    InvalidLabelLength,
    #[display("Invalid wildcard part")]
    InvalidWildcardPart,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_domain_parsing() {
        let domain = "example.com".parse::<Domain>().unwrap();
        assert!(!domain.is_fqdn());
        assert_eq!(domain.parts_len(), 2);
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["com", "example"]
        );

        let domain = "example.com.".parse::<Domain>().unwrap();
        assert!(domain.is_fqdn());
        assert_eq!(domain.parts_len(), 2);
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["com", "example"]
        );

        let domain = "*.example.com".parse::<Domain>().unwrap();
        assert!(!domain.is_fqdn());
        assert!(domain.is_wildcard());
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["com", "example", "*"]
        );

        let domain = "xn--fiq228c.xn--kpry57d.".parse::<Domain>().unwrap();
        assert!(domain.is_fqdn());
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["xn--kpry57d", "xn--fiq228c"]
        );

        let err = "123456.domain.invalid".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::InvalidCharacter));

        let err = "www-.domain.invalid".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::InvalidCharacter));

        let err = "server_1.domain.invalid".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::InvalidCharacter));

        let err = "www.*.invalid".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::InvalidWildcardPart));

        let err: DomainError = "www..domain.invalid.".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::InvalidLabelLength));

        let err = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.domain.invalid"
            .parse::<Domain>()
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidLabelLength));

        let domain = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com".parse::<Domain>().unwrap();
        assert!(!domain.is_fqdn());
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "com",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde"
            ]
        );

        let domain = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com.".parse::<Domain>().unwrap();
        assert!(domain.is_fqdn());
        assert_eq!(
            domain.parts().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "com",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde"
            ]
        );

        let err = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.invalid.".parse::<Domain>().unwrap_err();
        assert!(matches!(err, DomainError::DomainNameTooLong));
    }
}
