//! The identifier of one node in one namespace (OPC 10000-3 clause 8.2):
//! numeric or a string, written in the shortest of the binary encoding's
//! forms and read in any of them, and parsed from and printed in the
//! `ns=2;s=Orders` text every OPC UA tool writes.

use std::fmt;

use transport::error::{Result, protocol_error};

use crate::wire::{put_string, put_u8, put_u16, put_u32};

/// The identifier of one node in one namespace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeId {
    Numeric { namespace: u16, id: u32 },
    String { namespace: u16, id: String },
}

impl NodeId {
    #[must_use]
    pub const fn numeric(namespace: u16, id: u32) -> Self {
        Self::Numeric { namespace, id }
    }

    #[must_use]
    pub fn string(namespace: u16, id: impl Into<String>) -> Self {
        Self::String {
            namespace,
            id: id.into(),
        }
    }

    /// `ns=2;s=Orders`, `ns=1;i=5` or `i=2253`, as OPC UA writes them.
    ///
    /// # Errors
    /// Where the text is not one of those.
    pub fn parse(text: &str) -> Result<Self> {
        let wrong = || protocol_error(format!("{text:?} is not ns=<n>;s=<name> or ns=<n>;i=<n>"));
        let (namespace, rest) = match text.strip_prefix("ns=") {
            Some(rest) => {
                let (namespace, rest) = rest.split_once(';').ok_or_else(wrong)?;
                (namespace.parse::<u16>().map_err(|_| wrong())?, rest)
            }
            None => (0, text),
        };
        if let Some(id) = rest.strip_prefix("i=") {
            return Ok(Self::numeric(namespace, id.parse().map_err(|_| wrong())?));
        }
        rest.strip_prefix("s=")
            .map(|id| Self::string(namespace, id))
            .ok_or_else(wrong)
    }

    /// Append this node id in the shortest form that carries it.
    pub fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Numeric { namespace: 0, id } if *id < 256 => {
                put_u8(out, 0x00);
                put_u8(out, u8::try_from(*id).unwrap_or(u8::MAX));
            }
            Self::Numeric { namespace, id } if *namespace < 256 && *id < 65_536 => {
                put_u8(out, 0x01);
                put_u8(out, u8::try_from(*namespace).unwrap_or(u8::MAX));
                put_u16(out, u16::try_from(*id).unwrap_or(u16::MAX));
            }
            Self::Numeric { namespace, id } => {
                put_u8(out, 0x02);
                put_u16(out, *namespace);
                put_u32(out, *id);
            }
            Self::String { namespace, id } => {
                put_u8(out, 0x03);
                put_u16(out, *namespace);
                put_string(out, Some(id));
            }
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Numeric { namespace: 0, id } => write!(f, "i={id}"),
            Self::Numeric { namespace, id } => write!(f, "ns={namespace};i={id}"),
            Self::String { namespace, id } => write!(f, "ns={namespace};s={id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    #[test]
    fn a_node_id_takes_its_shortest_form_and_reads_back() {
        for (text, first_byte) in [
            ("i=84", 0x00),
            ("ns=1;i=5", 0x01),
            ("ns=300;i=5", 0x02),
            ("ns=2;s=Orders", 0x03),
        ] {
            let node = NodeId::parse(text).expect(text);
            let mut out = Vec::new();
            node.put(&mut out);
            assert_eq!(out[0], first_byte, "{text}");
            assert_eq!(Reader::new(&out).node_id().expect("read"), node);
            assert_eq!(node.to_string(), text);
        }
        assert!(NodeId::parse("ns=x;i=1").is_err());
        assert!(NodeId::parse("Orders").is_err());
        assert!(NodeId::parse("ns=1").is_err());
        let mut guid = vec![0x04, 0, 0];
        guid.extend_from_slice(&[9; 16]);
        assert_eq!(
            Reader::new(&guid).node_id().expect("guid"),
            NodeId::numeric(0, 0)
        );
        assert!(Reader::new(&[0x09]).node_id().is_err());
    }
}
