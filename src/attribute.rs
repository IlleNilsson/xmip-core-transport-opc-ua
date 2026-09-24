//! The attribute services a Stream takes (OPC 10000-4 clause 5.10): a
//! Read of one node's value attribute, with its source timestamp asked
//! for, and a Write of one, each answered with its one result.

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::node::NodeId;
use crate::service::{RequestHeader, ResponseHeader, body};
use crate::wire::{DataValue, UaBinary, UaBinaryWrite};

/// `ReadRequest_Encoding_DefaultBinary`.
pub const READ_REQUEST: u32 = 631;
/// `ReadResponse_Encoding_DefaultBinary`.
pub const READ_RESPONSE: u32 = 634;
/// `WriteRequest_Encoding_DefaultBinary`.
pub const WRITE_REQUEST: u32 = 673;
/// `WriteResponse_Encoding_DefaultBinary`.
pub const WRITE_RESPONSE: u32 = 676;

/// The attribute a Stream is: `Value`.
pub const VALUE_ATTRIBUTE: u32 = 13;

/// `ReadRequest` for one node's value, source timestamp asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub header: RequestHeader,
    pub node: NodeId,
}

impl Read {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(READ_REQUEST);
        self.header.put(&mut out);
        out.f64_le(0.0);
        out.u32_le(0);
        out.i32_le(1);
        self.node.put(&mut out);
        out.u32_le(VALUE_ATTRIBUTE);
        out.string(None);
        out.u16_le(0);
        out.string(None);
        out
    }

    /// # Errors
    /// Where the request is cut short, reads more than one node, or an
    /// attribute other than the value.
    pub fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        let header = RequestHeader::take(reader)?;
        reader.f64_le()?;
        reader.u32_le()?;
        if reader.count()? != 1 {
            return Err(protocol_error("a read of other than one node"));
        }
        let node = reader.node_id()?;
        if reader.u32_le()? != VALUE_ATTRIBUTE {
            return Err(protocol_error(
                "a read of an attribute other than the value",
            ));
        }
        Ok(Self { header, node })
    }
}

/// `ReadResponse` with one result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResult {
    pub header: ResponseHeader,
    pub value: DataValue,
}

impl ReadResult {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(READ_RESPONSE);
        self.header.put(&mut out);
        out.i32_le(1);
        self.value.put(&mut out);
        out.i32_le(0);
        out
    }

    /// # Errors
    /// Where the response is cut short or carries other than one result.
    pub fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        let header = ResponseHeader::take(reader)?;
        if reader.count()? != 1 {
            return Err(protocol_error("a read answered with other than one result"));
        }
        let value = DataValue::take(reader)?;
        Ok(Self { header, value })
    }
}

/// `WriteRequest` of one node's value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    pub header: RequestHeader,
    pub node: NodeId,
    pub value: DataValue,
}

impl Write {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(WRITE_REQUEST);
        self.header.put(&mut out);
        out.i32_le(1);
        self.node.put(&mut out);
        out.u32_le(VALUE_ATTRIBUTE);
        out.string(None);
        self.value.put(&mut out);
        out
    }

    /// # Errors
    /// Where the request is cut short, writes more than one node, an
    /// attribute other than the value, or a value that is not bytes.
    pub fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        let header = RequestHeader::take(reader)?;
        if reader.count()? != 1 {
            return Err(protocol_error("a write of other than one node"));
        }
        let node = reader.node_id()?;
        if reader.u32_le()? != VALUE_ATTRIBUTE {
            return Err(protocol_error(
                "a write of an attribute other than the value",
            ));
        }
        reader.string()?;
        let value = DataValue::take(reader)?;
        Ok(Self {
            header,
            node,
            value,
        })
    }
}

/// `WriteResponse` with one result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteResult {
    pub header: ResponseHeader,
    pub status: u32,
}

impl WriteResult {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(WRITE_RESPONSE);
        self.header.put(&mut out);
        out.i32_le(1);
        out.u32_le(self.status);
        out.i32_le(0);
        out
    }

    /// # Errors
    /// Where the response is cut short or carries other than one result.
    pub fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        let header = ResponseHeader::take(reader)?;
        if reader.count()? != 1 {
            return Err(protocol_error(
                "a write answered with other than one result",
            ));
        }
        let status = reader.u32_le()?;
        Ok(Self { header, status })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{BAD_TYPE_MISMATCH, GOOD, type_of};

    fn request() -> RequestHeader {
        RequestHeader {
            token: NodeId::numeric(0, 0),
            timestamp: 1,
            handle: 3,
            timeout_hint: 10_000,
        }
    }

    #[test]
    fn a_read_and_a_write_of_one_value_read_back_and_more_is_refused() {
        let node = NodeId::string(2, "Orders");
        let read = Read {
            header: request(),
            node: node.clone(),
        };
        let bytes = read.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, READ_REQUEST);
        assert_eq!(Read::take(&mut reader).expect("read"), read);
        let result = ReadResult {
            header: ResponseHeader::new(3, GOOD),
            value: DataValue::bytes(b"ISA*00*"),
        };
        let bytes = result.to_bytes();
        let (_, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(ReadResult::take(&mut reader).expect("result"), result);
        let write = Write {
            header: request(),
            node,
            value: DataValue::bytes(&[0, 0xff]),
        };
        let bytes = write.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, WRITE_REQUEST);
        assert_eq!(Write::take(&mut reader).expect("write"), write);
        let result = WriteResult {
            header: ResponseHeader::new(3, GOOD),
            status: BAD_TYPE_MISMATCH,
        };
        let bytes = result.to_bytes();
        let (_, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(WriteResult::take(&mut reader).expect("result"), result);
        let mut two = body(READ_REQUEST);
        request().put(&mut two);
        two.f64_le(0.0);
        two.u32_le(0);
        two.i32_le(2);
        let bytes = two;
        let (_, mut reader) = type_of(&bytes).expect("type");
        assert!(Read::take(&mut reader).is_err());
    }
}
