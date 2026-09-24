//! The OPC UA binary encoding (OPC 10000-6): little-endian integers
//! (codec's `*_le`), a string and a byte string counted with a length that
//! is minus one where there is none, a node id in the shortest of its
//! forms, a variant that says its type in one byte, and the data value that
//! wraps one with its status and timestamps. What is UA Binary's own is
//! written here over codec's cursor and writer; nothing here knows which
//! service is speaking.

use std::time::{SystemTime, UNIX_EPOCH};

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::node::NodeId;

/// Reading UA Binary's own fields off codec's cursor.
pub trait UaBinary<'a> {
    /// A boolean: one byte, zero false.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn bool(&mut self) -> Result<bool>;

    /// A counted byte string, `None` where the length is minus one.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn byte_string(&mut self) -> Result<Option<&'a [u8]>>;

    /// A counted string, `None` where there is none.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn string(&mut self) -> Result<Option<String>>;

    /// The count that opens an array, zero where it is minus one.
    ///
    /// # Errors
    /// Where the buffer ends first, or the count is absurd.
    fn count(&mut self) -> Result<usize>;

    /// A node id in any of its forms; a GUID or an opaque one is read and
    /// not carried.
    ///
    /// # Errors
    /// Where the buffer ends first or the form is unknown.
    fn node_id(&mut self) -> Result<NodeId>;

    /// Past a localized text.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn skip_localized_text(&mut self) -> Result<()>;

    /// Past a diagnostic info, however deep it nests.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn skip_diagnostic_info(&mut self) -> Result<()>;
}

impl<'a> UaBinary<'a> for Cursor<'a> {
    fn bool(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    fn byte_string(&mut self) -> Result<Option<&'a [u8]>> {
        let length = self.i32_le()?;
        if length < 0 {
            return Ok(None);
        }
        Ok(Some(self.take(usize::try_from(length).unwrap_or(0))?))
    }

    fn string(&mut self) -> Result<Option<String>> {
        Ok(self
            .byte_string()?
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned()))
    }

    fn count(&mut self) -> Result<usize> {
        let count = self.i32_le()?;
        if count < 0 {
            return Ok(0);
        }
        let count = usize::try_from(count).unwrap_or(0);
        if count > self.remaining().len() {
            return Err(protocol_error("an array longer than its encoding"));
        }
        Ok(count)
    }

    fn node_id(&mut self) -> Result<NodeId> {
        match self.byte()? & 0x3f {
            0x00 => Ok(NodeId::numeric(0, u32::from(self.byte()?))),
            0x01 => {
                let namespace = u16::from(self.byte()?);
                Ok(NodeId::numeric(namespace, u32::from(self.u16_le()?)))
            }
            0x02 => Ok(NodeId::numeric(self.u16_le()?, self.u32_le()?)),
            0x03 => {
                let namespace = self.u16_le()?;
                Ok(NodeId::string(
                    namespace,
                    self.string()?.unwrap_or_default(),
                ))
            }
            0x04 => {
                self.u16_le()?;
                self.skip(16)?;
                Ok(NodeId::numeric(0, 0))
            }
            0x05 => {
                self.u16_le()?;
                self.byte_string()?;
                Ok(NodeId::numeric(0, 0))
            }
            other => Err(protocol_error(format!("a node id of form {other:#04x}"))),
        }
    }

    fn skip_localized_text(&mut self) -> Result<()> {
        let mask = self.byte()?;
        if mask & 0x01 != 0 {
            self.string()?;
        }
        if mask & 0x02 != 0 {
            self.string()?;
        }
        Ok(())
    }

    fn skip_diagnostic_info(&mut self) -> Result<()> {
        let mask = self.byte()?;
        for bit in [0x01, 0x02, 0x04, 0x08] {
            if mask & bit != 0 {
                self.i32_le()?;
            }
        }
        if mask & 0x10 != 0 {
            self.string()?;
        }
        if mask & 0x20 != 0 {
            self.u32_le()?;
        }
        if mask & 0x40 != 0 {
            self.skip_diagnostic_info()?;
        }
        Ok(())
    }
}

/// Writing UA Binary's own fields beside codec's [`ByteWriter`].
pub trait UaBinaryWrite {
    /// A boolean: one byte.
    fn bool(&mut self, value: bool) -> &mut Self;

    /// A counted byte string, or minus one for none.
    fn byte_string(&mut self, bytes: Option<&[u8]>) -> &mut Self;

    /// A counted string, or minus one for none.
    fn string(&mut self, text: Option<&str>) -> &mut Self;

    /// A localized text of `text` alone, no locale.
    fn localized_text(&mut self, text: &str) -> &mut Self;

    /// A diagnostic info with nothing in it.
    fn no_diagnostic_info(&mut self) -> &mut Self;
}

impl UaBinaryWrite for Vec<u8> {
    fn bool(&mut self, value: bool) -> &mut Self {
        self.byte(u8::from(value))
    }

    fn byte_string(&mut self, bytes: Option<&[u8]>) -> &mut Self {
        match bytes {
            Some(bytes) => self
                .i32_le(i32::try_from(bytes.len()).unwrap_or(i32::MAX))
                .bytes(bytes),
            None => self.i32_le(-1),
        }
    }

    fn string(&mut self, text: Option<&str>) -> &mut Self {
        self.byte_string(text.map(str::as_bytes))
    }

    fn localized_text(&mut self, text: &str) -> &mut Self {
        self.byte(0x02).string(Some(text))
    }

    fn no_diagnostic_info(&mut self) -> &mut Self {
        self.byte(0)
    }
}

/// The variant type a Stream travels as.
const BYTE_STRING: u8 = 15;
/// The variant type a text value has.
const STRING: u8 = 12;

/// A value with its source timestamp, as a data value carries it: the
/// bytes of a byte string or a string, or nothing where the value is
/// null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataValue {
    pub bytes: Option<Vec<u8>>,
    pub status: u32,
    pub source_timestamp: Option<i64>,
}

impl DataValue {
    /// `bytes` as a byte string, good, stamped now.
    #[must_use]
    pub fn bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: Some(bytes.to_vec()),
            status: 0,
            source_timestamp: Some(now()),
        }
    }

    /// Append this value: the variant, the status where not good, the
    /// source timestamp where there is one.
    pub fn put(&self, out: &mut Vec<u8>) {
        let mut mask = 0u8;
        if self.bytes.is_some() {
            mask |= 0x01;
        }
        if self.status != 0 {
            mask |= 0x02;
        }
        if self.source_timestamp.is_some() {
            mask |= 0x04;
        }
        out.byte(mask);
        if let Some(bytes) = &self.bytes {
            out.byte(BYTE_STRING).byte_string(Some(bytes));
        }
        if self.status != 0 {
            out.u32_le(self.status);
        }
        if let Some(stamp) = self.source_timestamp {
            out.i64_le(stamp);
        }
    }

    /// The data value at the cursor.
    ///
    /// # Errors
    /// Where the buffer ends first, or the value is of a type that is not
    /// a byte string or a string — a Stream is bytes, and a number or a
    /// structure is a contract technology's to read.
    pub fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        let mask = reader.byte()?;
        let bytes = if mask & 0x01 == 0 {
            None
        } else {
            match reader.byte()? {
                BYTE_STRING | STRING => reader.byte_string()?.map(<[u8]>::to_vec),
                other => {
                    return Err(protocol_error(format!(
                        "a value of variant type {other}, and a Stream is a byte string"
                    )));
                }
            }
        };
        let status = if mask & 0x02 != 0 {
            reader.u32_le()?
        } else {
            0
        };
        let source_timestamp = if mask & 0x04 != 0 {
            Some(reader.i64_le()?)
        } else {
            None
        };
        if mask & 0x08 != 0 {
            reader.i64_le()?;
        }
        if mask & 0x10 != 0 {
            reader.u16_le()?;
        }
        if mask & 0x20 != 0 {
            reader.u16_le()?;
        }
        Ok(Self {
            bytes,
            status,
            source_timestamp,
        })
    }
}

/// The offset of 1601-01-01 from 1970-01-01 in hundred-nanosecond ticks.
const EPOCH_1601: i64 = 116_444_736_000_000_000;

/// Now, as an OPC UA `DateTime`: hundred-nanosecond ticks since 1601.
#[must_use]
pub fn now() -> i64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() / 100);
    i64::try_from(since).unwrap_or(i64::MAX - EPOCH_1601) + EPOCH_1601
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_primitive_reads_back_and_none_is_minus_one() {
        let mut out = Vec::new();
        out.byte(7)
            .u16_le(300)
            .u32_le(70_000)
            .i32_le(-2)
            .i64_le(-3)
            .f64_le(1.5)
            .bool(true)
            .byte_string(Some(b"ab"))
            .byte_string(None)
            .string(Some("x"))
            .localized_text("text")
            .no_diagnostic_info();
        let mut reader = Cursor::new(&out);
        assert_eq!(reader.byte().expect("u8"), 7);
        assert_eq!(reader.u16_le().expect("u16"), 300);
        assert_eq!(reader.u32_le().expect("u32"), 70_000);
        assert_eq!(reader.i32_le().expect("i32"), -2);
        assert_eq!(reader.i64_le().expect("i64"), -3);
        assert!((reader.f64_le().expect("f64") - 1.5).abs() < f64::EPSILON);
        assert!(reader.bool().expect("bool"));
        assert_eq!(reader.byte_string().expect("bytes"), Some(&b"ab"[..]));
        assert_eq!(reader.byte_string().expect("none"), None);
        assert_eq!(reader.string().expect("string"), Some("x".to_string()));
        reader.skip_localized_text().expect("text");
        reader.skip_diagnostic_info().expect("diagnostic");
        assert!(reader.remaining().is_empty());
        assert!(reader.byte().is_err(), "cut short");
        assert_eq!(Cursor::new(&[0xff; 4]).count().expect("minus one"), 0);
        assert!(Cursor::new(&[9, 0, 0, 0]).count().is_err(), "absurd");
        let error = Cursor::new(&[9, 0, 0, 0, 1])
            .byte_string()
            .expect_err("cut short");
        assert!(!error.retryable);
        assert!(error.message.contains("runs past"), "{error}");
    }

    #[test]
    fn a_data_value_carries_bytes_a_status_and_a_source_timestamp() {
        let value = DataValue::bytes(b"\0\xff");
        let mut out = Vec::new();
        value.put(&mut out);
        assert_eq!(out[0], 0x05);
        assert_eq!(
            DataValue::take(&mut Cursor::new(&out)).expect("value"),
            value
        );
        let bad = DataValue {
            bytes: None,
            status: 0x8034_0000,
            source_timestamp: None,
        };
        let mut out = Vec::new();
        bad.put(&mut out);
        assert_eq!(
            DataValue::take(&mut Cursor::new(&out)).expect("status"),
            bad
        );
        let mut text = vec![0x01, STRING];
        text.string(Some("hi"));
        assert_eq!(
            DataValue::take(&mut Cursor::new(&text))
                .expect("text")
                .bytes,
            Some(b"hi".to_vec())
        );
        let number = [0x01, 6, 1, 0, 0, 0];
        let error = DataValue::take(&mut Cursor::new(&number)).expect_err("an Int32");
        assert!(error.message.contains("variant type 6"), "{error}");
        assert!(now() > EPOCH_1601);
    }
}
