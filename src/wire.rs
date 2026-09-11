//! The OPC UA binary encoding (OPC 10000-6): little-endian integers, a
//! string and a byte string counted with a length that is minus one where
//! there is none, a node id in the shortest of its forms, a variant that
//! says its type in one byte, and the data value that wraps one with its
//! status and timestamps. Nothing here knows which service is speaking.

use std::time::{SystemTime, UNIX_EPOCH};

use transport::error::{Result, protocol_error};

use crate::node::NodeId;

/// A reader over one encoded buffer, moving forward and never past the end.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The bytes not yet taken.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    /// Exactly `count` bytes.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn fixed(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("an encoding cut short"))?;
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed(1)?[0])
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.fixed(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.fixed(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn i32(&mut self) -> Result<i32> {
        self.u32().map(u32::cast_signed)
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn i64(&mut self) -> Result<i64> {
        let b = self.fixed(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn f64(&mut self) -> Result<f64> {
        self.i64().map(|bits| f64::from_bits(bits.cast_unsigned()))
    }

    /// # Errors
    /// Where the buffer ends first.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// A counted byte string, `None` where the length is minus one.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn byte_string(&mut self) -> Result<Option<&'a [u8]>> {
        let length = self.i32()?;
        if length < 0 {
            return Ok(None);
        }
        self.fixed(usize::try_from(length).unwrap_or(0)).map(Some)
    }

    /// A counted string, `None` where there is none.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn string(&mut self) -> Result<Option<String>> {
        Ok(self
            .byte_string()?
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned()))
    }

    /// The count that opens an array, zero where it is minus one.
    ///
    /// # Errors
    /// Where the buffer ends first, or the count is absurd.
    pub fn count(&mut self) -> Result<usize> {
        let count = self.i32()?;
        if count < 0 {
            return Ok(0);
        }
        let count = usize::try_from(count).unwrap_or(0);
        if count > self.rest().len() {
            return Err(protocol_error("an array longer than its encoding"));
        }
        Ok(count)
    }

    /// A node id in any of its forms; a GUID or an opaque one is read and
    /// not carried.
    ///
    /// # Errors
    /// Where the buffer ends first or the form is unknown.
    pub fn node_id(&mut self) -> Result<NodeId> {
        match self.u8()? & 0x3f {
            0x00 => Ok(NodeId::numeric(0, u32::from(self.u8()?))),
            0x01 => {
                let namespace = u16::from(self.u8()?);
                Ok(NodeId::numeric(namespace, u32::from(self.u16()?)))
            }
            0x02 => Ok(NodeId::numeric(self.u16()?, self.u32()?)),
            0x03 => {
                let namespace = self.u16()?;
                Ok(NodeId::string(
                    namespace,
                    self.string()?.unwrap_or_default(),
                ))
            }
            0x04 => {
                self.u16()?;
                self.fixed(16)?;
                Ok(NodeId::numeric(0, 0))
            }
            0x05 => {
                self.u16()?;
                self.byte_string()?;
                Ok(NodeId::numeric(0, 0))
            }
            other => Err(protocol_error(format!("a node id of form {other:#04x}"))),
        }
    }

    /// Past a localized text.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn skip_localized_text(&mut self) -> Result<()> {
        let mask = self.u8()?;
        if mask & 0x01 != 0 {
            self.string()?;
        }
        if mask & 0x02 != 0 {
            self.string()?;
        }
        Ok(())
    }

    /// Past a diagnostic info, however deep it nests.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn skip_diagnostic_info(&mut self) -> Result<()> {
        let mask = self.u8()?;
        for bit in [0x01, 0x02, 0x04, 0x08] {
            if mask & bit != 0 {
                self.i32()?;
            }
        }
        if mask & 0x10 != 0 {
            self.string()?;
        }
        if mask & 0x20 != 0 {
            self.u32()?;
        }
        if mask & 0x40 != 0 {
            self.skip_diagnostic_info()?;
        }
        Ok(())
    }
}

pub fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_f64(out: &mut Vec<u8>, value: f64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

/// A counted byte string, or minus one for none.
pub fn put_byte_string(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            put_i32(out, i32::try_from(bytes.len()).unwrap_or(i32::MAX));
            out.extend_from_slice(bytes);
        }
        None => put_i32(out, -1),
    }
}

/// A counted string, or minus one for none.
pub fn put_string(out: &mut Vec<u8>, text: Option<&str>) {
    put_byte_string(out, text.map(str::as_bytes));
}

/// A localized text of `text` alone, no locale.
pub fn put_localized_text(out: &mut Vec<u8>, text: &str) {
    put_u8(out, 0x02);
    put_string(out, Some(text));
}

/// A diagnostic info with nothing in it.
pub fn put_no_diagnostic_info(out: &mut Vec<u8>) {
    put_u8(out, 0);
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
        put_u8(out, mask);
        if let Some(bytes) = &self.bytes {
            put_u8(out, BYTE_STRING);
            put_byte_string(out, Some(bytes));
        }
        if self.status != 0 {
            put_u32(out, self.status);
        }
        if let Some(stamp) = self.source_timestamp {
            put_i64(out, stamp);
        }
    }

    /// The data value at the reader.
    ///
    /// # Errors
    /// Where the buffer ends first, or the value is of a type that is not
    /// a byte string or a string — a Stream is bytes, and a number or a
    /// structure is a contract technology's to read.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let mask = reader.u8()?;
        let bytes = if mask & 0x01 == 0 {
            None
        } else {
            match reader.u8()? {
                BYTE_STRING | STRING => reader.byte_string()?.map(<[u8]>::to_vec),
                other => {
                    return Err(protocol_error(format!(
                        "a value of variant type {other}, and a Stream is a byte string"
                    )));
                }
            }
        };
        let status = if mask & 0x02 != 0 { reader.u32()? } else { 0 };
        let source_timestamp = if mask & 0x04 != 0 {
            Some(reader.i64()?)
        } else {
            None
        };
        if mask & 0x08 != 0 {
            reader.i64()?;
        }
        if mask & 0x10 != 0 {
            reader.u16()?;
        }
        if mask & 0x20 != 0 {
            reader.u16()?;
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
        put_u8(&mut out, 7);
        put_u16(&mut out, 300);
        put_u32(&mut out, 70_000);
        put_i32(&mut out, -2);
        put_i64(&mut out, -3);
        put_f64(&mut out, 1.5);
        put_bool(&mut out, true);
        put_byte_string(&mut out, Some(b"ab"));
        put_byte_string(&mut out, None);
        put_string(&mut out, Some("x"));
        put_localized_text(&mut out, "text");
        put_no_diagnostic_info(&mut out);
        let mut reader = Reader::new(&out);
        assert_eq!(reader.u8().expect("u8"), 7);
        assert_eq!(reader.u16().expect("u16"), 300);
        assert_eq!(reader.u32().expect("u32"), 70_000);
        assert_eq!(reader.i32().expect("i32"), -2);
        assert_eq!(reader.i64().expect("i64"), -3);
        assert!((reader.f64().expect("f64") - 1.5).abs() < f64::EPSILON);
        assert!(reader.bool().expect("bool"));
        assert_eq!(reader.byte_string().expect("bytes"), Some(&b"ab"[..]));
        assert_eq!(reader.byte_string().expect("none"), None);
        assert_eq!(reader.string().expect("string"), Some("x".to_string()));
        reader.skip_localized_text().expect("text");
        reader.skip_diagnostic_info().expect("diagnostic");
        assert!(reader.rest().is_empty());
        assert!(reader.u8().is_err(), "cut short");
        assert_eq!(Reader::new(&[0xff; 4]).count().expect("minus one"), 0);
        assert!(Reader::new(&[9, 0, 0, 0]).count().is_err(), "absurd");
    }

    #[test]
    fn a_data_value_carries_bytes_a_status_and_a_source_timestamp() {
        let value = DataValue::bytes(b"\0\xff");
        let mut out = Vec::new();
        value.put(&mut out);
        assert_eq!(out[0], 0x05);
        assert_eq!(
            DataValue::take(&mut Reader::new(&out)).expect("value"),
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
            DataValue::take(&mut Reader::new(&out)).expect("status"),
            bad
        );
        let mut text = vec![0x01, STRING];
        put_string(&mut text, Some("hi"));
        assert_eq!(
            DataValue::take(&mut Reader::new(&text))
                .expect("text")
                .bytes,
            Some(b"hi".to_vec())
        );
        let number = [0x01, 6, 1, 0, 0, 0];
        let error = DataValue::take(&mut Reader::new(&number)).expect_err("an Int32");
        assert!(error.message.contains("variant type 6"), "{error}");
        assert!(now() > EPOCH_1601);
    }
}
