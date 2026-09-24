//! The OPC UA connection protocol over TCP (OPC 10000-6 clause 7): a
//! message is three letters, whether it is final, its size and its body.
//! Hello and Acknowledge agree the buffers; Error says why the other side
//! is going; `OpenSecureChannel` carries the asymmetric security header —
//! the policy, which here is always None — and every message after it
//! carries the channel id, the token id and a sequence header. A message
//! longer than the far end's receive buffer crosses in chunks, each with
//! its own headers, the last marked final.

use std::io::{Read, Write};

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, TransportError, classify, protocol_error};

use crate::wire::{UaBinary, UaBinaryWrite};

/// The one security policy this crate speaks.
pub const NONE_POLICY: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
/// The protocol version every stack answers.
pub const PROTOCOL_VERSION: u32 = 0;

/// `HEL`.
pub const HELLO: [u8; 3] = *b"HEL";
/// `ACK`.
pub const ACKNOWLEDGE: [u8; 3] = *b"ACK";
/// `ERR`.
pub const ERROR: [u8; 3] = *b"ERR";
/// `OPN`.
pub const OPEN: [u8; 3] = *b"OPN";
/// `MSG`.
pub const MESSAGE: [u8; 3] = *b"MSG";
/// `CLO`.
pub const CLOSE: [u8; 3] = *b"CLO";

/// The bytes of a chunk that are not its body: the message header, the
/// channel id, the token id and the sequence header.
const CHUNK_OVERHEAD: usize = 24;
/// The smallest receive buffer the specification allows.
pub const MIN_BUFFER: u32 = 8_192;

/// What one side reads and sends: a chunk's size each way, the largest
/// message and the most chunks, zero for no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub receive_buffer: u32,
    pub send_buffer: u32,
    pub max_message: u32,
    pub max_chunks: u32,
}

impl Limits {
    /// Sixty-four kibibyte chunks, any message, any number of chunks.
    pub const DEFAULT: Self = Self {
        receive_buffer: 65_535,
        send_buffer: 65_535,
        max_message: 0,
        max_chunks: 0,
    };

    fn put(&self, out: &mut Vec<u8>) {
        out.u32_le(PROTOCOL_VERSION);
        out.u32_le(self.receive_buffer);
        out.u32_le(self.send_buffer);
        out.u32_le(self.max_message);
        out.u32_le(self.max_chunks);
    }

    fn take(reader: &mut Cursor<'_>) -> Result<Self> {
        reader.u32_le()?;
        let limits = Self {
            receive_buffer: reader.u32_le()?,
            send_buffer: reader.u32_le()?,
            max_message: reader.u32_le()?,
            max_chunks: reader.u32_le()?,
        };
        if limits.receive_buffer < MIN_BUFFER || limits.send_buffer < MIN_BUFFER {
            return Err(protocol_error(
                "a buffer under the eight kibibytes the protocol asks",
            ));
        }
        Ok(limits)
    }

    /// The largest body one chunk to a side with these limits carries.
    #[must_use]
    pub fn chunk_body(&self) -> usize {
        self.receive_buffer as usize - CHUNK_OVERHEAD
    }
}

/// Hello: the client's limits and the endpoint it wants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub limits: Limits,
    pub endpoint_url: String,
}

impl Hello {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.limits.put(&mut out);
        out.string(Some(&self.endpoint_url));
        out
    }

    /// # Errors
    /// Where the body is cut short or the limits are under the minimum.
    pub fn from_bytes(body: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(body);
        Ok(Self {
            limits: Limits::take(&mut reader)?,
            endpoint_url: reader.string()?.unwrap_or_default(),
        })
    }
}

/// Acknowledge: the server's limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acknowledge {
    pub limits: Limits,
}

impl Acknowledge {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.limits.put(&mut out);
        out
    }

    /// # Errors
    /// Where the body is cut short or the limits are under the minimum.
    pub fn from_bytes(body: &[u8]) -> Result<Self> {
        Ok(Self {
            limits: Limits::take(&mut Cursor::new(body))?,
        })
    }
}

/// Error: why the sender is closing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: u32,
    pub reason: String,
}

impl Fault {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.u32_le(self.code);
        out.string(Some(&self.reason));
        out
    }

    /// # Errors
    /// Where the body is cut short.
    pub fn from_bytes(body: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(body);
        Ok(Self {
            code: reader.u32_le()?,
            reason: reader.string()?.unwrap_or_default(),
        })
    }
}

/// Write one raw message: the kind, whether it is final, the size, the
/// body.
///
/// # Errors
/// Where the connection broke.
pub fn write_raw(writer: &mut impl Write, kind: [u8; 3], is_final: u8, body: &[u8]) -> Result<()> {
    let size = u32::try_from(body.len() + 8)
        .map_err(|_| protocol_error("a message longer than its size can say"))?;
    let mut message = Vec::with_capacity(body.len() + 8);
    message.extend_from_slice(&kind);
    message.push(is_final);
    message.u32_le(size);
    message.extend_from_slice(body);
    writer
        .write_all(&message)
        .and_then(|()| writer.flush())
        .map_err(|e| classify("writing a message", &e))
}

/// Read one raw message: its kind, whether it is final, and its body;
/// `None` where the connection closed cleanly before one began.
///
/// # Errors
/// Where the connection broke mid-message, or the message is over `max`.
pub fn read_raw(reader: &mut impl Read, max: usize) -> Result<Option<Raw>> {
    let mut head = [0u8; 8];
    match reader.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(classify("reading a message header", &e)),
    }
    let size = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
    if size < 8 || size - 8 > max {
        return Err(protocol_error(format!("a message of {size} bytes")));
    }
    let mut body = vec![0u8; size - 8];
    reader
        .read_exact(&mut body)
        .map_err(|e| classify("reading a message body", &e))?;
    Ok(Some(([head[0], head[1], head[2]], head[3], body)))
}

/// Read one raw message, which must be there.
///
/// # Errors
/// Where the connection closed or broke, or the message is over `max`.
pub fn expect_raw(reader: &mut impl Read, max: usize) -> Result<Raw> {
    read_raw(reader, max)?.ok_or_else(|| protocol_error("the other side closed the connection"))
}

/// One raw message: its kind, whether it is final, and its body.
pub type Raw = ([u8; 3], u8, Vec<u8>);

/// One message of the secure conversation, its security and sequence
/// headers taken off: an `OPN`, a `MSG` or a `CLO`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secure {
    pub kind: [u8; 3],
    pub channel_id: u32,
    pub token_id: u32,
    pub sequence: u32,
    pub request_id: u32,
    pub body: Vec<u8>,
}

/// Write `message` in chunks whose bodies fit `chunk`, each numbered
/// from its sequence on; the sequence after the last chunk comes back.
///
/// # Errors
/// Where the connection broke.
pub fn write_secure(writer: &mut impl Write, message: &Secure, chunk: usize) -> Result<u32> {
    let mut sequence = message.sequence;
    let chunk = chunk.max(1);
    let count = message.body.len().div_ceil(chunk).max(1);
    for (index, body) in message
        .body
        .chunks(chunk)
        .chain(std::iter::once(&[][..]).take(usize::from(message.body.is_empty())))
        .enumerate()
    {
        let mut out = Vec::with_capacity(body.len() + 64);
        out.u32_le(message.channel_id);
        if message.kind == OPEN {
            out.string(Some(NONE_POLICY));
            out.byte_string(None);
            out.byte_string(None);
        } else {
            out.u32_le(message.token_id);
        }
        out.u32_le(sequence);
        out.u32_le(message.request_id);
        out.extend_from_slice(body);
        let is_final = if index + 1 == count { b'F' } else { b'C' };
        write_raw(writer, message.kind, is_final, &out)?;
        sequence = sequence.wrapping_add(1);
    }
    Ok(sequence)
}

/// Read one secure message, chunk by chunk until the final one; an `ERR`
/// on the way is the error it names, and `None` is a connection closed
/// cleanly before a message began.
///
/// # Errors
/// Where the connection broke, the message is over `max`, the other side
/// sent an error or aborted, or the policy is not None.
pub fn read_secure(reader: &mut impl Read, max: usize) -> Result<Option<Secure>> {
    let mut message: Option<Secure> = None;
    loop {
        let Some((kind, is_final, raw)) = read_raw(reader, max)? else {
            if message.is_some() {
                return Err(protocol_error("the connection closed mid-message"));
            }
            return Ok(None);
        };
        if kind == ERROR {
            let fault = Fault::from_bytes(&raw)?;
            return Err(TransportError::permanent(format!(
                "the other side closed with {:#010x}: {}",
                fault.code, fault.reason
            )));
        }
        if kind != OPEN && kind != MESSAGE && kind != CLOSE {
            return Err(protocol_error(format!(
                "{} where a secure message was expected",
                String::from_utf8_lossy(&kind)
            )));
        }
        if is_final == b'A' {
            return Err(protocol_error("the other side aborted the message"));
        }
        let mut chunk = Cursor::new(&raw);
        let channel_id = chunk.u32_le()?;
        let token_id = if kind == OPEN {
            let policy = chunk.string()?.unwrap_or_default();
            if policy != NONE_POLICY {
                return Err(TransportError::permanent(format!(
                    "security policy {policy}, and this crate speaks None"
                )));
            }
            chunk.byte_string()?;
            chunk.byte_string()?;
            0
        } else {
            chunk.u32_le()?
        };
        let sequence = chunk.u32_le()?;
        let request_id = chunk.u32_le()?;
        let so_far = message.get_or_insert_with(|| Secure {
            kind,
            channel_id,
            token_id,
            sequence,
            request_id,
            body: Vec::new(),
        });
        if so_far.request_id != request_id || so_far.kind != kind {
            return Err(protocol_error(
                "a chunk of another message in the middle of this one",
            ));
        }
        if so_far.body.len() + chunk.remaining().len() > max {
            return Err(protocol_error(format!(
                "a message over the {max} bytes read here"
            )));
        }
        so_far.body.extend_from_slice(chunk.remaining());
        if is_final == b'F' {
            return Ok(message);
        }
    }
}

/// Read one secure message, which must be there.
///
/// # Errors
/// As [`read_secure`], and where the connection closed.
pub fn expect_secure(reader: &mut impl Read, max: usize) -> Result<Secure> {
    read_secure(reader, max)?.ok_or_else(|| protocol_error("the other side closed the connection"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_acknowledge_and_error_read_back_and_a_small_buffer_is_refused() {
        let hello = Hello {
            limits: Limits::DEFAULT,
            endpoint_url: "opc.tcp://localhost:4840/xmip".to_string(),
        };
        assert_eq!(Hello::from_bytes(&hello.to_bytes()).expect("hello"), hello);
        let ack = Acknowledge {
            limits: Limits::DEFAULT,
        };
        assert_eq!(Acknowledge::from_bytes(&ack.to_bytes()).expect("ack"), ack);
        let fault = Fault {
            code: 0x8080_0000,
            reason: "too large".to_string(),
        };
        assert_eq!(Fault::from_bytes(&fault.to_bytes()).expect("fault"), fault);
        let small = Acknowledge {
            limits: Limits {
                receive_buffer: 100,
                ..Limits::DEFAULT
            },
        };
        assert!(Acknowledge::from_bytes(&small.to_bytes()).is_err());
        assert_eq!(Limits::DEFAULT.chunk_body(), 65_535 - 24);
    }

    #[test]
    fn a_long_message_crosses_in_chunks_and_an_error_on_the_way_is_the_error() {
        let message = Secure {
            kind: MESSAGE,
            channel_id: 7,
            token_id: 8,
            sequence: 50,
            request_id: 9,
            body: (0..10_000u32).map(|n| (n % 251) as u8).collect(),
        };
        let mut wire = Vec::new();
        let next = write_secure(&mut wire, &message, 4_000).expect("written");
        assert_eq!(next, 53, "three chunks");
        assert_eq!(
            expect_secure(&mut &wire[..], 1 << 20).expect("read"),
            message
        );
        assert!(read_secure(&mut &wire[..], 5_000).is_err(), "over max");
        assert!(
            read_secure(&mut &wire[..100], 1 << 20).is_err(),
            "cut mid-message"
        );
        let empty = Secure {
            body: Vec::new(),
            kind: CLOSE,
            ..message.clone()
        };
        let mut wire = Vec::new();
        assert_eq!(write_secure(&mut wire, &empty, 4_000).expect("written"), 51);
        assert_eq!(expect_secure(&mut &wire[..], 1 << 20).expect("read"), empty);
        let open = Secure {
            kind: OPEN,
            token_id: 0,
            body: b"open".to_vec(),
            ..message
        };
        let mut wire = Vec::new();
        write_secure(&mut wire, &open, 4_000).expect("written");
        assert_eq!(expect_secure(&mut &wire[..], 1 << 20).expect("read"), open);
        let mut wire = Vec::new();
        write_raw(
            &mut wire,
            ERROR,
            b'F',
            &Fault {
                code: 1,
                reason: "no".into(),
            }
            .to_bytes(),
        )
        .expect("written");
        let error = read_secure(&mut &wire[..], 1 << 20).expect_err("an error");
        assert!(error.message.contains("0x00000001: no"), "{error}");
        let mut wire = Vec::new();
        write_raw(&mut wire, MESSAGE, b'A', &[0; 16]).expect("written");
        assert!(read_secure(&mut &wire[..], 1 << 20).is_err(), "aborted");
        let mut wire = Vec::new();
        write_raw(&mut wire, HELLO, b'F', &[]).expect("written");
        assert!(read_secure(&mut &wire[..], 1 << 20).is_err(), "not secure");
        assert_eq!(read_raw(&mut &wire[..0], 64).expect("closed"), None);
        assert!(expect_raw(&mut &wire[..0], 64).is_err(), "closed");
    }
}
