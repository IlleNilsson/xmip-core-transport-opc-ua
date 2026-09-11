//! The services a Stream takes (OPC 10000-4): the request header every
//! call carries and the response header every answer carries, the secure
//! channel opened and closed, a Read and a Write of one node's value
//! attribute, and the fault a server answers a call it will not run. A
//! body opens with the node id of what it is; the ids are the numeric
//! ones of the default binary encoding.

use transport::error::{Result, TransportError, protocol_error};

use crate::node::NodeId;
use crate::wire::{self, Reader};

/// `OpenSecureChannelRequest_Encoding_DefaultBinary`.
pub const OPEN_CHANNEL_REQUEST: u32 = 446;
/// `OpenSecureChannelResponse_Encoding_DefaultBinary`.
pub const OPEN_CHANNEL_RESPONSE: u32 = 449;
/// `CloseSecureChannelRequest_Encoding_DefaultBinary`.
pub const CLOSE_CHANNEL_REQUEST: u32 = 452;
/// `ServiceFault_Encoding_DefaultBinary`.
pub const SERVICE_FAULT: u32 = 397;

/// `Good`.
pub const GOOD: u32 = 0;
/// `Bad_ServiceUnsupported`.
pub const BAD_SERVICE_UNSUPPORTED: u32 = 0x800B_0000;
/// `Bad_SecureChannelIdInvalid`.
pub const BAD_SECURE_CHANNEL_ID_INVALID: u32 = 0x8022_0000;
/// `Bad_SessionIdInvalid`.
pub const BAD_SESSION_ID_INVALID: u32 = 0x8025_0000;
/// `Bad_SessionNotActivated`.
pub const BAD_SESSION_NOT_ACTIVATED: u32 = 0x8027_0000;
/// `Bad_IdentityTokenRejected`.
pub const BAD_IDENTITY_TOKEN_REJECTED: u32 = 0x8021_0000;
/// `Bad_NodeIdUnknown`.
pub const BAD_NODE_ID_UNKNOWN: u32 = 0x8034_0000;
/// `Bad_TypeMismatch`.
pub const BAD_TYPE_MISMATCH: u32 = 0x8074_0000;
/// `Bad_TcpEndpointUrlInvalid`.
pub const BAD_ENDPOINT_URL_INVALID: u32 = 0x8083_0000;
/// `Bad_TcpMessageTooLarge`.
pub const BAD_MESSAGE_TOO_LARGE: u32 = 0x8080_0000;
/// `Bad_ServerNotConnected`, a transient the client may retry.
pub const BAD_SERVER_NOT_CONNECTED: u32 = 0x8095_0000;

/// The failure a status code names, for a message: retryable where the
/// server said it is busy or not yet up.
#[must_use]
pub fn status_error(what: &str, code: u32) -> TransportError {
    let name = match code {
        BAD_SERVICE_UNSUPPORTED => "the service is not supported",
        BAD_SECURE_CHANNEL_ID_INVALID => "no such secure channel",
        BAD_SESSION_ID_INVALID => "no such session",
        BAD_SESSION_NOT_ACTIVATED => "the session is not activated",
        BAD_IDENTITY_TOKEN_REJECTED => "the identity token was rejected",
        BAD_NODE_ID_UNKNOWN => "no such node",
        BAD_TYPE_MISMATCH => "the value is not of the node's type",
        BAD_ENDPOINT_URL_INVALID => "no such endpoint",
        BAD_MESSAGE_TOO_LARGE => "the message is too large",
        BAD_SERVER_NOT_CONNECTED => "the server is not connected",
        0x8000_0000..=0xBFFF_FFFF => "a bad status",
        _ => "an uncertain status",
    };
    let message = format!("{what}: status {code:#010x}, {name}");
    if matches!(code, BAD_SERVER_NOT_CONNECTED | 0x8004_0000 | 0x8005_0000) {
        TransportError::retryable(message)
    } else {
        TransportError::permanent(message)
    }
}

/// What every request opens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    /// The session's authentication token; null before there is one.
    pub token: NodeId,
    pub timestamp: i64,
    pub handle: u32,
    pub timeout_hint: u32,
}

impl RequestHeader {
    /// A header for `handle` now, `token` in hand, hinting `timeout_hint`
    /// milliseconds.
    #[must_use]
    pub fn new(token: NodeId, handle: u32, timeout_hint: u32) -> Self {
        Self {
            token,
            timestamp: wire::now(),
            handle,
            timeout_hint,
        }
    }

    pub fn put(&self, out: &mut Vec<u8>) {
        self.token.put(out);
        wire::put_i64(out, self.timestamp);
        wire::put_u32(out, self.handle);
        wire::put_u32(out, 0);
        wire::put_string(out, None);
        wire::put_u32(out, self.timeout_hint);
        NodeId::numeric(0, 0).put(out);
        wire::put_u8(out, 0);
    }

    /// # Errors
    /// Where the header is cut short.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let token = reader.node_id()?;
        let timestamp = reader.i64()?;
        let handle = reader.u32()?;
        reader.u32()?;
        reader.string()?;
        let timeout_hint = reader.u32()?;
        reader.node_id()?;
        if reader.u8()? != 0 {
            return Err(protocol_error("a request with an additional header"));
        }
        Ok(Self {
            token,
            timestamp,
            handle,
            timeout_hint,
        })
    }
}

/// What every response opens with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    pub timestamp: i64,
    pub handle: u32,
    pub result: u32,
}

impl ResponseHeader {
    /// An answer to `handle` now, with `result`.
    #[must_use]
    pub fn new(handle: u32, result: u32) -> Self {
        Self {
            timestamp: wire::now(),
            handle,
            result,
        }
    }

    pub fn put(&self, out: &mut Vec<u8>) {
        wire::put_i64(out, self.timestamp);
        wire::put_u32(out, self.handle);
        wire::put_u32(out, self.result);
        wire::put_no_diagnostic_info(out);
        wire::put_i32(out, 0);
        NodeId::numeric(0, 0).put(out);
        wire::put_u8(out, 0);
    }

    /// # Errors
    /// Where the header is cut short.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let timestamp = reader.i64()?;
        let handle = reader.u32()?;
        let result = reader.u32()?;
        reader.skip_diagnostic_info()?;
        for _ in 0..reader.count()? {
            reader.string()?;
        }
        reader.node_id()?;
        if reader.u8()? != 0 {
            return Err(protocol_error("a response with an additional header"));
        }
        Ok(Self {
            timestamp,
            handle,
            result,
        })
    }
}

/// A body opened with the node id of `type_id`.
#[must_use]
pub fn body(type_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    NodeId::numeric(0, type_id).put(&mut out);
    out
}

/// The type a body is, and a reader over what follows.
///
/// # Errors
/// Where the body does not open with a numeric node id of namespace 0.
pub fn type_of(bytes: &[u8]) -> Result<(u32, Reader<'_>)> {
    let mut reader = Reader::new(bytes);
    match reader.node_id()? {
        NodeId::Numeric { namespace: 0, id } => Ok((id, reader)),
        other => Err(protocol_error(format!("a body of type {other}"))),
    }
}

/// `OpenSecureChannelRequest`: issue a token for a channel with security
/// mode None, for `requested_lifetime` milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenChannel {
    pub header: RequestHeader,
    pub requested_lifetime: u32,
}

impl OpenChannel {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(OPEN_CHANNEL_REQUEST);
        self.header.put(&mut out);
        wire::put_u32(&mut out, crate::channel::PROTOCOL_VERSION);
        wire::put_u32(&mut out, 0);
        wire::put_u32(&mut out, 1);
        wire::put_byte_string(&mut out, None);
        wire::put_u32(&mut out, self.requested_lifetime);
        out
    }

    /// # Errors
    /// Where the request is cut short, renews rather than issues, or asks
    /// for a security mode other than None.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let header = RequestHeader::take(reader)?;
        reader.u32()?;
        if reader.u32()? != 0 {
            return Err(protocol_error("a token renewal, and this side issues only"));
        }
        if reader.u32()? != 1 {
            return Err(protocol_error("a security mode other than None"));
        }
        reader.byte_string()?;
        Ok(Self {
            header,
            requested_lifetime: reader.u32()?,
        })
    }
}

/// `OpenSecureChannelResponse`: the channel and its token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOpened {
    pub header: ResponseHeader,
    pub channel_id: u32,
    pub token_id: u32,
    pub lifetime: u32,
}

impl ChannelOpened {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(OPEN_CHANNEL_RESPONSE);
        self.header.put(&mut out);
        wire::put_u32(&mut out, crate::channel::PROTOCOL_VERSION);
        wire::put_u32(&mut out, self.channel_id);
        wire::put_u32(&mut out, self.token_id);
        wire::put_i64(&mut out, self.header.timestamp);
        wire::put_u32(&mut out, self.lifetime);
        wire::put_byte_string(&mut out, None);
        out
    }

    /// # Errors
    /// Where the response is cut short.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let header = ResponseHeader::take(reader)?;
        reader.u32()?;
        let channel_id = reader.u32()?;
        let token_id = reader.u32()?;
        reader.i64()?;
        let lifetime = reader.u32()?;
        reader.byte_string()?;
        Ok(Self {
            header,
            channel_id,
            token_id,
            lifetime,
        })
    }
}

/// `CloseSecureChannelRequest`: the header alone.
#[must_use]
pub fn close_channel(header: &RequestHeader) -> Vec<u8> {
    let mut out = body(CLOSE_CHANNEL_REQUEST);
    header.put(&mut out);
    out
}

/// `ServiceFault`: the header alone, its result the fault.
#[must_use]
pub fn fault(header: &ResponseHeader) -> Vec<u8> {
    let mut out = body(SERVICE_FAULT);
    header.put(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RequestHeader {
        RequestHeader {
            token: NodeId::numeric(0, 0),
            timestamp: 1,
            handle: 3,
            timeout_hint: 10_000,
        }
    }

    #[test]
    fn the_channel_services_read_back_and_a_body_says_its_type() {
        let open = OpenChannel {
            header: request(),
            requested_lifetime: 60_000,
        };
        let bytes = open.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, OPEN_CHANNEL_REQUEST);
        assert_eq!(OpenChannel::take(&mut reader).expect("open"), open);
        let opened = ChannelOpened {
            header: ResponseHeader::new(3, GOOD),
            channel_id: 1,
            token_id: 2,
            lifetime: 60_000,
        };
        let bytes = opened.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, OPEN_CHANNEL_RESPONSE);
        assert_eq!(ChannelOpened::take(&mut reader).expect("opened"), opened);
        let bytes = close_channel(&request());
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, CLOSE_CHANNEL_REQUEST);
        assert_eq!(RequestHeader::take(&mut reader).expect("header"), request());
        let bytes = fault(&ResponseHeader::new(3, BAD_NODE_ID_UNKNOWN));
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, SERVICE_FAULT);
        assert_eq!(
            ResponseHeader::take(&mut reader).expect("header").result,
            BAD_NODE_ID_UNKNOWN
        );
        let mut string_typed = Vec::new();
        NodeId::string(2, "x").put(&mut string_typed);
        assert!(type_of(&string_typed).is_err());
    }

    #[test]
    fn a_status_names_its_failure_and_a_server_not_up_is_retryable() {
        let error = status_error("reading", BAD_NODE_ID_UNKNOWN);
        assert_eq!(error.message, "reading: status 0x80340000, no such node");
        assert!(!error.retryable);
        assert!(status_error("connecting", BAD_SERVER_NOT_CONNECTED).retryable);
        assert!(
            status_error("x", 0x8099_0000)
                .message
                .ends_with("a bad status")
        );
        assert!(
            status_error("x", 0x4000_0000)
                .message
                .ends_with("an uncertain status")
        );
    }
}
