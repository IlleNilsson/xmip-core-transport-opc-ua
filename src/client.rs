//! Xmip's side of one connection to an OPC UA server: Hello and the
//! Acknowledge, a secure channel under policy None, a session created and
//! activated anonymously, then a Read or a Write of one node's value, and
//! the session and channel closed behind it.

use std::io::BufReader;
use std::net::TcpStream;
use std::time::Duration;

use transport::error::{Result, protocol_error};
use transport::socket;
use transport::wire::MAX_BODY;

use crate::attribute;
use crate::attribute::{Read, ReadResult, Write, WriteResult};
use crate::channel::{self, Acknowledge, Hello, Limits, Secure};
use crate::endpoint::{self, ActivateSession, CreateSession, SessionCreated};
use crate::node::NodeId;
use crate::service::{self, ChannelOpened, GOOD, OpenChannel, RequestHeader, ResponseHeader};
use crate::wire::{DataValue, Reader};

/// How long a channel token and a session are asked for, in milliseconds.
const LIFETIME: u32 = 3_600_000;
/// What a call hints the server it will wait, in milliseconds.
const TIMEOUT_HINT: u32 = 10_000;

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    /// The largest body the server reads in one chunk.
    chunk: usize,
    channel_id: u32,
    token_id: u32,
    sequence: u32,
    request_id: u32,
    handle: u32,
    /// The session's authentication token; null until there is one.
    token: NodeId,
}

impl Client {
    /// Connect to `address`, open a channel for `endpoint_url`, and create
    /// and activate an anonymous session.
    ///
    /// # Errors
    /// Where the server could not be reached, closed with an error,
    /// speaks another policy, or offers no anonymous login.
    pub fn connect(address: &str, endpoint_url: &str, timeout: Option<Duration>) -> Result<Self> {
        let stream = socket::connect_tcp(address, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            chunk: Limits::DEFAULT.chunk_body(),
            channel_id: 0,
            token_id: 0,
            sequence: 1,
            request_id: 0,
            handle: 0,
            token: NodeId::numeric(0, 0),
        };
        client.hello(endpoint_url)?;
        client.open_channel()?;
        let created = client.create_session(endpoint_url)?;
        let policy = created.anonymous_policy()?.to_string();
        client.token = created.token;
        client.activate_session(&policy)?;
        Ok(client)
    }

    fn hello(&mut self, endpoint_url: &str) -> Result<()> {
        let hello = Hello {
            limits: Limits::DEFAULT,
            endpoint_url: endpoint_url.to_string(),
        };
        channel::write_raw(&mut self.writer, channel::HELLO, b'F', &hello.to_bytes())?;
        let (kind, _, body) = channel::expect_raw(&mut self.reader, MAX_BODY)?;
        if kind == channel::ERROR {
            let fault = channel::Fault::from_bytes(&body)?;
            return Err(service::status_error(&fault.reason, fault.code));
        }
        if kind != channel::ACKNOWLEDGE {
            return Err(protocol_error(format!(
                "{} where the acknowledge was expected",
                String::from_utf8_lossy(&kind)
            )));
        }
        self.chunk = Acknowledge::from_bytes(&body)?.limits.chunk_body();
        Ok(())
    }

    fn open_channel(&mut self) -> Result<()> {
        let request = OpenChannel {
            header: self.header(),
            requested_lifetime: LIFETIME,
        };
        let body = self.exchange(channel::OPEN, request.to_bytes())?;
        let mut reader = Self::expect(&body, service::OPEN_CHANNEL_RESPONSE)?;
        let opened = ChannelOpened::take(&mut reader)?;
        good(&opened.header, "opening the channel")?;
        self.channel_id = opened.channel_id;
        self.token_id = opened.token_id;
        Ok(())
    }

    fn create_session(&mut self, endpoint_url: &str) -> Result<SessionCreated> {
        let request = CreateSession {
            header: self.header(),
            endpoint_url: endpoint_url.to_string(),
            session_name: "xmip".to_string(),
        };
        let body = self.exchange(channel::MESSAGE, request.to_bytes())?;
        let mut reader = Self::expect(&body, endpoint::CREATE_SESSION_RESPONSE)?;
        let created = SessionCreated::take(&mut reader)?;
        good(&created.header, "creating the session")?;
        Ok(created)
    }

    fn activate_session(&mut self, policy_id: &str) -> Result<()> {
        let request = ActivateSession {
            header: self.header(),
            policy_id: policy_id.to_string(),
        };
        let body = self.exchange(channel::MESSAGE, request.to_bytes())?;
        let mut reader = Self::expect(&body, endpoint::ACTIVATE_SESSION_RESPONSE)?;
        good(
            &ResponseHeader::take(&mut reader)?,
            "activating the session",
        )
    }

    /// The value of `node`, with its status and source timestamp.
    ///
    /// # Errors
    /// Where the server refused the read, or the value is not bytes.
    pub fn read(&mut self, node: &NodeId) -> Result<DataValue> {
        let request = Read {
            header: self.header(),
            node: node.clone(),
        };
        let body = self.exchange(channel::MESSAGE, request.to_bytes())?;
        let mut reader = Self::expect(&body, attribute::READ_RESPONSE)?;
        let result = ReadResult::take(&mut reader)?;
        good(&result.header, "reading")?;
        Ok(result.value)
    }

    /// Write `bytes` as the value of `node`.
    ///
    /// # Errors
    /// Where the server refused the write, or the node did not take it.
    pub fn write(&mut self, node: &NodeId, bytes: &[u8]) -> Result<()> {
        let request = Write {
            header: self.header(),
            node: node.clone(),
            value: DataValue::bytes(bytes),
        };
        let body = self.exchange(channel::MESSAGE, request.to_bytes())?;
        let mut reader = Self::expect(&body, attribute::WRITE_RESPONSE)?;
        let result = WriteResult::take(&mut reader)?;
        good(&result.header, "writing")?;
        if result.status != GOOD {
            return Err(service::status_error(
                "the node refused the write",
                result.status,
            ));
        }
        Ok(())
    }

    /// Close the session and the channel.
    ///
    /// # Errors
    /// Where the server refused the close or the connection broke.
    pub fn close(mut self) -> Result<()> {
        let header = self.header();
        let body = self.exchange(channel::MESSAGE, endpoint::close_session(&header))?;
        let mut reader = Self::expect(&body, endpoint::CLOSE_SESSION_RESPONSE)?;
        good(&ResponseHeader::take(&mut reader)?, "closing the session")?;
        let header = self.header();
        self.send(channel::CLOSE, service::close_channel(&header))
    }

    fn header(&mut self) -> RequestHeader {
        self.handle = self.handle.wrapping_add(1);
        RequestHeader::new(self.token.clone(), self.handle, TIMEOUT_HINT)
    }

    fn send(&mut self, kind: [u8; 3], body: Vec<u8>) -> Result<()> {
        self.request_id = self.request_id.wrapping_add(1);
        let message = Secure {
            kind,
            channel_id: self.channel_id,
            token_id: self.token_id,
            sequence: self.sequence,
            request_id: self.request_id,
            body,
        };
        self.sequence = channel::write_secure(&mut self.writer, &message, self.chunk)?;
        Ok(())
    }

    /// One message out and its answer back, matched by request id.
    fn exchange(&mut self, kind: [u8; 3], body: Vec<u8>) -> Result<Vec<u8>> {
        self.send(kind, body)?;
        let answer = channel::expect_secure(&mut self.reader, MAX_BODY)?;
        if answer.request_id != self.request_id {
            return Err(protocol_error(format!(
                "an answer to request {} where {} was awaited",
                answer.request_id, self.request_id
            )));
        }
        Ok(answer.body)
    }

    /// A reader over the answer past its type, which must be `expected`;
    /// a service fault is the error it carries.
    fn expect(body: &[u8], expected: u32) -> Result<Reader<'_>> {
        let (id, mut reader) = service::type_of(body)?;
        if id == service::SERVICE_FAULT {
            let header = ResponseHeader::take(&mut reader)?;
            return Err(service::status_error("the server answered", header.result));
        }
        if id != expected {
            return Err(protocol_error(format!(
                "a response of type {id} where {expected} was expected"
            )));
        }
        Ok(reader)
    }
}

/// The header's result, as an error where it is not good.
fn good(header: &ResponseHeader, what: &str) -> Result<()> {
    if header.result == GOOD {
        Ok(())
    } else {
        Err(service::status_error(what, header.result))
    }
}
