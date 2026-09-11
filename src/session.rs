//! The server's side of one connection: what a test puts at the far end,
//! and what a Receive Location that accepts writes directly runs.
//!
//! Not an OPC UA server. One session answers one client's Hello, opens
//! its one secure channel under policy None, creates and activates its
//! one session for an anonymous identity, and serves reads and writes of
//! the value attribute over a namespace of nodes kept in memory: what is
//! written is handed up as a Stream and served back to reads. Browsing,
//! subscriptions and every other service are answered as unsupported.

use std::collections::BTreeMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use transport::Arrived;
use transport::error::{Result, protocol_error};
use transport::socket;
use transport::wire::MAX_BODY;

use crate::attribute::{self, Read, ReadResult, Write, WriteResult};
use crate::channel::{self, Acknowledge, Fault, Hello, Limits, NONE_POLICY, Secure};
use crate::endpoint::{self, ActivateSession, CreateSession, Endpoint, SessionCreated};
use crate::node::NodeId;
use crate::service::{self, ChannelOpened, OpenChannel};
use crate::service::{RequestHeader, ResponseHeader};
use crate::wire::{DataValue, Reader};

/// The one user token policy this session offers.
pub const ANONYMOUS_POLICY: &str = "anonymous";

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client created a session by this name.
    SessionCreated(String),
    /// The client activated its session under this policy.
    SessionActivated(String),
    /// The client read this node.
    Read(NodeId),
    /// The client wrote a node; here is the Stream.
    Written(Arrived),
    /// The client wrote a value that is not bytes, and was told so.
    Refused(NodeId),
    /// The client closed its session.
    SessionClosed,
    /// The client closed the channel.
    Closed,
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    /// What the client said it wanted.
    endpoint_url: String,
    /// The largest body the client reads in one chunk.
    chunk: usize,
    channel_id: u32,
    token_id: u32,
    sequence: u32,
    /// The session's authentication token once one is created.
    token: Option<NodeId>,
    activated: bool,
    values: BTreeMap<NodeId, DataValue>,
}

/// Channel ids handed out, one a session.
static CHANNELS: AtomicU32 = AtomicU32::new(1);

impl Session {
    /// Accept one client on `listener`: its Hello acknowledged, its
    /// channel opened.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not
    /// say Hello, or asked for a policy other than None.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            endpoint_url: String::new(),
            chunk: Limits::DEFAULT.chunk_body(),
            channel_id: CHANNELS.fetch_add(1, Ordering::Relaxed),
            token_id: 1,
            sequence: 1,
            token: None,
            activated: false,
            values: BTreeMap::new(),
        };
        session.hello()?;
        session.open_channel()?;
        Ok(session)
    }

    fn hello(&mut self) -> Result<()> {
        let (kind, _, body) = channel::expect_raw(&mut self.reader, MAX_BODY)?;
        if kind != channel::HELLO {
            let fault = Fault {
                code: service::BAD_ENDPOINT_URL_INVALID,
                reason: "not Hello".to_string(),
            };
            channel::write_raw(&mut self.writer, channel::ERROR, b'F', &fault.to_bytes())?;
            return Err(protocol_error(format!(
                "{} where Hello was expected",
                String::from_utf8_lossy(&kind)
            )));
        }
        let hello = Hello::from_bytes(&body)?;
        self.endpoint_url = hello.endpoint_url;
        self.chunk = hello.limits.chunk_body();
        let acknowledge = Acknowledge {
            limits: Limits::DEFAULT,
        };
        channel::write_raw(
            &mut self.writer,
            channel::ACKNOWLEDGE,
            b'F',
            &acknowledge.to_bytes(),
        )
    }

    fn open_channel(&mut self) -> Result<()> {
        let request = channel::expect_secure(&mut self.reader, MAX_BODY)?;
        if request.kind != channel::OPEN {
            return Err(protocol_error("a message before the channel was opened"));
        }
        let (id, mut reader) = service::type_of(&request.body)?;
        if id != service::OPEN_CHANNEL_REQUEST {
            return Err(protocol_error("an open that is not an OpenSecureChannel"));
        }
        let open = OpenChannel::take(&mut reader)?;
        let opened = ChannelOpened {
            header: ResponseHeader::new(open.header.handle, service::GOOD),
            channel_id: self.channel_id,
            token_id: self.token_id,
            lifetime: open.requested_lifetime,
        };
        self.reply(channel::OPEN, request.request_id, opened.to_bytes())
    }

    /// Serve these values to reads.
    #[must_use]
    pub fn with_values(mut self, values: BTreeMap<NodeId, Vec<u8>>) -> Self {
        self.values = values
            .into_iter()
            .map(|(node, bytes)| (node, DataValue::bytes(&bytes)))
            .collect();
        self
    }

    /// What `node` holds now.
    #[must_use]
    pub fn value(&self, node: &NodeId) -> Option<&[u8]> {
        self.values
            .get(node)
            .and_then(|value| value.bytes.as_deref())
    }

    /// The endpoint the client said Hello to.
    #[must_use]
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    /// The next value the client writes, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_write(&mut self) -> Result<Option<Arrived>> {
        loop {
            match self.next_event()? {
                Some(Event::Written(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next thing the client did, answered, or `None` when it closed
    /// the connection.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let Some(request) = channel::read_secure(&mut self.reader, MAX_BODY)? else {
            return Ok(None);
        };
        if request.kind == channel::CLOSE {
            return Ok(Some(Event::Closed));
        }
        if request.channel_id != self.channel_id {
            let fault = ResponseHeader::new(0, service::BAD_SECURE_CHANNEL_ID_INVALID);
            self.reply(channel::MESSAGE, request.request_id, service::fault(&fault))?;
            return Err(protocol_error("a message on another channel"));
        }
        let (answer, event) = self.answer(&request.body);
        self.reply(channel::MESSAGE, request.request_id, answer)?;
        Ok(Some(event))
    }

    /// The answer to one service call, and what it was.
    fn answer(&mut self, body: &[u8]) -> (Vec<u8>, Event) {
        let Ok((id, mut reader)) = service::type_of(body) else {
            return (fault(0, service::BAD_SERVICE_UNSUPPORTED), Event::Closed);
        };
        let served = match id {
            endpoint::CREATE_SESSION_REQUEST => self.create_session(&mut reader),
            endpoint::ACTIVATE_SESSION_REQUEST => self.activate_session(&mut reader),
            attribute::READ_REQUEST => self.read(&mut reader),
            attribute::WRITE_REQUEST => self.write(&mut reader),
            endpoint::CLOSE_SESSION_REQUEST => self.close_session(&mut reader),
            _ => Ok(Err(service::BAD_SERVICE_UNSUPPORTED)),
        };
        match served {
            Ok(Ok(answered)) => answered,
            Ok(Err(code)) => (fault(0, code), Event::Closed),
            Err(_) => (fault(0, service::BAD_SERVICE_UNSUPPORTED), Event::Closed),
        }
    }

    fn create_session(&mut self, reader: &mut Reader<'_>) -> Served {
        let create = CreateSession::take(reader)?;
        let token = NodeId::string(0, format!("xmip-session-{}", self.channel_id));
        self.token = Some(token.clone());
        self.activated = false;
        let created = SessionCreated {
            header: ResponseHeader::new(create.header.handle, service::GOOD),
            session_id: NodeId::numeric(1, self.channel_id),
            token,
            endpoints: vec![Endpoint {
                url: self.endpoint_url.clone(),
                security_policy: NONE_POLICY.to_string(),
                anonymous_policy: Some(ANONYMOUS_POLICY.to_string()),
            }],
        };
        Ok(Ok((
            created.to_bytes(),
            Event::SessionCreated(create.session_name),
        )))
    }

    fn activate_session(&mut self, reader: &mut Reader<'_>) -> Served {
        let activate = ActivateSession::take(reader)?;
        if self.token.as_ref() != Some(&activate.header.token) {
            return Ok(Err(service::BAD_SESSION_ID_INVALID));
        }
        if activate.policy_id != ANONYMOUS_POLICY {
            return Ok(Err(service::BAD_IDENTITY_TOKEN_REJECTED));
        }
        self.activated = true;
        let header = ResponseHeader::new(activate.header.handle, service::GOOD);
        Ok(Ok((
            endpoint::session_activated(&header),
            Event::SessionActivated(activate.policy_id),
        )))
    }

    fn read(&mut self, reader: &mut Reader<'_>) -> Served {
        let read = Read::take(reader)?;
        if let Err(code) = self.check(&read.header) {
            return Ok(Err(code));
        }
        let value = self.values.get(&read.node).cloned().unwrap_or(DataValue {
            bytes: None,
            status: service::BAD_NODE_ID_UNKNOWN,
            source_timestamp: None,
        });
        let result = ReadResult {
            header: ResponseHeader::new(read.header.handle, service::GOOD),
            value,
        };
        Ok(Ok((result.to_bytes(), Event::Read(read.node))))
    }

    fn write(&mut self, reader: &mut Reader<'_>) -> Served {
        let write = Write::take(reader)?;
        if let Err(code) = self.check(&write.header) {
            return Ok(Err(code));
        }
        let header = ResponseHeader::new(write.header.handle, service::GOOD);
        let Some(bytes) = write.value.bytes else {
            let result = WriteResult {
                header,
                status: service::BAD_TYPE_MISMATCH,
            };
            return Ok(Ok((result.to_bytes(), Event::Refused(write.node))));
        };
        let origin = format!("opc-ua://{}#{}", self.peer, write.node);
        self.values.insert(
            write.node,
            DataValue {
                bytes: Some(bytes.clone()),
                status: service::GOOD,
                source_timestamp: write
                    .value
                    .source_timestamp
                    .or_else(|| Some(crate::wire::now())),
            },
        );
        let result = WriteResult {
            header,
            status: service::GOOD,
        };
        Ok(Ok((
            result.to_bytes(),
            Event::Written(Arrived::new(origin, bytes)),
        )))
    }

    fn close_session(&mut self, reader: &mut Reader<'_>) -> Served {
        let header = RequestHeader::take(reader)?;
        if self.token.as_ref() != Some(&header.token) {
            return Ok(Err(service::BAD_SESSION_ID_INVALID));
        }
        self.token = None;
        self.activated = false;
        let header = ResponseHeader::new(header.handle, service::GOOD);
        Ok(Ok((
            endpoint::session_closed(&header),
            Event::SessionClosed,
        )))
    }

    /// That the call is on the activated session.
    fn check(&self, header: &RequestHeader) -> std::result::Result<(), u32> {
        if self.token.as_ref() != Some(&header.token) {
            return Err(service::BAD_SESSION_ID_INVALID);
        }
        if !self.activated {
            return Err(service::BAD_SESSION_NOT_ACTIVATED);
        }
        Ok(())
    }

    fn reply(&mut self, kind: [u8; 3], request_id: u32, body: Vec<u8>) -> Result<()> {
        let message = Secure {
            kind,
            channel_id: self.channel_id,
            token_id: self.token_id,
            sequence: self.sequence,
            request_id,
            body,
        };
        self.sequence = channel::write_secure(&mut self.writer, &message, self.chunk)?;
        Ok(())
    }
}

/// What serving one call comes to: the answer and the event, a status
/// to fault with, or a request that could not be read.
type Served = Result<std::result::Result<(Vec<u8>, Event), u32>>;

/// A service fault answering `handle` with `code`.
fn fault(handle: u32, code: u32) -> Vec<u8> {
    service::fault(&ResponseHeader::new(handle, code))
}
