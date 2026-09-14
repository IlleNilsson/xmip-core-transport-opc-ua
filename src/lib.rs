#![forbid(unsafe_code)]

//! Streams that arrive as the value of an OPC UA node. One value is one
//! Stream, the node it was read from kept beside it.
//!
//! OPC UA is how a plant's machines are read and told: a server holds an
//! address space of nodes, a client opens a secure channel and a session
//! and reads or writes their attributes (OPC 10000). What is spoken here
//! is the binary encoding over TCP (OPC 10000-6): Hello and Acknowledge,
//! `OpenSecureChannel` under security policy None, `CreateSession` and
//! `ActivateSession` with an anonymous identity, then a `Read` or a
//! `Write` of one node's value attribute as a byte string, in chunks
//! where the value is longer than the far end's buffer. A Receive
//! Location reads its node; a Send Location writes to one. Either may
//! instead accept clients directly through [`Session`], one client's
//! worth of server over a namespace in memory. Signing and encryption are
//! the other policies' and join with the capability's identity work; a
//! server that requires them refuses the channel, and this transport
//! says so.
//!
//! A node's value is not an artefact to claim — it is read, not taken —
//! so [`Transport::claims`] answers `None`, ADR-0024. A Receive Location
//! that polls reads the same value until it is written again; the source
//! timestamp is on the origin so the flow can tell a re-read from a new
//! value.
//!
//! The origin URI is the endpoint and the node: `opc-ua://host:4840/path
//! #ns=2;s=Orders?source=<timestamp>`. A send target is
//! `opc.tcp://host:4840/path#ns=2;s=Orders`, or a node id alone —
//! `ns=2;s=Orders`, `i=2253` — on the configured endpoint.

pub mod attribute;
pub mod channel;
pub mod client;
pub mod endpoint;
pub mod node;
pub mod service;
pub mod session;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
pub use node::NodeId;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};
pub use wire::DataValue;

/// The endpoint path and node the loopback pair agrees on.
const LOOPBACK_PATH: &str = "/xmip";
const LOOPBACK_NODE: &str = "ns=2;s=Probe";

#[derive(Clone)]
pub struct OpcUaTransport {
    /// `opc.tcp://host:port/path`.
    endpoint: String,
    node: NodeId,
    timeout: Option<Duration>,
}

impl OpcUaTransport {
    /// Speak to the server at `endpoint` — `opc.tcp://host:4840/path` —
    /// about `node`.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, node: NodeId) -> Self {
        Self {
            endpoint: endpoint.into(),
            node,
            timeout: None,
        }
    }

    /// Give up on a server that stops mid-answer.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Connect to the endpoint with a session activated.
    ///
    /// # Errors
    /// Where the endpoint cannot be read, the server not reached, or the
    /// session not opened.
    pub fn connect(&self) -> Result<Client> {
        let (authority, _) = split(&self.endpoint)?;
        Client::connect(authority, &self.endpoint, self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    /// The endpoint's authority is the bind address here.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(split(&self.endpoint)?.0)
    }

    /// Accept one client on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the client did not
    /// open a channel under policy None.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.timeout)
    }

    /// Where a target names the endpoint and node itself —
    /// `opc.tcp://host:port/path#node` — or is a node id alone on this
    /// transport's endpoint.
    fn resolve(&self, target: &str) -> Result<(String, NodeId)> {
        if target.starts_with("opc.tcp://") {
            let (endpoint, node) = target.split_once('#').ok_or_else(|| {
                protocol_error(format!(
                    "{target:?} names no node: opc.tcp://host/path#node"
                ))
            })?;
            return Ok((endpoint.to_string(), NodeId::parse(node)?));
        }
        Ok((self.endpoint.clone(), NodeId::parse(target)?))
    }
}

/// The authority and path of `opc.tcp://host:port/path`.
fn split(endpoint: &str) -> Result<(&str, &str)> {
    socket::target("opc.tcp", endpoint)
        .ok_or_else(|| protocol_error(format!("{endpoint:?} is not opc.tcp://host:port/path")))
}

impl Transport for OpcUaTransport {
    fn name(&self) -> &'static str {
        "opc-ua"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// The node's value, one Stream; none where the value is null.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let value = client.read(&self.node)?;
        client.close()?;
        if value.status != service::GOOD {
            return Err(service::status_error("reading the node", value.status));
        }
        let Some(bytes) = value.bytes else {
            return Ok(Vec::new());
        };
        let (authority, path) = split(&self.endpoint)?;
        let source = value.source_timestamp.unwrap_or(0);
        let origin = format!("opc-ua://{authority}/{path}#{}?source={source}", self.node);
        Ok(vec![Arrived::new(origin, bytes)])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (endpoint, node) = self.resolve(target)?;
        let (authority, _) = split(&endpoint)?;
        let mut client = Client::connect(authority, &endpoint, self.timeout)?;
        client.write(&node, bytes)?;
        client.close()
    }
}

impl OpcUaTransport {
    /// Both ends on this machine: an ephemeral local port, one node, the
    /// loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        let node = NodeId::parse(LOOPBACK_NODE).unwrap_or(NodeId::numeric(0, 0));
        Self::new(format!("opc.tcp://127.0.0.1:0{LOOPBACK_PATH}"), node)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for OpcUaTransport {
    fn take_one(&self, listener: &TcpListener) -> Result<Arrived> {
        let mut session = self.accept_one(listener)?;
        let arrived = session
            .next_write()?
            .ok_or_else(|| protocol_error("the client closed without writing"))?;
        // Serve the close that follows, so the client's goodbye is
        // answered rather than met by a closed socket.
        while session.next_event()?.is_some() {}
        Ok(arrived)
    }
}

impl Loopback for OpcUaTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening::new(self.clone(), listener, address)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new(
            format!("opc.tcp://{address}{LOOPBACK_PATH}"),
            self.node.clone(),
        )
        .timing_out_after(LOOPBACK_TIMEOUT)
        .send(&self.node.to_string(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use transport::payload::edge_payloads;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn node() -> NodeId {
        NodeId::string(2, "Orders")
    }

    #[test]
    fn the_loopback_writes_one_value_and_takes_it_in_chunks_where_long() {
        let pair = OpcUaTransport::loopback();
        let arrived = pair.round(b"ISA*00*").expect("round");
        assert_eq!(arrived.bytes, b"ISA*00*");
        assert!(arrived.origin_uri.starts_with("opc-ua://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("#ns=2;s=Probe"));
        let long: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        assert_eq!(pair.round(&long).expect("four chunks").bytes, long);
        assert_eq!(pair.name(), "opc-ua");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.claims().is_none(), "a value is read, not taken");
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = OpcUaTransport::loopback();
        assert!(pair.ceiling().is_none());
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn a_receive_reads_the_node_and_a_send_writes_the_node_the_target_names() {
        let far_end =
            OpcUaTransport::new("opc.tcp://127.0.0.1:0/plant", node()).timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let near = std::thread::spawn(move || {
            let endpoint = format!("opc.tcp://{address}/plant");
            let near = OpcUaTransport::new(&endpoint, node()).timing_out_after(secs(2));
            let read = near.receive()?;
            near.send(&format!("{endpoint}#ns=2;s=Recipe"), b"\0\xff")?;
            let unknown = OpcUaTransport::new(&endpoint, NodeId::string(2, "Unknown"))
                .timing_out_after(secs(2))
                .receive();
            Ok::<_, transport::TransportError>((read, unknown))
        });
        let mut values = BTreeMap::new();
        values.insert(node(), b"ISA*00*".to_vec());
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_values(values);
        assert!(session.endpoint_url().ends_with("/plant"));
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        assert_eq!(events[0], Event::SessionCreated("xmip".to_string()));
        assert_eq!(events[1], Event::SessionActivated("anonymous".to_string()));
        assert_eq!(events[2], Event::Read(node()));
        assert_eq!(events[3], Event::SessionClosed);
        assert_eq!(events[4], Event::Closed);
        let mut session = far_end.accept_one(&listener).expect("second");
        let written = session.next_write().expect("write").expect("one");
        assert_eq!(written.bytes, b"\0\xff");
        assert!(written.origin_uri.ends_with("#ns=2;s=Recipe"));
        assert_eq!(
            session.value(&NodeId::string(2, "Recipe")),
            Some(&b"\0\xff"[..])
        );
        while session.next_event().expect("event").is_some() {}
        let mut session = far_end.accept_one(&listener).expect("third");
        while session.next_event().expect("event").is_some() {}
        let (read, unknown) = near.join().expect("thread").expect("near");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].bytes, b"ISA*00*");
        assert!(read[0].origin_uri.starts_with("opc-ua://127.0.0.1:"));
        assert!(read[0].origin_uri.contains("/plant#ns=2;s=Orders?source="));
        let unknown = unknown.expect_err("an unknown node is refused");
        assert!(unknown.message.contains("no such node"), "{unknown}");
        assert!(!unknown.retryable);
    }

    #[test]
    fn a_bad_target_another_policy_and_a_call_before_the_session_are_refused() {
        let far_end =
            OpcUaTransport::new("opc.tcp://127.0.0.1:0/plant", node()).timing_out_after(secs(2));
        assert!(far_end.resolve("Orders").is_err());
        assert!(
            far_end.resolve("opc.tcp://h:4840/plant").is_err(),
            "no node"
        );
        assert_eq!(
            far_end.resolve("i=2253").expect("bare"),
            (
                "opc.tcp://127.0.0.1:0/plant".to_string(),
                NodeId::numeric(0, 2253)
            )
        );
        assert!(OpcUaTransport::new("http://h/", node()).bind().is_err());
        let (listener, address) = far_end.bind().expect("binding");
        let caller = std::thread::spawn(move || {
            let stream = socket::connect_tcp(&address, Some(secs(2))).expect("connect");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            let hello = channel::Hello {
                limits: channel::Limits::DEFAULT,
                endpoint_url: format!("opc.tcp://{address}/plant"),
            };
            channel::write_raw(&mut writer, channel::HELLO, b'F', &hello.to_bytes())
                .expect("hello");
            channel::expect_raw(&mut reader, 1 << 20).expect("ack");
            let open = service::OpenChannel {
                header: service::RequestHeader::new(NodeId::numeric(0, 0), 1, 1000),
                requested_lifetime: 1000,
            };
            let message = channel::Secure {
                kind: channel::OPEN,
                channel_id: 0,
                token_id: 0,
                sequence: 1,
                request_id: 1,
                body: open.to_bytes(),
            };
            channel::write_secure(&mut writer, &message, 4096).expect("open");
            let opened = channel::expect_secure(&mut reader, 1 << 20).expect("opened");
            let read = attribute::Read {
                header: service::RequestHeader::new(NodeId::numeric(0, 0), 2, 1000),
                node: node(),
            };
            let message = channel::Secure {
                kind: channel::MESSAGE,
                channel_id: opened.channel_id,
                token_id: opened.token_id,
                sequence: 2,
                request_id: 2,
                body: read.to_bytes(),
            };
            channel::write_secure(&mut writer, &message, 4096).expect("read");
            let answer = channel::expect_secure(&mut reader, 1 << 20).expect("answer");
            let (id, mut reader) = service::type_of(&answer.body).expect("type");
            (
                id,
                service::ResponseHeader::take(&mut reader)
                    .expect("header")
                    .result,
            )
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        while session.next_event().expect("event").is_some() {}
        assert_eq!(
            caller.join().expect("thread"),
            (service::SERVICE_FAULT, service::BAD_SESSION_ID_INVALID)
        );
    }
}
