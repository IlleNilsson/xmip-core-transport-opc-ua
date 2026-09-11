//! The session services (OPC 10000-4 clause 5.6) and the endpoint a
//! server describes when it creates one: `CreateSession` names the
//! endpoint and comes back with the session's authentication token and
//! the endpoints the server offers, each with the user token policies it
//! takes; `ActivateSession` presents an identity — anonymous here, by the
//! policy id the endpoint listed — and `CloseSession` ends it.

use transport::error::{Result, protocol_error};

use crate::channel::NONE_POLICY;
use crate::node::NodeId;
use crate::service::{RequestHeader, ResponseHeader, body};
use crate::wire::{self, Reader};

/// `CreateSessionRequest_Encoding_DefaultBinary`.
pub const CREATE_SESSION_REQUEST: u32 = 461;
/// `CreateSessionResponse_Encoding_DefaultBinary`.
pub const CREATE_SESSION_RESPONSE: u32 = 464;
/// `ActivateSessionRequest_Encoding_DefaultBinary`.
pub const ACTIVATE_SESSION_REQUEST: u32 = 467;
/// `ActivateSessionResponse_Encoding_DefaultBinary`.
pub const ACTIVATE_SESSION_RESPONSE: u32 = 470;
/// `CloseSessionRequest_Encoding_DefaultBinary`.
pub const CLOSE_SESSION_REQUEST: u32 = 473;
/// `CloseSessionResponse_Encoding_DefaultBinary`.
pub const CLOSE_SESSION_RESPONSE: u32 = 476;
/// `AnonymousIdentityToken_Encoding_DefaultBinary`.
pub const ANONYMOUS_IDENTITY_TOKEN: u32 = 321;

/// What this side says it is.
pub const APPLICATION_URI: &str = "urn:xmip:transport:opc-ua";
/// The transport profile of the binary encoding over TCP.
pub const BINARY_PROFILE: &str =
    "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

/// The application description, a client's or a server's.
fn put_application(out: &mut Vec<u8>, kind: u32) {
    wire::put_string(out, Some(APPLICATION_URI));
    wire::put_string(out, Some(APPLICATION_URI));
    wire::put_localized_text(out, "Xmip");
    wire::put_u32(out, kind);
    wire::put_string(out, None);
    wire::put_string(out, None);
    wire::put_i32(out, 0);
}

fn skip_application(reader: &mut Reader<'_>) -> Result<()> {
    reader.string()?;
    reader.string()?;
    reader.skip_localized_text()?;
    reader.u32()?;
    reader.string()?;
    reader.string()?;
    for _ in 0..reader.count()? {
        reader.string()?;
    }
    Ok(())
}

/// `CreateSessionRequest`: this client, the endpoint, a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSession {
    pub header: RequestHeader,
    pub endpoint_url: String,
    pub session_name: String,
}

impl CreateSession {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(CREATE_SESSION_REQUEST);
        self.header.put(&mut out);
        put_application(&mut out, 1);
        wire::put_string(&mut out, None);
        wire::put_string(&mut out, Some(&self.endpoint_url));
        wire::put_string(&mut out, Some(&self.session_name));
        wire::put_byte_string(&mut out, None);
        wire::put_byte_string(&mut out, None);
        wire::put_f64(&mut out, 60_000.0);
        wire::put_u32(&mut out, 0);
        out
    }

    /// # Errors
    /// Where the request is cut short.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let header = RequestHeader::take(reader)?;
        skip_application(reader)?;
        reader.string()?;
        let endpoint_url = reader.string()?.unwrap_or_default();
        let session_name = reader.string()?.unwrap_or_default();
        Ok(Self {
            header,
            endpoint_url,
            session_name,
        })
    }
}

/// One endpoint a server describes: where, under which policy, and the
/// id of its anonymous token policy where it has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub url: String,
    pub security_policy: String,
    pub anonymous_policy: Option<String>,
}

impl Endpoint {
    fn put(&self, out: &mut Vec<u8>) {
        wire::put_string(out, Some(&self.url));
        put_application(out, 0);
        wire::put_byte_string(out, None);
        wire::put_u32(out, 1);
        wire::put_string(out, Some(&self.security_policy));
        wire::put_i32(out, i32::from(self.anonymous_policy.is_some()));
        if let Some(policy) = &self.anonymous_policy {
            wire::put_string(out, Some(policy));
            wire::put_u32(out, 0);
            wire::put_string(out, None);
            wire::put_string(out, None);
            wire::put_string(out, None);
        }
        wire::put_string(out, Some(BINARY_PROFILE));
        wire::put_u8(out, 0);
    }

    fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let url = reader.string()?.unwrap_or_default();
        skip_application(reader)?;
        reader.byte_string()?;
        reader.u32()?;
        let security_policy = reader.string()?.unwrap_or_default();
        let mut anonymous_policy = None;
        for _ in 0..reader.count()? {
            let policy_id = reader.string()?;
            let token_type = reader.u32()?;
            reader.string()?;
            reader.string()?;
            reader.string()?;
            if token_type == 0 && anonymous_policy.is_none() {
                anonymous_policy = policy_id;
            }
        }
        reader.string()?;
        reader.u8()?;
        Ok(Self {
            url,
            security_policy,
            anonymous_policy,
        })
    }
}

/// `CreateSessionResponse`: the session, its token, and the endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCreated {
    pub header: ResponseHeader,
    pub session_id: NodeId,
    pub token: NodeId,
    pub endpoints: Vec<Endpoint>,
}

impl SessionCreated {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(CREATE_SESSION_RESPONSE);
        self.header.put(&mut out);
        self.session_id.put(&mut out);
        self.token.put(&mut out);
        wire::put_f64(&mut out, 60_000.0);
        wire::put_byte_string(&mut out, None);
        wire::put_byte_string(&mut out, None);
        wire::put_i32(&mut out, i32::try_from(self.endpoints.len()).unwrap_or(0));
        for endpoint in &self.endpoints {
            endpoint.put(&mut out);
        }
        wire::put_i32(&mut out, 0);
        wire::put_string(&mut out, None);
        wire::put_byte_string(&mut out, None);
        wire::put_u32(&mut out, 0);
        out
    }

    /// # Errors
    /// Where the response is cut short.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let header = ResponseHeader::take(reader)?;
        let session_id = reader.node_id()?;
        let token = reader.node_id()?;
        reader.f64()?;
        reader.byte_string()?;
        reader.byte_string()?;
        let mut endpoints = Vec::new();
        for _ in 0..reader.count()? {
            endpoints.push(Endpoint::take(reader)?);
        }
        Ok(Self {
            header,
            session_id,
            token,
            endpoints,
        })
    }

    /// The anonymous policy id of the first endpoint under policy None
    /// that has one.
    ///
    /// # Errors
    /// Where no endpoint offers an anonymous login over None.
    pub fn anonymous_policy(&self) -> Result<&str> {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.security_policy == NONE_POLICY)
            .find_map(|endpoint| endpoint.anonymous_policy.as_deref())
            .ok_or_else(|| {
                protocol_error("the server offers no anonymous login under security policy None")
            })
    }
}

/// `ActivateSessionRequest` with an anonymous identity under `policy_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivateSession {
    pub header: RequestHeader,
    pub policy_id: String,
}

impl ActivateSession {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = body(ACTIVATE_SESSION_REQUEST);
        self.header.put(&mut out);
        wire::put_string(&mut out, None);
        wire::put_byte_string(&mut out, None);
        wire::put_i32(&mut out, 0);
        wire::put_i32(&mut out, 0);
        NodeId::numeric(0, ANONYMOUS_IDENTITY_TOKEN).put(&mut out);
        wire::put_u8(&mut out, 1);
        let mut token = Vec::new();
        wire::put_string(&mut token, Some(&self.policy_id));
        wire::put_byte_string(&mut out, Some(&token));
        wire::put_string(&mut out, None);
        wire::put_byte_string(&mut out, None);
        out
    }

    /// # Errors
    /// Where the request is cut short or presents an identity other than
    /// anonymous.
    pub fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let header = RequestHeader::take(reader)?;
        reader.string()?;
        reader.byte_string()?;
        for _ in 0..reader.count()? {
            reader.byte_string()?;
            reader.byte_string()?;
        }
        for _ in 0..reader.count()? {
            reader.string()?;
        }
        let identity = reader.node_id()?;
        if identity != NodeId::numeric(0, ANONYMOUS_IDENTITY_TOKEN) || reader.u8()? != 1 {
            return Err(protocol_error(format!(
                "an identity token of type {identity}, and this side takes anonymous"
            )));
        }
        let token = reader.byte_string()?.unwrap_or_default();
        let policy_id = Reader::new(token).string()?.unwrap_or_default();
        Ok(Self { header, policy_id })
    }
}

/// `ActivateSessionResponse`: nothing beyond the header.
#[must_use]
pub fn session_activated(header: &ResponseHeader) -> Vec<u8> {
    let mut out = body(ACTIVATE_SESSION_RESPONSE);
    header.put(&mut out);
    wire::put_byte_string(&mut out, None);
    wire::put_i32(&mut out, 0);
    wire::put_i32(&mut out, 0);
    out
}

/// `CloseSessionRequest`, subscriptions deleted with it.
#[must_use]
pub fn close_session(header: &RequestHeader) -> Vec<u8> {
    let mut out = body(CLOSE_SESSION_REQUEST);
    header.put(&mut out);
    wire::put_bool(&mut out, true);
    out
}

/// `CloseSessionResponse`: the header alone.
#[must_use]
pub fn session_closed(header: &ResponseHeader) -> Vec<u8> {
    let mut out = body(CLOSE_SESSION_RESPONSE);
    header.put(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{GOOD, type_of};

    fn request() -> RequestHeader {
        RequestHeader {
            token: NodeId::numeric(0, 0),
            timestamp: 1,
            handle: 5,
            timeout_hint: 10_000,
        }
    }

    #[test]
    fn a_session_is_created_with_the_endpoints_and_the_anonymous_policy_found() {
        let create = CreateSession {
            header: request(),
            endpoint_url: "opc.tcp://localhost:4840/xmip".to_string(),
            session_name: "xmip".to_string(),
        };
        let bytes = create.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, CREATE_SESSION_REQUEST);
        assert_eq!(CreateSession::take(&mut reader).expect("create"), create);
        let created = SessionCreated {
            header: ResponseHeader::new(5, GOOD),
            session_id: NodeId::numeric(1, 42),
            token: NodeId::string(0, "token"),
            endpoints: vec![
                Endpoint {
                    url: "opc.tcp://localhost:4840/xmip".to_string(),
                    security_policy: "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
                        .to_string(),
                    anonymous_policy: Some("anon-secure".to_string()),
                },
                Endpoint {
                    url: "opc.tcp://localhost:4840/xmip".to_string(),
                    security_policy: NONE_POLICY.to_string(),
                    anonymous_policy: None,
                },
                Endpoint {
                    url: "opc.tcp://localhost:4840/xmip".to_string(),
                    security_policy: NONE_POLICY.to_string(),
                    anonymous_policy: Some("anonymous".to_string()),
                },
            ],
        };
        let bytes = created.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, CREATE_SESSION_RESPONSE);
        let read = SessionCreated::take(&mut reader).expect("created");
        assert_eq!(read, created);
        assert_eq!(read.anonymous_policy().expect("policy"), "anonymous");
        let none = SessionCreated {
            endpoints: Vec::new(),
            ..created
        };
        assert!(none.anonymous_policy().is_err());
    }

    #[test]
    fn a_session_is_activated_anonymously_and_closed() {
        let activate = ActivateSession {
            header: request(),
            policy_id: "anonymous".to_string(),
        };
        let bytes = activate.to_bytes();
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, ACTIVATE_SESSION_REQUEST);
        assert_eq!(
            ActivateSession::take(&mut reader).expect("activate"),
            activate
        );
        let bytes = session_activated(&ResponseHeader::new(5, GOOD));
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, ACTIVATE_SESSION_RESPONSE);
        assert_eq!(
            ResponseHeader::take(&mut reader).expect("header").result,
            GOOD
        );
        let bytes = close_session(&request());
        let (id, mut reader) = type_of(&bytes).expect("type");
        assert_eq!(id, CLOSE_SESSION_REQUEST);
        assert_eq!(RequestHeader::take(&mut reader).expect("header"), request());
        assert!(reader.bool().expect("delete subscriptions"));
        let bytes = session_closed(&ResponseHeader::new(5, GOOD));
        let (id, _) = type_of(&bytes).expect("type");
        assert_eq!(id, CLOSE_SESSION_RESPONSE);
        let mut user = body(ACTIVATE_SESSION_REQUEST);
        request().put(&mut user);
        wire::put_string(&mut user, None);
        wire::put_byte_string(&mut user, None);
        wire::put_i32(&mut user, 0);
        wire::put_i32(&mut user, 0);
        NodeId::numeric(0, 324).put(&mut user);
        wire::put_u8(&mut user, 1);
        let bytes = user;
        let (_, mut reader) = type_of(&bytes).expect("type");
        let error = ActivateSession::take(&mut reader).expect_err("a user name token");
        assert!(error.message.contains("i=324"), "{error}");
    }
}
