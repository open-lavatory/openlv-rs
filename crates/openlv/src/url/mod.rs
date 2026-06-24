use crate::{
    encryption::{PublicKeyHash, handshake::HandshakeKey}, errors::OpenLvError, signaling::SignalingProtocol, utils::redact_url,
};
use rand::RngCore;
use regex::Regex;
use std::fmt::Display;
use std::sync::LazyLock;
use url::form_urlencoded;

pub const OPENLV_PROTOCOL_VERSION: u8 = 1;

const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static URI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^openlv://([A-Za-z0-9_-]{16})@(\d+)\?(.+)$").expect("valid URI regex")
});
static HASH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{16}$").expect("valid hash regex"));
static SHARED_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{32}$").expect("valid shared key regex"));

#[derive(Debug, PartialEq, Clone)]
pub enum SessionUri {
    Version1(Version1SessionUri),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Version1SessionUri {
    pub session_id: String,
    pub key_hash: PublicKeyHash,
    pub shared_key: HandshakeKey,
    pub signaling_protocol: SignalingProtocol,
    pub signaling_server: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeParameters {
    pub version: u8,
    pub session_id: String,
    pub h: String,
    pub k: String,
    pub p: SignalingProtocol,
    pub s: String,
}

impl TryFrom<&str> for SessionUri {
    type Error = OpenLvError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        decode_connection_url(value)
    }
}

impl TryFrom<String> for SessionUri {
    type Error = OpenLvError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        decode_connection_url(&value)
    }
}

pub fn decode_connection_url(url: &str) -> Result<SessionUri, OpenLvError> {
    if url.trim().is_empty() {
        return Err(OpenLvError::InvalidUri("URL cannot be empty".into()));
    }

    if !url.starts_with("openlv://") {
        return Err(OpenLvError::InvalidUri(format!(
            "invalid URL format: must start with 'openlv://', got: {}",
            redact_url(url)
        )));
    }

    let captures = URI_REGEX.captures(url).ok_or_else(|| {
        OpenLvError::InvalidUri(format!("invalid URL format: {}", redact_url(url)))
    })?;

    let session_id = captures
        .get(1)
        .ok_or_else(|| OpenLvError::InvalidUri("session ID missing".into()))?
        .as_str()
        .to_string();

    let version: u8 = captures
        .get(2)
        .ok_or_else(|| OpenLvError::InvalidUri("version missing".into()))?
        .as_str()
        .parse()
        .map_err(|_| OpenLvError::InvalidUri("invalid version".into()))?;

    if version != OPENLV_PROTOCOL_VERSION {
        return Err(OpenLvError::InvalidUri(format!(
            "invalid protocol version: expected {OPENLV_PROTOCOL_VERSION}, got {version}"
        )));
    }

    let query_string = captures
        .get(3)
        .ok_or_else(|| OpenLvError::InvalidUri("query string missing".into()))?
        .as_str();

    let query_params: std::collections::HashMap<String, String> =
        form_urlencoded::parse(query_string.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();

    let h = query_params
        .get("h")
        .ok_or_else(|| OpenLvError::InvalidUri("h parameter is required".into()))?;

    if !HASH_REGEX.is_match(h) {
        return Err(OpenLvError::InvalidUri(
            "invalid public key hash format: must be 16 hex characters".into(),
        ));
    }

    let k = query_params
        .get("k")
        .ok_or_else(|| OpenLvError::InvalidUri("k parameter is required".into()))?;

    if !SHARED_KEY_REGEX.is_match(k) {
        return Err(OpenLvError::InvalidUri(
            "invalid shared key format: must be 32 lowercase hex characters".into(),
        ));
    }

    let p = query_params
        .get("p")
        .map(|value| SignalingProtocol::from(value.clone()))
        .unwrap_or(SignalingProtocol::Mqtt);

    let signaling_server = query_params.get("s").cloned().unwrap_or_default();

    Ok(SessionUri::Version1(Version1SessionUri {
        session_id,
        key_hash: PublicKeyHash(h.clone()),
        shared_key: HandshakeKey::from_hex(k)?,
        signaling_protocol: p,
        signaling_server,
    }))
}

pub fn encode_connection_url(parameters: &HandshakeParameters) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("h", &parameters.h);
    serializer.append_pair("k", &parameters.k);
    serializer.append_pair("p", &parameters.p.to_string());
    serializer.append_pair("s", &parameters.s);
    let query = serializer.finish();

    format!(
        "openlv://{}@{}?{}",
        parameters.session_id, parameters.version, query
    )
}

pub fn generate_session_id() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);

    bytes
        .iter()
        .map(|byte| URL_SAFE_ALPHABET[(*byte as usize) % URL_SAFE_ALPHABET.len()] as char)
        .collect()
}

impl SessionUri {
    pub fn new(
        key_hash: PublicKeyHash,
        shared_key: HandshakeKey,
        signaling_protocol: SignalingProtocol,
        signaling_server: String,
    ) -> Self {
        Self::Version1(Version1SessionUri {
            session_id: generate_session_id(),
            key_hash,
            shared_key,
            signaling_protocol,
            signaling_server,
        })
    }

    pub fn handshake_parameters(&self) -> HandshakeParameters {
        match self {
            Self::Version1(version1) => HandshakeParameters {
                version: OPENLV_PROTOCOL_VERSION,
                session_id: version1.session_id.clone(),
                h: version1.key_hash.0.clone(),
                k: version1.shared_key.to_hex().to_string(),
                p: version1.signaling_protocol.clone(),
                s: version1.signaling_server.clone(),
            },
        }
    }

    pub fn to_connection_url(&self) -> String {
        encode_connection_url(&self.handshake_parameters())
    }
}

impl Display for SessionUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version1(version1) => write!(f, "{}", version1.to_connection_url()),
        }
    }
}

impl Version1SessionUri {
    pub fn to_connection_url(&self) -> String {
        SessionUri::Version1(self.clone()).to_connection_url()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_connection_url() {
        let uri = "openlv://k7n8m9x2w5q1p3r6@1?h=a1b2c3d4e5f60708&k=0123456789abcdef0123456789abcdef&p=mqtt&s=wss%3A%2F%2Ftest.mosquitto.org%3A8081%2Fmqtt";
        let session_uri = SessionUri::try_from(uri).unwrap();
        let SessionUri::Version1(version1) = session_uri;

        assert_eq!(version1.session_id, "k7n8m9x2w5q1p3r6");
        assert_eq!(version1.key_hash.0, "a1b2c3d4e5f60708");
        assert_eq!(
            version1.shared_key.to_hex(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(version1.signaling_protocol, SignalingProtocol::Mqtt);
        assert_eq!(
            version1.signaling_server,
            "wss://test.mosquitto.org:8081/mqtt"
        );
    }

    #[test]
    fn test_encode_round_trip() {
        let parameters = HandshakeParameters {
            version: OPENLV_PROTOCOL_VERSION,
            session_id: "k7n8m9x2w5q1p3r6".to_string(),
            h: "a1b2c3d4e5f60708".to_string(),
            k: "0123456789abcdef0123456789abcdef".to_string(),
            p: SignalingProtocol::Mqtt,
            s: "wss://test.mosquitto.org:8081/mqtt".to_string(),
        };

        let encoded = encode_connection_url(&parameters);
        let decoded = decode_connection_url(&encoded).unwrap();
        let SessionUri::Version1(version1) = decoded;

        assert_eq!(version1.session_id, parameters.session_id);
        assert_eq!(version1.key_hash.0, parameters.h);
        assert_eq!(version1.shared_key.to_hex(), parameters.k);
        assert_eq!(version1.signaling_protocol, parameters.p);
        assert_eq!(version1.signaling_server, parameters.s);
    }

    #[test]
    fn test_generate_session_id_length() {
        let session_id = generate_session_id();
        assert_eq!(session_id.len(), 16);
        assert!(
            session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn test_invalid_uri_rejected() {
        assert!(decode_connection_url("not-a-uri").is_err());
        assert!(
            decode_connection_url(
                "openlv://short@1?h=abc&k=0123456789abcdef0123456789abcdef&p=mqtt&s=x"
            )
            .is_err()
        );
    }
}
