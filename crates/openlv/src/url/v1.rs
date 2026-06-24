use std::sync::LazyLock;

use regex::Regex;
use url::form_urlencoded;

use crate::{
    OpenLvError, SignalingProtocol,
    encryption::{HandshakeKey, PublicKeyHash},
    utils::redact_url,
};

const OPENLV_PROTOCOL_VERSION: u8 = 1;

static URI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^openlv://([A-Za-z0-9_-]{16})@(\d+)\?(.+)$").expect("valid URI regex")
});
static HASH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{16}$").expect("valid hash regex"));
static SHARED_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{32}$").expect("valid shared key regex"));

#[derive(Debug, PartialEq, Clone)]
pub struct Version1SessionUri {
    pub session_id: String,
    pub key_hash: PublicKeyHash,
    pub shared_key: HandshakeKey,
    pub signaling_protocol: SignalingProtocol,
    pub signaling_server: String,
}

impl Version1SessionUri {
    pub fn from_url(url: &str) -> Result<Self, OpenLvError> {
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

        Ok(Self {
            session_id,
            key_hash: PublicKeyHash(h.clone()),
            shared_key: HandshakeKey::from_hex(k)?,
            signaling_protocol: p,
            signaling_server,
        })
    }

    pub fn to_url(&self) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("h", &self.key_hash.0.to_string());
        serializer.append_pair("k", &self.shared_key.to_string());
        serializer.append_pair("p", &self.signaling_protocol.to_string());
        serializer.append_pair("s", &self.signaling_server);
        let query = serializer.finish();

        format!(
            "openlv://{}@{}?{}",
            self.session_id, OPENLV_PROTOCOL_VERSION, query
        )
    }
}
