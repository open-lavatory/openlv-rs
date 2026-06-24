use crate::{
    encryption::{PublicKeyHash, handshake::HandshakeKey},
    errors::OpenLvError,
    signaling::SignalingProtocol,
    url::v1::Version1SessionUri,
};
use rand::RngCore;
use std::fmt::Display;

pub mod v1;

const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, PartialEq, Clone)]
pub enum SessionUri {
    Version1(v1::Version1SessionUri),
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

    pub fn to_connection_url(&self) -> String {
        match self {
            Self::Version1(version1) => version1.to_url(),
        }
    }

    pub fn from_url(url: &str) -> Result<Self, OpenLvError> {
        let v1 = Version1SessionUri::from_url(url)?;

        Ok(Self::Version1(v1))
    }
}

impl TryFrom<&str> for SessionUri {
    type Error = OpenLvError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_url(value)
    }
}

impl TryFrom<String> for SessionUri {
    type Error = OpenLvError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_url(&value)
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
        let parameters = Version1SessionUri {
            session_id: "k7n8m9x2w5q1p3r6".to_string(),
            key_hash: PublicKeyHash("a1b2c3d4e5f60708".to_string()),
            shared_key: HandshakeKey::from_hex("0123456789abcdef0123456789abcdef").unwrap(),
            signaling_protocol: SignalingProtocol::Mqtt,
            signaling_server: "wss://test.mosquitto.org:8081/mqtt".to_string(),
        };

        let encoded = parameters.to_url();
        let decoded = Version1SessionUri::from_url(&encoded).unwrap();

        assert_eq!(decoded.session_id, parameters.session_id);
        assert_eq!(decoded.key_hash.0, parameters.key_hash.0);
        assert_eq!(decoded.shared_key.to_hex(), parameters.shared_key.to_hex());
        assert_eq!(decoded.signaling_protocol, parameters.signaling_protocol);
        assert_eq!(decoded.signaling_server, parameters.signaling_server);
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
        assert!(Version1SessionUri::from_url("not-a-uri").is_err());
        assert!(
            Version1SessionUri::from_url(
                "openlv://short@1?h=abc&k=0123456789abcdef0123456789abcdef&p=mqtt&s=x"
            )
            .is_err()
        );
    }
}
