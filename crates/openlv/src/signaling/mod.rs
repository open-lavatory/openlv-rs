pub mod channel;
pub mod layer;
pub mod message;
pub mod mqtt;
pub mod nostr;
pub mod ntfy;
pub mod wire;

use std::fmt::Display;

pub use channel::SignalingChannel;
pub use layer::{SignalState, SignalingLayer, SignalingProperties};
pub use message::{PeerCapabilities, PeerInfo, SignalingMessage};

use crate::{
    encryption::{EncryptionKey, KeyPair},
    errors::OpenLvError,
    url::v1::Version1SessionUri,
};

#[derive(Debug, PartialEq, Clone)]
pub enum SignalingProtocol {
    Mqtt,
    Ntfy,
    Nostr,
    Unsupported(String),
}

impl From<String> for SignalingProtocol {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "mqtt" => Self::Mqtt,
            "ntfy" => Self::Ntfy,
            "nostr" => Self::Nostr,
            other => Self::Unsupported(other.to_string()),
        }
    }
}

impl From<&str> for SignalingProtocol {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

impl Display for SignalingProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mqtt => write!(f, "mqtt"),
            Self::Ntfy => write!(f, "ntfy"),
            Self::Nostr => write!(f, "nostr"),
            Self::Unsupported(value) => write!(f, "{value}"),
        }
    }
}

pub fn create_signaling_channel(
    protocol: &SignalingProtocol,
    topic: &str,
    server: &str,
) -> Result<Box<dyn SignalingChannel>, OpenLvError> {
    match protocol {
        SignalingProtocol::Mqtt => Ok(Box::new(mqtt::MqttChannel::new(
            server.to_string(),
            topic.to_string(),
        ))),
        SignalingProtocol::Ntfy => Ok(Box::new(ntfy::NtfyChannel::new(
            topic.to_string(),
            server.to_string(),
        )?)),
        SignalingProtocol::Nostr => Ok(Box::new(nostr::NostrChannel::new(
            topic.to_string(),
            server.to_string(),
        )?)),
        SignalingProtocol::Unsupported(value) => {
            Err(OpenLvError::UnsupportedProtocol(value.clone()))
        }
    }
}

pub fn signaling_layer_from_version1(
    version1: &Version1SessionUri,
    key_pair: &KeyPair,
    is_host: bool,
    capabilities: PeerCapabilities,
) -> Result<SignalingLayer, OpenLvError> {
    signaling_layer_from_version1_with_resume(
        version1,
        key_pair,
        is_host,
        capabilities,
        false,
        None,
    )
}

pub fn signaling_layer_from_version1_with_resume(
    version1: &Version1SessionUri,
    key_pair: &KeyPair,
    is_host: bool,
    capabilities: PeerCapabilities,
    resume: bool,
    peer_key: Option<EncryptionKey>,
) -> Result<SignalingLayer, OpenLvError> {
    let channel = create_signaling_channel(
        &version1.signaling_protocol,
        &version1.session_id,
        &version1.signaling_server,
    )?;
    let properties = SignalingProperties {
        session_id: version1.session_id.clone(),
        is_host,
        h: version1.key_hash.0.clone(),
        handshake_key: (!resume).then(|| version1.shared_key.clone()),
        encryption_key: key_pair.encryption_key.clone(),
        decryption_key: key_pair.decryption_key.clone(),
        capabilities,
        resume,
        peer_key,
    };

    SignalingLayer::new(channel, properties)
}
