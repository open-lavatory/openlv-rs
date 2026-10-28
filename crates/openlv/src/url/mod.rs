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
        session_id: &str,
        key_hash: PublicKeyHash,
        shared_key: HandshakeKey,
        signaling_protocol: SignalingProtocol,
        signaling_server: String,
    ) -> Self {
        Self::Version1(Version1SessionUri {
            session_id: session_id.to_string(),
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
mod tests;
