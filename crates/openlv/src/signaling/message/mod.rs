use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SignalingMessage {
    #[serde(rename = "flash")]
    Flash { payload: Value, timestamp: u64 },
    #[serde(rename = "pubkey")]
    Pubkey {
        payload: PubkeyPayload,
        timestamp: u64,
    },
    #[serde(rename = "capabilities")]
    Capabilities {
        payload: PeerCapabilities,
        timestamp: u64,
    },
    #[serde(rename = "data")]
    Data { payload: Value, timestamp: u64 },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyPayload {
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub identity: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct PeerCapabilities {
    pub transports: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<PeerInfo>,
}

impl PeerInfo {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !is_bounded_string(&self.identity, 128) {
            return Err("peer identity must be 1-128 characters");
        }
        if !is_bounded_string(&self.name, 128) {
            return Err("peer name must be 1-128 characters");
        }
        if let Some(icon) = &self.icon
            && !is_bounded_string(icon, 8192)
        {
            return Err("peer icon must be 1-8192 characters");
        }
        Ok(())
    }
}

impl PeerCapabilities {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.transports.is_empty() || self.transports.len() > 8 {
            return Err("transports must contain 1-8 entries");
        }
        if !self
            .transports
            .iter()
            .all(|transport| is_bounded_string(transport, 32))
        {
            return Err("transport identifiers must be 1-32 characters");
        }
        if let Some(info) = &self.info {
            info.validate()?;
        }
        Ok(())
    }
}

impl SignalingMessage {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Flash { payload, .. } | Self::Data { payload, .. } if !payload.is_object() => {
                Err("signaling payload must be an object")
            }
            Self::Pubkey { payload, .. } if payload.public_key.is_empty() => {
                Err("public key must not be empty")
            }
            Self::Capabilities { payload, .. } => payload.validate(),
            _ => Ok(()),
        }
    }
}

fn is_bounded_string(value: &str, max_length: usize) -> bool {
    !value.is_empty() && value.len() <= max_length
}

#[cfg(test)]
mod tests;
