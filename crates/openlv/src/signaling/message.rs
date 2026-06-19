use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SignalingMessage {
    #[serde(rename = "flash")]
    Flash {
        payload: Value,
        timestamp: u64,
    },
    #[serde(rename = "pubkey")]
    Pubkey {
        payload: PubkeyPayload,
        timestamp: u64,
    },
    #[serde(rename = "ack")]
    Ack {
        #[serde(skip_serializing_if = "Option::is_none")]
        payload: Option<Value>,
        timestamp: u64,
    },
    #[serde(rename = "data")]
    Data {
        payload: Value,
        timestamp: u64,
    },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyPayload {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d_app_info: Option<DAppInfo>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DAppInfo {
    pub name: String,
    pub url: String,
    pub icon: String,
}
