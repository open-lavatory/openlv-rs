use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::OpenLvError;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct TransportNegotiationMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub payload: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(tag = "type")]
pub enum SessionMessage {
    #[serde(rename = "request")]
    Request {
        #[serde(rename = "messageId")]
        message_id: String,
        payload: Value,
    },
    #[serde(rename = "response")]
    Response {
        #[serde(rename = "messageId")]
        message_id: String,
        payload: Value,
    },
    #[serde(rename = "ack")]
    Ack {
        #[serde(rename = "messageId")]
        message_id: String,
    },
    #[serde(rename = "failed")]
    Failed {
        #[serde(rename = "messageId")]
        message_id: String,
    },
}

impl SessionMessage {
    pub fn reply(message_id: String, outcome: Result<Value, OpenLvError>) -> Self {
        match outcome {
            Ok(payload) => Self::Response {
                message_id,
                payload,
            },
            Err(_) => Self::Failed { message_id },
        }
    }
}

#[cfg(test)]
mod tests;
