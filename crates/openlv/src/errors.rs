use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenLvError {
    #[error("invalid session URI: {0}")]
    InvalidUri(String),

    #[error("signaling error: {0}")]
    Signaling(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("invalid wire frame: {0}")]
    WireFrame(String),

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("unsupported signaling protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("no signaling connection")]
    NoConnection,

    #[error("request timed out: {0}")]
    RequestTimeout(String),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for OpenLvError {
    fn from(value: serde_json::Error) -> Self {
        Self::Other(value.to_string())
    }
}
