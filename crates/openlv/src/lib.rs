pub mod encryption;
pub mod errors;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod url;

pub use errors::OpenLvError;
pub use session::{
    connect_session, create_session, dapp, request_handler, RequestHandler, Session,
    SessionConfig, SessionInitParameters, SessionState, SessionStateObject, wallet,
};
pub use signaling::{SignalState, SignalingProtocol};
pub use url::{decode_connection_url, encode_connection_url, HandshakeParameters, SessionUri};

/// Convenient re-exports for the most common use cases.
pub mod prelude {
    pub use crate::errors::OpenLvError;
    pub use crate::session::{
        dapp, request_handler, Session, SessionConfig, SessionState, wallet,
    };
    pub use crate::signaling::SignalingProtocol as Protocol;
    pub use serde_json::json;
}
