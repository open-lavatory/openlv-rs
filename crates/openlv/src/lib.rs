pub mod encryption;
pub mod errors;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod url;
pub mod utils;

pub use errors::OpenLvError;
pub use session::{
    RequestHandler, Session, SessionConfig, SessionInitParameters, SessionState,
    SessionStateObject, connect_session, create_session, dapp, request_handler, wallet,
};
pub use signaling::{SignalState, SignalingProtocol};
pub use url::SessionUri;

/// Convenient re-exports for the most common use cases.
pub mod prelude {
    pub use crate::errors::OpenLvError;
    pub use crate::session::{Session, SessionConfig, SessionState, dapp, request_handler, wallet};
    pub use crate::signaling::SignalingProtocol as Protocol;
    pub use serde_json::json;
}
