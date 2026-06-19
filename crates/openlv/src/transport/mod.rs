pub mod message;
pub mod webrtc;

pub use message::{SessionMessage, TransportNegotiationMessage};
pub use webrtc::{TransportEvent, TransportLayer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Standby,
    Connecting,
    Ready,
    Connected,
    Error,
}
