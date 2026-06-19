//! WebRTC transport. Instead of callback setters, the transport emits
//! [`TransportEvent`]s on an mpsc channel handed out at construction; the
//! session layer consumes them in a single loop.

use std::sync::{Arc, RwLock};

use tokio::sync::{broadcast, mpsc, Mutex};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use super::{message::TransportNegotiationMessage, TransportState};
use crate::errors::OpenLvError;

pub const DATA_CHANNEL_LABEL: &str = "openlv-data";

/// Events the transport emits towards the session layer.
#[derive(Debug)]
pub enum TransportEvent {
    /// SDP/ICE negotiation message that must be relayed over signaling.
    Negotiation(TransportNegotiationMessage),
    /// Raw (still encrypted) payload received over the data channel.
    Message(String),
}

pub struct TransportLayer {
    is_host: bool,
    state: Arc<RwLock<TransportState>>,
    state_tx: broadcast::Sender<TransportState>,
    event_tx: mpsc::Sender<TransportEvent>,
    peer_connection: Mutex<Option<Arc<RTCPeerConnection>>>,
    data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
}

impl TransportLayer {
    /// Returns the transport plus the receiver for its events.
    pub fn new(is_host: bool) -> (Self, mpsc::Receiver<TransportEvent>) {
        let (state_tx, _) = broadcast::channel(32);
        let (event_tx, event_rx) = mpsc::channel(64);

        (
            Self {
                is_host,
                state: Arc::new(RwLock::new(TransportState::Standby)),
                state_tx,
                event_tx,
                peer_connection: Mutex::new(None),
                data_channel: Arc::new(Mutex::new(None)),
            },
            event_rx,
        )
    }

    pub fn state(&self) -> TransportState {
        *self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn subscribe_state(&self) -> broadcast::Receiver<TransportState> {
        self.state_tx.subscribe()
    }

    fn set_state(&self, new_state: TransportState) {
        set_state(&self.state, &self.state_tx, new_state);
    }

    pub async fn setup(&self) -> Result<(), OpenLvError> {
        self.set_state(TransportState::Connecting);

        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(transport_error)?;

        let registry = register_default_interceptors(Default::default(), &mut media_engine)
            .map_err(transport_error)?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let config = RTCConfiguration {
            ice_servers: default_ice_servers(),
            ..Default::default()
        };

        let peer_connection = Arc::new(
            api.new_peer_connection(config)
                .await
                .map_err(transport_error)?,
        );

        peer_connection.on_ice_candidate(Box::new({
            let event_tx = self.event_tx.clone();
            move |candidate| {
                let event_tx = event_tx.clone();
                Box::pin(async move {
                    let Some(candidate) = candidate else { return };
                    let Ok(json) = candidate.to_json() else { return };
                    let Ok(payload) = serde_json::to_string(&json) else { return };

                    let _ = event_tx
                        .send(TransportEvent::Negotiation(
                            TransportNegotiationMessage::Candidate { payload },
                        ))
                        .await;
                })
            }
        }));

        // The client side receives the host-created data channel here.
        peer_connection.on_data_channel(Box::new({
            let data_channel = Arc::clone(&self.data_channel);
            let event_tx = self.event_tx.clone();
            let state = Arc::clone(&self.state);
            let state_tx = self.state_tx.clone();
            move |channel| {
                let data_channel = Arc::clone(&data_channel);
                let event_tx = event_tx.clone();
                let state = Arc::clone(&state);
                let state_tx = state_tx.clone();
                Box::pin(async move {
                    hook_data_channel(channel, data_channel, event_tx, state, state_tx).await;
                })
            }
        }));

        if self.is_host {
            let channel = peer_connection
                .create_data_channel(DATA_CHANNEL_LABEL, Some(RTCDataChannelInit::default()))
                .await
                .map_err(transport_error)?;

            hook_data_channel(
                channel,
                Arc::clone(&self.data_channel),
                self.event_tx.clone(),
                Arc::clone(&self.state),
                self.state_tx.clone(),
            )
            .await;

            let offer = peer_connection
                .create_offer(None)
                .await
                .map_err(transport_error)?;

            peer_connection
                .set_local_description(offer.clone())
                .await
                .map_err(transport_error)?;

            let _ = self
                .event_tx
                .send(TransportEvent::Negotiation(
                    TransportNegotiationMessage::Offer {
                        payload: serde_json::to_string(&offer)?,
                    },
                ))
                .await;
        }

        *self.peer_connection.lock().await = Some(peer_connection);
        self.set_state(TransportState::Ready);
        Ok(())
    }

    pub async fn teardown(&self) -> Result<(), OpenLvError> {
        if let Some(channel) = self.data_channel.lock().await.take() {
            let _ = channel.close().await;
        }

        if let Some(peer_connection) = self.peer_connection.lock().await.take() {
            peer_connection.close().await.map_err(transport_error)?;
        }

        self.set_state(TransportState::Standby);
        Ok(())
    }

    /// Send a pre-encrypted payload over the data channel.
    pub async fn send(&self, payload: &str) -> Result<(), OpenLvError> {
        if self.state() != TransportState::Connected {
            return Err(OpenLvError::Transport("transport not connected".into()));
        }

        let channel = self.data_channel.lock().await;
        let channel = channel
            .as_ref()
            .ok_or_else(|| OpenLvError::Transport("data channel not found".into()))?;

        channel
            .send_text(payload.to_string())
            .await
            .map_err(transport_error)?;

        Ok(())
    }

    /// Apply a negotiation message received over signaling.
    pub async fn handle(&self, message: TransportNegotiationMessage) -> Result<(), OpenLvError> {
        let peer_connection = self.peer_connection.lock().await;
        let peer_connection = peer_connection
            .as_ref()
            .ok_or_else(|| OpenLvError::Transport("peer connection not found".into()))?;

        match message {
            TransportNegotiationMessage::Offer { payload } => {
                let offer: RTCSessionDescription = serde_json::from_str(&payload)?;
                peer_connection
                    .set_remote_description(offer)
                    .await
                    .map_err(transport_error)?;

                let answer = peer_connection
                    .create_answer(None)
                    .await
                    .map_err(transport_error)?;

                peer_connection
                    .set_local_description(answer.clone())
                    .await
                    .map_err(transport_error)?;

                let _ = self
                    .event_tx
                    .send(TransportEvent::Negotiation(
                        TransportNegotiationMessage::Answer {
                            payload: serde_json::to_string(&answer)?,
                        },
                    ))
                    .await;
            }
            TransportNegotiationMessage::Answer { payload } => {
                let answer: RTCSessionDescription = serde_json::from_str(&payload)?;
                peer_connection
                    .set_remote_description(answer)
                    .await
                    .map_err(transport_error)?;
            }
            TransportNegotiationMessage::Candidate { payload } => {
                if payload.is_empty() {
                    return Ok(());
                }

                let candidate: RTCIceCandidateInit = serde_json::from_str(&payload)?;
                peer_connection
                    .add_ice_candidate(candidate)
                    .await
                    .map_err(transport_error)?;
            }
        }

        Ok(())
    }

    pub async fn wait_for(&self, target: TransportState) -> Result<(), OpenLvError> {
        let mut receiver = self.subscribe_state();

        if self.state() == target {
            return Ok(());
        }

        loop {
            match receiver.recv().await {
                Ok(state) if state == target => return Ok(()),
                Ok(_) => {
                    if self.state() == target {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    if self.state() == target {
                        return Ok(());
                    }
                    return Err(OpenLvError::Transport(
                        "transport state channel closed".into(),
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if self.state() == target {
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn hook_data_channel(
    channel: Arc<RTCDataChannel>,
    store: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    event_tx: mpsc::Sender<TransportEvent>,
    state: Arc<RwLock<TransportState>>,
    state_tx: broadcast::Sender<TransportState>,
) {
    *store.lock().await = Some(Arc::clone(&channel));

    channel.on_open(Box::new(move || {
        Box::pin(async move {
            set_state(&state, &state_tx, TransportState::Connected);
        })
    }));

    channel.on_message(Box::new(move |message| {
        let event_tx = event_tx.clone();
        Box::pin(async move {
            if let Ok(text) = String::from_utf8(message.data.to_vec()) {
                let _ = event_tx.send(TransportEvent::Message(text)).await;
            }
        })
    }));
}

fn set_state(
    state: &RwLock<TransportState>,
    state_tx: &broadcast::Sender<TransportState>,
    new_state: TransportState,
) {
    *state
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_state;
    let _ = state_tx.send(new_state);
}

fn transport_error(error: impl std::fmt::Display) -> OpenLvError {
    OpenLvError::Transport(error.to_string())
}

fn default_ice_servers() -> Vec<RTCIceServer> {
    vec![
        RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        },
        RTCIceServer {
            urls: vec!["stun:stun1.l.google.com:19302".to_string()],
            ..Default::default()
        },
    ]
}
