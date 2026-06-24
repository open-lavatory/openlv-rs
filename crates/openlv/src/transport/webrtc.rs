use std::sync::{Arc, RwLock};

use tokio::sync::{Mutex, broadcast, mpsc};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceServer, RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription,
    MediaEngine, Registry, register_default_interceptors,
};
use webrtc::runtime::{Runtime, default_runtime};

use super::{TransportState, message::TransportNegotiationMessage};
use crate::errors::OpenLvError;

pub const DATA_CHANNEL_LABEL: &str = "openlv-data";

#[derive(Debug)]
pub enum TransportEvent {
    Negotiation(TransportNegotiationMessage),
    Message(String),
}

struct TransportHandler {
    event_tx: mpsc::Sender<TransportEvent>,
    data_channel: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    state: Arc<RwLock<TransportState>>,
    state_tx: broadcast::Sender<TransportState>,
    runtime: Arc<dyn Runtime>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for TransportHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let Ok(json) = event.candidate.to_json() else {
            return;
        };
        let Ok(payload) = serde_json::to_string(&json) else {
            return;
        };

        let _ = self
            .event_tx
            .send(TransportEvent::Negotiation(
                TransportNegotiationMessage::Candidate { payload },
            ))
            .await;
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        store_and_poll_dc(
            dc,
            Arc::clone(&self.data_channel),
            self.event_tx.clone(),
            Arc::clone(&self.state),
            self.state_tx.clone(),
            Arc::clone(&self.runtime),
        )
        .await;
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        if state == RTCPeerConnectionState::Failed {
            set_state(&self.state, &self.state_tx, TransportState::Error);
        }
    }
}

pub struct TransportLayer {
    is_host: bool,
    state: Arc<RwLock<TransportState>>,
    state_tx: broadcast::Sender<TransportState>,
    event_tx: mpsc::Sender<TransportEvent>,
    peer_connection: Mutex<Option<Arc<dyn PeerConnection>>>,
    data_channel: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
}

impl TransportLayer {
    pub fn new(is_host: bool) -> (Self, mpsc::Receiver<TransportEvent>) {
        let (state_tx, _) = broadcast::channel(32);
        let (event_tx, event_rx) = mpsc::channel(64);

        (
            Self {
                is_host,
                state: Arc::new(RwLock::new(TransportState::Standby)),
                state_tx,
                event_tx: event_tx.clone(),
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

        let registry = Registry::new();
        let registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(transport_error)?;

        let runtime =
            default_runtime().ok_or_else(|| OpenLvError::Transport("no async runtime".into()))?;

        let handler = Arc::new(TransportHandler {
            event_tx: self.event_tx.clone(),
            data_channel: Arc::clone(&self.data_channel),
            state: Arc::clone(&self.state),
            state_tx: self.state_tx.clone(),
            runtime: Arc::clone(&runtime),
        });

        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(default_ice_servers())
            .build();

        let pc = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_handler(handler)
            .with_runtime(runtime.clone())
            .with_udp_addrs(vec!["0.0.0.0:0"])
            .build()
            .await
            .map_err(transport_error)?;

        if self.is_host {
            let dc = pc
                .create_data_channel(DATA_CHANNEL_LABEL, None)
                .await
                .map_err(transport_error)?;

            store_and_poll_dc(
                dc,
                Arc::clone(&self.data_channel),
                self.event_tx.clone(),
                Arc::clone(&self.state),
                self.state_tx.clone(),
                runtime,
            )
            .await;

            let offer = pc.create_offer(None).await.map_err(transport_error)?;

            pc.set_local_description(offer.clone())
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

        let pc: Arc<dyn PeerConnection> = Arc::new(pc);
        *self.peer_connection.lock().await = Some(pc);
        self.set_state(TransportState::Ready);
        Ok(())
    }

    pub async fn teardown(&self) -> Result<(), OpenLvError> {
        if let Some(dc) = self.data_channel.lock().await.take() {
            let _ = dc.close().await;
        }

        if let Some(pc) = self.peer_connection.lock().await.take() {
            pc.close().await.map_err(transport_error)?;
        }

        self.set_state(TransportState::Standby);
        Ok(())
    }

    pub async fn send(&self, payload: &str) -> Result<(), OpenLvError> {
        if self.state() != TransportState::Connected {
            return Err(OpenLvError::Transport("transport not connected".into()));
        }

        let channel = self.data_channel.lock().await;
        let dc = channel
            .as_ref()
            .ok_or_else(|| OpenLvError::Transport("data channel not found".into()))?;

        dc.send_text(payload)
            .await
            .map_err(transport_error)?;

        Ok(())
    }

    pub async fn handle(&self, message: TransportNegotiationMessage) -> Result<(), OpenLvError> {
        let peer_connection = self.peer_connection.lock().await;
        let pc = peer_connection
            .as_ref()
            .ok_or_else(|| OpenLvError::Transport("peer connection not found".into()))?;

        match message {
            TransportNegotiationMessage::Offer { payload } => {
                let offer: RTCSessionDescription = serde_json::from_str(&payload)?;
                pc.set_remote_description(offer)
                    .await
                    .map_err(transport_error)?;

                let answer = pc.create_answer(None).await.map_err(transport_error)?;

                pc.set_local_description(answer.clone())
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
                pc.set_remote_description(answer)
                    .await
                    .map_err(transport_error)?;
            }
            TransportNegotiationMessage::Candidate { payload } => {
                if payload.is_empty() {
                    return Ok(());
                }

                let candidate: webrtc::peer_connection::RTCIceCandidateInit =
                    serde_json::from_str(&payload)?;
                pc.add_ice_candidate(candidate)
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

async fn store_and_poll_dc(
    channel: Arc<dyn DataChannel>,
    store: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    event_tx: mpsc::Sender<TransportEvent>,
    state: Arc<RwLock<TransportState>>,
    state_tx: broadcast::Sender<TransportState>,
    runtime: Arc<dyn Runtime>,
) {
    *store.lock().await = Some(Arc::clone(&channel));

    runtime.spawn(Box::pin(async move {
        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    set_state(&state, &state_tx, TransportState::Connected);
                }
                DataChannelEvent::OnMessage(msg) => {
                    if let Ok(text) = String::from_utf8(msg.data.to_vec()) {
                        let _ = event_tx.send(TransportEvent::Message(text)).await;
                    }
                }
                DataChannelEvent::OnClose => break,
                _ => {}
            }
        }
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