//! Session orchestration: wires the signaling layer to the WebRTC transport
//! and exposes the request/ack/response messaging API.
//!
//! The public [`Session`] is a thin handle; all shared state lives in
//! `Arc<SessionInner>`, which the background loops spawned by
//! [`Session::connect`] operate on directly.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
};

use serde_json::Value;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    encryption::{init_hash, DecryptionKey, EncryptionKey, HandshakeKey, KeyPair},
    errors::OpenLvError,
    signaling::{
        create_signaling_channel, signaling_layer_from_version1, SignalState, SignalingLayer,
        SignalingProperties, SignalingProtocol,
    },
    transport::{
        SessionMessage, TransportEvent, TransportLayer, TransportNegotiationMessage,
        TransportState,
    },
    url::{
        decode_connection_url, encode_connection_url, generate_session_id, HandshakeParameters,
        SessionUri, OPENLV_PROTOCOL_VERSION,
    },
};

/// Default timeouts matching the JS implementation (10s ack, 1h response).
pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 3_600_000;

pub type RequestHandlerFuture = Pin<Box<dyn Future<Output = Result<Value, OpenLvError>> + Send>>;

/// Async handler invoked for every incoming request (parity with the JS
/// async `onMessage`).
pub type RequestHandler = Arc<dyn Fn(Value) -> RequestHandlerFuture + Send + Sync>;

/// Build a [`RequestHandler`] from an async closure.
pub fn request_handler<F, Fut>(handler: F) -> RequestHandler
where
    F: Fn(Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value, OpenLvError>> + Send + 'static,
{
    Arc::new(move |message| Box::pin(handler(message)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Created,
    Signaling,
    Ready,
    Linking,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct SessionStateObject {
    pub status: SessionState,
    pub signaling: Option<SignalState>,
}

#[derive(Default)]
pub struct SessionInitParameters {
    pub session_id: Option<String>,
    pub h: Option<String>,
    pub k: Option<HandshakeKey>,
    pub p: Option<String>,
    pub s: Option<String>,
}

// ---------------------------------------------------------------------------
// Builder API
// ---------------------------------------------------------------------------

/// Configuration builder for creating a session.
///
/// Use [`dapp()`] to start a host (dApp) session or [`wallet(url)`](wallet())
/// to connect as a client (wallet).
pub struct SessionConfig {
    connect_url: Option<String>,
    session_id: Option<String>,
    protocol: Option<SignalingProtocol>,
    server: Option<String>,
    handshake_key: Option<HandshakeKey>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connect_url: None,
            session_id: None,
            protocol: None,
            server: None,
            handshake_key: None,
        }
    }
}

impl SessionConfig {
    /// Set a fixed session ID (16 URL-safe chars). Auto-generated if omitted.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the signaling protocol ("ntfy" or "mqtt").
    pub fn protocol(mut self, p: impl Into<SignalingProtocol>) -> Self {
        self.protocol = Some(p.into());
        self
    }

    /// Set the signaling server URL.
    pub fn server(mut self, s: impl Into<String>) -> Self {
        self.server = Some(s.into());
        self
    }

    /// Set a pre-shared handshake key.
    pub fn handshake_key(mut self, k: HandshakeKey) -> Self {
        self.handshake_key = Some(k);
        self
    }

    pub(crate) fn connect_url(mut self, url: String) -> Self {
        self.connect_url = Some(url);
        self
    }

    /// Finalize the session with an incoming-request handler.
    pub async fn on_request<F, Fut>(self, handler: F) -> Result<Session, OpenLvError>
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, OpenLvError>> + Send + 'static,
    {
        let handler = request_handler(handler);
        match self.connect_url {
            Some(url) => connect_session(&url, handler).await,
            None => {
                let protocol = self
                    .protocol
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "ntfy".to_string());
                let server = self
                    .server
                    .unwrap_or_else(|| "https://ntfy.sh/".to_string());
                create_session(
                    SessionInitParameters {
                        session_id: self.session_id,
                        p: Some(protocol),
                        s: Some(server),
                        k: self.handshake_key,
                        ..Default::default()
                    },
                    handler,
                )
                .await
            }
        }
    }
}

/// Start building a host (dApp) session.
pub fn dapp() -> SessionConfig {
    SessionConfig::default()
}

/// Start building a client (wallet) session from an `openlv://` URL.
pub fn wallet(url: &str) -> SessionConfig {
    SessionConfig::default().connect_url(url.to_owned())
}

// ---------------------------------------------------------------------------
// Session handle
// ---------------------------------------------------------------------------

pub struct Session {
    inner: Arc<SessionInner>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    transport_events: Mutex<Option<mpsc::Receiver<TransportEvent>>>,
}

struct SessionInner {
    session_id: String,
    is_host: bool,
    handshake_key: HandshakeKey,
    hash: String,
    protocol: SignalingProtocol,
    server: String,
    status: RwLock<SessionState>,
    state_tx: broadcast::Sender<SessionStateObject>,
    request_tx: broadcast::Sender<Value>,
    response_tx: broadcast::Sender<SessionMessage>,
    signaling: SignalingLayer,
    transport: TransportLayer,
    relying_key: Arc<RwLock<Option<EncryptionKey>>>,
    decryption_key: DecryptionKey,
    on_message: RequestHandler,
}

pub async fn create_session(
    init: SessionInitParameters,
    on_message: RequestHandler,
) -> Result<Session, OpenLvError> {
    let session_id = init.session_id.unwrap_or_else(generate_session_id);
    let key_pair = KeyPair::generate()?;
    let handshake_key = match init.k {
        Some(key) => key,
        None => HandshakeKey::generate()?,
    };

    let init_hash = init_hash(init.h.as_deref(), &key_pair.encryption_key)?;
    let protocol = SignalingProtocol::from(init.p.unwrap_or_else(|| "ntfy".to_string()));
    let server = init.s.unwrap_or_else(|| "https://ntfy.sh/".to_string());

    let channel = create_signaling_channel(&protocol, &session_id, &server)?;
    let signaling = SignalingLayer::new(
        channel,
        SignalingProperties {
            is_host: init_hash.is_host,
            h: init_hash.hash.clone(),
            handshake_key: Some(handshake_key.clone()),
            encryption_key: key_pair.encryption_key.clone(),
            decryption_key: key_pair.decryption_key.clone(),
        },
    );

    Ok(build_session(
        session_id,
        init_hash.is_host,
        handshake_key,
        init_hash.hash,
        protocol,
        server,
        signaling,
        key_pair.decryption_key,
        on_message,
    ))
}

pub async fn connect_session(
    connection_url: &str,
    on_message: RequestHandler,
) -> Result<Session, OpenLvError> {
    let uri = decode_connection_url(connection_url)?;
    let SessionUri::Version1(version1) = uri;

    let key_pair = KeyPair::generate()?;
    let init_hash = init_hash(Some(&version1.key_hash.0), &key_pair.encryption_key)?;

    let signaling = signaling_layer_from_version1(&version1, &key_pair, init_hash.is_host)?;

    Ok(build_session(
        version1.session_id.clone(),
        init_hash.is_host,
        version1.shared_key.clone(),
        init_hash.hash,
        version1.signaling_protocol.clone(),
        version1.signaling_server.clone(),
        signaling,
        key_pair.decryption_key,
        on_message,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_session(
    session_id: String,
    is_host: bool,
    handshake_key: HandshakeKey,
    hash: String,
    protocol: SignalingProtocol,
    server: String,
    signaling: SignalingLayer,
    decryption_key: DecryptionKey,
    on_message: RequestHandler,
) -> Session {
    let (state_tx, _) = broadcast::channel(32);
    let (request_tx, _) = broadcast::channel(32);
    let (response_tx, _) = broadcast::channel(64);
    let (transport, transport_events) = TransportLayer::new(is_host);
    let relying_key = signaling.relying_key_handle();

    Session {
        inner: Arc::new(SessionInner {
            session_id,
            is_host,
            handshake_key,
            hash,
            protocol,
            server,
            status: RwLock::new(SessionState::Created),
            state_tx,
            request_tx,
            response_tx,
            signaling,
            transport,
            relying_key,
            decryption_key,
            on_message,
        }),
        tasks: Mutex::new(Vec::new()),
        transport_events: Mutex::new(Some(transport_events)),
    }
}

impl Session {
    pub async fn connect(&self) -> Result<(), OpenLvError> {
        let transport_events = self
            .transport_events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| OpenLvError::Session("session already connected".into()))?;

        self.inner.set_status(SessionState::Signaling);

        let handles = vec![
            tokio::spawn(Arc::clone(&self.inner).run_signal_state_loop()),
            tokio::spawn(Arc::clone(&self.inner).run_signal_message_loop()),
            tokio::spawn(Arc::clone(&self.inner).run_transport_event_loop(transport_events)),
        ];
        self.tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(handles);

        self.inner.signaling.setup().await
    }

    pub async fn close(&self) -> Result<(), OpenLvError> {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }

        self.inner.transport.teardown().await?;
        self.inner.signaling.teardown().await?;
        self.inner.set_status(SessionState::Disconnected);
        Ok(())
    }

    pub fn state(&self) -> SessionStateObject {
        SessionStateObject {
            status: self.inner.status(),
            signaling: Some(self.inner.signaling.state()),
        }
    }

    pub fn subscribe_state(&self) -> broadcast::Receiver<SessionStateObject> {
        self.inner.state_tx.subscribe()
    }

    pub fn handshake_parameters(&self) -> HandshakeParameters {
        HandshakeParameters {
            version: OPENLV_PROTOCOL_VERSION,
            session_id: self.inner.session_id.clone(),
            h: self.inner.hash.clone(),
            k: self.inner.handshake_key.to_hex().to_string(),
            p: self.inner.protocol.clone(),
            s: self.inner.server.clone(),
        }
    }

    pub fn connection_url(&self) -> String {
        encode_connection_url(&self.handshake_parameters())
    }

    pub fn is_host(&self) -> bool {
        self.inner.is_host
    }

    /// Wait until the WebRTC transport reports connected.
    pub async fn wait_for_link(&self) -> Result<(), OpenLvError> {
        let mut transport_rx = self.inner.transport.subscribe_state();

        match self.inner.status() {
            SessionState::Connected => return Ok(()),
            SessionState::Disconnected => {
                return Err(OpenLvError::Session("session failed to connect".into()));
            }
            _ => {}
        }

        if self.inner.transport.state() == TransportState::Connected {
            self.inner.set_status(SessionState::Connected);
            return Ok(());
        }

        loop {
            match transport_rx.recv().await {
                Ok(TransportState::Connected) => {
                    self.inner.set_status(SessionState::Connected);
                    return Ok(());
                }
                Ok(TransportState::Error) => {
                    self.inner.set_status(SessionState::Disconnected);
                    return Err(OpenLvError::Session("session failed to connect".into()));
                }
                Ok(_) => {
                    if self.inner.transport.state() == TransportState::Connected {
                        self.inner.set_status(SessionState::Connected);
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    if self.inner.transport.state() == TransportState::Connected {
                        self.inner.set_status(SessionState::Connected);
                        return Ok(());
                    }
                    return Err(OpenLvError::Session(
                        "transport state channel closed".into(),
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if self.inner.transport.state() == TransportState::Connected {
                        self.inner.set_status(SessionState::Connected);
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Send a request with the JS-default timeouts (10s ack, 1h response).
    pub async fn send(&self, message: Value) -> Result<Value, OpenLvError> {
        self.send_with_timeouts(message, DEFAULT_ACK_TIMEOUT_MS, DEFAULT_RESPONSE_TIMEOUT_MS)
            .await
    }

    pub async fn send_with_timeouts(
        &self,
        message: Value,
        ack_timeout_ms: u64,
        response_timeout_ms: u64,
    ) -> Result<Value, OpenLvError> {
        if self.inner.signaling.state() != SignalState::Encrypted {
            return Err(OpenLvError::Session("session not ready".into()));
        }

        let message_id = Uuid::new_v4().to_string();
        let session_message = SessionMessage::Request {
            message_id: message_id.clone(),
            payload: message,
        };

        // Subscribe before sending so a fast ack/response cannot be lost.
        let mut receiver = self.inner.response_tx.subscribe();
        self.inner.send_session_message(&session_message).await?;

        let ack_deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_millis(ack_timeout_ms);
        let mut ack_received = false;

        loop {
            let timeout = if ack_received {
                tokio::time::Duration::from_millis(response_timeout_ms)
            } else {
                ack_deadline.saturating_duration_since(tokio::time::Instant::now())
            };

            match tokio::time::timeout(timeout, receiver.recv()).await {
                Ok(Ok(SessionMessage::Ack { message_id: id })) if id == message_id => {
                    ack_received = true;
                }
                Ok(Ok(SessionMessage::Response {
                    message_id: id,
                    payload,
                })) if id == message_id => {
                    return Ok(payload);
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => {
                    return Err(OpenLvError::RequestTimeout(
                        "response channel closed".into(),
                    ));
                }
                Err(_) if ack_received => {
                    return Err(OpenLvError::RequestTimeout(
                        "no response after acknowledgement".into(),
                    ));
                }
                Err(_) => {
                    return Err(OpenLvError::RequestTimeout(
                        "remote peer did not acknowledge".into(),
                    ));
                }
            }
        }
    }

    pub fn subscribe_requests(&self) -> broadcast::Receiver<Value> {
        self.inner.request_tx.subscribe()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

impl SessionInner {
    fn status(&self) -> SessionState {
        *self
            .status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_status(&self, new_status: SessionState) {
        *self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_status;
        let _ = self.state_tx.send(SessionStateObject {
            status: new_status,
            signaling: Some(self.signaling.state()),
        });
    }

    /// Maps signaling states onto session states; sets up the transport once
    /// the signaling handshake completes.
    async fn run_signal_state_loop(self: Arc<Self>) {
        let mut state_rx = self.signaling.subscribe_state();

        while let Ok(signal_state) = state_rx.recv().await {
            match signal_state {
                SignalState::Ready => self.set_status(SessionState::Ready),
                SignalState::Handshake | SignalState::HandshakePartial => {
                    self.set_status(SessionState::Linking);
                }
                SignalState::Encrypted => {
                    if let Err(error) = self.transport.setup().await {
                        tracing::error!("transport setup failed: {error}");
                    }
                }
                SignalState::Error => self.set_status(SessionState::Disconnected),
                _ => {}
            }
        }
    }

    /// Routes transport negotiation messages arriving over signaling.
    /// Handles both standalone transport messages (JS-style) and
    /// SessionMessage::Request wrapping (Rust-style).
    async fn run_signal_message_loop(self: Arc<Self>) {
        let mut message_rx = self.signaling.subscribe_messages();

        while let Ok(payload) = message_rx.recv().await {
            let negotiation = match serde_json::from_value::<TransportNegotiationMessage>(
                payload.clone(),
            ) {
                Ok(nego) => Some(nego),
                Err(_) => serde_json::from_value::<SessionMessage>(payload)
                    .ok()
                    .and_then(|msg| match msg {
                        SessionMessage::Request { payload, .. } => {
                            serde_json::from_value::<TransportNegotiationMessage>(payload).ok()
                        }
                        other => {
                            let _ = self.response_tx.send(other);
                            None
                        }
                    }),
            };

            if let Some(negotiation) = negotiation {
                if let Err(error) = self.transport.handle(negotiation).await {
                    tracing::warn!("transport negotiation failed: {error}");
                }
            }
        }
    }

    /// Consumes transport events: outbound negotiation messages are relayed
    /// over signaling, inbound data-channel payloads are decrypted and routed.
    async fn run_transport_event_loop(
        self: Arc<Self>,
        mut events: mpsc::Receiver<TransportEvent>,
    ) {
        while let Some(event) = events.recv().await {
            match event {
                TransportEvent::Negotiation(negotiation) => {
                    if let Err(error) = self.relay_negotiation(negotiation).await {
                        tracing::warn!("failed to relay negotiation over signaling: {error}");
                    }
                }
                TransportEvent::Message(raw) => {
                    if let Err(error) = self.handle_transport_payload(raw).await {
                        tracing::warn!("failed to handle transport message: {error}");
                    }
                }
            }
        }
    }

    /// Sends a transport negotiation message wrapped in a session request envelope.
    async fn relay_negotiation(
        &self,
        negotiation: TransportNegotiationMessage,
    ) -> Result<(), OpenLvError> {
        let request = SessionMessage::Request {
            message_id: Uuid::new_v4().to_string(),
            payload: serde_json::to_value(negotiation)?,
        };
        self.signaling.send(serde_json::to_value(request)?).await
    }

    async fn handle_transport_payload(self: &Arc<Self>, raw: String) -> Result<(), OpenLvError> {
        let plaintext = self.decryption_key.decrypt(&raw)?;
        let message: SessionMessage = serde_json::from_str(&plaintext)?;

        match message {
            SessionMessage::Request {
                message_id,
                payload,
            } => {
                let inner = Arc::clone(self);
                tokio::spawn(async move {
                    inner.handle_remote_request(message_id, payload).await;
                });
            }
            other => {
                let _ = self.response_tx.send(other);
            }
        }

        Ok(())
    }

    /// Ack the request, invoke the user handler, and send back its response.
    async fn handle_remote_request(self: Arc<Self>, message_id: String, payload: Value) {
        let ack = SessionMessage::Ack {
            message_id: message_id.clone(),
        };
        if let Err(error) = self.send_session_message(&ack).await {
            tracing::warn!("failed to ack request: {error}");
        }

        let _ = self.request_tx.send(payload.clone());

        match (self.on_message)(payload).await {
            Ok(result) => {
                let response = SessionMessage::Response {
                    message_id,
                    payload: result,
                };
                if let Err(error) = self.send_session_message(&response).await {
                    tracing::warn!("failed to send response: {error}");
                }
            }
            Err(error) => tracing::warn!("request handler failed: {error}"),
        }
    }

    /// Encrypt a session message for the peer and send it over the transport.
    async fn send_session_message(&self, message: &SessionMessage) -> Result<(), OpenLvError> {
        let plaintext = serde_json::to_string(message)?;
        let encrypted = {
            let relying_key = self
                .relying_key
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let relying_key = relying_key.as_ref().ok_or_else(|| {
                OpenLvError::Session("relying party public key not found".into())
            })?;
            relying_key.encrypt(&plaintext)?
        };

        self.transport.send(&encrypted).await
    }
}
