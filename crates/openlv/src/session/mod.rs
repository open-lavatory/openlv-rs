mod control;
mod response;

use control::{HandlerPermit, SessionControl};

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use serde_json::Value;
use tokio::sync::{OnceCell, broadcast, mpsc};
use uuid::Uuid;

use crate::{
    encryption::{
        EncryptionKey, HandshakeKey, KeyPair, PublicKeyHash, init_hash, validate_public_key_hash,
    },
    errors::OpenLvError,
    signaling::{
        PeerCapabilities, PeerInfo, SignalState, SignalingLayer, SignalingProperties,
        SignalingProtocol, create_signaling_channel, signaling_layer_from_version1,
    },
    transport::{
        SessionMessage, TransportEvent, TransportLayer, TransportNegotiationMessage, TransportState,
    },
    url::{SessionUri, generate_session_id},
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
    pub peer_info: Option<PeerInfo>,
    pub error: Option<String>,
}

/// Key material and negotiated transport needed to resume a completed session.
pub struct SessionConnectionParameters {
    pub uri: SessionUri,
    pub key_pair: KeyPair,
    pub peer_key: EncryptionKey,
    pub selected_transport: String,
}

impl std::fmt::Debug for SessionConnectionParameters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionConnectionParameters")
            .field("uri", &self.uri)
            .field("selected_transport", &self.selected_transport)
            .finish_non_exhaustive()
    }
}

impl SessionConnectionParameters {
    fn into_init(self) -> SessionInitParameters {
        let SessionUri::Version1(version1) = self.uri;
        SessionInitParameters {
            session_id: Some(version1.session_id),
            h: Some(version1.key_hash.0),
            k: Some(version1.shared_key),
            p: Some(version1.signaling_protocol.to_string()),
            s: Some(version1.signaling_server),
            info: None,
            key_pair: Some(self.key_pair),
            peer_key: Some(self.peer_key),
            selected_transport: Some(self.selected_transport),
        }
    }
}

#[derive(Default)]
pub struct SessionInitParameters {
    pub session_id: Option<String>,
    pub h: Option<String>,
    pub k: Option<HandshakeKey>,
    pub p: Option<String>,
    pub s: Option<String>,
    pub info: Option<PeerInfo>,
    pub key_pair: Option<KeyPair>,
    pub peer_key: Option<EncryptionKey>,
    pub selected_transport: Option<String>,
}

/// Configuration builder for creating a session.
///
/// Use [`dapp()`] to start a host (dApp) session or [`wallet(url)`](wallet())
/// to connect as a client (wallet).
#[derive(Default)]
pub struct SessionConfig {
    connect_url: Option<String>,
    session_id: Option<String>,
    protocol: Option<SignalingProtocol>,
    server: Option<String>,
    handshake_key: Option<HandshakeKey>,
    info: Option<PeerInfo>,
    resume: Option<SessionConnectionParameters>,
}

impl SessionConfig {
    /// Set a fixed session ID (16 URL-safe chars). Auto-generated if omitted.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set the signaling protocol ("ntfy", "mqtt" or "nostr").
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

    /// Set the identity shared with the remote peer during the handshake.
    pub fn info(mut self, info: PeerInfo) -> Self {
        self.info = Some(info);
        self
    }

    /// Resume a previously connected session using persisted key material.
    pub fn resume(mut self, parameters: SessionConnectionParameters) -> Self {
        self.resume = Some(parameters);
        self
    }

    fn connect_url(mut self, url: String) -> Self {
        self.connect_url = Some(url);
        self
    }

    /// Finalize the session with an automatic incoming-request handler.
    /// An `Err` is answered with `failed`.
    pub async fn on_request<F, Fut>(self, handler: F) -> Result<Session, OpenLvError>
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, OpenLvError>> + Send + 'static,
    {
        let handler = request_handler(handler);
        if let Some(info) = &self.info {
            info.validate()
                .map_err(|reason| OpenLvError::Session(reason.into()))?;
        }
        if let Some(connection) = self.resume {
            return create_session(connection.into_init(), handler).await;
        }
        match self.connect_url {
            Some(url) => connect_session_with_info(&url, handler, self.info).await,
            None => {
                create_session(
                    SessionInitParameters {
                        session_id: self.session_id,
                        p: self.protocol.map(|p| p.to_string()),
                        s: self.server,
                        k: self.handshake_key,
                        info: self.info,
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

#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
    transport_events: Arc<Mutex<Option<mpsc::Receiver<TransportEvent>>>>,
}

struct SessionInner {
    uri: SessionUri,
    key_pair: KeyPair,
    is_host: bool,
    status: RwLock<SessionState>,
    state_tx: broadcast::Sender<SessionStateObject>,
    request_tx: broadcast::Sender<Value>,
    response_tx: broadcast::Sender<SessionMessage>,
    signaling: SignalingLayer,
    transport: TransportLayer,
    error: RwLock<Option<String>>,
    on_message: RequestHandler,
    control: Arc<SessionControl>,
    close_result: OnceCell<Result<(), OpenLvError>>,
    peer_closed: AtomicBool,
}

pub async fn create_session(
    init: SessionInitParameters,
    on_message: RequestHandler,
) -> Result<Session, OpenLvError> {
    let session_id = init.session_id.clone().unwrap_or_else(generate_session_id);
    let key_pair = match init.key_pair {
        Some(key_pair) => key_pair,
        None => KeyPair::generate()?,
    };
    let peer_key = init.peer_key;
    let resume = peer_key.is_some();
    if resume && init.selected_transport.as_deref() != Some("wrtc") {
        return Err(OpenLvError::Session(
            "resumption requires the previously selected wrtc transport".into(),
        ));
    }
    let handshake_key = match init.k {
        Some(key) => key,
        None => HandshakeKey::generate()?,
    };

    let init_hash = init_hash(init.h.as_deref(), &key_pair.encryption_key)?;
    if let Some(peer_key) = &peer_key {
        if peer_key.as_bytes() == key_pair.encryption_key.as_bytes() {
            return Err(OpenLvError::Session(
                "resumption requires distinct local and peer keys".into(),
            ));
        }
        if !init_hash.is_host && !validate_public_key_hash(peer_key, &init_hash.hash)? {
            return Err(OpenLvError::Session(
                "resumed peer key does not match the session host hash".into(),
            ));
        }
    }
    let protocol = SignalingProtocol::from(
        init.p
            .ok_or_else(|| OpenLvError::Session("signaling protocol is required".into()))?,
    );
    let server = init
        .s
        .ok_or_else(|| OpenLvError::Session("signaling server is required".into()))?;

    let channel = create_signaling_channel(&protocol, &session_id, &server)?;
    let signaling = SignalingLayer::new(
        channel,
        SignalingProperties {
            session_id: session_id.clone(),
            is_host: init_hash.is_host,
            h: init_hash.hash.clone(),
            handshake_key: (!resume).then(|| handshake_key.clone()),
            encryption_key: key_pair.encryption_key.clone(),
            decryption_key: key_pair.decryption_key.clone(),
            capabilities: PeerCapabilities {
                transports: vec!["wrtc".to_string()],
                info: init.info,
            },
            resume,
            peer_key,
        },
    )?;

    let uri = SessionUri::new(
        &session_id,
        PublicKeyHash(init_hash.hash),
        handshake_key,
        protocol,
        server,
    );

    Ok(build_session(
        uri,
        init_hash.is_host,
        signaling,
        key_pair,
        on_message,
    ))
}

pub async fn resume_session(
    parameters: SessionConnectionParameters,
    on_message: RequestHandler,
) -> Result<Session, OpenLvError> {
    create_session(parameters.into_init(), on_message).await
}

pub async fn connect_session(
    connection_url: &str,
    on_message: RequestHandler,
) -> Result<Session, OpenLvError> {
    connect_session_with_info(connection_url, on_message, None).await
}

async fn connect_session_with_info(
    connection_url: &str,
    on_message: RequestHandler,
    info: Option<PeerInfo>,
) -> Result<Session, OpenLvError> {
    let uri = SessionUri::from_url(connection_url)?;
    let SessionUri::Version1(version1) = uri.clone();

    let key_pair = KeyPair::generate()?;
    let init_hash = init_hash(Some(&version1.key_hash.0), &key_pair.encryption_key)?;

    let signaling = signaling_layer_from_version1(
        &version1,
        &key_pair,
        init_hash.is_host,
        PeerCapabilities {
            transports: vec!["wrtc".to_string()],
            info,
        },
    )?;

    Ok(build_session(
        uri,
        init_hash.is_host,
        signaling,
        key_pair,
        on_message,
    ))
}

fn build_session(
    uri: SessionUri,
    is_host: bool,
    signaling: SignalingLayer,
    key_pair: KeyPair,
    on_message: RequestHandler,
) -> Session {
    let (state_tx, _) = broadcast::channel(32);
    let (request_tx, _) = broadcast::channel(32);
    let (response_tx, _) = broadcast::channel(64);
    let (transport, transport_events) = TransportLayer::new(is_host);

    Session {
        inner: Arc::new(SessionInner {
            uri,
            key_pair,
            is_host,
            status: RwLock::new(SessionState::Created),
            state_tx,
            request_tx,
            response_tx,
            signaling,
            transport,
            error: RwLock::new(None),
            on_message,
            control: Arc::new(SessionControl::new()),
            close_result: OnceCell::new(),
            peer_closed: AtomicBool::new(false),
        }),
        transport_events: Arc::new(Mutex::new(Some(transport_events))),
    }
}

impl Session {
    /// Start signaling and the session's background event loops.
    pub async fn connect(&self) -> Result<(), OpenLvError> {
        let inner = Arc::clone(&self.inner);
        let transport_events = Arc::clone(&self.transport_events);
        self.inner
            .control
            .run_operation(async move {
                let transport_events = transport_events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .ok_or_else(|| OpenLvError::Session("session already connected".into()))?;

                inner.set_status(SessionState::Signaling);
                inner.start_event_loops(transport_events)?;

                inner.signaling.setup().await
            })
            .await
    }

    /// Permanently close the session, cancel its work, and release its transports.
    ///
    /// Concurrent and repeated calls share the same teardown result.
    pub async fn close(&self) -> Result<(), OpenLvError> {
        self.inner.control.close();
        self.inner
            .close_result
            .get_or_init(|| async {
                if let Err(error) = self
                    .inner
                    .send_session_message(&SessionMessage::Close)
                    .await
                {
                    tracing::debug!(error = %error, "close message not sent");
                }
                self.inner.control.wait_for_tasks().await;

                let transport_result = self.inner.transport.teardown().await;
                let signaling_result = self.inner.signaling.teardown().await;
                self.inner.set_status(SessionState::Disconnected);
                transport_result.and(signaling_result)
            })
            .await
            .clone()
    }

    /// Wait for permanent closure, including when the session is already closed.
    pub async fn closed(&self) {
        self.inner.control.closed().await;
    }

    pub fn state(&self) -> SessionStateObject {
        SessionStateObject {
            status: self.inner.status(),
            signaling: Some(self.inner.signaling.state()),
            peer_info: self
                .inner
                .signaling
                .peer_capabilities()
                .and_then(|capabilities| capabilities.info),
            error: self.inner.error(),
        }
    }

    pub fn subscribe_state(&self) -> broadcast::Receiver<SessionStateObject> {
        self.inner.state_tx.subscribe()
    }

    pub fn is_host(&self) -> bool {
        self.inner.is_host
    }

    pub fn uri(&self) -> &SessionUri {
        &self.inner.uri
    }

    /// Return the persisted key material required to resume this session.
    pub fn resume_parameters(&self) -> Result<SessionConnectionParameters, OpenLvError> {
        if self.inner.signaling.state() != SignalState::Encrypted
            || self.inner.transport.state() != TransportState::Connected
        {
            return Err(OpenLvError::Session(
                "session is not connected and cannot be resumed".into(),
            ));
        }

        let peer_key = self
            .inner
            .signaling
            .relying_key_handle()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| OpenLvError::Session("peer key is not available".into()))?;
        let selected_transport = self
            .inner
            .select_transport()
            .ok_or_else(|| OpenLvError::Session("no selected transport".into()))?;

        Ok(SessionConnectionParameters {
            uri: self.inner.uri.clone(),
            key_pair: self.inner.key_pair.clone(),
            peer_key,
            selected_transport,
        })
    }

    /// Wait until the WebRTC transport reports connected.
    pub async fn wait_for_link(&self) -> Result<(), OpenLvError> {
        let inner = Arc::clone(&self.inner);
        self.inner
            .control
            .run_operation(async move { inner.wait_for_link().await })
            .await
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
        let inner = Arc::clone(&self.inner);
        self.inner
            .control
            .run_operation(async move {
                if inner.signaling.state() != SignalState::Encrypted {
                    return Err(OpenLvError::Session("session not ready".into()));
                }

                let message_id = Uuid::new_v4().to_string();
                let session_message = SessionMessage::Request {
                    message_id: message_id.clone(),
                    payload: message,
                };

                // Subscribe before sending so a fast ack/response cannot be lost.
                let mut receiver = inner.response_tx.subscribe();
                inner.send_session_message(&session_message).await?;
                response::receive_response(
                    &mut receiver,
                    &message_id,
                    ack_timeout_ms,
                    response_timeout_ms,
                )
                .await
            })
            .await
    }

    /// Observe accepted request payloads without owning their responses.
    ///
    /// This broadcast stream may lag; the configured handler owns each response.
    pub fn subscribe_requests(&self) -> broadcast::Receiver<Value> {
        self.inner.request_tx.subscribe()
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        self.control.close();
    }
}

impl SessionInner {
    fn start_event_loops(
        self: &Arc<Self>,
        transport_events: mpsc::Receiver<TransportEvent>,
    ) -> Result<(), OpenLvError> {
        self.control
            .spawn(Arc::clone(self).run_signal_state_loop())?;
        self.control
            .spawn(Arc::clone(self).run_signal_message_loop())?;
        self.control
            .spawn(Arc::clone(self).run_transport_state_loop())?;
        self.control
            .spawn(Arc::clone(self).run_transport_event_loop(transport_events))?;
        Ok(())
    }

    async fn wait_for_link(&self) -> Result<(), OpenLvError> {
        let mut state_rx = self.state_tx.subscribe();
        loop {
            match self.status() {
                SessionState::Connected => return Ok(()),
                SessionState::Disconnected => {
                    return Err(OpenLvError::Session(
                        self.error()
                            .unwrap_or_else(|| "session failed to connect".into()),
                    ));
                }
                _ => {}
            }

            match state_rx.recv().await {
                Ok(SessionStateObject {
                    status: SessionState::Connected,
                    ..
                }) => return Ok(()),
                Ok(SessionStateObject {
                    status: SessionState::Disconnected,
                    error,
                    ..
                }) => {
                    return Err(OpenLvError::Session(
                        error.unwrap_or_else(|| "session failed to connect".into()),
                    ));
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(OpenLvError::Session("session state channel closed".into()));
                }
            }
        }
    }

    fn status(&self) -> SessionState {
        *self
            .status
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn error(&self) -> Option<String> {
        self.error
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_error(&self, error: impl Into<String>) {
        *self
            .error
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.into());
    }

    fn clear_error(&self) {
        *self
            .error
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn set_transport_error(&self) {
        if !self.peer_closed.load(Ordering::SeqCst) {
            self.set_error("peer-to-peer transport failed");
        }
    }

    fn select_transport(&self) -> Option<String> {
        let peer = self.signaling.peer_capabilities()?;
        select_transport_id(self.is_host, &["wrtc"], &peer.transports).map(str::to_string)
    }

    fn set_status(&self, new_status: SessionState) {
        *self
            .status
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_status;
        let _ = self.state_tx.send(SessionStateObject {
            status: new_status,
            signaling: Some(self.signaling.state()),
            peer_info: self
                .signaling
                .peer_capabilities()
                .and_then(|capabilities| capabilities.info),
            error: self.error(),
        });
    }

    async fn run_signal_state_loop(self: Arc<Self>) {
        let mut state_rx = self.signaling.subscribe_state();

        while let Ok(signal_state) = state_rx.recv().await {
            match signal_state {
                SignalState::Ready if self.status() != SessionState::Linking => {
                    self.set_status(SessionState::Ready);
                }
                SignalState::Ready => {}
                SignalState::Handshake | SignalState::HandshakePartial => {
                    self.set_status(SessionState::Linking);
                }
                SignalState::Encrypted => {
                    if self.select_transport().is_none() {
                        self.set_error("no common transport with peer");
                        self.set_status(SessionState::Disconnected);
                    } else if let Err(error) = self.transport.setup().await {
                        tracing::error!("transport setup failed: {error}");
                        self.set_error(error.to_string());
                        self.set_status(SessionState::Disconnected);
                    }
                }
                SignalState::Error => {
                    self.set_error("signaling failed or timed out");
                    self.set_status(SessionState::Disconnected);
                }
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
            let negotiation =
                match serde_json::from_value::<TransportNegotiationMessage>(payload.clone()) {
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

            if let Some(negotiation) = negotiation
                && let Err(error) = self.transport.handle(negotiation).await
            {
                tracing::warn!("transport negotiation failed: {error}");
            }
        }
    }

    async fn run_transport_state_loop(self: Arc<Self>) {
        let mut state_rx = self.transport.subscribe_state();
        while let Ok(state) = state_rx.recv().await {
            match state {
                TransportState::Connected => {
                    self.signaling.mark_transport_connected();
                    self.clear_error();
                    self.set_status(SessionState::Connected);
                }
                TransportState::Error => {
                    if self.transport.state() != TransportState::Error {
                        continue;
                    }
                    self.set_transport_error();
                    if self.status() == SessionState::Connected {
                        self.set_status(SessionState::Linking);
                        if let Err(error) = self.recover_transport().await {
                            self.set_error(error.to_string());
                            self.set_status(SessionState::Disconnected);
                            return;
                        }
                    } else if self.status() != SessionState::Linking {
                        self.set_status(SessionState::Disconnected);
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    async fn recover_transport(&self) -> Result<(), OpenLvError> {
        self.transport.teardown().await?;
        self.signaling.resume().await?;
        self.transport.setup().await
    }

    async fn run_transport_event_loop(self: Arc<Self>, mut events: mpsc::Receiver<TransportEvent>) {
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
        let cipher = self
            .signaling
            .peer_cipher()
            .ok_or_else(|| OpenLvError::Session("peer cipher not ready".into()))?;
        let plaintext = cipher.decrypt(&raw)?;
        self.handle_session_frame(&plaintext)
    }

    fn handle_session_frame(self: &Arc<Self>, plaintext: &str) -> Result<(), OpenLvError> {
        let message: SessionMessage = serde_json::from_str(plaintext)?;

        match message {
            SessionMessage::Request {
                message_id,
                payload,
            } => self.dispatch_request(message_id, payload)?,
            SessionMessage::Close => {
                self.peer_closed.store(true, Ordering::SeqCst);
                self.clear_error();
                let _ = self.response_tx.send(SessionMessage::Close);
                self.set_status(SessionState::Disconnected);
            }
            SessionMessage::Unknown => tracing::debug!("ignoring session message of unknown type"),
            other => {
                let _ = self.response_tx.send(other);
            }
        }

        Ok(())
    }

    fn dispatch_request(
        self: &Arc<Self>,
        message_id: String,
        payload: Value,
    ) -> Result<(), OpenLvError> {
        let permit = self.control.admit_handler()?;
        self.observe_request(&payload);
        let inner = Arc::clone(self);
        self.control.spawn(async move {
            inner
                .handle_remote_request(message_id, permit, payload)
                .await;
        })?;
        Ok(())
    }

    fn observe_request(&self, payload: &Value) {
        if self.request_tx.receiver_count() != 0 {
            let _ = self.request_tx.send(payload.clone());
        }
    }

    /// Keep admission through the ack, response production, and wire response.
    async fn handle_remote_request(
        &self,
        message_id: String,
        permit: HandlerPermit,
        payload: Value,
    ) {
        let result = async move {
            let _permit = permit;
            let ack = SessionMessage::Ack {
                message_id: message_id.clone(),
            };
            if let Err(error) = self.send_session_message(&ack).await {
                tracing::warn!("failed to ack request: {error}");
            }

            let outcome = (self.on_message)(payload).await;
            if let Err(error) = &outcome {
                tracing::warn!(error = %error, "request handler failed");
            }
            self.send_session_message(&SessionMessage::reply(message_id, outcome))
                .await
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(error = %error, "request handling failed");
        }
    }

    async fn send_session_message(&self, message: &SessionMessage) -> Result<(), OpenLvError> {
        let plaintext = serde_json::to_string(message)?;
        let cipher = self
            .signaling
            .peer_cipher()
            .ok_or_else(|| OpenLvError::Session("peer cipher not ready".into()))?;
        let encrypted = cipher.encrypt(&plaintext)?;

        self.transport.send(&encrypted).await
    }
}

fn select_transport_id<'a>(
    is_host: bool,
    own_transports: &'a [&'a str],
    peer_transports: &'a [String],
) -> Option<&'a str> {
    let host_preference: Vec<&str> = if is_host {
        own_transports.to_vec()
    } else {
        peer_transports.iter().map(String::as_str).collect()
    };
    let client_supported: Vec<&str> = if is_host {
        peer_transports.iter().map(String::as_str).collect()
    } else {
        own_transports.to_vec()
    };
    host_preference
        .into_iter()
        .find(|transport| client_supported.contains(transport))
}

#[cfg(test)]
mod tests;
