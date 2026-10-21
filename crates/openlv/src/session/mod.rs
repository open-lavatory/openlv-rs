mod control;
mod response;

use control::{HandlerPermit, SessionControl};

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
};

use serde_json::Value;
use tokio::{
    sync::{OnceCell, broadcast, mpsc},
    task::JoinSet,
};
use uuid::Uuid;

use crate::{
    encryption::{DecryptionKey, EncryptionKey, HandshakeKey, KeyPair, PublicKeyHash, init_hash},
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

#[derive(Default)]
pub struct SessionInitParameters {
    pub session_id: Option<String>,
    pub h: Option<String>,
    pub k: Option<HandshakeKey>,
    pub p: Option<String>,
    pub s: Option<String>,
    pub info: Option<PeerInfo>,
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

    /// Set the identity shared with the remote peer during the handshake.
    pub fn info(mut self, info: PeerInfo) -> Self {
        self.info = Some(info);
        self
    }

    pub(crate) fn connect_url(mut self, url: String) -> Self {
        self.connect_url = Some(url);
        self
    }

    /// Finalize the session with an automatic incoming-request handler.
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
        match self.connect_url {
            Some(url) => connect_session_with_info(&url, handler, self.info).await,
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
    is_host: bool,
    status: RwLock<SessionState>,
    state_tx: broadcast::Sender<SessionStateObject>,
    request_tx: broadcast::Sender<Value>,
    response_tx: broadcast::Sender<SessionMessage>,
    signaling: SignalingLayer,
    transport: TransportLayer,
    relying_key: Arc<RwLock<Option<EncryptionKey>>>,
    error: RwLock<Option<String>>,
    decryption_key: DecryptionKey,
    on_message: RequestHandler,
    control: Arc<SessionControl>,
    close_result: OnceCell<Result<(), OpenLvError>>,
    tasks: Mutex<SessionTasks>,
}

#[derive(Default)]
struct SessionTasks {
    closed: bool,
    running: JoinSet<()>,
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
            capabilities: PeerCapabilities {
                transports: vec!["wrtc".to_string()],
                info: init.info,
            },
        },
    );

    let uri = SessionUri::new(
        &session_id,
        PublicKeyHash::from(&key_pair.encryption_key),
        handshake_key,
        protocol,
        server,
    );

    Ok(build_session(
        uri,
        true,
        signaling,
        key_pair.decryption_key,
        on_message,
    ))
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
        key_pair.decryption_key,
        on_message,
    ))
}

fn build_session(
    uri: SessionUri,
    is_host: bool,
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
            uri,
            is_host,
            status: RwLock::new(SessionState::Created),
            state_tx,
            request_tx,
            response_tx,
            signaling,
            transport,
            relying_key,
            error: RwLock::new(None),
            decryption_key,
            on_message,
            control: Arc::new(SessionControl::new()),
            close_result: OnceCell::new(),
            tasks: Mutex::new(SessionTasks::default()),
        }),
        transport_events: Arc::new(Mutex::new(Some(transport_events))),
    }
}

impl Session {
    /// Start signaling and the session's background event loops.
    pub async fn connect(&self) -> Result<(), OpenLvError> {
        self.inner
            .control
            .run_operation(async {
                let transport_events = self
                    .transport_events
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .ok_or_else(|| OpenLvError::Session("session already connected".into()))?;

                self.inner.start_event_loops(transport_events);

                self.inner.signaling.setup().await
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
                self.inner.control.wait_for_operations().await;

                self.inner.stop_tasks().await;
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

    /// Wait until the WebRTC transport reports connected.
    pub async fn wait_for_link(&self) -> Result<(), OpenLvError> {
        self.inner
            .control
            .run_operation(self.wait_for_link_inner())
            .await
    }

    async fn wait_for_link_inner(&self) -> Result<(), OpenLvError> {
        let mut transport_rx = self.inner.transport.subscribe_state();

        match self.inner.status() {
            SessionState::Connected => return Ok(()),
            SessionState::Disconnected => {
                return Err(OpenLvError::Session(
                    self.inner
                        .error()
                        .unwrap_or_else(|| "session failed to connect".into()),
                ));
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
                    self.inner.set_error("peer-to-peer transport failed");
                    self.inner.set_status(SessionState::Disconnected);
                    return Err(OpenLvError::Session(
                        self.inner
                            .error()
                            .unwrap_or_else(|| "session failed to connect".into()),
                    ));
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
        self.inner
            .control
            .run_operation(async {
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
    fn spawn_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut registry = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return;
        }
        while registry.running.try_join_next().is_some() {}
        registry.running.spawn(task);
    }

    fn start_event_loops(self: &Arc<Self>, transport_events: mpsc::Receiver<TransportEvent>) {
        self.spawn_task(Arc::clone(self).run_signal_state_loop());
        self.spawn_task(Arc::clone(self).run_signal_message_loop());
        self.spawn_task(Arc::clone(self).run_transport_state_loop());
        self.spawn_task(Arc::clone(self).run_transport_event_loop(transport_events));
    }

    async fn stop_tasks(&self) {
        let mut running = {
            let mut registry = self
                .tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.closed = true;
            std::mem::take(&mut registry.running)
        };
        running.abort_all();
        while running.join_next().await.is_some() {}
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
                SignalState::Ready => self.set_status(SessionState::Ready),
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
                TransportState::Connected => self.set_status(SessionState::Connected),
                TransportState::Error => {
                    self.set_error("peer-to-peer transport failed");
                    self.set_status(SessionState::Disconnected);
                    return;
                }
                _ => {}
            }
        }
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
        let plaintext = self.decryption_key.decrypt(&raw)?;
        let message: SessionMessage = serde_json::from_str(&plaintext)?;

        match message {
            SessionMessage::Request {
                message_id,
                payload,
            } => self.dispatch_request(message_id, payload)?,
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
        self.spawn_task(async move {
            inner
                .handle_remote_request(message_id, permit, payload)
                .await;
        });
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
        let result = self
            .control
            .run_operation(async move {
                let _permit = permit;
                let ack = SessionMessage::Ack {
                    message_id: message_id.clone(),
                };
                if let Err(error) = self.send_session_message(&ack).await {
                    tracing::warn!("failed to ack request: {error}");
                }

                let response = SessionMessage::Response {
                    message_id,
                    payload: (self.on_message)(payload).await?,
                };
                self.send_session_message(&response).await
            })
            .await;
        if let Err(error) = result {
            tracing::warn!("request handling failed: {error}");
        }
    }

    async fn send_session_message(&self, message: &SessionMessage) -> Result<(), OpenLvError> {
        let plaintext = serde_json::to_string(message)?;
        let encrypted = {
            let relying_key = self
                .relying_key
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let relying_key = relying_key
                .as_ref()
                .ok_or_else(|| OpenLvError::Session("relying party public key not found".into()))?;
            relying_key.encrypt(&plaintext)?
        };

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
mod tests {
    use super::select_transport_id;

    use futures::FutureExt;
    use serde_json::json;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::{Semaphore, mpsc};

    use crate::{OpenLvError, Session, SessionState, dapp, wallet};

    async fn callback_session() -> Session {
        dapp()
            .on_request(|message| async move { Ok(message) })
            .await
            .unwrap()
    }

    fn assert_session_closed<T>(result: Result<T, OpenLvError>) {
        assert!(matches!(result, Err(OpenLvError::Session(_))));
    }

    #[tokio::test]
    async fn closing_before_wait_for_link_returns_a_persistent_session_error() {
        let session = callback_session().await;
        session.close().await.unwrap();

        assert_session_closed(session.wait_for_link().await);
        session.closed().await;
        assert_eq!(session.state().status, SessionState::Disconnected);
    }

    #[tokio::test]
    async fn closing_cancels_an_already_waiting_public_link_operation() {
        let session = callback_session().await;
        let mut waiting = Box::pin(session.wait_for_link());
        assert!(waiting.as_mut().now_or_never().is_none());

        let (closed, result) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(session.close(), waiting)
        })
        .await
        .expect("session close did not cancel the waiting link operation");
        closed.unwrap();
        assert_session_closed(result);
    }

    #[tokio::test]
    async fn operations_created_before_close_cannot_start_after_close() {
        let session = callback_session().await;
        let connecting = session.connect();
        let waiting = session.wait_for_link();
        let sending = session.send(json!({"method": "eth_chainId"}));

        session.close().await.unwrap();

        assert_session_closed(connecting.await);
        assert_session_closed(waiting.await);
        assert_session_closed(sending.await);
    }

    #[tokio::test]
    async fn public_operations_reject_calls_after_close() {
        let session = callback_session().await;
        session.close().await.unwrap();

        assert_session_closed(session.connect().await);
        assert_session_closed(session.wait_for_link().await);
        assert_session_closed(session.send(json!(null)).await);
        assert_session_closed(session.send_with_timeouts(json!(null), 1, 1).await);
    }

    #[tokio::test]
    async fn close_is_shared_by_clones_and_wakes_existing_and_late_observers() {
        let session = callback_session().await;
        let clone = session.clone();
        let mut observed_close = Box::pin(session.closed());
        assert!(observed_close.as_mut().now_or_never().is_none());

        let (first, second, ()) = tokio::join!(session.close(), clone.close(), observed_close);
        first.unwrap();
        second.unwrap();
        clone.close().await.unwrap();
        clone.closed().await;
    }

    #[tokio::test]
    async fn callback_wallet_builder_preserves_the_connection_uri() {
        let host = callback_session().await;
        let url = host.uri().to_string();
        let client = wallet(&url)
            .on_request(|message| async move { Ok(message) })
            .await
            .unwrap();

        assert_eq!(client.uri().to_string(), url);
        assert!(!client.is_host());
        client.close().await.unwrap();
        host.close().await.unwrap();
    }

    struct CallbackResource(mpsc::UnboundedSender<()>);

    impl Drop for CallbackResource {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[tokio::test]
    async fn handler_admission_is_bounded_reusable_and_observational() {
        let gate = Arc::new(Semaphore::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let (dropped, mut drops) = mpsc::unbounded_channel();
        let session = dapp()
            .on_request({
                let gate = Arc::clone(&gate);
                move |_| {
                    let gate = Arc::clone(&gate);
                    let started = started.clone();
                    let resource = CallbackResource(dropped.clone());
                    async move {
                        let _resource = resource;
                        started.send(()).unwrap();
                        gate.acquire().await.unwrap().forget();
                        Ok(json!(null))
                    }
                }
            })
            .await
            .unwrap();
        let mut observations = session.subscribe_requests();

        for index in 0..256 {
            session
                .inner
                .dispatch_request(index.to_string(), json!(index))
                .unwrap();
            assert_eq!(observations.try_recv().unwrap(), json!(index));
        }
        for _ in 0..256 {
            tokio::time::timeout(Duration::from_secs(2), starts.recv())
                .await
                .unwrap()
                .unwrap();
        }
        assert!(matches!(
            session
                .inner
                .dispatch_request("overload".into(), json!("overload")),
            Err(OpenLvError::Session(_))
        ));
        assert!(matches!(
            observations.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), drops.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if session
                    .inner
                    .dispatch_request("replacement".into(), json!("replacement"))
                    .is_ok()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed callback did not release admission");
        assert_eq!(observations.try_recv().unwrap(), json!("replacement"));
        tokio::time::timeout(Duration::from_secs(2), starts.recv())
            .await
            .unwrap()
            .unwrap();

        session.close().await.unwrap();
        for _ in 0..256 {
            drops
                .try_recv()
                .expect("close retained a callback resource");
        }
        assert_session_closed(session.inner.dispatch_request("closed".into(), json!(null)));
    }

    #[tokio::test]
    async fn close_does_not_invoke_admitted_but_unpolled_callbacks() {
        let invoked = Arc::new(AtomicUsize::new(0));
        let session = dapp()
            .on_request({
                let invoked = Arc::clone(&invoked);
                move |_| {
                    invoked.fetch_add(1, Ordering::SeqCst);
                    async { Ok(json!(null)) }
                }
            })
            .await
            .unwrap();
        session
            .inner
            .dispatch_request("unpolled".into(), json!(null))
            .unwrap();
        session.close().await.unwrap();
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_racing_handler_admission_destroys_every_started_callback() {
        let started = Arc::new(AtomicUsize::new(0));
        let (dropped, mut drops) = mpsc::unbounded_channel();
        let session = dapp()
            .on_request({
                let started = Arc::clone(&started);
                move |_| {
                    let started = Arc::clone(&started);
                    let dropped = dropped.clone();
                    async move {
                        let _resource = CallbackResource(dropped);
                        started.fetch_add(1, Ordering::SeqCst);
                        futures::future::pending::<Result<serde_json::Value, OpenLvError>>().await
                    }
                }
            })
            .await
            .unwrap();
        let gate = Arc::new(tokio::sync::Barrier::new(97));
        let mut tasks = Vec::new();
        for index in 0..96 {
            let session = session.clone();
            let gate = Arc::clone(&gate);
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                session
                    .inner
                    .dispatch_request(index.to_string(), json!(index))
            }));
        }
        gate.wait().await;
        session.close().await.unwrap();
        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            if let Err(error) = result {
                assert_session_closed::<()>(Err(error));
            }
        }
        let mut destroyed = 0;
        while drops.try_recv().is_ok() {
            destroyed += 1;
        }
        assert_eq!(destroyed, started.load(Ordering::SeqCst));
        assert_session_closed(session.inner.dispatch_request("late".into(), json!(null)));
    }

    #[test]
    fn selects_the_first_host_preference_supported_by_the_client() {
        let host = ["ws", "wrtc"];
        let client = vec!["wrtc".to_string(), "ws".to_string()];
        assert_eq!(select_transport_id(true, &host, &client), Some("ws"));

        let client_own = ["wrtc", "ws"];
        let host_peer = vec!["ws".to_string(), "wrtc".to_string()];
        assert_eq!(
            select_transport_id(false, &client_own, &host_peer),
            Some("ws")
        );
    }

    #[test]
    fn rejects_disjoint_transport_lists() {
        let host = ["wrtc"];
        let client = vec!["ws".to_string()];
        assert_eq!(select_transport_id(true, &host, &client), None);
    }
}
