//! UniFFI bridge for the openlv session API.
//!
//! Options, messages and states cross the boundary as JSON strings.

use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

uniffi::setup_scaffolding!();

/// A failed bridge call.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BridgeError {
    /// `kind` is the snake case name of the failure, such as `session_closed`.
    #[error("{message}")]
    Failure { kind: String, message: String },
}

impl BridgeError {
    fn failure(kind: &str, message: impl std::fmt::Display) -> Self {
        Self::Failure {
            kind: kind.to_owned(),
            message: message.to_string(),
        }
    }
}

impl From<openlv::OpenLvError> for BridgeError {
    fn from(value: openlv::OpenLvError) -> Self {
        use openlv::OpenLvError as E;
        let kind = match &value {
            E::InvalidUri(_) => "invalid_uri",
            E::Signaling(_) => "signaling",
            E::Transport(_) => "transport",
            E::Session(_) => "session",
            E::SessionClosed => "session_closed",
            E::RequestLimitReached => "request_limit_reached",
            E::RequestFailed => "request_failed",
            E::InvalidRequestTimeout => "invalid_request_timeout",
            E::ResponseChannelClosed => "response_channel_closed",
            E::Encryption(_) => "encryption",
            E::WireFrame(_) => "wire_frame",
            E::ProtocolViolation(_) => "protocol_violation",
            E::UnsupportedProtocol(_) => "unsupported_protocol",
            E::NoConnection => "no_connection",
            E::RequestTimeout(_) => "request_timeout",
            E::Other(_) => "other",
        };
        Self::failure(kind, value)
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("the bridge needs its Tokio runtime for every session")
    });
    &RUNTIME
}

// Foreign executors poll bridge futures outside Tokio, so the work runs on the
// bridge runtime. Dropping the foreign future cancels that work.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn on_runtime<T: Send + 'static>(
    future: impl Future<Output = Result<T, BridgeError>> + Send + 'static,
) -> Result<T, BridgeError> {
    let mut task = AbortOnDrop(runtime().spawn(future));
    (&mut task.0)
        .await
        .map_err(|error| BridgeError::failure("other", error))?
}

#[derive(Deserialize)]
struct PeerInfo {
    identity: String,
    name: String,
    icon: Option<String>,
}

impl TryFrom<PeerInfo> for openlv::PeerInfo {
    type Error = BridgeError;

    fn try_from(value: PeerInfo) -> Result<Self, Self::Error> {
        let info = Self {
            identity: value.identity,
            name: value.name,
            icon: value.icon,
        };
        info.validate()
            .map_err(|reason| BridgeError::failure("session", reason))?;
        Ok(info)
    }
}

#[derive(Deserialize)]
struct SessionOptions {
    session_id: Option<String>,
    protocol: Option<String>,
    server: Option<String>,
    handshake_key: Option<String>,
    peer_info: Option<PeerInfo>,
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, BridgeError> {
    serde_json::from_str(value).map_err(|error| BridgeError::failure("other", error))
}

// The native handler either returns a response or reports that it failed. A
// failure makes the core answer the peer with `failed`.
type Answer = Result<String, openlv::OpenLvError>;

struct Request {
    id: u64,
    message: String,
}

struct Requests {
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
    sender: mpsc::UnboundedSender<Request>,
    receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<Request>>,
    stop: watch::Sender<bool>,
}

// Remove entries if the core cancels a request while the handler is pending.
struct PendingRequest {
    requests: Arc<Requests>,
    id: u64,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.requests.pending.lock().remove(&self.id);
    }
}

impl Requests {
    fn new() -> Arc<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let (stop, _) = watch::channel(false);
        Arc::new(Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
            stop,
        })
    }

    async fn handle(
        self: Arc<Self>,
        value: serde_json::Value,
    ) -> Result<serde_json::Value, openlv::OpenLvError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock();
            if *self.stop.borrow() {
                return Err(openlv::OpenLvError::SessionClosed);
            }
            pending.insert(id, tx);
            let request = Request {
                id,
                message: value.to_string(),
            };
            if self.sender.send(request).is_err() {
                pending.remove(&id);
                return Err(openlv::OpenLvError::SessionClosed);
            }
        }
        let _pending = PendingRequest { requests: self, id };
        let reply = rx.await.map_err(|_| openlv::OpenLvError::SessionClosed)??;
        serde_json::from_str(&reply).map_err(Into::into)
    }

    async fn next(&self) -> Option<Request> {
        let mut stop = self.stop.subscribe();
        let mut receiver = self.receiver.lock().await;
        loop {
            if *stop.borrow() {
                return None;
            }
            tokio::select! {
                biased;
                _ = stop.changed() => return None,
                request = receiver.recv() => match request {
                    Some(request) if self.pending.lock().contains_key(&request.id) => {
                        return Some(request);
                    }
                    Some(_) => continue,
                    None => return None,
                }
            }
        }
    }

    fn stop(&self) {
        let mut pending = self.pending.lock();
        self.stop.send_replace(true);
        pending.clear();
    }

    fn reply(&self, id: u64, answer: Answer) -> Result<(), BridgeError> {
        let sender = self
            .pending
            .lock()
            .remove(&id)
            .ok_or_else(|| BridgeError::failure("session", "Request is no longer pending"))?;
        sender
            .send(answer)
            .map_err(|_| BridgeError::failure("session", "Request is no longer pending"))
    }

    fn fail(&self, id: u64) -> Result<(), BridgeError> {
        let error = openlv::OpenLvError::Other("native request handler failed".into());
        self.reply(id, Err(error))
    }
}

/// An openlv session. Remote requests arrive through [`Session::next_request`].
#[derive(uniffi::Object)]
pub struct Session {
    inner: openlv::Session,
    requests: Arc<Requests>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.requests.stop();
    }
}

impl Session {
    async fn create(config: openlv::SessionConfig) -> Result<Arc<Self>, BridgeError> {
        let requests = Requests::new();
        let handler = Arc::clone(&requests);
        let inner = config
            .on_request(move |value| Arc::clone(&handler).handle(value))
            .await?;
        Ok(Arc::new(Self { inner, requests }))
    }
}

/// Create a host (dApp) session from JSON options with the required keys `protocol` and `server`
/// and the optional keys `session_id`, `handshake_key` (hex) and `peer_info`.
#[uniffi::export]
pub async fn create_dapp(options_json: String) -> Result<Arc<Session>, BridgeError> {
    on_runtime(async move {
        let options: SessionOptions = parse_json(&options_json)?;
        let peer = options
            .peer_info
            .map(openlv::PeerInfo::try_from)
            .transpose()?;
        let mut config = openlv::dapp();
        if let Some(id) = options.session_id {
            config = config.session_id(id);
        }
        if let Some(protocol) = options.protocol {
            config = config.protocol(protocol);
        }
        if let Some(server) = options.server {
            config = config.server(server);
        }
        if let Some(key) = options.handshake_key {
            config = config.handshake_key(openlv::encryption::HandshakeKey::from_hex(&key)?);
        }
        if let Some(peer) = peer {
            config = config.info(peer);
        }
        Session::create(config).await
    })
    .await
}

/// Create a client (wallet) session from an `openlv://` connection URL.
/// `peer_info_json` is `null` or an object with `identity`, `name` and `icon`.
#[uniffi::export]
pub async fn create_wallet(
    uri: String,
    peer_info_json: String,
) -> Result<Arc<Session>, BridgeError> {
    on_runtime(async move {
        let peer: Option<PeerInfo> = parse_json(&peer_info_json)?;
        let mut config = openlv::wallet(&uri);
        if let Some(peer) = peer {
            config = config.info(peer.try_into()?);
        }
        Session::create(config).await
    })
    .await
}

/// Parse an `openlv://` connection URL into a JSON object with `session_id`,
/// `key_hash`, `handshake_key`, `protocol` and `server`.
#[uniffi::export]
pub fn parse_session_uri(url: String) -> Result<String, BridgeError> {
    let openlv::SessionUri::Version1(uri) = openlv::SessionUri::from_url(&url)?;
    Ok(json!({
        "session_id": uri.session_id,
        "key_hash": uri.key_hash.0,
        "handshake_key": uri.shared_key.to_hex().to_string(),
        "protocol": uri.signaling_protocol.to_string(),
        "server": uri.signaling_server,
    })
    .to_string())
}

/// Generate a random session id.
#[uniffi::export]
pub fn generate_session_id() -> String {
    openlv::url::generate_session_id()
}

fn state_json(state: openlv::SessionStateObject) -> String {
    let status = match state.status {
        openlv::SessionState::Created => "created",
        openlv::SessionState::Signaling => "signaling",
        openlv::SessionState::Ready => "ready",
        openlv::SessionState::Linking => "linking",
        openlv::SessionState::Connected => "connected",
        openlv::SessionState::Recovering => "recovering",
        openlv::SessionState::Disconnected => "disconnected",
    };
    let signaling = state.signaling.map(|signaling| match signaling {
        openlv::SignalState::Standby => "standby",
        openlv::SignalState::Connecting => "connecting",
        openlv::SignalState::Ready => "ready",
        openlv::SignalState::Handshake => "handshake",
        openlv::SignalState::HandshakePartial => "handshake_partial",
        openlv::SignalState::Encrypted => "encrypted",
        openlv::SignalState::Error => "error",
    });
    let peer = state.peer_info.map(|peer| {
        json!({
            "identity": peer.identity,
            "name": peer.name,
            "icon": peer.icon,
        })
    });
    json!({
        "status": status,
        "signaling": signaling,
        "peer": peer,
        "error": state.error,
    })
    .to_string()
}

#[uniffi::export]
impl Session {
    // uniffi-bindgen-dart 0.2.0 cannot call a synchronous object method that
    // returns a string, so these three stay async.

    /// The `openlv://` connection URL.
    pub async fn uri(&self) -> String {
        self.inner.uri().to_string()
    }

    /// The session id from the connection URL.
    pub async fn session_id(&self) -> String {
        let openlv::SessionUri::Version1(uri) = self.inner.uri();
        uri.session_id.clone()
    }

    /// The current state as a JSON object with `status`, `signaling`, `peer`
    /// and `error`. Status and signaling values are snake case.
    pub async fn state(&self) -> String {
        state_json(self.inner.state())
    }

    /// Whether this side is the host (dApp).
    pub fn is_host(&self) -> bool {
        self.inner.is_host()
    }

    /// Subscribe to state changes from now on.
    pub fn subscribe_states(&self) -> Arc<StateSubscription> {
        Arc::new(StateSubscription {
            inner: self.inner.clone(),
            receiver: Arc::new(tokio::sync::Mutex::new(self.inner.subscribe_state())),
        })
    }

    /// Connect the signaling layer and start the handshake.
    pub async fn connect(&self) -> Result<(), BridgeError> {
        let session = self.inner.clone();
        on_runtime(async move { Ok(session.connect().await?) }).await
    }

    /// Wait until the peer-to-peer transport is connected.
    pub async fn wait_for_link(&self) -> Result<(), BridgeError> {
        let session = self.inner.clone();
        on_runtime(async move { Ok(session.wait_for_link().await?) }).await
    }

    /// Send a JSON request with the default timeouts and return the JSON
    /// response.
    pub async fn send(&self, message: String) -> Result<String, BridgeError> {
        let session = self.inner.clone();
        on_runtime(async move {
            let response = session.send(parse_json(&message)?).await?;
            Ok(response.to_string())
        })
        .await
    }

    /// Send a JSON request and return the JSON response. The response timeout
    /// starts at the acknowledgement.
    pub async fn send_with_timeouts(
        &self,
        message: String,
        ack_timeout_ms: u64,
        response_timeout_ms: u64,
    ) -> Result<String, BridgeError> {
        let session = self.inner.clone();
        on_runtime(async move {
            let response = session
                .send_with_timeouts(parse_json(&message)?, ack_timeout_ms, response_timeout_ms)
                .await?;
            Ok(response.to_string())
        })
        .await
    }

    /// Wait for the next remote request, as a JSON object with the numeric `id`
    /// for [`Session::respond`] or [`Session::fail`] and the JSON `message`.
    /// `None` once the session is closed.
    pub async fn next_request(&self) -> Result<Option<String>, BridgeError> {
        let requests = Arc::clone(&self.requests);
        let session = self.inner.clone();
        on_runtime(async move {
            let request = tokio::select! {
                biased;
                () = session.closed() => None,
                request = requests.next() => request,
            };
            Ok(request
                .map(|request| json!({"id": request.id, "message": request.message}).to_string()))
        })
        .await
    }

    /// Answer request `id` with a JSON response.
    pub fn respond(&self, id: u64, response: String) -> Result<(), BridgeError> {
        self.requests.reply(id, Ok(response))
    }

    /// Answer request `id` with `failed`, so the requester fails at once.
    pub fn fail(&self, id: u64) -> Result<(), BridgeError> {
        self.requests.fail(id)
    }

    /// Cancel pending requests and close the session.
    pub async fn shutdown(&self) -> Result<(), BridgeError> {
        self.requests.stop();
        let session = self.inner.clone();
        on_runtime(async move { Ok(session.close().await?) }).await
    }
}

/// A stream of session states.
#[derive(uniffi::Object)]
pub struct StateSubscription {
    inner: openlv::Session,
    receiver: Arc<tokio::sync::Mutex<broadcast::Receiver<openlv::SessionStateObject>>>,
}

#[uniffi::export]
impl StateSubscription {
    /// Wait for the next state as JSON, shaped as in [`Session::state`].
    /// `None` once the session is closed.
    pub async fn next_state(&self) -> Result<Option<String>, BridgeError> {
        let session = self.inner.clone();
        let receiver = Arc::clone(&self.receiver);
        on_runtime(async move {
            let mut receiver = receiver.lock().await;
            loop {
                tokio::select! {
                    biased;
                    () = session.closed() => return Ok(None),
                    state = receiver.recv() => match state {
                        Ok(state) => return Ok(Some(state_json(state))),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return Ok(None),
                    }
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests;
