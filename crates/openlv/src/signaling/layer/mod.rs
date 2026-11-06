//! Signaling state machine and the two-stage message-authenticated handshake.

use std::sync::{
    Arc, Mutex as StdMutex, RwLock,
    atomic::{AtomicBool, Ordering},
};

use serde_json::Value;
use tokio::{
    sync::{Mutex, broadcast, oneshot},
    task::JoinHandle,
};

use super::{
    channel::SignalingChannel,
    message::{PeerCapabilities, PubkeyPayload, SignalingMessage},
    wire::{WirePrefix, WireRecipient, compose_frame, is_recipient, parse_frame},
};
use crate::{
    encryption::{
        AcceptedPeer, DecryptionKey, EncryptionKey, HandshakeKey, KeyPair, PeerCipher, accept_peer,
        create_peer_cipher, parse_encryption_key, validate_public_key_hash,
    },
    errors::OpenLvError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalState {
    Standby,
    Connecting,
    Ready,
    Handshake,
    HandshakePartial,
    Encrypted,
    Error,
}

#[derive(Clone)]
pub struct SignalingProperties {
    pub session_id: String,
    pub is_host: bool,
    pub h: String,
    pub handshake_key: Option<HandshakeKey>,
    pub encryption_key: EncryptionKey,
    pub decryption_key: DecryptionKey,
    pub capabilities: PeerCapabilities,
    pub resume: bool,
    pub peer_key: Option<EncryptionKey>,
}

pub struct SignalingLayer {
    inner: Arc<SignalingInner>,
}

struct SignalingInner {
    channel_type: String,
    properties: SignalingProperties,
    state: RwLock<SignalState>,
    relying_key: Arc<RwLock<Option<EncryptionKey>>>,
    peer_cipher: StdMutex<Option<PeerCipher>>,
    peer_capabilities: Arc<RwLock<Option<PeerCapabilities>>>,
    channel: Mutex<Box<dyn SignalingChannel>>,
    receive_lock: Mutex<()>,
    resume_waiter: StdMutex<Option<oneshot::Sender<()>>>,
    transport_active: AtomicBool,
    state_tx: broadcast::Sender<SignalState>,
    message_tx: broadcast::Sender<Value>,
    handshake_task: StdMutex<Option<JoinHandle<()>>>,
    deadline_task: StdMutex<Option<JoinHandle<()>>>,
}

impl SignalingLayer {
    pub fn new(
        channel: Box<dyn SignalingChannel>,
        properties: SignalingProperties,
    ) -> Result<Self, OpenLvError> {
        if properties.resume {
            if properties.peer_key.is_none() || properties.handshake_key.is_some() {
                return Err(OpenLvError::Signaling(
                    "resumed signaling requires a pinned peer and no handshake key".into(),
                ));
            }
        } else if properties.peer_key.is_some() || properties.handshake_key.is_none() {
            return Err(OpenLvError::Signaling(
                "fresh signaling requires a handshake key and no pinned peer".into(),
            ));
        }
        let (state_tx, _) = broadcast::channel(32);
        let (message_tx, _) = broadcast::channel(32);
        let peer_key = properties.peer_key.clone();
        let peer_cipher = if let Some(peer_key) = peer_key.as_ref() {
            let key_pair = KeyPair {
                encryption_key: properties.encryption_key.clone(),
                decryption_key: properties.decryption_key.clone(),
            };
            Some(create_peer_cipher(&key_pair, peer_key)?)
        } else {
            None
        };

        Ok(Self {
            inner: Arc::new(SignalingInner {
                channel_type: channel.channel_type().to_string(),
                properties,
                state: RwLock::new(SignalState::Standby),
                relying_key: Arc::new(RwLock::new(peer_key)),
                peer_cipher: StdMutex::new(peer_cipher),
                peer_capabilities: Arc::new(RwLock::new(None)),
                channel: Mutex::new(channel),
                receive_lock: Mutex::new(()),
                resume_waiter: StdMutex::new(None),
                transport_active: AtomicBool::new(false),
                state_tx,
                message_tx,
                handshake_task: StdMutex::new(None),
                deadline_task: StdMutex::new(None),
            }),
        })
    }

    /// Return the authenticated cipher negotiated with the peer.
    pub fn peer_cipher(&self) -> Option<PeerCipher> {
        self.inner
            .peer_cipher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn channel_type(&self) -> &str {
        &self.inner.channel_type
    }

    pub fn state(&self) -> SignalState {
        self.inner.state()
    }

    pub fn subscribe_state(&self) -> broadcast::Receiver<SignalState> {
        self.inner.state_tx.subscribe()
    }

    pub fn subscribe_messages(&self) -> broadcast::Receiver<Value> {
        self.inner.message_tx.subscribe()
    }

    /// Shared handle to the peer's public key, populated during the handshake.
    pub fn relying_key_handle(&self) -> Arc<RwLock<Option<EncryptionKey>>> {
        Arc::clone(&self.inner.relying_key)
    }

    pub fn peer_capabilities(&self) -> Option<PeerCapabilities> {
        self.inner
            .peer_capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Re-authenticate the existing peer and wait for its resumed capabilities.
    pub async fn resume(&self) -> Result<(), OpenLvError> {
        if self.state() != SignalState::Encrypted {
            return Err(OpenLvError::Signaling(
                "only an encrypted signaling session can resume".into(),
            ));
        }

        self.inner.transport_active.store(false, Ordering::SeqCst);
        let (resume_tx, resume_rx) = oneshot::channel();
        {
            let mut waiter = self
                .inner
                .resume_waiter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if waiter.is_some() {
                return Err(OpenLvError::Signaling(
                    "signaling resume is already in progress".into(),
                ));
            }
            *waiter = Some(resume_tx);
        }

        self.inner
            .send_repeating_retrying(
                WirePrefix::Encrypted,
                self.inner.remote_recipient(),
                self.inner.capabilities_message(),
            )
            .await;

        let result =
            match tokio::time::timeout(tokio::time::Duration::from_secs(45), resume_rx).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(OpenLvError::SessionClosed),
                Err(_) => Err(OpenLvError::Signaling(
                    "timed out resuming signaling".into(),
                )),
            };

        self.inner.stop_repeating();
        self.inner
            .resume_waiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        result
    }

    /// Mark signaling as active so late negotiation messages can be ignored.
    pub fn mark_transport_connected(&self) {
        self.inner.transport_active.store(true, Ordering::SeqCst);
    }

    pub async fn setup(&self) -> Result<(), OpenLvError> {
        let inner = &self.inner;
        inner.set_state(SignalState::Connecting);

        {
            let mut channel = inner.channel.lock().await;
            channel.setup().await?;

            let receiver = Arc::clone(inner);
            channel
                .subscribe(Box::new(move |payload| {
                    let receiver = Arc::clone(&receiver);
                    tokio::spawn(async move {
                        if let Err(error) = receiver.handle_receive(&payload).await {
                            tracing::debug!(%error, "dropping signaling frame");
                        }
                    });
                }))
                .await?;
        }

        if inner.properties.resume {
            inner.set_state(SignalState::Ready);
            inner.start_handshake_deadline();
            if !inner.properties.is_host {
                inner
                    .send_repeating_retrying(
                        WirePrefix::Encrypted,
                        WireRecipient::Host,
                        inner.capabilities_message(),
                    )
                    .await;
            }
        } else if inner.can_encrypt() {
            inner.set_state(SignalState::Encrypted);
        } else if inner.properties.is_host {
            inner.set_state(SignalState::Ready);
        } else {
            inner.set_state(SignalState::Handshake);
            inner.start_handshake_deadline();
            inner
                .send_repeating(
                    WirePrefix::Handshake,
                    WireRecipient::Host,
                    SignalingMessage::Flash {
                        payload: serde_json::json!({}),
                        timestamp: current_timestamp(),
                    },
                )
                .await?;
        }

        Ok(())
    }

    pub async fn teardown(&self) -> Result<(), OpenLvError> {
        self.inner.stop_handshake_tasks();
        let mut channel = self.inner.channel.lock().await;
        channel.teardown().await
    }

    /// Send an application payload (`data` message) to the remote peer.
    pub async fn send(&self, message: Value) -> Result<(), OpenLvError> {
        let inner = &self.inner;

        if !inner.can_encrypt() {
            return Err(OpenLvError::Signaling(
                "cannot encrypt message before keys are exchanged".into(),
            ));
        }

        inner
            .send_message(
                WirePrefix::Encrypted,
                inner.remote_recipient(),
                SignalingMessage::Data {
                    payload: message,
                    timestamp: current_timestamp(),
                },
            )
            .await
    }
}

impl SignalingInner {
    fn state(&self) -> SignalState {
        *self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_state(&self, new_state: SignalState) {
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_state;
        if matches!(new_state, SignalState::Encrypted | SignalState::Error) {
            self.stop_handshake_tasks();
        }
        let _ = self.state_tx.send(new_state);
    }

    fn can_encrypt(&self) -> bool {
        self.peer_cipher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    fn remote_recipient(&self) -> WireRecipient {
        if self.properties.is_host {
            WireRecipient::Client
        } else {
            WireRecipient::Host
        }
    }

    fn key_pair(&self) -> KeyPair {
        KeyPair {
            encryption_key: self.properties.encryption_key.clone(),
            decryption_key: self.properties.decryption_key.clone(),
        }
    }

    fn pubkey_message(&self) -> SignalingMessage {
        SignalingMessage::Pubkey {
            payload: PubkeyPayload {
                public_key: self.properties.encryption_key.to_string().to_string(),
            },
            timestamp: current_timestamp(),
        }
    }

    fn capabilities_message(&self) -> SignalingMessage {
        SignalingMessage::Capabilities {
            payload: self.properties.capabilities.clone(),
            timestamp: current_timestamp(),
        }
    }

    fn start_handshake_deadline(self: &Arc<Self>) {
        if self
            .deadline_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
        {
            return;
        }

        let inner = Arc::clone(self);
        let task = tokio::spawn(async move {
            let timeout = if inner.properties.resume { 45 } else { 30 };
            tokio::time::sleep(tokio::time::Duration::from_secs(timeout)).await;
            if inner.state() != SignalState::Encrypted {
                inner.set_state(SignalState::Error);
            }
        });
        *self
            .deadline_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }

    async fn send_repeating(
        self: &Arc<Self>,
        prefix: WirePrefix,
        recipient: WireRecipient,
        message: SignalingMessage,
    ) -> Result<(), OpenLvError> {
        self.stop_repeating();
        self.send_message(prefix, recipient, message.clone())
            .await?;
        self.start_repeating(prefix, recipient, message);
        Ok(())
    }

    async fn send_repeating_retrying(
        self: &Arc<Self>,
        prefix: WirePrefix,
        recipient: WireRecipient,
        message: SignalingMessage,
    ) {
        self.stop_repeating();
        if let Err(error) = self.send_message(prefix, recipient, message.clone()).await {
            tracing::debug!(%error, "initial signaling publish failed; retrying");
        }
        self.start_repeating(prefix, recipient, message);
    }

    fn start_repeating(
        self: &Arc<Self>,
        prefix: WirePrefix,
        recipient: WireRecipient,
        message: SignalingMessage,
    ) {
        let inner = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                if inner
                    .send_message(prefix, recipient, message.clone())
                    .await
                    .is_err()
                {
                    tracing::debug!("failed to resend signaling handshake message");
                }
            }
        });
        *self
            .handshake_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }

    fn stop_repeating(&self) {
        if let Some(task) = self
            .handshake_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }

    fn stop_handshake_tasks(&self) {
        self.stop_repeating();
        if let Some(task) = self
            .deadline_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }

    async fn send_message(
        &self,
        prefix: WirePrefix,
        recipient: WireRecipient,
        message: SignalingMessage,
    ) -> Result<(), OpenLvError> {
        let plaintext = serde_json::to_string(&message)?;
        let ciphertext = match prefix {
            WirePrefix::Handshake => self
                .properties
                .handshake_key
                .as_ref()
                .ok_or_else(|| OpenLvError::Signaling("handshake key is required".into()))?
                .encrypt(&plaintext)?,
            WirePrefix::Encrypted => self
                .peer_cipher
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .ok_or_else(|| OpenLvError::Signaling("peer cipher is not ready".into()))?
                .encrypt(&plaintext)?,
        };

        let frame = compose_frame(prefix, recipient, ciphertext);
        let channel = self.channel.lock().await;
        channel.publish(&frame).await
    }

    async fn handle_receive(self: &Arc<Self>, payload: &str) -> Result<(), OpenLvError> {
        let _receive_guard = self.receive_lock.lock().await;
        let frame = parse_frame(payload)?;

        if !is_recipient(&frame, self.properties.is_host) {
            return Ok(());
        }

        let mut accepted_peer = None;
        let plaintext = match frame.prefix {
            WirePrefix::Handshake => self
                .properties
                .handshake_key
                .as_ref()
                .ok_or_else(|| OpenLvError::Signaling("handshake key is required".into()))?
                .decrypt(&frame.ciphertext)?,
            WirePrefix::Encrypted => {
                if let Some(cipher) = self
                    .peer_cipher
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .cloned()
                {
                    cipher.decrypt(&frame.ciphertext)?
                } else if self.properties.is_host && self.state() == SignalState::Handshake {
                    let accepted = accept_peer(&self.key_pair(), &frame.ciphertext)?;
                    let message = accepted.message.clone();
                    accepted_peer = Some(accepted);
                    message
                } else {
                    return Ok(());
                }
            }
        };

        let message: SignalingMessage = serde_json::from_str(&plaintext)?;
        if let Err(reason) = message.validate() {
            tracing::debug!(%reason, "dropping invalid signaling message");
            return Ok(());
        }

        if self.transport_active.load(Ordering::SeqCst)
            && matches!(&message, SignalingMessage::Capabilities { .. })
        {
            tracing::debug!("ignoring late capabilities after transport connected");
            return Ok(());
        }

        if let Some(accepted) = accepted_peer {
            return self.handle_accepted_peer(accepted, message).await;
        }

        let is_host = self.properties.is_host;
        match (frame.prefix, &message, self.state(), is_host) {
            (WirePrefix::Handshake, SignalingMessage::Flash { .. }, SignalState::Ready, true) => {
                self.set_state(SignalState::Handshake);
                self.start_handshake_deadline();
                self.send_repeating(
                    WirePrefix::Handshake,
                    WireRecipient::Client,
                    self.pubkey_message(),
                )
                .await?;
            }
            (
                WirePrefix::Handshake,
                SignalingMessage::Pubkey { payload, .. },
                SignalState::Handshake,
                false,
            ) => {
                let received_key = parse_encryption_key(&payload.public_key)?;
                if !validate_public_key_hash(&received_key, &self.properties.h)? {
                    tracing::warn!("host public key does not match expected hash");
                    self.set_state(SignalState::Error);
                    return Ok(());
                }

                let cipher = create_peer_cipher(&self.key_pair(), &received_key)?;
                if !self.store_peer(received_key, cipher) {
                    return Ok(());
                }
                self.set_state(SignalState::HandshakePartial);
                self.send_repeating(
                    WirePrefix::Encrypted,
                    WireRecipient::Host,
                    self.pubkey_message(),
                )
                .await?;
            }
            (WirePrefix::Encrypted, SignalingMessage::Capabilities { payload, .. }, state, _)
                if state == SignalState::HandshakePartial
                    || (self.properties.resume && state == SignalState::Ready) =>
            {
                self.store_peer_capabilities(payload.clone());
                self.set_state(SignalState::Encrypted);
                if !is_host || self.properties.resume {
                    self.send_message(
                        WirePrefix::Encrypted,
                        self.remote_recipient(),
                        self.capabilities_message(),
                    )
                    .await?;
                }
            }
            (
                WirePrefix::Encrypted,
                SignalingMessage::Capabilities { payload, .. },
                SignalState::Encrypted,
                _,
            ) if self.is_resuming() => {
                self.store_peer_capabilities(payload.clone());
                if self.properties.is_host {
                    self.send_message(
                        WirePrefix::Encrypted,
                        self.remote_recipient(),
                        self.capabilities_message(),
                    )
                    .await?;
                }
                self.finish_resume();
            }
            (
                WirePrefix::Encrypted,
                SignalingMessage::Capabilities { .. },
                SignalState::Encrypted,
                false,
            ) if !self.properties.resume => {
                self.send_message(
                    WirePrefix::Encrypted,
                    WireRecipient::Host,
                    self.capabilities_message(),
                )
                .await?;
            }
            (
                WirePrefix::Encrypted,
                SignalingMessage::Data { payload, .. },
                SignalState::Encrypted,
                _,
            ) => {
                let _ = self.message_tx.send(payload.clone());
            }
            (prefix, message, state, _) => {
                tracing::debug!(?prefix, ?state, "ignoring signaling message: {message:?}");
            }
        }

        Ok(())
    }

    async fn handle_accepted_peer(
        self: &Arc<Self>,
        accepted: AcceptedPeer,
        message: SignalingMessage,
    ) -> Result<(), OpenLvError> {
        if !self.properties.is_host || self.state() != SignalState::Handshake {
            return Ok(());
        }

        let SignalingMessage::Pubkey { payload, .. } = message else {
            return Ok(());
        };
        if payload.public_key != accepted.peer_key.to_string() {
            tracing::debug!("ignoring pubkey that differs from the frame key");
            return Ok(());
        }
        if !self.store_peer(accepted.peer_key, accepted.cipher) {
            return Ok(());
        }

        self.set_state(SignalState::HandshakePartial);
        self.send_repeating(
            WirePrefix::Encrypted,
            WireRecipient::Client,
            self.capabilities_message(),
        )
        .await
    }

    fn store_peer(&self, key: EncryptionKey, cipher: PeerCipher) -> bool {
        let mut relying_key = self
            .relying_key
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if relying_key.is_some() {
            return false;
        }
        *relying_key = Some(key);
        *self
            .peer_cipher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cipher);
        true
    }

    fn store_peer_capabilities(&self, capabilities: PeerCapabilities) {
        let mut peer_capabilities = self
            .peer_capabilities
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *peer_capabilities = Some(capabilities);
    }

    fn is_resuming(&self) -> bool {
        self.resume_waiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    fn finish_resume(&self) {
        if let Some(waiter) = self
            .resume_waiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = waiter.send(());
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
