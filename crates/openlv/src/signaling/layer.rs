//! Signaling state machine, mirroring `createSignalingLayer` in
//! `@openlv/signaling`. A thin [`SignalingLayer`] handle wraps an
//! `Arc<SignalingInner>` so the channel receive callback and public API share
//! the same state without duplicated plumbing.

use std::sync::{Arc, RwLock};

use serde_json::Value;
use tokio::sync::{broadcast, Mutex};

use super::{
    channel::SignalingChannel,
    message::{PubkeyPayload, SignalingMessage},
    wire::{compose_frame, is_recipient, parse_frame, WirePrefix, WireRecipient},
};
use crate::{
    encryption::{
        parse_encryption_key, validate_public_key_hash, DecryptionKey, EncryptionKey,
        HandshakeKey,
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
    pub is_host: bool,
    pub h: String,
    pub handshake_key: Option<HandshakeKey>,
    pub encryption_key: EncryptionKey,
    pub decryption_key: DecryptionKey,
}

pub struct SignalingLayer {
    inner: Arc<SignalingInner>,
}

struct SignalingInner {
    channel_type: String,
    properties: SignalingProperties,
    state: RwLock<SignalState>,
    relying_key: Arc<RwLock<Option<EncryptionKey>>>,
    channel: Mutex<Box<dyn SignalingChannel>>,
    state_tx: broadcast::Sender<SignalState>,
    message_tx: broadcast::Sender<Value>,
}

impl SignalingLayer {
    pub fn new(channel: Box<dyn SignalingChannel>, properties: SignalingProperties) -> Self {
        let (state_tx, _) = broadcast::channel(32);
        let (message_tx, _) = broadcast::channel(32);

        Self {
            inner: Arc::new(SignalingInner {
                channel_type: channel.channel_type().to_string(),
                properties,
                state: RwLock::new(SignalState::Standby),
                relying_key: Arc::new(RwLock::new(None)),
                channel: Mutex::new(channel),
                state_tx,
                message_tx,
            }),
        }
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
                            tracing::warn!("signaling receive error: {error}");
                        }
                    });
                }))
                .await?;
        }

        if inner.can_encrypt() {
            inner.set_state(SignalState::Encrypted);
        } else if inner.properties.is_host {
            inner.set_state(SignalState::Ready);
        } else {
            inner.set_state(SignalState::Ready);
            inner
                .send_message(
                    WirePrefix::Handshake,
                    WireRecipient::Host,
                    SignalingMessage::Flash {
                        payload: Value::Object(Default::default()),
                        timestamp: current_timestamp(),
                    },
                )
                .await?;
            inner.set_state(SignalState::Handshake);
        }

        Ok(())
    }

    pub async fn teardown(&self) -> Result<(), OpenLvError> {
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
        let _ = self.state_tx.send(new_state);
    }

    fn can_encrypt(&self) -> bool {
        self.relying_key
            .read()
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

    fn pubkey_message(&self) -> SignalingMessage {
        SignalingMessage::Pubkey {
            payload: PubkeyPayload {
                public_key: self.properties.encryption_key.to_string().to_string(),
                d_app_info: None,
            },
            timestamp: current_timestamp(),
        }
    }

    fn ack_message(&self) -> SignalingMessage {
        SignalingMessage::Ack {
            payload: None,
            timestamp: current_timestamp(),
        }
    }

    /// Encrypt a signaling message for the given wire prefix and publish it.
    async fn send_message(
        &self,
        prefix: WirePrefix,
        recipient: WireRecipient,
        message: SignalingMessage,
    ) -> Result<(), OpenLvError> {
        let plaintext = serde_json::to_string(&message)?;
        let body = match prefix {
            WirePrefix::Handshake => {
                let handshake_key = self.properties.handshake_key.as_ref().ok_or_else(|| {
                    OpenLvError::Signaling("handshake key is required".into())
                })?;
                handshake_key.encrypt(&plaintext)?
            }
            WirePrefix::Encrypted => {
                let relying_key = self
                    .relying_key
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let relying_key = relying_key.as_ref().ok_or_else(|| {
                    OpenLvError::Signaling("relying party public key not found".into())
                })?;
                relying_key.encrypt(&plaintext)?
            }
        };

        let frame = compose_frame(prefix, recipient, body);
        let channel = self.channel.lock().await;
        channel.publish(&frame).await
    }

    async fn handle_receive(self: &Arc<Self>, payload: &str) -> Result<(), OpenLvError> {
        let frame = parse_frame(payload)?;

        if !is_recipient(&frame, self.properties.is_host) {
            return Ok(());
        }

        let plaintext = match frame.prefix {
            WirePrefix::Handshake => {
                let handshake_key = self.properties.handshake_key.as_ref().ok_or_else(|| {
                    OpenLvError::Signaling("handshake key is required".into())
                })?;
                handshake_key.decrypt(&frame.body)?
            }
            WirePrefix::Encrypted => self.properties.decryption_key.decrypt(&frame.body)?,
        };

        let message: SignalingMessage = serde_json::from_str(&plaintext)?;
        let is_host = self.properties.is_host;

        match (frame.prefix, &message, self.state(), is_host) {
            // Host receives the client's flash and replies with its pubkey.
            (WirePrefix::Handshake, SignalingMessage::Flash { .. }, SignalState::Ready, true) => {
                self.set_state(SignalState::Handshake);
                self.send_message(
                    WirePrefix::Handshake,
                    WireRecipient::Client,
                    self.pubkey_message(),
                )
                .await?;
            }

            // Client validates the host pubkey against `h` and replies with
            // its own pubkey under peer encryption.
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

                self.store_relying_key(received_key);
                self.set_state(SignalState::HandshakePartial);
                self.send_message(
                    WirePrefix::Encrypted,
                    WireRecipient::Host,
                    self.pubkey_message(),
                )
                .await?;
            }

            // Host records the client pubkey, sends ack, and enters encrypted
            // mode (matching JS behaviour where no ack echo is required).
            (
                WirePrefix::Encrypted,
                SignalingMessage::Pubkey { payload, .. },
                SignalState::Handshake,
                true,
            ) => {
                let received_key = parse_encryption_key(&payload.public_key)?;

                self.store_relying_key(received_key);
                self.send_message(
                    WirePrefix::Encrypted,
                    WireRecipient::Client,
                    self.ack_message(),
                )
                .await?;
                self.set_state(SignalState::Encrypted);
            }

            // Both sides enter encrypted mode on ack; the client echoes a
            // final ack back to the host for robustness.
            (
                WirePrefix::Encrypted,
                SignalingMessage::Ack { .. },
                SignalState::HandshakePartial,
                _,
            ) => {
                self.set_state(SignalState::Encrypted);

                if !is_host {
                    self.send_message(
                        WirePrefix::Encrypted,
                        WireRecipient::Host,
                        self.ack_message(),
                    )
                    .await?;
                }
            }

            // Ignore ack echoes when already encrypted (harmless race).
            (
                WirePrefix::Encrypted,
                SignalingMessage::Ack { .. },
                SignalState::Encrypted,
                _,
            ) => {
                // already encrypted, ack echo is redundant
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

    fn store_relying_key(&self, key: EncryptionKey) {
        *self
            .relying_key
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(key);
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
