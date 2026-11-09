use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use k256::schnorr::SigningKey;
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

use super::channel::{MessageHandler, SignalingChannel};
use crate::errors::OpenLvError;

const KIND: u16 = 21_337;

#[cfg(test)]
mod tests;

enum Command {
    Publish(String),
    Subscribe {
        handler: MessageHandler,
        subscribed: oneshot::Sender<Result<(), OpenLvError>>,
    },
}

pub struct NostrChannel {
    relay: String,
    topic: String,
    signing_key: SigningKey,
    commands: Option<mpsc::UnboundedSender<Command>>,
}

impl NostrChannel {
    pub fn new(topic: String, relay: String) -> Result<Self, OpenLvError> {
        if relay.is_empty() {
            return Err(OpenLvError::Signaling(
                "nostr signaling requires a relay URL".into(),
            ));
        }
        Ok(Self {
            relay,
            topic,
            signing_key: SigningKey::random(&mut rand::thread_rng()),
            commands: None,
        })
    }

    fn event(&self, content: &str, created_at: u64) -> Result<Value, OpenLvError> {
        let pubkey = hex(&self.signing_key.verifying_key().to_bytes());
        let tags = [["x", self.topic.as_str()]];
        let serialized = serde_json::to_vec(&(0, &pubkey, created_at, KIND, tags, content))?;
        let id = Sha256::digest(serialized);

        let mut aux_rand = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut aux_rand);
        let sig = self
            .signing_key
            .sign_raw(&id, &aux_rand)
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        Ok(json!({
            "id": hex(&id),
            "pubkey": pubkey,
            "created_at": created_at,
            "kind": KIND,
            "tags": tags,
            "content": content,
            "sig": hex(&sig.to_bytes()),
        }))
    }

    fn commands(&self) -> Result<&mpsc::UnboundedSender<Command>, OpenLvError> {
        self.commands.as_ref().ok_or(OpenLvError::NoConnection)
    }
}

#[async_trait]
impl SignalingChannel for NostrChannel {
    fn channel_type(&self) -> &'static str {
        "nostr"
    }

    async fn setup(&mut self) -> Result<(), OpenLvError> {
        let (socket, _) = connect_async(self.relay.as_str()).await.map_err(|error| {
            OpenLvError::Signaling(format!(
                "could not connect to nostr relay {}: {error}",
                self.relay
            ))
        })?;
        let (commands, receiver) = mpsc::unbounded_channel();
        tokio::spawn(run(socket, self.topic.clone(), receiver));
        self.commands = Some(commands);
        Ok(())
    }

    async fn teardown(&mut self) -> Result<(), OpenLvError> {
        self.commands = None;
        Ok(())
    }

    async fn publish(&self, payload: &str) -> Result<(), OpenLvError> {
        let commands = self.commands()?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_secs();
        let event = self.event(payload, created_at)?;
        commands
            .send(Command::Publish(json!(["EVENT", event]).to_string()))
            .map_err(|_| relay_closed())
    }

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError> {
        let (subscribed, confirmation) = oneshot::channel();
        self.commands()?
            .send(Command::Subscribe {
                handler,
                subscribed,
            })
            .map_err(|_| relay_closed())?;
        confirmation.await.map_err(|_| relay_closed())?
    }
}

async fn run(
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    topic: String,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let (mut sink, mut stream) = socket.split();
    let mut handler = None;
    let mut subscribed = None;

    loop {
        tokio::select! {
            command = commands.recv() => {
                let outgoing = match command {
                    Some(Command::Publish(event)) => event,
                    Some(Command::Subscribe { handler: next, subscribed: confirmation }) => {
                        handler = Some(next);
                        subscribed = Some(confirmation);
                        json!(["REQ", topic, { "kinds": [KIND], "#x": [topic] }]).to_string()
                    }
                    None => break,
                };
                if sink.send(Message::text(outgoing)).await.is_err() {
                    break;
                }
            }
            incoming = stream.next() => {
                let text = match incoming {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => continue,
                };
                let Ok(Value::Array(message)) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };

                match message.as_slice() {
                    [kind, subscription, event, ..] if *kind == "EVENT" && *subscription == topic => {
                        if let (Some(handler), Some(content)) =
                            (&handler, event.get("content").and_then(Value::as_str))
                        {
                            handler(content.to_owned());
                        }
                    }
                    [kind, subscription, ..] if *kind == "EOSE" && *subscription == topic => {
                        if let Some(confirmation) = subscribed.take() {
                            let _ = confirmation.send(Ok(()));
                        }
                    }
                    [kind, subscription, rest @ ..] if *kind == "CLOSED" && *subscription == topic => {
                        let reason = rest.first().and_then(Value::as_str).unwrap_or_default();
                        tracing::warn!(nostr.reason = reason, "nostr relay closed subscription");
                        if let Some(confirmation) = subscribed.take() {
                            let _ = confirmation.send(Err(OpenLvError::Signaling(format!(
                                "nostr relay closed subscription: {reason}"
                            ))));
                        }
                    }
                    [kind, _, accepted, rest @ ..] if *kind == "OK" && *accepted == false => {
                        let reason = rest.first().and_then(Value::as_str).unwrap_or_default();
                        tracing::warn!(nostr.reason = reason, "nostr relay refused event");
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = sink.close().await;
}

fn relay_closed() -> OpenLvError {
    OpenLvError::Signaling("nostr relay closed the connection".into())
}

fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}
