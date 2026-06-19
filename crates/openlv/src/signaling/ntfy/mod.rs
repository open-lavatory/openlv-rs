use std::sync::Arc;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use regex::Regex;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::channel::{MessageHandler, SignalingChannel};
use crate::errors::OpenLvError;

pub mod url;

#[derive(Debug, Clone)]
struct NtfyConnectionInfo {
    host: String,
    protocol: &'static str,
    ws_protocol: &'static str,
    parameters: Option<String>,
}

pub struct NtfyChannel {
    topic: String,
    connection_info: NtfyConnectionInfo,
    handler: Arc<Mutex<Option<MessageHandler>>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    http_client: Option<reqwest::Client>,
}

impl NtfyChannel {
    pub fn new(topic: String, url: String) -> Result<Self, OpenLvError> {
        Ok(Self {
            topic,
            connection_info: url::parse_ntfy_url(&url)?,
            handler: Arc::new(Mutex::new(None)),
            shutdown_tx: None,
            http_client: None,
        })
    }
}

#[async_trait]
impl SignalingChannel for NtfyChannel {
    fn channel_type(&self) -> &'static str {
        "ntfy"
    }

    async fn setup(&mut self) -> Result<(), OpenLvError> {
        let ws_url = format!(
            "{}://{}/{}/ws{}",
            self.connection_info.ws_protocol,
            self.connection_info.host,
            self.topic,
            self.connection_info.parameters.as_deref().unwrap_or("")
        );

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
        let (mut write, mut read) = ws_stream.split();

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let handler = Arc::clone(&self.handler);
        let mut ready_tx = Some(ready_tx);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    message = read.next() => {
                        match message {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                                    match data.get("event").and_then(|value| value.as_str()) {
                                        Some("open") => {
                                            if let Some(tx) = ready_tx.take() {
                                                let _ = tx.send(());
                                            }
                                        }
                                        Some("message") => {
                                            if let Some(body) = data.get("message").and_then(|value| value.as_str()) {
                                                let guard = handler.lock().await;
                                                if let Some(handler) = guard.as_ref() {
                                                    handler(body.to_string());
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }
                }
            }
            let _ = write.close().await;
        });

        tokio::time::timeout(tokio::time::Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| OpenLvError::Signaling("ntfy server did not confirm open within 10s".into()))?
            .map_err(|_| OpenLvError::Signaling("ntfy ready sender dropped".into()))?;

        self.http_client = Some(reqwest::Client::new());
        Ok(())
    }

    async fn teardown(&mut self) -> Result<(), OpenLvError> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        self.http_client = None;
        Ok(())
    }

    async fn publish(&self, payload: &str) -> Result<(), OpenLvError> {
        let publish_url = format!(
            "{}://{}/{}",
            self.connection_info.protocol, self.connection_info.host, self.topic
        );

        let client = self
            .http_client
            .as_ref()
            .ok_or_else(|| OpenLvError::Signaling("ntfy client not initialized".into()))?;

        client
            .post(publish_url)
            .header("Content-Type", "application/json")
            .body(payload.to_owned())
            .send()
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        Ok(())
    }

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError> {
        *self.handler.lock().await = Some(handler);
        Ok(())
    }
}
