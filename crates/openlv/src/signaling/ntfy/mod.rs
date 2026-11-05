use std::{fmt, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{SinkExt, StreamExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::header::{AUTHORIZATION, HeaderValue},
    },
};

use super::channel::{MessageHandler, SignalingChannel};
use crate::errors::OpenLvError;

pub mod url;

#[derive(Debug, Clone)]
pub struct NtfyConnectionInfo {
    host: String,
    protocol: &'static str,
    ws_protocol: &'static str,
    credentials: Option<NtfyCredentials>,
    parameters: Option<String>,
}

/// Credentials from the userinfo part of an ntfy server URL.
#[derive(Clone, PartialEq, Eq)]
enum NtfyCredentials {
    UserPassword { user: String, password: String },
    Token(String),
}

impl NtfyCredentials {
    fn authorization(&self) -> String {
        match self {
            Self::UserPassword { user, password } => {
                format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
            }
            Self::Token(token) => format!("Bearer {token}"),
        }
    }
}

impl fmt::Debug for NtfyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserPassword { .. } => formatter.write_str("UserPassword(..)"),
            Self::Token(_) => formatter.write_str("Token(..)"),
        }
    }
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

fn is_allowed_attachment(attachment_url: &str, origin: &str) -> bool {
    let Ok(attachment) = ::url::Url::parse(attachment_url) else {
        return false;
    };
    let Ok(origin) = ::url::Url::parse(origin) else {
        return false;
    };

    attachment.scheme() == origin.scheme()
        && attachment.host_str() == origin.host_str()
        && attachment.port_or_known_default() == origin.port_or_known_default()
        && attachment.username().is_empty()
        && attachment.password().is_none()
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

        let mut ws_request = ws_url
            .into_client_request()
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
        if let Some(credentials) = &self.connection_info.credentials {
            let authorization = HeaderValue::from_str(&credentials.authorization())
                .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
            ws_request
                .headers_mut()
                .insert(AUTHORIZATION, authorization);
        }

        let (ws_stream, _) = connect_async(ws_request)
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
        let (mut write, mut read) = ws_stream.split();

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let handler = Arc::clone(&self.handler);
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
        let attachment_origin = format!(
            "{}://{}",
            self.connection_info.protocol, self.connection_info.host
        );
        let attachment_client = http_client.clone();
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
                                                let body = match data
                                                    .get("attachment")
                                                    .and_then(|attachment| attachment.get("url"))
                                                    .and_then(|url| url.as_str())
                                                {
                                                    Some(url) => {
                                                        if !is_allowed_attachment(url, &attachment_origin) {
                                                            continue;
                                                        }
                                                        match attachment_client.get(url).send().await {
                                                            Ok(response) => match response.text().await {
                                                                Ok(text) => text,
                                                                Err(_) => continue,
                                                            },
                                                            Err(_) => continue,
                                                        }
                                                    }
                                                    None => body.to_owned(),
                                                };

                                                let guard = handler.lock().await;
                                                if let Some(handler) = guard.as_ref() {
                                                    handler(body);
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
            .map_err(|_| {
                OpenLvError::Signaling("ntfy server did not confirm open within 10s".into())
            })?
            .map_err(|_| OpenLvError::Signaling("ntfy ready sender dropped".into()))?;

        self.http_client = Some(http_client);
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

        let mut request = client.post(publish_url);
        if let Some(credentials) = &self.connection_info.credentials {
            request = request.header(AUTHORIZATION, credentials.authorization());
        }

        request
            .header("Content-Type", "application/json")
            .body(payload.to_owned())
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        Ok(())
    }

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError> {
        *self.handler.lock().await = Some(handler);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_allowed_attachment;

    #[test]
    fn attachment_fetch_is_same_origin_and_non_redirecting() {
        let origin = "https://ntfy.example";
        assert!(is_allowed_attachment(
            "https://ntfy.example/file",
            origin
        ));
        assert!(!is_allowed_attachment("http://ntfy.example/file", origin));
        assert!(!is_allowed_attachment("https://127.0.0.1/file", origin));
        assert!(!is_allowed_attachment(
            "https://ntfy.example@127.0.0.1/file",
            origin
        ));
    }
}
