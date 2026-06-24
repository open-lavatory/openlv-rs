use std::sync::Arc;

use async_trait::async_trait;
use mqtt5::client::MqttClient;
use tokio::sync::Mutex;

use super::channel::{MessageHandler, SignalingChannel};
use crate::errors::OpenLvError;

pub struct MqttChannel {
    server: String,
    topic: String,
    client: Option<MqttClient>,
    handler: Arc<Mutex<Option<MessageHandler>>>,
}

impl MqttChannel {
    pub fn new(server: String, topic: String) -> Self {
        Self {
            server,
            topic,
            client: None,
            handler: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl SignalingChannel for MqttChannel {
    fn channel_type(&self) -> &'static str {
        "mqtt"
    }

    async fn setup(&mut self) -> Result<(), OpenLvError> {
        let client = MqttClient::new("");
        client
            .connect(&self.server)
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        let topic = self.topic.clone();
        let handler = Arc::clone(&self.handler);

        client
            .subscribe(topic, move |message| {
                let payload = String::from_utf8_lossy(&message.payload).to_string();
                let handler = Arc::clone(&handler);
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let guard = handler.lock().await;
                        if let Some(handler) = guard.as_ref() {
                            handler(payload);
                        }
                    });
                }
            })
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        self.client = Some(client);
        Ok(())
    }

    async fn teardown(&mut self) -> Result<(), OpenLvError> {
        if let Some(client) = self.client.take() {
            client
                .disconnect()
                .await
                .map_err(|error| OpenLvError::Signaling(error.to_string()))?;
        }
        Ok(())
    }

    async fn publish(&self, payload: &str) -> Result<(), OpenLvError> {
        let client = self.client.as_ref().ok_or(OpenLvError::NoConnection)?;

        client
            .publish(self.topic.clone(), payload.as_bytes())
            .await
            .map_err(|error| OpenLvError::Signaling(error.to_string()))?;

        Ok(())
    }

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError> {
        *self.handler.lock().await = Some(handler);
        Ok(())
    }
}
