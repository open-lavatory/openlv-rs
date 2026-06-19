use async_trait::async_trait;

use crate::errors::OpenLvError;

pub type MessageHandler = Box<dyn Fn(String) + Send + Sync>;

#[async_trait]
pub trait SignalingChannel: Send + Sync {
    fn channel_type(&self) -> &'static str;

    async fn setup(&mut self) -> Result<(), OpenLvError>;

    async fn teardown(&mut self) -> Result<(), OpenLvError>;

    async fn publish(&self, payload: &str) -> Result<(), OpenLvError>;

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError>;
}
