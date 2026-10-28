use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::*;
use crate::encryption::{KeyPair, init_hash};
use crate::signaling::channel::MessageHandler;

struct MemoryChannel {
    handlers: Arc<Mutex<Vec<MessageHandler>>>,
}

#[async_trait]
impl SignalingChannel for MemoryChannel {
    fn channel_type(&self) -> &'static str {
        "memory"
    }

    async fn setup(&mut self) -> Result<(), OpenLvError> {
        Ok(())
    }

    async fn teardown(&mut self) -> Result<(), OpenLvError> {
        Ok(())
    }

    async fn publish(&self, payload: &str) -> Result<(), OpenLvError> {
        let handlers = self
            .handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for handler in handlers.iter() {
            handler(payload.to_string());
        }
        Ok(())
    }

    async fn subscribe(&mut self, handler: MessageHandler) -> Result<(), OpenLvError> {
        self.handlers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(handler);
        Ok(())
    }
}

fn properties(
    is_host: bool,
    hash: String,
    key_pair: &KeyPair,
    handshake_key: HandshakeKey,
    identity: &str,
) -> SignalingProperties {
    SignalingProperties {
        is_host,
        h: hash,
        handshake_key: Some(handshake_key),
        encryption_key: key_pair.encryption_key.clone(),
        decryption_key: key_pair.decryption_key.clone(),
        capabilities: PeerCapabilities {
            transports: vec!["wrtc".into()],
            info: Some(crate::signaling::message::PeerInfo {
                identity: identity.into(),
                name: identity.into(),
                icon: None,
            }),
        },
    }
}

#[tokio::test]
async fn exchanges_capabilities_before_entering_encrypted_state() {
    let handlers = Arc::new(Mutex::new(Vec::new()));
    let host_key_pair = KeyPair::generate().unwrap();
    let client_key_pair = KeyPair::generate().unwrap();
    let hash = init_hash(None, &host_key_pair.encryption_key).unwrap().hash;
    let handshake_key = HandshakeKey::generate().unwrap();

    let host = SignalingLayer::new(
        Box::new(MemoryChannel {
            handlers: Arc::clone(&handlers),
        }),
        properties(
            true,
            hash.clone(),
            &host_key_pair,
            handshake_key.clone(),
            "com.example.dapp",
        ),
    );
    let client = SignalingLayer::new(
        Box::new(MemoryChannel { handlers }),
        properties(
            false,
            hash,
            &client_key_pair,
            handshake_key,
            "com.example.wallet",
        ),
    );

    host.setup().await.unwrap();
    client.setup().await.unwrap();

    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        loop {
            if host.state() == SignalState::Encrypted && client.state() == SignalState::Encrypted {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    assert_eq!(
        host.peer_capabilities().unwrap().info.unwrap().identity,
        "com.example.wallet"
    );
    assert_eq!(
        client.peer_capabilities().unwrap().info.unwrap().identity,
        "com.example.dapp"
    );
}
