use super::*;

#[test]
fn serializes_the_v0_1_capabilities_wire_shape() {
    let message = SignalingMessage::Capabilities {
        payload: PeerCapabilities {
            transports: vec!["wrtc".into(), "ws".into()],
            info: Some(PeerInfo {
                identity: "com.example.wallet".into(),
                name: "Example Wallet".into(),
                icon: Some("https://example.com/icon.png".into()),
            }),
        },
        timestamp: 1_750_000_000_000,
    };

    assert_eq!(
        serde_json::to_value(message).unwrap(),
        serde_json::json!({
            "type": "capabilities",
            "payload": {
                "transports": ["wrtc", "ws"],
                "info": {
                    "identity": "com.example.wallet",
                    "name": "Example Wallet",
                    "icon": "https://example.com/icon.png"
                }
            },
            "timestamp": 1_750_000_000_000u64
        })
    );
}

#[test]
fn validates_capabilities_bounds() {
    let valid = PeerCapabilities {
        transports: vec!["wrtc".into()],
        info: Some(PeerInfo {
            identity: "com.example.wallet".into(),
            name: "Example Wallet".into(),
            icon: None,
        }),
    };
    assert!(valid.validate().is_ok());

    assert!(
        PeerCapabilities {
            transports: vec![],
            info: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        PeerInfo {
            identity: "".into(),
            name: "Example Wallet".into(),
            icon: None,
        }
        .validate()
        .is_err()
    );
    assert!(
        PeerInfo {
            identity: "com.example.wallet".into(),
            name: "Example Wallet".into(),
            icon: Some("x".repeat(8193)),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn rejects_the_retired_handshake_ack_packet() {
    assert!(
        serde_json::from_value::<SignalingMessage>(serde_json::json!({
            "type": "ack",
            "timestamp": 1,
            "payload": null,
        }))
        .is_err()
    );
}
