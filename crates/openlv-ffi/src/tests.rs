use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn failed_native_handler_fails_the_request_once() {
    let requests = Requests::new();
    let handler = tokio::spawn(Arc::clone(&requests).handle(json!({"method": "boom"})));
    let request = requests.next().await.unwrap();

    requests.fail(request.id).unwrap();

    assert!(matches!(
        handler.await.unwrap(),
        Err(openlv::OpenLvError::Other(_))
    ));
    assert!(requests.reply(request.id, Ok("{}".into())).is_err());
}

#[tokio::test]
async fn stop_closes_pending_and_new_requests() {
    let requests = Requests::new();
    let pending = tokio::spawn(Arc::clone(&requests).handle(json!({"method": "slow"})));
    let request = requests.next().await.unwrap();

    requests.stop();

    assert!(matches!(
        pending.await.unwrap(),
        Err(openlv::OpenLvError::SessionClosed)
    ));
    assert!(requests.reply(request.id, Ok("{}".into())).is_err());
    assert!(requests.next().await.is_none());
    assert!(matches!(
        Arc::clone(&requests).handle(json!({})).await,
        Err(openlv::OpenLvError::SessionClosed)
    ));
}

#[test]
fn request_errors_keep_distinct_kinds() {
    use openlv::OpenLvError as E;
    let kinds = [
        (E::Session("x".into()), "session"),
        (E::SessionClosed, "session_closed"),
        (E::RequestLimitReached, "request_limit_reached"),
        (E::RequestFailed, "request_failed"),
        (E::InvalidRequestTimeout, "invalid_request_timeout"),
        (E::ResponseChannelClosed, "response_channel_closed"),
        (E::RequestTimeout("x".into()), "request_timeout"),
    ];
    for (error, expected) in kinds {
        let BridgeError::Failure { kind, .. } = BridgeError::from(error);
        assert_eq!(kind, expected);
    }
}

#[test]
fn state_json_uses_snake_case_names() {
    let state = openlv::SessionStateObject {
        status: openlv::SessionState::Disconnected,
        signaling: Some(openlv::SignalState::HandshakePartial),
        peer_info: Some(openlv::PeerInfo {
            identity: "wallet".into(),
            name: "Wallet".into(),
            icon: None,
        }),
        error: Some("closed by peer".into()),
    };

    let value: Value = serde_json::from_str(&state_json(state)).unwrap();

    assert_eq!(
        value,
        json!({
            "status": "disconnected",
            "signaling": "handshake_partial",
            "peer": {"identity": "wallet", "name": "Wallet", "icon": null},
            "error": "closed by peer",
        })
    );
}
