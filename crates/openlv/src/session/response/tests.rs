use super::*;
use serde_json::json;
use tokio::time::{Duration, advance};

#[tokio::test(start_paused = true)]
async fn response_deadline_survives_unrelated_messages_and_duplicate_acks() {
    let (sender, mut receiver) = broadcast::channel(16);
    let pending =
        tokio::spawn(async move { receive_response(&mut receiver, "request", 100, 300).await });
    tokio::task::yield_now().await;
    sender
        .send(SessionMessage::Ack {
            message_id: "request".into(),
        })
        .unwrap();
    tokio::task::yield_now().await;

    for _ in 0..2 {
        advance(Duration::from_millis(100)).await;
        sender
            .send(SessionMessage::Response {
                message_id: "another-request".into(),
                payload: json!("unrelated"),
            })
            .unwrap();
        sender
            .send(SessionMessage::Ack {
                message_id: "request".into(),
            })
            .unwrap();
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
    }
    advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    assert!(
        pending.is_finished(),
        "traffic extended the response deadline"
    );
    assert!(matches!(
        pending.await.unwrap(),
        Err(OpenLvError::RequestTimeout(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn unrelated_messages_do_not_extend_ack_deadline() {
    let (sender, mut receiver) = broadcast::channel(16);
    let pending =
        tokio::spawn(async move { receive_response(&mut receiver, "request", 100, 300).await });
    tokio::task::yield_now().await;
    advance(Duration::from_millis(50)).await;
    sender
        .send(SessionMessage::Ack {
            message_id: "another-request".into(),
        })
        .unwrap();
    tokio::task::yield_now().await;
    advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert!(
        pending.is_finished(),
        "traffic extended the acknowledgement deadline"
    );
    assert!(matches!(
        pending.await.unwrap(),
        Err(OpenLvError::RequestTimeout(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn matching_response_completes_after_unrelated_traffic() {
    let (sender, mut receiver) = broadcast::channel(16);
    sender
        .send(SessionMessage::Ack {
            message_id: "request".into(),
        })
        .unwrap();
    sender
        .send(SessionMessage::Response {
            message_id: "another-request".into(),
            payload: json!("unrelated"),
        })
        .unwrap();
    sender
        .send(SessionMessage::Response {
            message_id: "request".into(),
            payload: json!("result"),
        })
        .unwrap();
    assert_eq!(
        receive_response(&mut receiver, "request", 100, 300)
            .await
            .unwrap(),
        json!("result")
    );
}
