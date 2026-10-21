//! Request response deadlines, independent of the signaling transport.

use serde_json::Value;
use tokio::sync::broadcast;

use crate::{errors::OpenLvError, transport::SessionMessage};

pub(super) async fn receive_response(
    receiver: &mut broadcast::Receiver<SessionMessage>,
    message_id: &str,
    ack_timeout_ms: u64,
    response_timeout_ms: u64,
) -> Result<Value, OpenLvError> {
    let deadline_after = |milliseconds| {
        tokio::time::Instant::now()
            .checked_add(tokio::time::Duration::from_millis(milliseconds))
            .ok_or_else(|| OpenLvError::RequestTimeout("timeout exceeds supported range".into()))
    };
    let mut deadline = deadline_after(ack_timeout_ms)?;
    let mut ack_received = false;

    loop {
        let timeout_reason = if ack_received {
            "no response after acknowledgement"
        } else {
            "remote peer did not acknowledge"
        };
        // Check the deadline explicitly: a continuously ready stream of unrelated
        // messages can keep recv() from yielding back to timeout_at.
        if tokio::time::Instant::now() >= deadline {
            return Err(OpenLvError::RequestTimeout(timeout_reason.into()));
        }
        match tokio::time::timeout_at(deadline, receiver.recv()).await {
            Ok(Ok(SessionMessage::Ack { message_id: id })) if id == message_id => {
                if !ack_received {
                    deadline = deadline_after(response_timeout_ms)?;
                    ack_received = true;
                }
            }
            Ok(Ok(SessionMessage::Response {
                message_id: id,
                payload,
            })) if id == message_id => return Ok(payload),
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => {
                return Err(OpenLvError::RequestTimeout(
                    "response channel closed".into(),
                ));
            }
            Err(_) => return Err(OpenLvError::RequestTimeout(timeout_reason.into())),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
