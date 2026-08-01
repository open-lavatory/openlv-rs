//! Request response deadlines, independent of the signaling transport.

use serde_json::Value;
use tokio::sync::broadcast;

use crate::{errors::OpenLvError, transport::SessionMessage};

pub async fn receive_response(
    receiver: &mut broadcast::Receiver<SessionMessage>,
    message_id: &str,
    ack_timeout_ms: u64,
    response_timeout_ms: u64,
) -> Result<Value, OpenLvError> {
    let deadline_after = |milliseconds| {
        tokio::time::Instant::now()
            .checked_add(tokio::time::Duration::from_millis(milliseconds))
            .ok_or(OpenLvError::InvalidRequestTimeout)
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
            Ok(Ok(SessionMessage::Failed { message_id: id })) if id == message_id => {
                return Err(OpenLvError::RequestFailed);
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return Err(OpenLvError::ResponseChannelClosed),
            Err(_) => return Err(OpenLvError::RequestTimeout(timeout_reason.into())),
        }
    }
}

#[cfg(test)]
mod tests;
