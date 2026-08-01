use serde_json::json;

use super::*;

#[test]
fn failed_frame_carries_only_type_and_message_id() {
    let failed = SessionMessage::reply(
        "5b0e6f3c".into(),
        Err(OpenLvError::Other("secret key material".into())),
    );

    assert_eq!(
        serde_json::to_value(&failed).unwrap(),
        json!({"type": "failed", "messageId": "5b0e6f3c"})
    );
}
