use super::*;

#[test]
fn rejects_responses_that_do_not_answer_the_request() {
    let id = json!(7);
    let rejected = [
        json!({"jsonrpc": "2.0", "id": 8, "result": "0x1"}),
        json!({"jsonrpc": "2.0", "result": "0x1"}),
        json!({"id": 7, "result": "0x1"}),
        json!({"jsonrpc": "1.0", "id": 7, "result": "0x1"}),
        json!("0x1"),
    ];

    for response in rejected {
        assert!(
            matches!(
                settle(&id, Ok(response.clone())),
                Err(ExchangeError::InvalidResponse(_))
            ),
            "accepted {response}"
        );
    }
}

#[test]
fn accepts_a_response_with_the_request_id() {
    let response = json!({"jsonrpc": "2.0", "id": "a", "result": "0x1"});

    assert_eq!(settle(&json!("a"), Ok(response.clone())).unwrap(), response);
}

#[test]
fn failed_request_becomes_an_internal_error_with_the_request_id() {
    let response = settle(&json!(7), Err(OpenLvError::RequestFailed)).unwrap();

    assert_eq!(
        response,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "error": {"code": -32603, "message": "Internal error"},
        })
    );
}

#[test]
fn other_session_errors_stay_transport_errors() {
    assert!(matches!(
        settle(&json!(7), Err(OpenLvError::SessionClosed)),
        Err(ExchangeError::Session(OpenLvError::SessionClosed))
    ));
}
