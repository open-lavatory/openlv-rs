use serde_json::{Value, json};
use thiserror::Error;

use crate::{OpenLvError, Session};

const INTERNAL_ERROR_CODE: i64 = -32603;

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error(transparent)]
    Session(#[from] OpenLvError),

    #[error("wallet response is not a JSON-RPC 2.0 response: {0}")]
    InvalidResponse(&'static str),
}

pub async fn exchange(session: &Session, request: Value) -> Result<Value, ExchangeError> {
    let id = request["id"].clone();
    settle(&id, session.send(request).await)
}

fn settle(id: &Value, outcome: Result<Value, OpenLvError>) -> Result<Value, ExchangeError> {
    let response = match outcome {
        Ok(response) => response,
        Err(OpenLvError::RequestFailed) => {
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": INTERNAL_ERROR_CODE, "message": "Internal error"},
            }));
        }
        Err(error) => return Err(error.into()),
    };

    if response["jsonrpc"] != "2.0" {
        return Err(ExchangeError::InvalidResponse(
            "`jsonrpc` is missing or not \"2.0\"",
        ));
    }
    if response.get("id") != Some(id) {
        return Err(ExchangeError::InvalidResponse(
            "`id` is missing or differs from the request",
        ));
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
