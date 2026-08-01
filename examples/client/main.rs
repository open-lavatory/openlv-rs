//! Wallet (client) example for the openlv library.
//!
//! Connects to a dApp session from an `openlv://` URL.
//!
//! Usage:
//!   cargo run --example client -- "openlv://..."

use std::{env, process};

use alloy_primitives::hex;
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use openlv::prelude::*;
use serde_json::Value;
use tokio::sync::broadcast;

const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";

fn test_signer() -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    Ok(MnemonicBuilder::<English>::default()
        .phrase(ANVIL_MNEMONIC)
        .index(0)?
        .build()?)
}

fn handle_rpc_request(request: Value, signer: &PrivateKeySigner) -> Value {
    let id = request["id"].clone();
    let response = match request.get("method").and_then(Value::as_str) {
        Some("eth_accounts") => Ok(json!([signer.address().to_string()])),
        Some("eth_chainId") => Ok(json!("0x1")),
        Some("personal_sign") => personal_sign(&request, signer),
        Some(method) => Err(json!({
            "code": -32601,
            "message": format!("Method {method} not found"),
        })),
        None => Err(json!({
            "code": -32600,
            "message": "Invalid request",
        })),
    };

    match response {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
    }
}

fn personal_sign(request: &Value, signer: &PrivateKeySigner) -> Result<Value, Value> {
    let Some(params) = request.get("params").and_then(Value::as_array) else {
        return Err(invalid_params(
            "personal_sign requires message and account parameters",
        ));
    };
    let [message, account] = params.as_slice() else {
        return Err(invalid_params(
            "personal_sign requires exactly two parameters",
        ));
    };
    let (Some(message), Some(account)) = (message.as_str(), account.as_str()) else {
        return Err(invalid_params("personal_sign parameters must be strings"));
    };
    if account != signer.address().to_string() {
        return Err(json!({
            "code": 4100,
            "message": "Requested account is not available",
        }));
    }

    let message = match message.strip_prefix("0x").map(hex::decode).transpose() {
        Ok(Some(message)) => message,
        _ => {
            return Err(invalid_params(
                "personal_sign message must be 0x-prefixed hex",
            ));
        }
    };
    match signer.sign_message_sync(&message) {
        Ok(signature) => Ok(json!(signature.to_string())),
        Err(error) => {
            tracing::error!(error = %error, "personal_sign failed");
            Err(json!({
                "code": -32603,
                "message": "Internal error",
            }))
        }
    }
}

fn invalid_params(message: &str) -> Value {
    json!({
        "code": -32602,
        "message": message,
    })
}

#[tokio::main]
async fn main() {
    let url = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: client <openlv://...>");
        process::exit(1);
    });

    println!("Connecting to: {url}");
    let signer = test_signer().unwrap_or_else(|error| {
        eprintln!("Failed to derive test account: {error}");
        process::exit(1);
    });
    println!("Wallet account: {}", signer.address());

    let wallet = openlv::wallet(&url)
        .on_request(move |msg| {
            let signer = signer.clone();
            async move {
                println!("Received request: {msg}");
                Ok(handle_rpc_request(msg, &signer))
            }
        })
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to create session: {e}");
            process::exit(1);
        });

    wallet.connect().await.unwrap_or_else(|e| {
        eprintln!("Connection failed: {e}");
        process::exit(1);
    });

    wallet.wait_for_link().await.unwrap_or_else(|e| {
        eprintln!("Link failed: {e}");
        process::exit(1);
    });

    println!("Connected!");

    let mut requests = wallet.subscribe_requests();

    loop {
        tokio::select! {
            msg = requests.recv() => {
                match msg {
                    Ok(payload) => {
                        println!("Incoming request: {payload}");
                        // TODO: respond
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        eprintln!("Warning: missed some requests");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        eprintln!("Request channel closed, exiting.");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                // keep alive
            }
        }
    }

    let _ = wallet.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responds_to_standard_wallet_requests() {
        let signer = test_signer().unwrap();
        let address = signer.address().to_string();
        assert_eq!(address, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(
            handle_rpc_request(
                json!({"jsonrpc": "2.0", "id": 1, "method": "eth_accounts", "params": []}),
                &signer,
            ),
            json!({"jsonrpc": "2.0", "id": 1, "result": [address]}),
        );
        assert_eq!(
            handle_rpc_request(
                json!({"jsonrpc": "2.0", "id": 2, "method": "eth_chainId", "params": []}),
                &signer,
            ),
            json!({"jsonrpc": "2.0", "id": 2, "result": "0x1"}),
        );
    }

    #[test]
    fn signs_personal_messages_for_the_configured_account() {
        let signer = test_signer().unwrap();
        let response = handle_rpc_request(
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "personal_sign",
                "params": [
                    "0x48656c6c6f2c20776f726c6421",
                    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                ]
            }),
            &signer,
        );
        assert!(
            response["result"]
                .as_str()
                .is_some_and(|signature| signature.starts_with("0x"))
        );
        assert_eq!(response["result"].as_str().unwrap().len(), 132);
    }
}
