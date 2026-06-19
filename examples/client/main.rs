//! Wallet (client) example for the openlv library.
//!
//! Connects to a dApp session from an `openlv://` URL.
//!
//! Usage:
//!   cargo run --example client -- "openlv://..."

use std::{env, process};

use openlv::prelude::*;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    let url = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: client <openlv://...>");
        process::exit(1);
    });

    println!("Connecting to: {url}");

    let wallet = openlv::wallet(&url)
        .on_request(|msg| async move {
            println!("Received request: {msg}");
            Ok(json!({"status": "ok"}))
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
