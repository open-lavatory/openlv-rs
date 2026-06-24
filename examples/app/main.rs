//! dApp (host) example for the openlv library.
//!
//! Creates a session, waits for a wallet to connect, sends a test request,
//! and prints the response.
//!
//! Usage:
//!   cargo run --example dapp

use openlv::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dapp = openlv::dapp()
        .protocol(Protocol::Ntfy)
        .server("https://ntfy.sh/")
        .on_request(|msg| async move {
            println!("[dapp] received request: {msg}");
            Ok(json!({"result": "ok"}))
        })
        .await?;

    dapp.connect().await?;
    println!("Connection URL: {}", dapp.uri());
    println!("Waiting for wallet to connect...");
    dapp.wait_for_link().await?;
    println!("Connected!");

    let resp = dapp.send(json!({"test": "hello from dapp"})).await?;
    println!("Response: {resp}");

    dapp.close().await?;
    Ok(())
}
