/*!
Open Lavatory (openlv for short) is a secure peer-to-peer wallet connectivity protocol.

It allows for establishing a secure connection between a dApp and a wallet leveraging public infrastructure, p2p, and encryption.

# Usage

## dApp (host)

```rust,no_run
use openlv::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dapp = openlv::dapp()
        .protocol(Protocol::Ntfy)
        .server("https://ntfy.sh/")
        .on_request(|msg| async move {
            println!("received: {msg}");
            Ok(json!({"result": "ok", "id": msg["id"], "jsonrpc": "2.0"}))
        })
        .await?;

    dapp.connect().await?;
    println!("Connection URL: {}", dapp.uri());
    dapp.wait_for_link().await?;

    let resp = dapp.send(json!({"method": "eth_chainId", "params": [], "id": 1, "jsonrpc": "2.0"})).await?;
    println!("Response: {resp}");

    dapp.close().await?;
    Ok(())
}
```

## Wallet (client)

```rust,no_run
use openlv::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = openlv::wallet("openlv://...")
        .on_request(|msg| async move {
            println!("received: {msg}");
            Ok(json!({"result": "ok", "id": msg["id"], "jsonrpc": "2.0"}))
        })
        .await?;

    wallet.connect().await?;
    wallet.wait_for_link().await?;
    println!("Connected!");

    wallet.close().await?;
    Ok(())
}
```
*/

#[cfg(any(feature = "alloy-1", feature = "alloy-2"))]
#[path = "provider/mod.rs"]
pub mod alloy;
pub mod encryption;
pub mod errors;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod url;
pub mod utils;

pub use errors::OpenLvError;
pub use session::{
    RequestHandler, Session, SessionConfig, SessionState, SessionStateObject, connect_session,
    create_session, dapp, request_handler, wallet,
};
pub use signaling::{PeerCapabilities, PeerInfo, SignalState, SignalingProtocol};
pub use url::SessionUri;

/// Convenient re-exports for the most common use cases.
pub mod prelude {
    pub use crate::errors::OpenLvError;
    pub use crate::session::{Session, SessionConfig, SessionState, dapp, request_handler, wallet};
    pub use crate::signaling::PeerInfo;
    pub use crate::signaling::SignalingProtocol as Protocol;
    pub use serde_json::json;
}
