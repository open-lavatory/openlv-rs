# openlv (Rust)

Native Rust implementation of the [Open Lavatory](https://openlv.sh) protocol for interoperability with the TypeScript `@openlv/*` packages.

## Parity status

| Layer | Status |
|-------|--------|
| URI encode/decode + validation | Done |
| Handshake crypto (AES-128-GCM) | Done |
| Peer crypto (X25519 + XSalsa20-Poly1305) | Done |
| Wire frames (`h`/`x` + `h`/`c`) | Done |
| Signaling state machine | Done |
| NTFY signaling channel | Done |
| MQTT signaling channel | Done |
| WebRTC transport (`openlv-data`) | Done |
| Session API (`create_session` / `connect_session`) | Done |
| GunDB signaling | Not implemented |

## Usage

```rust
use openlv::{create_session, SessionInitParameters};
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), openlv::OpenLvError> {
    let session = create_session(
        SessionInitParameters {
            session_id: Some("mytestsession111".into()),
            p: Some("ntfy".into()),
            s: Some("https://ntfy.sh/".into()),
            ..Default::default()
        },
        Arc::new(|_msg| Ok(json!({"result": "success"}))),
    )
    .await?;

    session.connect().await?;
    println!("{}", session.connection_url());
    Ok(())
}
```
