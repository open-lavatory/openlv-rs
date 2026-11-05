# openlv (Rust)

Native Rust implementation of the [Open Lavatory](https://openlv.sh) protocol for interoperability with the [typescript implementation](https://github.com/v3xlabs/open-lavatory)

## Parity status

| Layer | Status |
|-------|--------|
| URI encode/decode + validation | Done |
| Handshake crypto (AES-128-GCM) | Done |
| Peer crypto (static X25519 + HKDF-SHA256 + directional AES-256-GCM) | Done |
| Wire frames (`h`/`x` + `h`/`c`) | Done |
| Signaling state machine | Done |
| NTFY signaling channel | Done |
| MQTT signaling channel | Done |
| WebRTC transport (`openlv-data`) | Done |
| Session API (`create_session` / `connect_session` / resume) | In progress |

## Security model

- The invitation `k` is a pre-shared authorization secret. Bootstrap frames use
  AES-GCM with fresh random IVs.
- Peer signaling and transport frames use per-message directional AES-256-GCM
  derived from the per-session X25519 shared secret and both static public
  keys. Each ciphertext carries the sender public key.
- X25519 and AEAD provide key possession authentication and integrity; this
  protocol does not use digital signatures or provide non-repudiation.
- Peer ciphertexts use random nonces but the current version has no replay
  counter or replay cache.
- The URL `h` is a 64-bit truncated SHA-256 pin for the host public key. It is
  an identity check, not a frame authenticator.

## Usage

```rust
use openlv::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dapp = openlv::dapp()
        .protocol(Protocol::Ntfy)
        .server("https://ntfy.sh/")
        .on_request(|msg| async move {
            println!("received: {msg}");
            Ok(json!({"result": "ok"}))
        })
        .await?;

    dapp.connect().await?;
    println!("Connection URL: {}", dapp.uri());
    dapp.wait_for_link().await?;

    dapp.close().await?;
    Ok(())
}
```
