# openlv (Rust)

Native Rust implementation of the [Open Lavatory](https://openlv.sh) protocol.
A wallet-dApp connectivity protocol.

For sdks in other languages see [github.com/open-lavatory](https://github.com/open-lavatory)
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
