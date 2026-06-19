# openlv-rs development commands

_default:
    @just --list

# Build the library and examples
build:
    cargo build --examples

# Run unit + integration tests
test:
    cargo test

# Run the dApp example (host — creates session, prints connection URL)
dapp:
    cargo run --example dapp

# Run the wallet example (client — connects to a session URL)
# Usage: just example-client "openlv://..."
connect url:
    cargo run --example client -- '{{url}}'

# Build release artifacts
release:
    cargo build --release --examples

# Check compilation
check:
    cargo check --tests --examples

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt --check
