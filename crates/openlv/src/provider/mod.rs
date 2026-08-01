mod jsonrpc;

#[cfg(feature = "alloy-1")]
#[path = "alloy_1.rs"]
pub mod v1;
#[cfg(feature = "alloy-2")]
#[path = "alloy_2.rs"]
pub mod v2;
