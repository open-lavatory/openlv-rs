use std::task::{Context, Poll};

use alloy_json_rpc_1::{RequestPacket, Response, ResponsePacket, SerializedRequest};
use alloy_rpc_client_1::RpcClient;
use alloy_transport_1::{TransportError, TransportErrorKind, TransportFut};
use tower::Service;

#[derive(Clone)]
pub struct Transport {
    session: crate::Session,
}

/// Creates an Alloy 1 [`RpcClient`] using the given session as the transport layer.
///
/// ```rust,no_run
/// # let _ = async {
/// # use openlv::prelude::*;
/// # let session = openlv::dapp()
/// #     .on_request(|request| async move {
/// #         Ok(json!({"jsonrpc": "2.0", "id": request["id"], "result": "success"}))
/// #     })
/// #     .await
/// #     ?;
/// let client = openlv::alloy::v1::rpc_client(session);
/// # let _ = client;
/// # Ok::<(), openlv::OpenLvError>(())
/// # };
/// ```
pub fn rpc_client(session: crate::Session) -> RpcClient {
    RpcClient::new(Transport::new(session), false)
}

impl Transport {
    pub fn new(session: crate::Session) -> Self {
        Self { session }
    }
}

impl Service<RequestPacket> for Transport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let session = self.session.clone();
        Box::pin(async move {
            match req {
                RequestPacket::Single(request) => Ok(ResponsePacket::Single(
                    dispatch_one(&session, request).await?,
                )),
                RequestPacket::Batch(requests) => {
                    let mut responses = Vec::with_capacity(requests.len());
                    for request in requests {
                        responses.push(dispatch_one(&session, request).await?);
                    }
                    Ok(ResponsePacket::Batch(responses))
                }
            }
        })
    }
}

async fn dispatch_one(
    session: &crate::Session,
    req: SerializedRequest,
) -> Result<Response, TransportError> {
    let request =
        serde_json::from_str(req.into_serialized().get()).map_err(TransportErrorKind::custom)?;
    let response = super::jsonrpc::exchange(session, request)
        .await
        .map_err(TransportErrorKind::custom)?;

    serde_json::from_value(response).map_err(TransportErrorKind::custom)
}
