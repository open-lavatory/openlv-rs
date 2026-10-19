use super::select_transport_id;

use futures::FutureExt;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc};

use crate::{OpenLvError, Session, SessionState, dapp, wallet};

async fn callback_session() -> Session {
    dapp()
        .on_request(|message| async move { Ok(message) })
        .await
        .unwrap()
}

fn assert_session_closed<T>(result: Result<T, OpenLvError>) {
    assert!(matches!(result, Err(OpenLvError::SessionClosed)));
}

#[tokio::test]
async fn closing_before_wait_for_link_returns_a_persistent_session_error() {
    let session = callback_session().await;
    session.close().await.unwrap();

    assert_session_closed(session.wait_for_link().await);
    session.closed().await;
    assert_eq!(session.state().status, SessionState::Disconnected);
}

#[tokio::test]
async fn closing_cancels_an_already_waiting_public_link_operation() {
    let session = callback_session().await;
    let mut waiting = Box::pin(session.wait_for_link());
    assert!(waiting.as_mut().now_or_never().is_none());

    let (closed, result) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::join!(session.close(), waiting)
    })
    .await
    .expect("session close did not cancel the waiting link operation");
    closed.unwrap();
    assert_session_closed(result);
}

#[tokio::test]
async fn close_does_not_wait_for_a_suspended_operation_that_is_not_polled() {
    let session = callback_session().await;
    let mut waiting = Box::pin(session.wait_for_link());
    assert!(waiting.as_mut().now_or_never().is_none());

    tokio::time::timeout(Duration::from_secs(1), session.close())
        .await
        .expect("close waited for a suspended operation")
        .unwrap();
    assert_eq!(session.state().status, SessionState::Disconnected);
    assert_session_closed(waiting.await);
}

#[tokio::test]
async fn close_releases_an_unpolled_connect_that_holds_the_signaling_channel() {
    // Completes TCP connections from its backlog but never answers the
    // websocket upgrade, so signaling setup stays suspended.
    let silent_server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let session = dapp()
        .server(format!("http://{}/", silent_server.local_addr().unwrap()))
        .on_request(|message| async move { Ok(message) })
        .await
        .unwrap();
    let mut states = session.subscribe_state();
    let mut connecting = Box::pin(session.connect());
    assert!(connecting.as_mut().now_or_never().is_none());

    let signaling = tokio::time::timeout(Duration::from_secs(1), states.recv())
        .await
        .expect("connect did not report a state")
        .unwrap();
    assert_eq!(signaling.status, SessionState::Signaling);

    tokio::time::timeout(Duration::from_secs(1), session.close())
        .await
        .expect("close waited for a suspended connect")
        .unwrap();
    assert_eq!(
        states.recv().await.unwrap().status,
        SessionState::Disconnected
    );
    assert_session_closed(connecting.await);
}

#[tokio::test]
async fn operations_created_before_close_cannot_start_after_close() {
    let session = callback_session().await;
    let connecting = session.connect();
    let waiting = session.wait_for_link();
    let sending = session.send(json!({"method": "eth_chainId"}));

    session.close().await.unwrap();

    assert_session_closed(connecting.await);
    assert_session_closed(waiting.await);
    assert_session_closed(sending.await);
}

#[tokio::test]
async fn public_operations_reject_calls_after_close() {
    let session = callback_session().await;
    session.close().await.unwrap();

    assert_session_closed(session.connect().await);
    assert_session_closed(session.wait_for_link().await);
    assert_session_closed(session.send(json!(null)).await);
    assert_session_closed(session.send_with_timeouts(json!(null), 1, 1).await);
}

#[tokio::test]
async fn close_is_shared_by_clones_and_wakes_existing_and_late_observers() {
    let session = callback_session().await;
    let clone = session.clone();
    let mut observed_close = Box::pin(session.closed());
    assert!(observed_close.as_mut().now_or_never().is_none());

    let (first, second, ()) = tokio::join!(session.close(), clone.close(), observed_close);
    first.unwrap();
    second.unwrap();
    clone.close().await.unwrap();
    clone.closed().await;
}

#[tokio::test]
async fn callback_wallet_builder_preserves_the_connection_uri() {
    let host = callback_session().await;
    let url = host.uri().to_string();
    let client = wallet(&url)
        .on_request(|message| async move { Ok(message) })
        .await
        .unwrap();

    assert_eq!(client.uri().to_string(), url);
    assert!(!client.is_host());
    client.close().await.unwrap();
    host.close().await.unwrap();
}

struct CallbackResource(mpsc::UnboundedSender<()>);

impl Drop for CallbackResource {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[tokio::test]
async fn handler_admission_is_bounded_reusable_and_observational() {
    let gate = Arc::new(Semaphore::new(0));
    let (started, mut starts) = mpsc::unbounded_channel();
    let (dropped, mut drops) = mpsc::unbounded_channel();
    let session = dapp()
        .on_request({
            let gate = Arc::clone(&gate);
            move |_| {
                let gate = Arc::clone(&gate);
                let started = started.clone();
                let resource = CallbackResource(dropped.clone());
                async move {
                    let _resource = resource;
                    started.send(()).unwrap();
                    gate.acquire().await.unwrap().forget();
                    Ok(json!(null))
                }
            }
        })
        .await
        .unwrap();
    let mut observations = session.subscribe_requests();

    for index in 0..256 {
        session
            .inner
            .dispatch_request(index.to_string(), json!(index))
            .unwrap();
        assert_eq!(observations.try_recv().unwrap(), json!(index));
    }
    for _ in 0..256 {
        tokio::time::timeout(Duration::from_secs(2), starts.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(matches!(
        session
            .inner
            .dispatch_request("overload".into(), json!("overload")),
        Err(OpenLvError::RequestLimitReached)
    ));
    assert!(matches!(
        observations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), drops.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if session
                .inner
                .dispatch_request("replacement".into(), json!("replacement"))
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed callback did not release admission");
    assert_eq!(observations.try_recv().unwrap(), json!("replacement"));
    tokio::time::timeout(Duration::from_secs(2), starts.recv())
        .await
        .unwrap()
        .unwrap();

    session.close().await.unwrap();
    for _ in 0..256 {
        drops
            .try_recv()
            .expect("close retained a callback resource");
    }
    assert_session_closed(session.inner.dispatch_request("closed".into(), json!(null)));
}

#[tokio::test]
async fn close_does_not_invoke_admitted_but_unpolled_callbacks() {
    let invoked = Arc::new(AtomicUsize::new(0));
    let session = dapp()
        .on_request({
            let invoked = Arc::clone(&invoked);
            move |_| {
                invoked.fetch_add(1, Ordering::SeqCst);
                async { Ok(json!(null)) }
            }
        })
        .await
        .unwrap();
    session
        .inner
        .dispatch_request("unpolled".into(), json!(null))
        .unwrap();
    session.close().await.unwrap();
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_racing_handler_admission_destroys_every_started_callback() {
    let started = Arc::new(AtomicUsize::new(0));
    let (dropped, mut drops) = mpsc::unbounded_channel();
    let session = dapp()
        .on_request({
            let started = Arc::clone(&started);
            move |_| {
                let started = Arc::clone(&started);
                let dropped = dropped.clone();
                async move {
                    let _resource = CallbackResource(dropped);
                    started.fetch_add(1, Ordering::SeqCst);
                    futures::future::pending::<Result<serde_json::Value, OpenLvError>>().await
                }
            }
        })
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Barrier::new(97));
    let mut tasks = Vec::new();
    for index in 0..96 {
        let session = session.clone();
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            gate.wait().await;
            session
                .inner
                .dispatch_request(index.to_string(), json!(index))
        }));
    }
    gate.wait().await;
    session.close().await.unwrap();
    for task in tasks {
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        if let Err(error) = result {
            assert_session_closed::<()>(Err(error));
        }
    }
    let mut destroyed = 0;
    while drops.try_recv().is_ok() {
        destroyed += 1;
    }
    assert_eq!(destroyed, started.load(Ordering::SeqCst));
    assert_session_closed(session.inner.dispatch_request("late".into(), json!(null)));
}

#[test]
fn selects_the_first_host_preference_supported_by_the_client() {
    let host = ["ws", "wrtc"];
    let client = vec!["wrtc".to_string(), "ws".to_string()];
    assert_eq!(select_transport_id(true, &host, &client), Some("ws"));

    let client_own = ["wrtc", "ws"];
    let host_peer = vec!["ws".to_string(), "wrtc".to_string()];
    assert_eq!(
        select_transport_id(false, &client_own, &host_peer),
        Some("ws")
    );
}

#[test]
fn rejects_disjoint_transport_lists() {
    let host = ["wrtc"];
    let client = vec!["ws".to_string()];
    assert_eq!(select_transport_id(true, &host, &client), None);
}
