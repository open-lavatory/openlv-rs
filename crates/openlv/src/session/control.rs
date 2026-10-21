//! Automatic request admission and session operation cancellation.

use std::{
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};

use tokio::sync::{Notify, watch};

use crate::errors::OpenLvError;

const MAX_ACTIVE_HANDLERS: usize = 256;

/// All registration and shutdown decisions share one lock, so no handler or
/// operation can be admitted after close.
pub(super) struct SessionControl {
    state: Mutex<ControlState>,
    operations_idle: Notify,
    shutdown: watch::Sender<bool>,
}

struct ControlState {
    closed: bool,
    active_operations: usize,
    active_handlers: usize,
}

impl SessionControl {
    pub(super) fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            state: Mutex::new(ControlState {
                closed: false,
                active_operations: 0,
                active_handlers: 0,
            }),
            operations_idle: Notify::new(),
            shutdown,
        }
    }

    pub(super) async fn run_operation<T>(
        self: &Arc<Self>,
        operation: impl Future<Output = Result<T, OpenLvError>>,
    ) -> Result<T, OpenLvError> {
        let _operation_guard = {
            let mut state = lock(&self.state);
            if state.closed {
                return Err(session_closed());
            }
            state.active_operations += 1;
            ActiveOperation {
                control: Arc::clone(self),
            }
        };
        // Drop the operation before its guard announces idleness, including
        // when this future is canceled externally.
        {
            let operation = operation;
            tokio::pin!(operation);
            tokio::select! {
                // Prioritize cancellation when both branches are ready.
                biased;
                _ = self.closed() => Err(session_closed()),
                result = &mut operation => result,
            }
        }
    }

    pub(super) fn close(&self) {
        let mut state = lock(&self.state);
        if state.closed {
            return;
        }
        state.closed = true;
        self.shutdown.send_replace(true);
    }

    /// Wait until tracked futures have actually been destroyed, not merely
    /// until their cancellation has been signaled.
    pub(super) async fn wait_for_operations(&self) {
        loop {
            let idle = self.operations_idle.notified();
            tokio::pin!(idle);
            // Register before checking: notify_waiters does not save a permit.
            idle.as_mut().enable();
            if lock(&self.state).active_operations == 0 {
                return;
            }
            idle.await;
        }
    }

    pub(super) async fn closed(&self) {
        let mut shutdown = self.shutdown.subscribe();
        if !*shutdown.borrow_and_update() {
            let _ = shutdown.changed().await;
        }
    }

    pub(super) fn admit_handler(self: &Arc<Self>) -> Result<HandlerPermit, OpenLvError> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(session_closed());
        }
        if state.active_handlers >= MAX_ACTIVE_HANDLERS {
            return Err(OpenLvError::Session(
                "incoming request limit reached; request declined".into(),
            ));
        }
        state.active_handlers += 1;
        Ok(HandlerPermit {
            control: Arc::clone(self),
        })
    }
}

struct ActiveOperation {
    control: Arc<SessionControl>,
}

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        let mut state = lock(&self.control.state);
        state.active_operations -= 1;
        if state.active_operations == 0 {
            self.control.operations_idle.notify_waiters();
        }
    }
}

pub(super) struct HandlerPermit {
    control: Arc<SessionControl>,
}

impl Drop for HandlerPermit {
    fn drop(&mut self) {
        lock(&self.control.state).active_handlers -= 1;
    }
}

fn session_closed() -> OpenLvError {
    OpenLvError::Session("session is closed".into())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::time::Duration;
    use tokio::sync::oneshot;

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    fn assert_session_error<T>(result: Result<T, OpenLvError>) {
        assert!(matches!(result, Err(OpenLvError::Session(_))));
    }

    #[tokio::test]
    async fn shutdown_wakes_all_observers_and_is_persistent() {
        let control = Arc::new(SessionControl::new());
        let mut closed = Box::pin(control.closed());
        let mut another_closed = Box::pin(control.closed());
        assert!(closed.as_mut().now_or_never().is_none());
        assert!(another_closed.as_mut().now_or_never().is_none());
        control.close();
        tokio::time::timeout(TEST_TIMEOUT, closed).await.unwrap();
        tokio::time::timeout(TEST_TIMEOUT, another_closed)
            .await
            .unwrap();
        assert!(control.closed().now_or_never().is_some());
    }

    #[tokio::test]
    async fn persistent_shutdown_cancels_and_destroys_operation_future() {
        let control = Arc::new(SessionControl::new());
        let (dropped, mut observed) = oneshot::channel::<()>();
        let operation = async move {
            let _resource = dropped;
            futures::future::pending::<Result<(), OpenLvError>>().await
        };
        let mut result = Box::pin(control.run_operation(operation));
        assert!(result.as_mut().now_or_never().is_none());
        control.close();
        assert_session_error(tokio::time::timeout(TEST_TIMEOUT, result).await.unwrap());
        assert!(matches!(
            observed.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert_session_error(
            control
                .run_operation(async {
                    panic!("closed session polled operation");
                    #[allow(unreachable_code)]
                    Ok::<(), OpenLvError>(())
                })
                .await,
        );
    }

    struct ObserveDrop {
        control: Arc<SessionControl>,
        dropped: Option<oneshot::Sender<bool>>,
    }

    impl Drop for ObserveDrop {
        fn drop(&mut self) {
            let active = lock(&self.control.state).active_operations != 0;
            let _ = self.dropped.take().unwrap().send(active);
        }
    }

    #[tokio::test]
    async fn operation_resource_is_destroyed_before_idle_on_close() {
        let control = Arc::new(SessionControl::new());
        let (dropped, observed) = oneshot::channel();
        let resource = ObserveDrop {
            control: Arc::clone(&control),
            dropped: Some(dropped),
        };
        let mut operation = Box::pin(control.run_operation(async move {
            let _resource = resource;
            futures::future::pending::<Result<(), OpenLvError>>().await
        }));
        assert!(operation.as_mut().now_or_never().is_none());
        control.close();
        assert_session_error(operation.await);
        assert!(observed.await.unwrap());
        assert!(control.wait_for_operations().now_or_never().is_some());
    }

    #[tokio::test]
    async fn operation_resource_is_destroyed_before_idle_on_external_cancellation() {
        let control = Arc::new(SessionControl::new());
        let (dropped, observed) = oneshot::channel();
        let resource = ObserveDrop {
            control: Arc::clone(&control),
            dropped: Some(dropped),
        };
        let mut operation = Box::pin(control.run_operation(async move {
            let _resource = resource;
            futures::future::pending::<Result<(), OpenLvError>>().await
        }));
        assert!(operation.as_mut().now_or_never().is_none());
        drop(operation);
        assert!(observed.await.unwrap());
        assert!(control.wait_for_operations().now_or_never().is_some());
    }

    #[tokio::test]
    async fn teardown_waits_for_future_destruction_and_wakes_all_waiters() {
        let control = Arc::new(SessionControl::new());
        let mut operation =
            Box::pin(control.run_operation(futures::future::pending::<Result<(), OpenLvError>>()));
        assert!(operation.as_mut().now_or_never().is_none());
        let mut idle = Box::pin(control.wait_for_operations());
        let mut another_idle = Box::pin(control.wait_for_operations());
        assert!(idle.as_mut().now_or_never().is_none());
        assert!(another_idle.as_mut().now_or_never().is_none());
        control.close();
        assert!(idle.as_mut().now_or_never().is_none());
        assert_session_error(operation.await);
        tokio::time::timeout(TEST_TIMEOUT, idle).await.unwrap();
        tokio::time::timeout(TEST_TIMEOUT, another_idle)
            .await
            .unwrap();
    }
}
