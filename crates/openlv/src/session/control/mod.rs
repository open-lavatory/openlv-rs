//! Session task ownership, automatic request admission, and shutdown.

use std::{
    future::Future,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Mutex, MutexGuard},
};

use futures::FutureExt;
use tokio::{
    runtime::Handle,
    sync::{oneshot, watch},
    task::{AbortHandle, JoinSet},
};

use crate::errors::OpenLvError;

/// Upper bound on remote requests whose handler has not finished.
///
/// Each admitted request holds a session task and the handler future until
/// its response is sent, so this bounds the tasks and memory that one peer
/// can make a session hold. 256 is a chosen margin, not a measured limit: it
/// leaves room for a dApp that sends many JSON-RPC calls in parallel while
/// wallet handlers wait for user approval. A lower value declines legitimate
/// bursts; a higher value lets a misbehaving peer hold more memory. A
/// declined request gets no ack, so the remote peer fails it after its own
/// ack timeout (10 s in the JS implementation and in
/// [`DEFAULT_ACK_TIMEOUT_MS`](super::DEFAULT_ACK_TIMEOUT_MS)).
const MAX_ACTIVE_HANDLERS: usize = 256;

/// All spawn, admission and shutdown decisions share one lock, so no task,
/// operation or handler can be admitted after close.
pub struct SessionControl {
    state: Mutex<ControlState>,
    shutdown: watch::Sender<bool>,
}

struct ControlState {
    closed: bool,
    active_handlers: usize,
    tasks: JoinSet<()>,
}

impl SessionControl {
    pub fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            state: Mutex::new(ControlState {
                closed: false,
                active_handlers: 0,
                tasks: JoinSet::new(),
            }),
            shutdown,
        }
    }

    /// Run `operation` as a session task, so close can destroy it even when
    /// the caller keeps this future without polling it.
    pub async fn run_operation<T: Send + 'static>(
        &self,
        operation: impl Future<Output = Result<T, OpenLvError>> + Send + 'static,
    ) -> Result<T, OpenLvError> {
        let (result_tx, result_rx) = oneshot::channel();
        let _task = AbortOnDrop(self.spawn(async move {
            let _ = result_tx.send(AssertUnwindSafe(operation).catch_unwind().await);
        })?);
        match result_rx.await {
            Ok(Ok(result)) => result,
            Ok(Err(panic)) => panic::resume_unwind(panic),
            Err(_) => Err(OpenLvError::SessionClosed),
        }
    }

    pub fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<AbortHandle, OpenLvError> {
        // Runtime lookup and panic payload destruction must happen outside the lock.
        let runtime = Handle::current();
        let mut state = self.state();
        if state.closed {
            return Err(OpenLvError::SessionClosed);
        }
        let mut completed = Vec::new();
        while let Some(result) = state.tasks.try_join_next() {
            completed.push(result);
        }
        let handle = state.tasks.spawn_on(task, &runtime);
        drop(state);
        drop(completed);
        Ok(handle)
    }

    pub fn close(&self) {
        let mut state = self.state();
        if state.closed {
            return;
        }
        state.closed = true;
        state.tasks.abort_all();
        self.shutdown.send_replace(true);
    }

    /// Wait until every task spawned before close has been destroyed.
    pub async fn wait_for_tasks(&self) {
        let mut tasks = std::mem::take(&mut self.state().tasks);
        while tasks.join_next().await.is_some() {}
    }

    pub async fn closed(&self) {
        let mut shutdown = self.shutdown.subscribe();
        if !*shutdown.borrow_and_update() {
            let _ = shutdown.changed().await;
        }
    }

    pub fn admit_handler(self: &Arc<Self>) -> Result<HandlerPermit, OpenLvError> {
        let mut state = self.state();
        if state.closed {
            return Err(OpenLvError::SessionClosed);
        }
        if state.active_handlers >= MAX_ACTIVE_HANDLERS {
            return Err(OpenLvError::RequestLimitReached);
        }
        state.active_handlers += 1;
        Ok(HandlerPermit {
            control: Arc::clone(self),
        })
    }

    fn state(&self) -> MutexGuard<'_, ControlState> {
        self.state
            .lock()
            .expect("no code under the session control lock panics")
    }
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct HandlerPermit {
    control: Arc<SessionControl>,
}

impl Drop for HandlerPermit {
    fn drop(&mut self) {
        self.control.state().active_handlers -= 1;
    }
}

#[cfg(test)]
mod tests;
