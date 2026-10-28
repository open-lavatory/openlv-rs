use super::*;
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

fn assert_session_error<T>(result: Result<T, OpenLvError>) {
    assert!(matches!(result, Err(OpenLvError::SessionClosed)));
}

async fn pending_operation_holding(resource: oneshot::Sender<()>) -> Result<(), OpenLvError> {
    let _resource = resource;
    futures::future::pending().await
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
async fn close_destroys_an_operation_whose_caller_stopped_polling() {
    let control = Arc::new(SessionControl::new());
    let (resource, mut observed) = oneshot::channel();
    let mut operation = Box::pin(control.run_operation(pending_operation_holding(resource)));
    assert!(operation.as_mut().now_or_never().is_none());

    control.close();
    tokio::time::timeout(TEST_TIMEOUT, control.wait_for_tasks())
        .await
        .unwrap();
    assert!(matches!(
        observed.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    assert_session_error(operation.await);
    assert_session_error(
        control
            .run_operation(futures::future::lazy(|_| -> Result<(), OpenLvError> {
                panic!("closed session ran an operation")
            }))
            .await,
    );
}

#[tokio::test]
async fn dropping_an_operation_destroys_its_task() {
    let control = Arc::new(SessionControl::new());
    let (resource, observed) = oneshot::channel();
    let mut operation = Box::pin(control.run_operation(pending_operation_holding(resource)));
    assert!(operation.as_mut().now_or_never().is_none());

    drop(operation);
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, observed)
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
#[should_panic(expected = "operation bug")]
async fn operation_panics_reach_the_caller() {
    let control = Arc::new(SessionControl::new());
    let _ = control
        .run_operation(futures::future::lazy(|_| -> Result<(), OpenLvError> {
            panic!("operation bug")
        }))
        .await;
}
