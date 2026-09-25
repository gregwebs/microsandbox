//! Shared synchronization helpers for crate unit tests.

use std::sync::{Arc, Mutex, MutexGuard};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Serializes process-global environment mutation across SDK unit tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Serializes process-global `tracing` subscriber installation across tests.
static TRACING_LOCK: Mutex<()> = Mutex::new(());

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Captures formatted `tracing` events emitted while installed.
///
/// Used by redaction tests: a credential value must never reach a log line, so
/// the test installs this subscriber, runs the code under test with a canary
/// value, and asserts the canary never appears in a captured event.
pub(crate) struct CapturedEvents {
    events: Mutex<Vec<String>>,
}

impl CapturedEvents {
    /// Every captured event's formatted field values, in order.
    pub(crate) fn formatted(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl tracing::Subscriber for CapturedEvents {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct ValueVisitor(String);

        impl tracing::field::Visit for ValueVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?};", field.name()));
            }
        }

        let mut visitor = ValueVisitor(String::new());
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(visitor.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Lock process-global environment mutation for the duration of a unit test.
pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Run `body` with a capturing `tracing` subscriber installed.
///
/// Returns the body's result and every event the body logged. The test-global
/// subscriber is process-wide, so callers must hold the returned guard for the
/// duration of the measurement; tests that call this take `lock_tracing()`.
pub(crate) fn capture_events<T>(body: impl FnOnce() -> T) -> (T, Vec<String>) {
    let capture = Arc::new(CapturedEvents {
        events: Mutex::new(Vec::new()),
    });
    let guard = tracing::subscriber::set_default(capture.clone());
    let result = body();
    drop(guard);
    let events = capture.formatted();
    (result, events)
}

/// Lock process-global `tracing` subscriber installation for a unit test.
pub(crate) fn lock_tracing() -> MutexGuard<'static, ()> {
    TRACING_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}
