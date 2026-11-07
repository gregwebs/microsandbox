//! Reads the runtime's `network.log` through the SDK's live `Network` log stream.
//!
//! Two test binaries need the same reader — `network_refusal_e2e.rs` and
//! `tls_intercept.rs` — and a test target cannot import another one, so each
//! includes this file with `#[path = "support/refusal_log.rs"] mod refusal_log;`.
//! It adds no dependency and no production code.
//!
//! Every wait here is bounded by a caller-chosen deadline — [`RECORD_DEADLINE`]
//! is the specification's 5 s live bound — and fails with the records it did
//! see, so a missing record is reported as one, not as a hang.

#![allow(dead_code)]

use std::time::Duration;

use futures::StreamExt;
use microsandbox::Sandbox;
use microsandbox::logs::{
    LogSource, LogStreamOptions, LogStreamStart, NetworkLogEvent, NetworkLogRecord, NetworkRefusal,
    NetworkSuppressed, RefusalSite,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

/// Longest any helper waits for a record, matching the specification's live bound.
pub const RECORD_DEADLINE: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A live `Network` log stream, drained in the background.
pub struct RefusalLog {
    records: Vec<NetworkLogRecord>,
    incoming: mpsc::UnboundedReceiver<Result<NetworkLogRecord, String>>,
    task: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RefusalLog {
    /// Open a `[Network]` stream at the beginning of the log, before any probe.
    ///
    /// The stream is requested before the guest does anything, which is the
    /// property AC3 asks for: this reader has to pick up records as they are
    /// written, on a file the runtime created at sandbox boot.
    pub async fn open(sandbox: &Sandbox) -> Self {
        let stream = sandbox
            .log_stream(&LogStreamOptions {
                sources: vec![LogSource::Network],
                start: LogStreamStart::Beginning,
                until: None,
                follow: true,
            })
            .await
            .expect("open the network log stream");
        let (sender, incoming) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut stream = std::pin::pin!(stream);
            while let Some(item) = stream.next().await {
                let item = item
                    .map_err(|error| format!("the network log stream failed: {error}"))
                    .and_then(|entry| {
                        serde_json::from_slice::<NetworkLogRecord>(entry.data.as_ref()).map_err(
                            |error| {
                                format!(
                                    "a network entry's data is not a NetworkLogRecord \
                                     ({error}): {:?}",
                                    String::from_utf8_lossy(entry.data.as_ref())
                                )
                            },
                        )
                    });
                let failed = item.is_err();
                if sender.send(item).is_err() || failed {
                    return;
                }
            }
        });
        Self {
            records: Vec::new(),
            incoming,
            task,
        }
    }

    /// Every record received so far, in arrival order.
    pub fn records(&self) -> &[NetworkLogRecord] {
        &self.records
    }

    /// Wait for the first refusal matching `pred`, ignoring other records.
    pub async fn expect_refusal(
        &mut self,
        what: &str,
        pred: impl Fn(&NetworkRefusal) -> bool,
    ) -> NetworkLogRecord {
        self.expect(
            what,
            RECORD_DEADLINE,
            |record| matches!(&record.event, NetworkLogEvent::Refusal(refusal) if pred(refusal)),
        )
        .await
    }

    /// Wait for a `suppressed` record at `site` within `window`.
    pub async fn expect_suppressed(
        &mut self,
        site: RefusalSite,
        window: Duration,
    ) -> NetworkSuppressed {
        let record = self
            .expect(&format!("suppressed record for {site:?}"), window, |record| {
                matches!(&record.event, NetworkLogEvent::Suppressed(suppressed) if suppressed.site == site)
            })
            .await;
        match record.event {
            NetworkLogEvent::Suppressed(suppressed) => suppressed,
            // The predicate above can only select a suppressed record.
            NetworkLogEvent::Refusal(_) | _ => {
                unreachable!("the predicate selected a suppressed record")
            }
        }
    }

    /// Fail if a refusal matching `pred` arrives within `window`.
    ///
    /// The window is the only way to assert that a *flow* produced no record,
    /// because absence has no event to wait for; it is a bounded wait that fails
    /// fast on the record it forbids, never a sleep that hides one.
    pub async fn expect_no_refusal(
        &mut self,
        what: &str,
        window: Duration,
        pred: impl Fn(&NetworkRefusal) -> bool,
    ) {
        let started = Instant::now();
        while started.elapsed() < window {
            let remaining = window.saturating_sub(started.elapsed());
            let received = timeout(remaining, self.incoming.recv()).await;
            match received {
                Ok(Some(item)) => {
                    let record = self.accept(item, what);
                    if let NetworkLogEvent::Refusal(refusal) = &record.event
                        && pred(refusal)
                    {
                        panic!("{what} was recorded, but it must produce no record: {record:?}");
                    }
                }
                Ok(None) => panic!("the network log stream closed while waiting for {what}"),
                Err(_) => return,
            }
        }
    }

    /// How many refusals at `site` have been received so far.
    ///
    /// Because the runtime writes from one queue in order, a record that arrived
    /// later is a barrier: every refusal decided before it has already been
    /// counted.
    pub fn count_refusals(&self, site: RefusalSite) -> usize {
        self.records
            .iter()
            .filter(|record| {
                matches!(&record.event, NetworkLogEvent::Refusal(refusal) if refusal.site == site)
            })
            .count()
    }

    /// The record's wire form.
    ///
    /// The record's `protocol` type is not re-exported by the SDK, so tests
    /// assert its spelling on the serialized record — which is also where the
    /// field names and the omitted optional fields live. Both are part of the
    /// format contract.
    pub fn wire(record: &NetworkLogRecord) -> Value {
        serde_json::to_value(record).expect("a network record serializes")
    }

    /// One visible record, or the refusal inside it.
    ///
    /// Panics on a `suppressed` record, because a caller asking for a refusal
    /// wants the decision, not a count of the ones it could not see.
    pub fn refusal(record: &NetworkLogRecord) -> &NetworkRefusal {
        match &record.event {
            NetworkLogEvent::Refusal(refusal) => refusal,
            NetworkLogEvent::Suppressed(suppressed) => {
                panic!("expected a refusal record, got a suppressed record: {suppressed:?}")
            }
            // A record kind this SDK does not know is skipped by the parser, so
            // it can never reach here.
            _ => unreachable!("a network record always carries a known event"),
        }
    }

    async fn expect(
        &mut self,
        what: &str,
        window: Duration,
        pred: impl Fn(&NetworkLogRecord) -> bool,
    ) -> NetworkLogRecord {
        let started = Instant::now();
        loop {
            let remaining = window.saturating_sub(started.elapsed());
            let received = timeout(remaining, self.incoming.recv()).await;
            match received {
                Ok(Some(item)) => {
                    let record = self.accept(item, what);
                    if pred(&record) {
                        return record;
                    }
                }
                Ok(None) => panic!("the network log stream closed while waiting for {what}"),
                Err(_) => {
                    let seen = self.describe();
                    panic!("no {what} within {window:?}; records seen: {seen}");
                }
            }
        }
    }

    fn accept(&mut self, item: Result<NetworkLogRecord, String>, what: &str) -> NetworkLogRecord {
        match item {
            Ok(record) => {
                self.records.push(record.clone());
                record
            }
            Err(error) => panic!("{what}: {error}"),
        }
    }

    /// Every record seen, as one line, for a failure message.
    fn describe(&self) -> String {
        if self.records.is_empty() {
            return "none".to_owned();
        }
        self.records
            .iter()
            .map(|record| serde_json::to_string(record).expect("a network record serializes"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Drop for RefusalLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}
