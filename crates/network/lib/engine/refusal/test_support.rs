//! Test-only refusal sink: collect what a deny site reports, then assert on it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox_types::{NetworkRefusal, RefusalSite};

use crate::netstack::shared::{ResolvedHostnameFamily, SharedState};
use crate::refusal::RefusalSink;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Collects every refusal it is given, so a test can assert what a deny site records.
#[derive(Default)]
pub(crate) struct CollectingSink(Mutex<Vec<NetworkRefusal>>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CollectingSink {
    /// A sink to install on shared state with [`SharedState::set_refusal_sink`].
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Everything recorded since the last call, in the order it was recorded.
    pub(crate) fn take(&self) -> Vec<NetworkRefusal> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl RefusalSink for CollectingSink {
    /// A test sink keeps everything: it never suppresses a refusal.
    fn admits(&self, _site: RefusalSite) -> bool {
        true
    }

    fn record(&self, refusal: NetworkRefusal) {
        self.0.lock().unwrap().push(refusal);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Shared state with a collecting sink installed, and the sink.
pub(crate) fn recording_state(queue_capacity: usize) -> (Arc<SharedState>, Arc<CollectingSink>) {
    let shared = Arc::new(SharedState::new(queue_capacity));
    let sink = CollectingSink::new();
    shared.set_refusal_sink(sink.clone());
    (shared, sink)
}

/// Bind one live name to `addr` in the guest's DNS index, so a `dns-cache` record can be asserted.
pub(crate) fn cache_name(shared: &SharedState, name: &str, addr: IpAddr) {
    let family = match addr {
        IpAddr::V4(_) => ResolvedHostnameFamily::Ipv4,
        IpAddr::V6(_) => ResolvedHostnameFamily::Ipv6,
    };
    assert!(shared.cache_resolved_hostname(name, family, [addr], Duration::from_secs(60)));
}
