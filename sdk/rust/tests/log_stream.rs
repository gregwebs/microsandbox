//! Integration tests for the public `log_stream` / `read_logs` API.
//!
//! Drives the full caller path —
//! `microsandbox::logs::log_stream(name, opts)` — against
//! a synthetic on-disk log directory. No real microVM is booted;
//! we set `MSB_HOME` to a tempdir, lay out `sandboxes/<name>/logs/`
//! with hand-crafted `exec.log` / `runtime.log` / `kernel.log`,
//! and verify the streamed entries.
//!
//! Each test uses a unique sandbox name so they can run in
//! parallel under the shared `MSB_HOME`.
//!
//! These tests don't require any external infrastructure
//! (libkrunfw, kernel image, etc.) — they're pure I/O exercises
//! against the streaming engine through its public entry points.

use std::path::PathBuf;
use std::sync::OnceLock;

use futures::TryStreamExt;
use microsandbox::logs;
use microsandbox::logs::{LogCursor, LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use tempfile::TempDir;

/// Singleton MSB_HOME for the whole test binary. We set it once
/// before any code touches the global config; tests share the root
/// and use distinct sandbox names so they don't collide.
static MSB_HOME: OnceLock<TempDir> = OnceLock::new();

fn msb_home() -> &'static TempDir {
    MSB_HOME.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("msb-log-stream-test-")
            .tempdir()
            .expect("failed to create MSB_HOME tempdir");
        // SAFETY: integration test setup; runs before any other
        // code in this binary reads the env.
        unsafe {
            std::env::set_var("MSB_HOME", dir.path());
        }
        dir
    })
}

/// Create the log directory layout for a fresh sandbox name and
/// return its path.
fn make_log_dir(name: &str) -> PathBuf {
    let root = msb_home().path();
    let log_dir = root.join("sandboxes").join(name).join("logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");
    log_dir
}

fn jsonl(ts: &str, source: &str, data: &str, id: u64) -> String {
    format!(r#"{{"t":"{ts}","s":"{source}","d":"{data}","id":{id}}}"#)
}

fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn write_lines(path: &std::path::Path, lines: &[String]) {
    let mut blob = String::new();
    for l in lines {
        blob.push_str(l);
        blob.push('\n');
    }
    std::fs::write(path, blob).expect("write log file");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn log_stream_drains_exec_log_with_default_sources() {
    let name = "log-stream-default-sources";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "first line", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stderr", "warning", 1),
            jsonl("2026-05-01T10:00:02.000Z", "output", "pty out", 1),
        ],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].source, LogSource::Stdout);
    assert_eq!(entries[0].data.as_ref(), b"first line");
    assert_eq!(entries[1].source, LogSource::Stderr);
    assert_eq!(entries[2].source, LogSource::Output);
}

#[tokio::test]
async fn log_stream_includes_system_files_when_requested() {
    let name = "log-stream-system-sources";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T10:00:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T09:59:00.000Z INFO runtime started".to_string()],
    );
    write_lines(
        &log_dir.join("kernel.log"),
        &["2026-05-01T09:58:00.000Z kernel boot complete".to_string()],
    );

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    // Should see the exec stdout entry and both system entries.
    let has_user = entries
        .iter()
        .any(|e| e.source == LogSource::Stdout && e.data.as_ref() == b"user output");
    let has_runtime = entries.iter().any(|e| {
        e.source == LogSource::System
            && std::str::from_utf8(&e.data)
                .unwrap_or("")
                .contains("runtime started")
    });
    let has_kernel = entries.iter().any(|e| {
        e.source == LogSource::System
            && std::str::from_utf8(&e.data)
                .unwrap_or("")
                .contains("kernel boot complete")
    });
    assert!(has_user, "missing user stdout entry: {entries:?}");
    assert!(has_runtime, "missing runtime.log entry: {entries:?}");
    assert!(has_kernel, "missing kernel.log entry: {entries:?}");
}

#[tokio::test]
async fn log_stream_includes_rotated_exec_files() {
    let name = "log-stream-rotated";
    let log_dir = make_log_dir(name);
    // Older entry in a rotated file, newer in the active file.
    write_lines(
        &log_dir.join("exec.log.1"),
        &[jsonl(
            "2026-05-01T08:00:00.000Z",
            "stdout",
            "from rotated",
            1,
        )],
    );
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T09:00:00.000Z",
            "stdout",
            "from active",
            1,
        )],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    assert_eq!(entries.len(), 2);
    // Per-source order: rotated file drained first, then active.
    assert_eq!(entries[0].data.as_ref(), b"from rotated");
    assert_eq!(entries[1].data.as_ref(), b"from active");
}

#[tokio::test]
async fn log_stream_resume_from_cursor_continues_after_seen_entries() {
    let name = "log-stream-resume";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stdout", "b", 1),
            jsonl("2026-05-01T10:00:02.000Z", "stdout", "c", 1),
        ],
    );

    // First pass: drain everything to grab a cursor.
    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("first stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain first stream");
    assert_eq!(entries.len(), 3);
    let cursor_after_b = entries[1].cursor.clone();

    // Second pass: resume from cursor; should yield only "c".
    let stream2 = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(cursor_after_b),
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let entries2: Vec<_> = stream2.try_collect().await.expect("drain resumed stream");
    assert_eq!(entries2.len(), 1);
    assert_eq!(entries2[0].data.as_ref(), b"c");
}

#[tokio::test]
async fn log_stream_cursor_serializes_and_round_trips() {
    let name = "log-stream-cursor-rt";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "x", 1)],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert_eq!(entries.len(), 1);

    // Cursor round-trips through string form.
    let cursor_str = entries[0].cursor.to_string();
    let parsed: LogCursor = cursor_str.parse().expect("cursor parses");
    assert_eq!(parsed, entries[0].cursor);
}

#[tokio::test]
async fn log_stream_follow_picks_up_appended_entries() {
    let name = "log-stream-follow";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "first", 1)],
    );

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            follow: true,
            ..Default::default()
        },
    )
    .await
    .expect("open follow stream");
    let mut stream = Box::pin(stream);
    use futures::StreamExt;

    // First entry from backfill.
    let first = tokio::time::timeout(std::time::Duration::from_secs(3), stream.next())
        .await
        .expect("first entry within 3s")
        .expect("stream not ended")
        .expect("not an error");
    assert_eq!(first.data.as_ref(), b"first");

    // Append a new entry.
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "first", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stdout", "second", 1),
        ],
    );

    let second = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("second entry within 5s")
        .expect("stream not ended")
        .expect("not an error");
    assert_eq!(second.data.as_ref(), b"second");
}

#[tokio::test]
async fn read_logs_returns_sorted_snapshot() {
    let name = "read-logs-sorted";
    let log_dir = make_log_dir(name);
    // Put runtime.log (older) and exec.log (newer) — read_logs
    // should sort the merged result chronologically.
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T08:00:00.000Z INFO early runtime".to_string()],
    );
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T09:00:00.000Z",
            "stdout",
            "late stdout",
            1,
        )],
    );

    let entries = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    // Chronological order: runtime (08:00) before exec stdout (09:00).
    assert!(
        entries.len() >= 2,
        "expected at least 2 entries: {entries:?}"
    );
    assert!(
        std::str::from_utf8(&entries[0].data)
            .unwrap_or("")
            .contains("early runtime"),
        "expected runtime entry first: {entries:?}",
    );
    assert!(
        entries[entries.len() - 1].data.as_ref() == b"late stdout",
        "expected stdout entry last: {entries:?}",
    );
}

#[tokio::test]
async fn read_logs_sorted_cursor_resumes_after_selected_entry() {
    let name = "read-logs-sorted-cursor-resume";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1),
            jsonl("2026-05-01T10:02:00.000Z", "stdout", "c", 1),
        ],
    );
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T10:01:00.000Z INFO b".to_string()],
    );

    let entries = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].data.as_ref(), b"a");
    assert!(
        std::str::from_utf8(&entries[1].data)
            .unwrap()
            .contains("INFO b")
    );
    assert_eq!(entries[2].data.as_ref(), b"c");

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            start: LogStreamStart::From(entries[1].cursor.clone()),
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let resumed: Vec<_> = stream.try_collect().await.expect("drain resumed stream");

    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].data.as_ref(), b"c");
}

#[tokio::test]
async fn read_logs_snapshot_cursor_advances_past_since_filtered_entries() {
    let name = "read-logs-snapshot-cursor-since-filter";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "old", 1)],
    );

    let snapshot = logs::read_logs_snapshot(
        name,
        &LogOptions {
            since: Some(ts("2026-05-01T10:01:00.000Z")),
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    assert!(snapshot.entries.is_empty());

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(snapshot.cursor),
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let resumed: Vec<_> = stream.try_collect().await.expect("drain resumed stream");

    assert!(
        resumed.is_empty(),
        "since-filtered entries replayed after snapshot cursor: {resumed:?}"
    );
}

#[tokio::test]
async fn log_stream_invalid_cursor_returns_error_upfront() {
    let name = "log-stream-invalid-cursor";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1)],
    );

    // Craft a cursor pointing at a non-existent exec.log generation.
    // We get a valid cursor first, then mangle the string. Simpler:
    // use a cursor from a different sandbox name.
    let other = "log-stream-invalid-cursor-other";
    let other_dir = make_log_dir(other);
    write_lines(
        &other_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "x", 1)],
    );
    let other_stream = logs::log_stream(other, &LogStreamOptions::default())
        .await
        .expect("open other stream");
    let other_entries: Vec<_> = other_stream
        .try_collect()
        .await
        .expect("drain other stream");
    let foreign_cursor = other_entries[0].cursor.clone();

    // Resume the first sandbox with the other sandbox's cursor.
    // The exec generation won't match, so InvalidCursor fires.
    let result = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(foreign_cursor),
            ..Default::default()
        },
    )
    .await;
    assert!(
        matches!(
            result,
            Err(microsandbox::MicrosandboxError::InvalidCursor(_))
        ),
        "expected InvalidCursor, got: {:?}",
        result.as_ref().err(),
    );
}
//--------------------------------------------------------------------------------------------------
// network.log — egress refusal records
//--------------------------------------------------------------------------------------------------

fn network_line(t: &str, site: &str, dst_port: u16) -> String {
    format!(
        r#"{{"v":1,"t":"{t}","s":"network","event":"refusal","site":"{site}","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":{dst_port},"name":"api.example.com","name_source":"dns-cache","revision":2}}"#
    )
}

fn network_options(start: LogStreamStart) -> LogStreamOptions {
    LogStreamOptions {
        sources: vec![LogSource::Network],
        start,
        ..Default::default()
    }
}

#[tokio::test]
async fn log_stream_reads_network_log_when_requested() {
    let name = "log-stream-network-only";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-11-05T14:03:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );
    write_lines(
        &log_dir.join("network.log"),
        &[network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443)],
    );

    let stream = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open network stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].source, LogSource::Network);
    assert_eq!(entries[0].session_id, None);

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::Network],
            ..Default::default()
        },
    )
    .await
    .expect("open mixed stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().any(|e| e.source == LogSource::Network)
            && entries.iter().any(|e| e.source == LogSource::Stdout)
    );
}

#[tokio::test]
async fn network_entry_data_is_the_whole_record_line() {
    let name = "log-stream-network-whole-line";
    let log_dir = make_log_dir(name);
    let line = network_line("2026-11-05T14:03:07.412Z", "udp", 9999);
    write_lines(&log_dir.join("network.log"), std::slice::from_ref(&line));

    let stream = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open network stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].data.as_ref(), format!("{line}\n").as_bytes());
    assert_eq!(entries[0].timestamp, ts("2026-11-05T14:03:07.412Z"));

    let record: logs::NetworkLogRecord = serde_json::from_slice(&entries[0].data)
        .expect("whole line deserializes as a network log record");
    assert_eq!(record.v, logs::NETWORK_LOG_FORMAT_VERSION);
    assert_eq!(record.s, LogSource::Network);
    match record.event {
        logs::NetworkLogEvent::Refusal(refusal) => {
            assert_eq!(refusal.site, logs::RefusalSite::Udp);
            assert_eq!(refusal.dst_port, Some(9999));
            assert_eq!(refusal.name_source, logs::NameSource::DnsCache);
            assert_eq!(refusal.name.as_deref(), Some("api.example.com"));
            assert_eq!(refusal.revision, 2);
        }
        other => panic!("expected a refusal record, got {other:?}"),
    }
}

/// The bytes the runtime's writer produces survive the file and the SDK unchanged.
///
/// The writer encodes a `NetworkLogRecord` with the types crate's serializer and appends one line
/// per record; this encodes records with that same serializer, so what it puts on disk is what
/// `NetworkLog::open` + `write` produce. The reader must then hand a caller the same line, and it
/// must decode as the same typed record — for a record with every optional field, for a record
/// with `dst_ip`/`dst_port`/`name` absent, and for a `suppressed` record.
#[tokio::test]
async fn network_records_the_writer_encodes_round_trip_through_the_file_and_the_sdk() {
    use microsandbox::logs::{
        NETWORK_LOG_FORMAT_VERSION, NameSource, NetworkLogEvent, NetworkLogRecord, NetworkRefusal,
        NetworkSuppressed, RefusalLayer, RefusalSite,
    };

    let name = "log-stream-network-writer-round-trip";
    let log_dir = make_log_dir(name);
    let longest = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(longest.len(), 253, "the longest name a record may carry");

    let at = |second: &str| ts(&format!("2026-11-05T14:03:{second}.000Z"));
    let refusal = |site, layer, protocol, dst_ip, dst_port, name: Option<&str>, source| {
        NetworkLogEvent::Refusal(NetworkRefusal {
            site,
            layer,
            protocol,
            dst_ip,
            dst_port,
            name: name.map(str::to_owned),
            name_source: source,
            revision: 7,
        })
    };

    let events = [
        // Every field present, with the longest name R3 allows.
        refusal(
            RefusalSite::TcpHostname,
            RefusalLayer::Tenant,
            microsandbox_types::Protocol::Tcp,
            Some("203.0.113.10".parse().unwrap()),
            Some(443),
            Some(&longest),
            NameSource::Sni,
        ),
        // ICMP: no port, no name.
        refusal(
            RefusalSite::Icmp,
            RefusalLayer::Platform,
            microsandbox_types::Protocol::Icmpv6,
            Some("2001:db8::7".parse().unwrap()),
            None,
            None,
            NameSource::Absent,
        ),
        // A DNS query whose addressed resolver the engine could not determine: no `dst_ip`.
        refusal(
            RefusalSite::DnsQuery,
            RefusalLayer::Tenant,
            microsandbox_types::Protocol::Udp,
            None,
            Some(53),
            Some("_sip._tcp.example"),
            NameSource::DnsQuery,
        ),
        NetworkLogEvent::Suppressed(NetworkSuppressed {
            site: RefusalSite::Udp,
            count: 4744,
        }),
    ];

    let mut lines = Vec::new();
    for (index, event) in events.into_iter().enumerate() {
        let record = NetworkLogRecord {
            v: NETWORK_LOG_FORMAT_VERSION,
            t: at(&format!("0{index}")),
            s: LogSource::Network,
            event,
        };
        lines.push(serde_json::to_string(&record).expect("the writer's encoding"));
    }
    write_lines(&log_dir.join("network.log"), &lines);

    // `read_logs` and the stream see the same bytes.
    let snapshot = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Network],
            ..Default::default()
        },
    )
    .await
    .expect("read the network log");
    let entries: Vec<_> = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open the network stream")
        .try_collect()
        .await
        .expect("drain the stream");

    for entries in [&snapshot, &entries] {
        assert_eq!(entries.len(), lines.len());
        for (entry, line) in entries.iter().zip(&lines) {
            assert_eq!(entry.source, LogSource::Network);
            assert_eq!(entry.session_id, None);
            assert_eq!(
                entry.data.as_ref(),
                format!("{line}\n").as_bytes(),
                "the entry is the record's exact line plus the newline"
            );
            let record: NetworkLogRecord =
                serde_json::from_slice(&entry.data).expect("decodes as a network record");
            assert_eq!(entry.timestamp, record.t);
        }
    }

    // The optional fields survive omission: absent `dst_ip`/`dst_port`/`name` stay absent, and
    // the name that is present is byte-for-byte the one the writer was given.
    let decoded: Vec<NetworkLogRecord> = snapshot
        .iter()
        .map(|entry| serde_json::from_slice(&entry.data).expect("record"))
        .collect();
    let NetworkLogEvent::Refusal(name_with_every_field) = &decoded[0].event else {
        panic!("expected a refusal");
    };
    assert_eq!(
        name_with_every_field.name.as_deref(),
        Some(longest.as_str())
    );
    assert_eq!(name_with_every_field.name_source, NameSource::Sni);
    assert_eq!(name_with_every_field.revision, 7);
    let NetworkLogEvent::Refusal(icmp) = &decoded[1].event else {
        panic!("expected a refusal");
    };
    assert_eq!(
        (icmp.dst_port, &icmp.name, icmp.name_source),
        (None, &None, NameSource::Absent)
    );
    let NetworkLogEvent::Refusal(no_resolver) = &decoded[2].event else {
        panic!("expected a refusal");
    };
    assert_eq!(no_resolver.dst_ip, None);
    assert_eq!(no_resolver.name.as_deref(), Some("_sip._tcp.example"));
    let NetworkLogEvent::Suppressed(suppressed) = &decoded[3].event else {
        panic!("expected a suppressed record");
    };
    assert_eq!(
        (suppressed.site, suppressed.count),
        (RefusalSite::Udp, 4744)
    );
}

#[tokio::test]
async fn default_sources_exclude_network() {
    let name = "log-stream-network-default";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-11-05T14:03:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );
    write_lines(
        &log_dir.join("network.log"),
        &[network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443)],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open default stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert!(
        entries.iter().all(|e| e.source != LogSource::Network),
        "default log_stream must not yield network entries: {entries:?}"
    );
    assert_eq!(entries.len(), 1);

    let entries = logs::read_logs(name, &LogOptions::default())
        .await
        .expect("default snapshot");
    assert!(
        entries.iter().all(|e| e.source != LogSource::Network),
        "default read_logs must not yield network entries: {entries:?}"
    );
}

#[tokio::test]
async fn log_stream_follow_picks_up_network_log_created_later() {
    let name = "log-stream-network-follow-late";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-11-05T14:03:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Network],
            follow: true,
            ..Default::default()
        },
    )
    .await
    .expect("open follow stream");
    let mut stream = Box::pin(stream);
    use futures::StreamExt;

    write_lines(
        &log_dir.join("network.log"),
        &[network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443)],
    );

    let entry = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("entry within 5s")
        .expect("stream not ended")
        .expect("not an error");
    assert_eq!(entry.source, LogSource::Network);
    assert!(
        serde_json::from_slice::<logs::NetworkLogRecord>(&entry.data).is_ok(),
        "followed entry decodes as a network log record"
    );
}

#[tokio::test]
async fn log_stream_reads_rotated_network_files_in_order() {
    let name = "log-stream-network-rotated";
    let log_dir = make_log_dir(name);
    for (index, second) in [(4, "00"), (3, "01"), (2, "02"), (1, "03")] {
        write_lines(
            &log_dir.join(format!("network.log.{index}")),
            &[network_line(
                &format!("2026-11-05T14:00:{second}.000Z"),
                "udp",
                index as u16,
            )],
        );
    }
    write_lines(
        &log_dir.join("network.log"),
        &[network_line("2026-11-05T14:00:04.000Z", "tcp-syn", 443)],
    );

    let stream = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open network stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    let timestamps: Vec<_> = entries
        .iter()
        .map(|entry| entry.timestamp.to_rfc3339())
        .collect();

    assert_eq!(
        timestamps,
        vec![
            "2026-11-05T14:00:00+00:00",
            "2026-11-05T14:00:01+00:00",
            "2026-11-05T14:00:02+00:00",
            "2026-11-05T14:00:03+00:00",
            "2026-11-05T14:00:04+00:00",
        ]
    );
}

#[tokio::test]
async fn existing_selection_cursor_is_unchanged_by_network_log() {
    let name = "log-stream-network-cursor-stable";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-11-05T14:03:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );
    let options = LogStreamOptions {
        sources: vec![LogSource::Stdout],
        ..Default::default()
    };

    let without: Vec<_> = logs::log_stream(name, &options)
        .await
        .expect("open stdout stream")
        .try_collect()
        .await
        .expect("drain");

    write_lines(
        &log_dir.join("network.log"),
        &[network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443)],
    );

    let with: Vec<_> = logs::log_stream(name, &options)
        .await
        .expect("open stdout stream")
        .try_collect()
        .await
        .expect("drain");

    assert_eq!(without.len(), 1);
    assert_eq!(with.len(), 1);
    assert_eq!(without[0].cursor.to_string(), with[0].cursor.to_string());
}

#[tokio::test]
async fn cursor_taken_before_network_log_exists_resumes_from_its_start() {
    let name = "log-stream-network-late-cursor";
    make_log_dir(name);

    let drained: Vec<_> = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open network stream")
        .try_collect()
        .await
        .expect("drain empty");
    assert!(drained.is_empty(), "no network log yet: {drained:?}");

    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("network.log"),
        &[
            network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443),
            network_line("2026-11-05T14:03:08.412Z", "tcp-syn", 8443),
        ],
    );

    let entries: Vec<_> = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("reopen network stream")
        .try_collect()
        .await
        .expect("drain");
    assert_eq!(entries.len(), 2);

    let resumed: Vec<_> = logs::log_stream(
        name,
        &network_options(LogStreamStart::From(entries[0].cursor.clone())),
    )
    .await
    .expect("resume network stream")
    .try_collect()
    .await
    .expect("drain resumed");
    assert_eq!(resumed.len(), 1);
    assert_eq!(
        resumed[0].timestamp.to_rfc3339(),
        "2026-11-05T14:03:08.412+00:00"
    );
}

/// AC10 through the public API, and the reader rule R2 states for a `network` line: the line is
/// yielded exactly when it decodes as a `NetworkLogRecord` at a version this SDK knows, whatever
/// else it carries, and every line — yielded or skipped — advances the cursor.
///
/// The skipped shapes are the ones a later format, another writer or a truncated file can
/// produce: `v: 2`, an unknown `event`, an unknown `site`, and a line cut off mid-object. Each is
/// followed by a valid line, so a reader that stopped (or restarted) at the first unreadable line
/// would lose records the guest can never get back.
#[tokio::test]
async fn network_lines_are_decoded_independently_of_the_exec_envelope_and_unreadable_ones_are_skipped()
 {
    use microsandbox::logs::NetworkLogRecord;

    let name = "log-stream-network-independent-decode";
    let log_dir = make_log_dir(name);

    // A line with every field the `exec.log` envelope also uses, spelled differently on purpose:
    // `d` is not a string, `id` is a session id this entry must not adopt, `e` is an encoding tag
    // it must ignore, and `future` is an additive field at `v: 1`.
    let enriched = concat!(
        r#"{"v":1,"t":"2026-11-05T14:03:15.000Z","s":"network","event":"refusal","site":"tcp-syn","#,
        r#""layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"#,
        r#""name_source":"none","revision":1,"d":17,"id":42,"e":"b64","future":true}"#
    );
    let stripped = network_line("2026-11-05T14:03:07.412Z", "tcp-syn", 443);
    let future_version = stripped.replace(r#""v":1"#, r#""v":2"#);
    let unknown_event = stripped.replace(r#""event":"refusal""#, r#""event":"invented""#);
    let unknown_site = stripped.replace("tcp-syn", "tcp-future");
    let malformed = r#"{"v":1,"t":"2026-11-05T14:03:09.500Z","s":"network","event":"#;
    let after_future = network_line("2026-11-05T14:03:11.000Z", "udp", 1);
    let after_event = network_line("2026-11-05T14:03:12.000Z", "udp", 2);
    let after_site = network_line("2026-11-05T14:03:13.000Z", "udp", 3);
    let after_malformed = network_line("2026-11-05T14:03:14.000Z", "udp", 4);

    let lines = vec![
        future_version,
        after_future.clone(),
        unknown_event,
        after_event.clone(),
        unknown_site,
        after_site.clone(),
        malformed.to_owned(),
        after_malformed.clone(),
        enriched.to_owned(),
    ];
    write_lines(&log_dir.join("network.log"), &lines);

    let yielded = |entries: &[logs::LogEntry]| -> Vec<String> {
        entries
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.data).into_owned())
            .collect()
    };
    let expected = vec![
        format!("{after_future}\n"),
        format!("{after_event}\n"),
        format!("{after_site}\n"),
        format!("{after_malformed}\n"),
        format!("{enriched}\n"),
    ];

    let streamed: Vec<_> = logs::log_stream(name, &network_options(LogStreamStart::Beginning))
        .await
        .expect("open network stream")
        .try_collect()
        .await
        .expect("drain network stream");
    assert_eq!(
        yielded(&streamed),
        expected,
        "stream: every valid line once"
    );

    let snapshot = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Network],
            ..Default::default()
        },
    )
    .await
    .expect("read the network log");
    assert_eq!(yielded(&snapshot), expected, "snapshot: the same lines");

    // Every yielded body is the record's exact line and decodes as this SDK's record type; the
    // envelope-shaped extras changed nothing about the entry itself.
    let records: Vec<NetworkLogRecord> = snapshot
        .iter()
        .map(|entry| {
            serde_json::from_slice::<NetworkLogRecord>(entry.data.as_ref())
                .expect("a yielded network body decodes as NetworkLogRecord")
        })
        .collect();
    assert_eq!(records.len(), expected.len());
    assert_eq!(records[0].t.to_rfc3339(), "2026-11-05T14:03:11+00:00");
    assert_eq!(records[4].t.to_rfc3339(), "2026-11-05T14:03:15+00:00");
    assert!(
        snapshot
            .iter()
            .all(|entry| entry.source == LogSource::Network && entry.session_id.is_none()),
        "`id` on a network line is not a session id: {snapshot:?}"
    );

    // A cursor taken after the skipped lines resumes after the admitted ones: a skipped line
    // still advances the reader's position, so a launcher cannot be handed a record twice.
    let resumed: Vec<_> = logs::log_stream(
        name,
        &network_options(LogStreamStart::From(snapshot[1].cursor.clone())),
    )
    .await
    .expect("resume from a cursor")
    .try_collect()
    .await
    .expect("drain resumed");
    assert_eq!(
        yielded(&resumed),
        vec![
            format!("{after_site}\n"),
            format!("{after_malformed}\n"),
            format!("{enriched}\n"),
        ],
        "a cursor taken mid-file resumes exactly after that entry"
    );

    // A non-network line keeps the `exec.log` interpretation: a body that is not a string is not
    // a yielded entry, and the ordinary stdout line after it is unchanged.
    write_lines(
        &log_dir.join("exec.log"),
        &[
            r#"{"t":"2026-11-05T14:03:00.000Z","s":"stdout","d":{"nested":true},"id":1}"#
                .to_owned(),
            jsonl("2026-11-05T14:03:01.000Z", "stdout", "user output", 2),
        ],
    );
    let mixed: Vec<_> = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open default stream")
        .try_collect()
        .await
        .expect("drain");
    assert_eq!(mixed.len(), 1, "the unparsable stdout envelope is skipped");
    assert_eq!(mixed[0].source, LogSource::Stdout);
    assert_eq!(mixed[0].data.as_ref(), b"user output");
    assert_eq!(
        mixed[0].session_id.map(|id| id.to_string()),
        Some("2".to_owned())
    );
}
