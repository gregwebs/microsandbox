//! Reading one log file: the [`FileHandle`] wrapper around an open
//! file (tracking inode + offset for rotation-aware identity), and
//! the format-specific [`ParserKind`] dispatcher for JSON Lines
//! and plain text with RFC 3339 prefixes.
//!
//! [`ParserKind::parse_from`] takes a mutable [`FileHandle`], reads
//! up to one chunk, parses, and returns `(entry, position)` pairs.
//! Parsers don't stamp cursors — the stream layer composes the
//! cross-file [`LogCursor`] from the per-file positions returned
//! here.

use std::path::Path;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use microsandbox_utils::log_text::{base64_decode, split_leading_timestamp, strip_ansi};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::cursor::{FilePosition, LogCursor};
use super::types::{LogEntry, LogSource, NETWORK_LOG_FORMAT_VERSION, NetworkLogRecord};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Per-tick read ceiling. Caps how many bytes one read iteration
/// pulls off disk so very large backfills don't materialize the
/// whole file into memory before yielding the first entry.
const MAX_READ_BYTES: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// FileHandle
//--------------------------------------------------------------------------------------------------

/// Open file handle paired with its inode and current read offset.
/// The handle survives renames (rotation), so once opened we can
/// keep reading the same inode regardless of where its path moves.
pub(super) struct FileHandle {
    pub(super) file: tokio::fs::File,
    pub(super) inode: u64,
    pub(super) offset: u64,
}

impl FileHandle {
    /// Asynchronously open a file as a [`FileHandle`]. Returns
    /// `Ok(None)` if the file doesn't exist (treated as "producer
    /// hasn't created it yet, retry later"); other I/O errors
    /// propagate.
    pub(super) async fn open(path: &Path) -> MicrosandboxResult<Option<Self>> {
        let file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(MicrosandboxError::Io(e)),
        };
        let inode = Self::inode_of_file(&file).await?;
        Ok(Some(Self {
            file,
            inode,
            offset: 0,
        }))
    }

    /// Compute the file-identity discriminator (inode on Unix; a
    /// hash of file metadata on other platforms) from a sync
    /// `Metadata`.
    #[cfg(unix)]
    pub(super) fn generation_of_meta(meta: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }

    #[cfg(not(unix))]
    pub(super) fn generation_of_meta(meta: &std::fs::Metadata) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        if let Ok(created) = meta.created()
            && let Ok(d) = created.duration_since(std::time::UNIX_EPOCH)
        {
            d.as_nanos().hash(&mut h);
        }
        meta.len().hash(&mut h);
        h.finish()
    }

    /// Convenience: stat a path and return its current generation,
    /// or `None` if the path can't be stat'd.
    pub(super) async fn generation_of_path(path: &Path) -> Option<u64> {
        tokio::fs::metadata(path)
            .await
            .ok()
            .map(|m| Self::generation_of_meta(&m))
    }

    /// Inode of an already-open tokio file handle.
    pub(super) async fn inode_of_file(file: &tokio::fs::File) -> MicrosandboxResult<u64> {
        let meta = file.metadata().await.map_err(MicrosandboxError::Io)?;
        Ok(Self::generation_of_meta(&meta))
    }

    /// File modification time of a path, falling back to `Utc::now`
    /// when the path can't be stat'd. Used by the text parser as
    /// the timestamp for lines that don't carry a parseable
    /// leading RFC 3339.
    pub(super) async fn mtime_of_path(path: &Path) -> DateTime<Utc> {
        tokio::fs::metadata(path)
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| -> DateTime<Utc> { t.into() })
            .unwrap_or_else(Utc::now)
    }
}

//--------------------------------------------------------------------------------------------------
// RawEntry — the JSONL wire format
//--------------------------------------------------------------------------------------------------

/// The `exec.log` body envelope.
///
/// `s` is not a field here: the source is read first, from the line's own `s`, by
/// [`jsonl_source`], so identifying which reader a line belongs to never depends on this decode.
#[derive(Debug, Deserialize)]
pub(super) struct RawEntry {
    pub(super) t: String,
    #[serde(default)]
    pub(super) d: String,
    #[serde(default)]
    pub(super) id: Option<u64>,
    #[serde(default)]
    pub(super) e: Option<String>,
}

impl RawEntry {
    /// Decode the body bytes, applying base64 decoding when the
    /// entry is tagged with `e: "b64"` (raw-mode capture).
    pub(super) fn decode_body(&self) -> Bytes {
        if self.e.as_deref() == Some("b64") {
            match base64_decode(&self.d) {
                Some(bytes) => Bytes::from(bytes),
                None => Bytes::from(self.d.clone().into_bytes()),
            }
        } else {
            Bytes::from(self.d.clone().into_bytes())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// ParserKind
//--------------------------------------------------------------------------------------------------

pub(super) struct ParsedChunk {
    pub(super) entries: Vec<(LogEntry, FilePosition)>,
    pub(super) position: Option<FilePosition>,
}

/// How a reader parses bytes from its source file.
pub(super) enum ParserKind {
    /// JSON Lines (one record per line). Filters by `sources`.
    Jsonl { sources: Vec<LogSource> },
    /// Plain text, one entry per line, with optional leading
    /// RFC 3339 timestamp; lines without a parseable timestamp
    /// fall back to the file's `mtime`. Always emits entries
    /// tagged as [`LogSource::System`].
    Text,
}

impl ParserKind {
    /// Read a chunk from `src` and parse it. Advances `src.offset`
    /// by the bytes consumed.
    pub(super) async fn parse_from(
        &self,
        src: &mut FileHandle,
        primary_path: &Path,
        since: Option<DateTime<Utc>>,
    ) -> MicrosandboxResult<ParsedChunk> {
        let mut buf = vec![0u8; MAX_READ_BYTES];
        src.file
            .seek(std::io::SeekFrom::Start(src.offset))
            .await
            .map_err(MicrosandboxError::Io)?;
        let read = src
            .file
            .read(&mut buf)
            .await
            .map_err(MicrosandboxError::Io)?;
        if read == 0 {
            return Ok(ParsedChunk {
                entries: Vec::new(),
                position: None,
            });
        }
        let mut entries = Vec::new();
        let consumed = match self {
            Self::Jsonl { sources } => Self::parse_jsonl(
                &buf[..read],
                src.offset,
                src.inode,
                sources,
                since,
                &mut entries,
            ),
            Self::Text => {
                let mtime = FileHandle::mtime_of_path(primary_path).await;
                Self::parse_text(
                    &buf[..read],
                    src.offset,
                    src.inode,
                    mtime,
                    since,
                    &mut entries,
                )
            }
        };
        src.offset += consumed as u64;
        let position = (consumed > 0).then_some(FilePosition {
            generation: src.inode,
            offset: src.offset,
        });
        Ok(ParsedChunk { entries, position })
    }

    /// Parse JSON Lines bytes. Emits `(entry, position)` pairs;
    /// each `position` carries the file's `generation` and the
    /// byte offset just after the entry's terminating newline.
    ///
    /// A `network` line is decoded as its own record type and yielded with the whole line as its
    /// body; any other `network` line is skipped.
    pub(super) fn parse_jsonl(
        bytes: &[u8],
        base_offset: u64,
        generation: u64,
        sources: &[LogSource],
        since: Option<DateTime<Utc>>,
        out: &mut Vec<(LogEntry, FilePosition)>,
    ) -> usize {
        Self::walk_lines(bytes, base_offset, out, |line, entry_end_offset| {
            // Identify the source without decoding the `exec.log` envelope: a `network` record is
            // a different shape, so an envelope decode would reject a valid line.
            let source = jsonl_source(line)?;
            if !sources.contains(&source) {
                return None;
            }

            // A network record is its own payload: hand the consumer the exact line so it
            // deserializes as `NetworkLogRecord`, with the newline every other line-oriented
            // entry carries. Only records this SDK understands are yielded; a newer format, an
            // unknown site, event or field value, or a malformed line is skipped exactly like an
            // unknown source, and the cursor still advances past it.
            //
            // Everything else is the `exec.log` envelope: its body, its session id and its own
            // timestamp, exactly as before.
            let (timestamp, session_id, data) = if source == LogSource::Network {
                let record: NetworkLogRecord = serde_json::from_slice(line).ok()?;
                if record.v > NETWORK_LOG_FORMAT_VERSION {
                    return None;
                }
                let mut payload = line.to_vec();
                payload.push(b'\n');
                // A network entry never belongs to a session, whatever the line carries.
                (record.t, None, Bytes::from(payload))
            } else {
                let raw: RawEntry = serde_json::from_slice(line).ok()?;
                let timestamp = DateTime::parse_from_rfc3339(&raw.t)
                    .ok()?
                    .with_timezone(&Utc);
                (timestamp, raw.id, raw.decode_body())
            };

            if since.is_some_and(|s| timestamp < s) {
                return None;
            }
            Some((
                LogEntry {
                    timestamp,
                    source,
                    session_id,
                    data,
                    cursor: LogCursor::empty(),
                },
                FilePosition {
                    generation,
                    offset: entry_end_offset,
                },
            ))
        })
    }

    /// Parse plain-text bytes. Lines without a parseable leading
    /// RFC 3339 timestamp fall back to `mtime_fallback`. Always
    /// emits entries tagged as [`LogSource::System`].
    pub(super) fn parse_text(
        bytes: &[u8],
        base_offset: u64,
        generation: u64,
        mtime_fallback: DateTime<Utc>,
        since: Option<DateTime<Utc>>,
        out: &mut Vec<(LogEntry, FilePosition)>,
    ) -> usize {
        Self::walk_lines(bytes, base_offset, out, |raw_line, entry_end_offset| {
            let line = String::from_utf8_lossy(raw_line);
            let stripped = strip_ansi(&line);
            let (timestamp, body) = match split_leading_timestamp(&stripped) {
                Some((s, rest)) => (
                    DateTime::parse_from_rfc3339(s)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or(mtime_fallback),
                    rest.trim_start().to_string(),
                ),
                None => (mtime_fallback, stripped.clone()),
            };
            if since.is_some_and(|s| timestamp < s) {
                return None;
            }
            Some((
                LogEntry {
                    timestamp,
                    source: LogSource::System,
                    session_id: None,
                    data: Bytes::from(format!("{body}\n").into_bytes()),
                    cursor: LogCursor::empty(),
                },
                FilePosition {
                    generation,
                    offset: entry_end_offset,
                },
            ))
        })
    }

    /// Walk `bytes` line-by-line (`\n`-delimited), invoking
    /// `handler` on each complete line with its end-of-line file
    /// offset. Trailing partial lines (no terminating `\n`) are
    /// left unconsumed. Returns the number of bytes consumed.
    fn walk_lines<F>(
        bytes: &[u8],
        base_offset: u64,
        out: &mut Vec<(LogEntry, FilePosition)>,
        mut handler: F,
    ) -> usize
    where
        F: FnMut(&[u8], u64) -> Option<(LogEntry, FilePosition)>,
    {
        let mut pos = 0usize;
        while pos < bytes.len() {
            let nl_rel = match bytes[pos..].iter().position(|&b| b == b'\n') {
                Some(n) => n,
                None => break,
            };
            let line_end = pos + nl_rel;
            let line = &bytes[pos..line_end];
            let entry_end_offset = base_offset + (line_end as u64) + 1;
            if !line.is_empty()
                && let Some(pair) = handler(line, entry_end_offset)
            {
                out.push(pair);
            }
            pos = line_end + 1;
        }
        pos
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// The [`LogSource`] one JSON Lines entry names, read without decoding the rest of the line.
///
/// Source detection must not depend on [`RawEntry`]: a `network.log` record carries its own
/// fields, so an additive or differently typed one there would make the `exec.log` envelope
/// decode fail and hide a line this reader understands. `None` means the line names no source
/// this reader knows, which is skipped like any other unknown value.
fn jsonl_source(line: &[u8]) -> Option<LogSource> {
    #[derive(Deserialize)]
    struct SourceTag<'a> {
        #[serde(borrow)]
        s: &'a str,
    }

    let tag: SourceTag<'_> = serde_json::from_slice(line).ok()?;
    match tag.s {
        "stdout" => Some(LogSource::Stdout),
        "stderr" => Some(LogSource::Stderr),
        "output" => Some(LogSource::Output),
        "system" => Some(LogSource::System),
        "network" => Some(LogSource::Network),
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::types::{
        NameSource, NetworkLogEvent, NetworkRefusal, RefusalLayer, RefusalSite,
    };
    use super::*;
    use chrono::TimeZone;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    // -- parse_jsonl ---------------------------------------------------

    #[test]
    fn jsonl_parses_single_complete_line() {
        let bytes = br#"{"t":"2026-04-30T20:32:59.000Z","s":"stdout","d":"hi\n","id":7}
"#;
        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(bytes, 0, 42, &[LogSource::Stdout], None, &mut out);
        assert_eq!(consumed, bytes.len());
        assert_eq!(out.len(), 1);
        let (entry, pos) = &out[0];
        assert_eq!(entry.source, LogSource::Stdout);
        assert_eq!(entry.session_id, Some(7));
        assert_eq!(entry.data, Bytes::from("hi\n".as_bytes()));
        assert_eq!(entry.timestamp, ts("2026-04-30T20:32:59Z"));
        assert_eq!(pos.generation, 42);
        assert_eq!(pos.offset, bytes.len() as u64);
    }

    #[test]
    fn jsonl_leaves_trailing_partial_line_unconsumed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            br#"{"t":"2026-04-30T20:32:59.000Z","s":"stdout","d":"a","id":1}
"#,
        );
        let after_first = bytes.len();
        bytes.extend_from_slice(br#"{"t":"2026-04-30T20:33:00.000Z","s":"stdout","d":"b"#);

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(&bytes, 0, 1, &[LogSource::Stdout], None, &mut out);
        assert_eq!(consumed, after_first);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn jsonl_filters_by_sources() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      {\"t\":\"2026-04-30T00:00:01Z\",\"s\":\"stderr\",\"d\":\"b\"}\n\
                      {\"t\":\"2026-04-30T00:00:02Z\",\"s\":\"system\",\"d\":\"c\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stderr], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.source, LogSource::Stderr);
        assert_eq!(out[0].0.data, Bytes::from("b".as_bytes()));
    }

    #[test]
    fn jsonl_filters_by_since() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"early\"}\n\
                      {\"t\":\"2026-04-30T00:00:05Z\",\"s\":\"stdout\",\"d\":\"late\"}\n";
        let mut out = Vec::new();
        let since = Some(ts("2026-04-30T00:00:03Z"));
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], since, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("late".as_bytes()));
    }

    #[test]
    fn jsonl_skips_malformed_lines() {
        let bytes = b"this is not json\n\
                      {\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"ok\"}\n\
                      {malformed json\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("ok".as_bytes()));
    }

    #[test]
    fn jsonl_skips_unknown_source_values() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"alien\",\"d\":\"x\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn jsonl_decodes_base64_body_when_tagged() {
        let bytes =
            b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"aGVsbG8=\",\"e\":\"b64\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn jsonl_position_offsets_are_relative_to_base() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      {\"t\":\"2026-04-30T00:00:01Z\",\"s\":\"stdout\",\"d\":\"b\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 1000, 99, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1.generation, 99);
        assert!(out[0].1.offset > 1000);
        assert_eq!(out[1].1.offset, 1000 + bytes.len() as u64);
    }

    #[test]
    fn jsonl_skips_empty_lines() {
        let bytes = b"\n\
                      {\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      \n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
    }

    // -- parse_text ----------------------------------------------------

    #[test]
    fn text_parses_lines_with_rfc3339_prefix() {
        let bytes = b"2026-04-30T20:30:00.000Z INFO starting up\n\
                      2026-04-30T20:30:01.000Z WARN something\n";
        let mut out = Vec::new();
        let mtime = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        ParserKind::parse_text(bytes, 0, 7, mtime, None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.source, LogSource::System);
        assert_eq!(out[0].0.timestamp, ts("2026-04-30T20:30:00Z"));
        assert_eq!(out[0].0.data, Bytes::from("INFO starting up\n".as_bytes()));
        assert_eq!(out[0].1.generation, 7);
    }

    #[test]
    fn text_falls_back_to_mtime_without_timestamp_prefix() {
        let bytes = b"[ 0.123] kernel boot message\n";
        let mut out = Vec::new();
        let mtime = ts("2026-01-15T10:00:00Z");
        ParserKind::parse_text(bytes, 0, 0, mtime, None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.timestamp, mtime);
    }

    #[test]
    fn text_replaces_invalid_utf8_lossily() {
        let bytes = b"2026-04-30T20:30:00.000Z bad \xff line\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            std::str::from_utf8(&out[0].0.data).unwrap(),
            "bad \u{fffd} line\n"
        );
    }

    #[test]
    fn text_strips_ansi_escapes() {
        let bytes = b"\x1b[31m2026-04-30T20:30:00.000Z\x1b[0m ERROR boom\n";
        let mut out = Vec::new();
        let mtime = Utc::now();
        ParserKind::parse_text(bytes, 0, 0, mtime, None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.timestamp, ts("2026-04-30T20:30:00Z"));
    }

    #[test]
    fn text_filters_by_since() {
        let bytes = b"2026-04-30T00:00:00Z early line\n\
                      2026-04-30T00:00:10Z late line\n";
        let mut out = Vec::new();
        let mtime = Utc::now();
        let since = Some(ts("2026-04-30T00:00:05Z"));
        ParserKind::parse_text(bytes, 0, 0, mtime, since, &mut out);
        assert_eq!(out.len(), 1);
        assert!(
            std::str::from_utf8(&out[0].0.data)
                .unwrap()
                .contains("late line")
        );
    }

    #[test]
    fn text_leaves_partial_trailing_line_unconsumed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"2026-04-30T00:00:00Z complete\n");
        let after_first = bytes.len();
        bytes.extend_from_slice(b"2026-04-30T00:00:01Z partial");

        let mut out = Vec::new();
        let consumed = ParserKind::parse_text(&bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(consumed, after_first);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn text_always_emits_system_source() {
        let bytes = b"hello world\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.source, LogSource::System);
        assert_eq!(out[0].0.session_id, None);
    }

    #[test]
    fn text_position_offsets_are_relative_to_base() {
        let bytes = b"2026-04-30T00:00:00Z first\n2026-04-30T00:00:01Z second\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 500, 99, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1.generation, 99);
        assert!(out[0].1.offset > 500);
        assert_eq!(out[1].1.offset, 500 + bytes.len() as u64);
    }

    // -- RawEntry::decode_body -----------------------------------------

    #[test]
    fn decode_body_returns_plain_bytes_without_base64_tag() {
        let raw = RawEntry {
            t: "x".into(),
            d: "hello".into(),
            id: None,
            e: None,
        };
        assert_eq!(raw.decode_body(), Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn decode_body_base64_decodes_when_tagged_b64() {
        let raw = RawEntry {
            t: "x".into(),
            d: "aGVsbG8=".into(),
            id: None,
            e: Some("b64".into()),
        };
        assert_eq!(raw.decode_body(), Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn decode_body_falls_back_to_raw_on_invalid_base64() {
        let raw = RawEntry {
            t: "x".into(),
            d: "not valid b64!".into(),
            id: None,
            e: Some("b64".into()),
        };
        assert_eq!(raw.decode_body(), Bytes::from("not valid b64!".as_bytes()));
    }

    // -- network records -----------------------------------------------

    const NETWORK_REFUSAL_LINE: &str = r#"{"v":1,"t":"2026-11-05T14:03:07.412Z","s":"network","event":"refusal","site":"tcp-syn","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"name":"api.example.com","name_source":"dns-cache","revision":2}"#;

    fn network_lines() -> Vec<NetworkLogRecord> {
        let refusal: NetworkLogRecord = serde_json::from_str(NETWORK_REFUSAL_LINE).unwrap();
        let suppressed: NetworkLogRecord = serde_json::from_str(
            r#"{"v":1,"t":"2026-11-05T14:03:09.000Z","s":"network","event":"suppressed","site":"udp","count":4744}"#,
        )
        .unwrap();
        vec![refusal, suppressed]
    }

    #[test]
    fn jsonl_parses_network_record_as_whole_line() {
        let bytes = format!("{NETWORK_REFUSAL_LINE}\n");
        let mut out = Vec::new();
        ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            7,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(out.len(), 1);
        let (entry, position) = &out[0];
        assert_eq!(entry.source, LogSource::Network);
        assert_eq!(entry.session_id, None);
        assert_eq!(entry.data, Bytes::from(bytes.clone().into_bytes()));
        assert_eq!(entry.timestamp, ts("2026-11-05T14:03:07.412Z"));
        let record: NetworkLogRecord = serde_json::from_slice(&entry.data).unwrap();
        assert_eq!(
            record,
            serde_json::from_str::<NetworkLogRecord>(NETWORK_REFUSAL_LINE).unwrap()
        );
        assert_eq!(position.offset, bytes.len() as u64);
    }

    #[test]
    fn jsonl_filters_network_unless_requested() {
        let mut bytes = String::new();
        bytes.push_str(NETWORK_REFUSAL_LINE);
        bytes.push('\n');
        bytes.push_str("{\"t\":\"2026-11-05T14:03:08.000Z\",\"s\":\"stdout\",\"d\":\"hi\"}\n");

        let mut out = Vec::new();
        let consumed =
            ParserKind::parse_jsonl(bytes.as_bytes(), 0, 0, &[LogSource::Stdout], None, &mut out);

        assert_eq!(consumed, bytes.len(), "the skipped line is consumed");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.source, LogSource::Stdout);
    }

    #[test]
    fn jsonl_skips_network_lines_a_newer_or_unknown_reader_cannot_decode() {
        let future_version = NETWORK_REFUSAL_LINE.replace(r#""v":1"#, r#""v":2"#);
        let unknown_site = NETWORK_REFUSAL_LINE.replace("tcp-syn", "tcp-future");
        let unknown_event =
            NETWORK_REFUSAL_LINE.replace(r#""event":"refusal""#, r#""event":"invented""#);
        let unknown_layer =
            NETWORK_REFUSAL_LINE.replace(r#""layer":"tenant""#, r#""layer":"host""#);
        let unknown_name_source =
            NETWORK_REFUSAL_LINE.replace(r#""name_source":"dns-cache""#, r#""name_source":"rdns""#);
        let unknown_protocol =
            NETWORK_REFUSAL_LINE.replace(r#""protocol":"tcp""#, r#""protocol":"sctp""#);
        let malformed = r#"{"v":1,"t":"2026-11-05T14:03:07.412Z","s":"network","event":"#;

        let mut bytes = String::new();
        for line in [
            &future_version,
            &unknown_site,
            &unknown_event,
            &unknown_layer,
            &unknown_name_source,
            &unknown_protocol,
            malformed,
        ] {
            bytes.push_str(line);
            bytes.push('\n');
        }
        bytes.push_str(NETWORK_REFUSAL_LINE);
        bytes.push('\n');

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(consumed, bytes.len(), "every line is consumed");
        assert_eq!(out.len(), 1, "only the valid line is yielded");
        assert_eq!(
            out[0].0.data,
            Bytes::from(format!("{NETWORK_REFUSAL_LINE}\n"))
        );
    }

    #[test]
    fn jsonl_ignores_unknown_fields_on_a_network_record() {
        let line = NETWORK_REFUSAL_LINE.replace(r#""revision":2"#, r#""revision":2,"future":1"#);
        let mut bytes = line.clone();
        bytes.push('\n');

        let mut out = Vec::new();
        ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from(bytes.into_bytes()));
    }

    /// Network detection does not go through the `exec.log` envelope: a record whose fields do
    /// not decode as one is still yielded, and it never borrows an `id` as its session id.
    #[test]
    fn jsonl_decodes_network_records_without_the_exec_envelope() {
        // `d` is a string in the exec envelope, so the envelope decode rejects this line.
        let non_string_body =
            NETWORK_REFUSAL_LINE.replace(r#""revision":2"#, r#""revision":2,"d":17"#);
        // `id` is the exec envelope's session id; a network entry never has one.
        let with_session_id =
            NETWORK_REFUSAL_LINE.replace(r#""revision":2"#, r#""revision":2,"id":42"#);
        let with_both = NETWORK_REFUSAL_LINE.replace(
            r#""revision":2"#,
            r#""revision":2,"d":{"nested":true},"id":42,"e":"b64""#,
        );

        let mut bytes = String::new();
        for line in [&non_string_body, &with_session_id, &with_both] {
            bytes.push_str(line);
            bytes.push('\n');
        }

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(consumed, bytes.len());
        assert_eq!(
            out.len(),
            3,
            "every line is a record this reader understands"
        );
        for (entry, _) in &out {
            assert_eq!(entry.source, LogSource::Network);
            assert_eq!(
                entry.session_id, None,
                "a network entry never carries a session id"
            );
            assert_eq!(
                entry.timestamp,
                ts("2026-11-05T14:03:07.412Z"),
                "the timestamp comes from the record itself"
            );
            assert!(serde_json::from_slice::<NetworkLogRecord>(&entry.data).is_ok());
        }
    }

    /// A record the runtime wrote with a hostile name is still one line, and the SDK yields it
    /// with the name intact: the escaping is the serializer's, so no name can split a line.
    #[test]
    fn jsonl_yields_a_network_record_whose_name_is_hostile() {
        let names = [
            "quote\"and\\slash.example",
            "new\nline.example",
            "carriage\rreturn.example",
            "line\u{2028}separator.example",
            "nul\u{0}byte.example",
            "snowman-\u{2603}.example",
        ];
        let mut bytes = String::new();
        for name in names {
            // Exactly how the runtime's writer encodes it: the serializer escapes the name.
            let record = NetworkLogRecord {
                v: NETWORK_LOG_FORMAT_VERSION,
                t: "2026-11-05T14:03:07.412Z".parse().unwrap(),
                s: LogSource::Network,
                event: NetworkLogEvent::Refusal(NetworkRefusal {
                    site: RefusalSite::TcpHostname,
                    layer: RefusalLayer::Tenant,
                    protocol: microsandbox_types::Protocol::Tcp,
                    dst_ip: Some("203.0.113.10".parse().unwrap()),
                    dst_port: Some(443),
                    name: Some(name.to_owned()),
                    name_source: NameSource::Sni,
                    revision: 1,
                }),
            };
            bytes.push_str(&serde_json::to_string(&record).unwrap());
            bytes.push('\n');
        }

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(consumed, bytes.len());
        assert_eq!(
            out.len(),
            names.len(),
            "one line per record, so no name split a line"
        );
        for ((entry, _), name) in out.iter().zip(names) {
            let record: NetworkLogRecord = serde_json::from_slice(&entry.data).unwrap();
            let NetworkLogEvent::Refusal(refusal) = record.event else {
                panic!("expected a refusal");
            };
            assert_eq!(refusal.name.as_deref(), Some(name));
            assert_eq!(entry.data.iter().filter(|byte| **byte == b'\n').count(), 1);
        }
    }

    /// `since` filters a network line by the record's own `t`, and a filtered line still advances
    /// the cursor.
    #[test]
    fn jsonl_applies_since_to_network_records_by_their_own_timestamp() {
        let earlier = NETWORK_REFUSAL_LINE.replace("14:03:07.412Z", "14:03:00.000Z");
        let mut bytes = format!("{earlier}\n{NETWORK_REFUSAL_LINE}\n");
        let since = Some(ts("2026-11-05T14:03:05Z"));

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            9,
            &[LogSource::Network],
            since,
            &mut out,
        );

        assert_eq!(consumed, bytes.len(), "the filtered line is consumed too");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.timestamp, ts("2026-11-05T14:03:07.412Z"));
        assert_eq!(out[0].1.offset, bytes.len() as u64);

        // A cut-off past every record yields nothing, and still consumes the bytes.
        bytes.clear();
        bytes.push_str(NETWORK_REFUSAL_LINE);
        bytes.push('\n');
        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            9,
            &[LogSource::Network],
            Some(ts("2027-01-01T00:00:00Z")),
            &mut out,
        );
        assert_eq!(consumed, bytes.len());
        assert!(out.is_empty());
    }

    /// Shapes the reader must survive without depending on field order, on the `exec.log`
    /// envelope, or on any line being well-formed.
    ///
    /// The rule under test is R2's reader rule: a `network` line is yielded exactly when it
    /// deserializes as `NetworkLogRecord` with `v <= NETWORK_LOG_FORMAT_VERSION`, whatever else
    /// the line holds; everything else is skipped, and the cursor advances past every line.
    #[test]
    fn jsonl_network_lines_follow_the_documented_reader_rule_for_odd_shapes() {
        // The source tag is read wherever it appears in the object: a record is not required to
        // put `s` before its payload.
        let source_last = r#"{"v":1,"t":"2026-11-05T14:03:07.412Z","event":"refusal","site":"tcp-syn","layer":"tenant","protocol":"tcp","dst_ip":"203.0.113.10","dst_port":443,"name_source":"none","revision":1,"d":17,"s":"network"}"#.to_string();
        // `v: 0` is not a future version, so the documented rule still yields it.
        let zero_version = NETWORK_REFUSAL_LINE.replace(r#""v":1"#, r#""v":0"#);

        // Skipped: values the record's own decoder rejects, and lines that are not an object
        // with a known source at all.
        let negative_count = r#"{"v":1,"t":"2026-11-05T14:03:09.000Z","s":"network","event":"suppressed","site":"udp","count":-1}"#;
        let fractional_count = r#"{"v":1,"t":"2026-11-05T14:03:09.000Z","s":"network","event":"suppressed","site":"udp","count":1.5}"#;
        let unparsable_timestamp = NETWORK_REFUSAL_LINE.replace("14:03:07.412Z", "yesterday");
        let array_line = r#"["network",1]"#;
        let bare_string = r#""network""#;
        let no_source = r#"{"v":1,"t":"2026-11-05T14:03:07.412Z","event":"refusal"}"#;

        let mut bytes = String::new();
        for line in [
            negative_count,
            fractional_count,
            unparsable_timestamp.as_str(),
            array_line,
            bare_string,
            no_source,
            "",
        ] {
            bytes.push_str(line);
            bytes.push('\n');
        }
        bytes.push_str(&source_last);
        bytes.push('\n');
        bytes.push_str(&zero_version);
        bytes.push('\n');

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(consumed, bytes.len(), "every line is consumed");
        assert_eq!(
            out.len(),
            2,
            "only the two decodable records are yielded: {:?}",
            out.iter().map(|(entry, _)| &entry.data).collect::<Vec<_>>()
        );
        assert_eq!(out[0].0.data, Bytes::from(format!("{source_last}\n")));
        assert_eq!(out[0].0.session_id, None);
        assert_eq!(out[1].0.data, Bytes::from(format!("{zero_version}\n")));

        // A non-network line keeps the `exec.log` interpretation: a body that is not a string is
        // skipped, exactly as before this source existed.
        let object_body =
            r#"{"t":"2026-11-05T14:03:07.412Z","s":"stdout","d":{"nested":true},"id":1}"#;
        let plain_body = jsonl_stdout_line();
        let bytes = format!("{object_body}\n{plain_body}\n");
        let mut out = Vec::new();
        let consumed =
            ParserKind::parse_jsonl(bytes.as_bytes(), 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(consumed, bytes.len());
        assert_eq!(out.len(), 1, "the unparsable envelope is skipped");
        assert_eq!(out[0].0.source, LogSource::Stdout);
    }

    /// One ordinary `stdout` line, in the `exec.log` envelope.
    fn jsonl_stdout_line() -> String {
        r#"{"t":"2026-11-05T14:03:07.412Z","s":"stdout","d":"hi\n","id":7}"#.to_owned()
    }

    #[test]
    fn jsonl_yields_every_network_event_kind() {
        let mut bytes = String::new();
        for record in network_lines() {
            bytes.push_str(&serde_json::to_string(&record).unwrap());
            bytes.push('\n');
        }

        let mut out = Vec::new();
        ParserKind::parse_jsonl(
            bytes.as_bytes(),
            0,
            0,
            &[LogSource::Network],
            None,
            &mut out,
        );

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.timestamp, ts("2026-11-05T14:03:07.412Z"));
        assert_eq!(out[1].0.timestamp, ts("2026-11-05T14:03:09Z"));
    }
}
