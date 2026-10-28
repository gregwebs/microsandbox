//! The checked session's console loop, apart from the console.
//!
//! A Windows terminal is not a file: host input arrives from a pump thread and
//! guest output is written with `WriteConsoleW`, so this loop differs from Unix
//! in where its events come from and where its output goes — not in what it
//! guarantees. Both are behind [`ConsoleEvents`] and [`ConsoleSink`], which is
//! what lets the loop be compiled and tested on a host with no Windows console:
//! only the adapters in `windows.rs` are `cfg(windows)`.

use std::future::Future;
use std::sync::Arc;

use microsandbox_protocol::{
    exec::{ExecResize, ExecStdin},
    message::{Message, MessageType},
};
use tokio::sync::mpsc;

use crate::{MicrosandboxResult, agent::AgentClient};

use super::checked::{
    CheckedEnd, CheckedEvent, CheckedFailure, GuestSend, classify_checked_message, closed_session,
    finish_send, finish_with_teardown, start_send,
};
use super::error::{AttachFailureKind, AttachSessionError, TeardownStage};
use super::{
    DetachKeys, FilteredStdin, InputRoute, STDIN_FILTER_TASK_ENDED, StdinFilter, recv_filtered,
    route_input,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One console event, as the checked loop sees it.
pub(super) enum ConsoleEvent {
    /// Bytes typed or pasted at the console.
    Input(Vec<u8>),
    /// The console changed size.
    Resize { cols: u16, rows: u16 },
    /// The console could not be read.
    Error(String),
}

/// A checked session's source of console events.
///
/// `None` means the source ended, which is never a guest exit: the console went
/// away under a guest that is still running.
pub(super) trait ConsoleEvents {
    /// The next console event.
    ///
    /// Must be cancel-safe: `select!` drops this future whenever another arm
    /// completes first, and the event it was waiting for has to survive that.
    fn recv(&mut self) -> impl Future<Output = Option<ConsoleEvent>> + Send;
}

/// Where a checked session's guest output goes, and how the console is left.
///
/// Output is written inline by the loop, so a console that stopped accepting
/// bytes is that write's own failure. There is no writer thread here whose
/// failure could arrive as a separate session event, as on Unix.
pub(super) trait ConsoleSink {
    /// Write one decoded chunk of guest output.
    fn write_output(&mut self, data: &[u8]) -> MicrosandboxResult<()>;

    /// Write the decoded tail after the last chunk.
    fn finish_output(&mut self) -> MicrosandboxResult<()>;

    /// Put the console back the way the session found it.
    fn restore(&mut self) -> MicrosandboxResult<()>;
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The checked session's loop: how the guest ended it, or the failure that
/// ended it first.
///
/// One `select!` in which every arm whose guard allows it is live on every
/// iteration. Nothing in a handler awaits the transport in a way that could
/// stop the loop from receiving the guest's exit or the guest channel closing.
pub(super) async fn checked_bridge<S, W>(
    client: &Arc<AgentClient>,
    id: u32,
    rx: &mut mpsc::Receiver<Message>,
    sink: &mut W,
    events: &mut S,
    detach_keys: Option<&DetachKeys>,
    stdin_filter: Option<Box<dyn StdinFilter>>,
) -> Result<CheckedEnd, AttachSessionError>
where
    S: ConsoleEvents,
    W: ConsoleSink,
{
    let mut match_pos = 0usize;
    // A guest that stopped reading its stdin (`EPIPE`, or `EIO` because its PTY
    // is gone while it exits) keeps its session: only feeding stops, and its own
    // exit event still ends it.
    let mut feeding_input = true;
    // Same task boundary as the legacy session and as Unix.
    let mut filtered_stdin = stdin_filter.map(FilteredStdin::spawn);
    // At most one send to the guest is in flight. A handler only *starts* one;
    // this loop polls it to completion as its own arm, so a transport that
    // stopped accepting bytes cannot hold the guest's exit, its output or its
    // channel closure hostage — nor leave the console raw until the caller gives
    // up. Holding console input and resizes until the send finishes keeps them
    // in order and never restarts a frame that may already be on its way.
    let mut outbound: Option<GuestSend> = None;

    let end = 'session: loop {
        tokio::select! {
            // The in-flight send's verdict. A rejected send is a lost session:
            // the transport, not the guest, refused the frame.
            result = finish_send(&mut outbound), if outbound.is_some() => {
                outbound = None;
                result?;
            }

            // Console input and resizes wait behind that one send. The pump's
            // channel is unbounded and the console delivers its events in order,
            // so nothing typed or resized meanwhile is lost, duplicated or
            // overtaken while they wait.
            event = events.recv(), if outbound.is_none() => {
                // The console's event pump ends on console EOF or on its own
                // read error, never because the agent connection closed: say
                // what actually happened.
                let Some(event) = event else {
                    return Err(host_failure(
                        "host console input ended before the guest reported its exit",
                    ));
                };
                match event {
                    ConsoleEvent::Input(data) => {
                        // The guest closed its input: `EPIPE`, or `EIO` because
                        // its PTY is gone while it exits. The console keeps
                        // reading keystrokes, because the pump also carries
                        // resize and error events, so routing stops here — before
                        // the detach scan and before the filter. Otherwise a
                        // filter's unbounded input queue would grow for as long
                        // as the guest stays alive, and `Ctrl-]` would report a
                        // detach instead of waiting for the guest's own exit.
                        if !feeding_input {
                            continue;
                        }
                        // Shared routing: a filter sees the same chunks, one at a
                        // time and in order, as it would without the checked
                        // session; only the failure conventions differ.
                        match route_input(
                            &data,
                            detach_keys,
                            &mut match_pos,
                            filtered_stdin.as_ref(),
                        ) {
                            InputRoute::Detach => {
                                return Err(AttachSessionError::new(
                                    AttachFailureKind::Detached,
                                    "the detach key sequence ended the session before the guest reported its exit",
                                ));
                            }
                            InputRoute::Filtered => {}
                            InputRoute::WorkerEnded => {
                                return Err(AttachSessionError::new(
                                    AttachFailureKind::StdinFilter,
                                    STDIN_FILTER_TASK_ENDED,
                                ));
                            }
                            InputRoute::Forward => {
                                outbound = Some(start_send(
                                    client,
                                    id,
                                    MessageType::ExecStdin,
                                    ExecStdin { data },
                                    "forwarding console input",
                                ));
                            }
                        }
                    }
                    ConsoleEvent::Resize { cols, rows } => {
                        // A resize that arrives while a send is in flight is
                        // recorded by the console's pump and forwarded once that
                        // send completes, so the geometry the guest ends up with
                        // is the latest one.
                        outbound = Some(start_send(
                            client,
                            id,
                            MessageType::ExecResize,
                            ExecResize { rows, cols },
                            "sending a console resize to the guest",
                        ));
                    }
                    ConsoleEvent::Error(error) => {
                        return Err(host_failure(format!("reading console input: {error}")));
                    }
                }
            }

            // Filtered bytes reach the guest only here, one produced chunk at a
            // time: the worker is the only thing that holds a chunk back, so
            // input order is preserved without this arm ever overtaking the one
            // above, and it waits behind the same single send.
            filtered = recv_filtered(&mut filtered_stdin), if feeding_input && filtered_stdin.is_some() && outbound.is_none() => {
                let Some(data) = filtered else {
                    return Err(AttachSessionError::new(
                        AttachFailureKind::StdinFilter,
                        STDIN_FILTER_TASK_ENDED,
                    ));
                };
                outbound = Some(start_send(
                    client,
                    id,
                    MessageType::ExecStdin,
                    ExecStdin { data },
                    "forwarding console input",
                ));
            }

            // Never held back by a send: the guest's own exit, its output and a
            // closed channel are all observed while one waits.
            message = rx.recv() => {
                let Some(message) = message else {
                    return Err(closed_session());
                };
                if let Some(end) =
                    handle_checked_message(message, sink, &mut feeding_input)?
                {
                    break 'session end;
                }
                let mut drained = None;
                while drained.is_none() {
                    match rx.try_recv() {
                        Ok(next) => {
                            drained =
                                handle_checked_message(next, sink, &mut feeding_input)?;
                        }
                        Err(_) => break,
                    }
                }
                if let Some(end) = drained {
                    break 'session end;
                }
            }
        }
    };

    Ok(end)
}

/// The session's result from the loop's, with the console put back whatever
/// ended it.
///
/// The two teardown steps are attempted in this order even when the first one
/// fails, and a session failure keeps its own kind and text: only the console's
/// own failures are added beside it. A run whose only failure was a teardown
/// step is an error too, because a session that could not flush or restore has
/// failed as a session — the alternative is reporting the guest's status while
/// the caller's console is still in raw mode.
pub(super) fn conclude<W: ConsoleSink>(
    primary: Result<CheckedEnd, AttachSessionError>,
    console: &mut W,
) -> Result<i32, CheckedFailure> {
    let primary = match primary {
        Ok(CheckedEnd::Exited(code)) => Ok(code),
        Ok(CheckedEnd::Failed(failure)) => Err(CheckedFailure::Spawn(failure)),
        Err(error) => Err(CheckedFailure::from(error)),
    };

    let mut teardown = Vec::new();
    if let Err(error) = console.finish_output() {
        teardown.push((
            TeardownStage::FlushConsoleOutput,
            AttachSessionError::host(AttachFailureKind::Output, error),
        ));
    }
    if let Err(error) = console.restore() {
        teardown.push((
            TeardownStage::RestoreConsole,
            AttachSessionError::host(AttachFailureKind::HostTerminal, error),
        ));
    }
    finish_with_teardown(
        primary,
        teardown,
        "the guest reported its exit but the console session did not finish cleanly",
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// One session event: `Some` ends the session, `None` continues it.
///
/// Nothing here awaits: a handler that blocked on the console could not receive
/// the guest's exit or a closed channel behind it. Decoding is shared with the
/// Unix loop; the console is this platform's own sink for guest output.
fn handle_checked_message<W: ConsoleSink>(
    message: Message,
    sink: &mut W,
    feeding_input: &mut bool,
) -> Result<Option<CheckedEnd>, AttachSessionError> {
    match classify_checked_message(message)? {
        CheckedEvent::Output(data) => {
            sink.write_output(&data)
                .map_err(|error| AttachSessionError::host(AttachFailureKind::Output, error))?;
            Ok(None)
        }
        CheckedEvent::End(end) => Ok(Some(end)),
        CheckedEvent::InputClosed => {
            *feeding_input = false;
            Ok(None)
        }
        CheckedEvent::Ignored => Ok(None),
    }
}

/// A failure of the console itself: setup, reading input, or restoring it.
fn host_failure(text: impl Into<String>) -> AttachSessionError {
    AttachSessionError::new(AttachFailureKind::HostTerminal, text)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! The checked console loop without a console.
    //!
    //! Only a Windows host can run the adapters, so the loop is driven here
    //! through the two seams: a console whose events the test injects, and a
    //! sink that records what reached the screen and how the console was left.
    //! The relay is a real `AgentClient` connection over a deliberately small
    //! duplex, so "the transport is stalled" is a property of the fixture rather
    //! than a sleep.

    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use microsandbox_protocol::codec;
    use microsandbox_protocol::core::Ready;
    use microsandbox_protocol::exec::{ExecExited, ExecStdin, ExecStdinError, ExecStdout};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;

    use crate::agent::AgentClient;
    use crate::sandbox::{SandboxConfig, build_exec_request};

    use super::*;

    //----------------------------------------------------------------------------------------------
    // Constants
    //----------------------------------------------------------------------------------------------

    /// The relay's buffer for the cases that never want a send to stall.
    const OPEN_RELAY_BYTES: usize = 64 * 1024;

    /// The relay's buffer, in bytes: smaller than one frame, so every send the
    /// loop starts stays in flight until the test reads what it wrote.
    const STALLED_RELAY_BYTES: usize = 16;

    //----------------------------------------------------------------------------------------------
    // Types
    //----------------------------------------------------------------------------------------------

    /// The console's side of the seam, driven directly by a test.
    struct TestConsole {
        rx: mpsc::UnboundedReceiver<ConsoleEvent>,
    }

    /// What the session wrote to the console, and how it left it.
    ///
    /// Shared, because the session holds the sink mutably for as long as it
    /// runs.
    #[derive(Clone, Default)]
    struct Screen {
        written: Arc<Mutex<Vec<u8>>>,
        steps: Arc<Mutex<Vec<&'static str>>>,
    }

    /// The sink the loop writes to: a console that always accepts.
    struct TestSink(Screen);

    /// Records every chunk it is given and forwards one fixed byte.
    ///
    /// The record is the regression's evidence: an input path that still routes
    /// console input after the guest closed its input calls this.
    struct TaggingFilter {
        seen: mpsc::UnboundedSender<Vec<u8>>,
    }

    /// Replaces every host chunk with `n` bytes of `b'z'`, one frame larger than
    /// the stalled relay's buffer.
    struct Expand(usize);

    /// A checked loop over a relay this test owns, a console it drives and a
    /// screen it reads.
    struct ConsoleFixture {
        client: Arc<AgentClient>,
        /// The relay's end of the connection: tests read the frames the session
        /// sends from it, and never answer.
        relay: DuplexStream,
        /// Guest events, injected straight into the loop's receiver.
        events: mpsc::Sender<Message>,
        rx: mpsc::Receiver<Message>,
        /// The connection's own decoded stream. Held open, never read: dropping
        /// it would stop the connection's reader.
        client_rx: mpsc::Receiver<Message>,
        /// The exec request's correlation id.
        id: u32,
        /// Console events the test injects.
        console_tx: mpsc::UnboundedSender<ConsoleEvent>,
        /// The console the loop reads.
        console: TestConsole,
        /// What the loop wrote to the console and how it left it.
        screen: Screen,
        /// The same console, as the loop's sink.
        sink: TestSink,
    }

    //----------------------------------------------------------------------------------------------
    // Methods
    //----------------------------------------------------------------------------------------------

    impl Screen {
        /// Everything the session wrote so far.
        fn bytes(&self) -> Vec<u8> {
            self.written.lock().expect("the screen").clone()
        }

        /// The teardown steps the session asked for, in order.
        fn steps(&self) -> Vec<&'static str> {
            self.steps.lock().expect("the screen").clone()
        }

        /// Wait until `marker` has reached the console.
        ///
        /// Guest events are handled in channel order, so waiting for a marker
        /// that was injected behind another event is a barrier proving the
        /// earlier one was handled.
        async fn wait_for(&self, marker: &[u8]) {
            within(async {
                while !self
                    .bytes()
                    .windows(marker.len())
                    .any(|window| window == marker)
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
        }
    }

    //----------------------------------------------------------------------------------------------
    // Trait Implementations
    //----------------------------------------------------------------------------------------------

    impl ConsoleEvents for TestConsole {
        fn recv(&mut self) -> impl Future<Output = Option<ConsoleEvent>> + Send {
            self.rx.recv()
        }
    }

    impl ConsoleSink for TestSink {
        fn write_output(&mut self, data: &[u8]) -> MicrosandboxResult<()> {
            self.0
                .written
                .lock()
                .expect("the screen")
                .extend_from_slice(data);
            Ok(())
        }

        fn finish_output(&mut self) -> MicrosandboxResult<()> {
            self.0.steps.lock().expect("the screen").push("flush");
            Ok(())
        }

        fn restore(&mut self) -> MicrosandboxResult<()> {
            self.0.steps.lock().expect("the screen").push("restore");
            Ok(())
        }
    }

    impl StdinFilter for TaggingFilter {
        fn filter<'a>(
            &'a mut self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let seen = self.seen.clone();
            let chunk = data.to_vec();
            Box::pin(async move {
                let _ = seen.send(chunk);
                vec![b'f']
            })
        }
    }

    impl StdinFilter for Expand {
        fn filter<'a>(
            &'a mut self,
            _data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
            let expanded = vec![b'z'; self.0];
            Box::pin(async move { expanded })
        }
    }

    //----------------------------------------------------------------------------------------------
    // Functions
    //----------------------------------------------------------------------------------------------

    /// A checked loop over a relay buffer of `bytes`, with nothing written yet.
    async fn fixture(bytes: usize) -> ConsoleFixture {
        let (mut relay, client_stream) = tokio::io::duplex(bytes);
        // The handshake and the exec request each have to be read while they
        // are written: the relay's buffer is smaller than one frame.
        let (client, ()) = tokio::join!(
            AgentClient::connect_stream_with_timeout(client_stream, Duration::from_secs(10)),
            handshake(&mut relay),
        );
        let client = client.expect("the fixture relay handshake");
        let request = build_exec_request(
            &SandboxConfig::default(),
            "bash".to_string(),
            Vec::new(),
            None,
            None,
            &[],
            &[],
            true,
            24,
            80,
        );
        let (streamed, _request_frame) = tokio::join!(
            client.stream(MessageType::ExecRequest, &request),
            codec::read_raw_frame(&mut relay),
        );
        let (id, client_rx) = streamed.expect("a stream id");

        let (console_tx, console_rx) = mpsc::unbounded_channel();
        let (events, rx) = mpsc::channel(16);
        let screen = Screen::default();
        ConsoleFixture {
            client: Arc::new(client),
            relay,
            events,
            rx,
            client_rx,
            id,
            console_tx,
            console: TestConsole { rx: console_rx },
            screen: screen.clone(),
            sink: TestSink(screen),
        }
    }

    /// The agent relay's handshake, exactly as the fake relay performs it.
    async fn handshake(io: &mut DuplexStream) {
        io.write_all(&1u32.to_be_bytes())
            .await
            .expect("a protocol generation");
        io.write_all(&1024u32.to_be_bytes())
            .await
            .expect("a frame bound");
        let ready = Ready {
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            agent_version: "console".to_string(),
            ..Default::default()
        };
        let frame = Message::with_payload(MessageType::Ready, 0, &ready).expect("a ready frame");
        codec::write_message(io, &frame)
            .await
            .expect("the relay writes its ready frame");
    }

    /// A bounded wait: a session that never concludes fails the test instead of
    /// hanging the suite.
    async fn within<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("the checked console loop did not make progress")
    }

    /// Wait for something the session itself has to do.
    ///
    /// `Box::pin` makes a future movable, not started: every wait a test does
    /// while the session is live is polled beside the session here, or the loop
    /// would never run and the wait would simply time out.
    async fn while_running<F, T>(session: &mut Pin<Box<F>>, wait: impl Future<Output = T>) -> T
    where
        F: Future<Output = Result<CheckedEnd, AttachSessionError>>,
    {
        tokio::select! {
            value = within(wait) => value,
            end = session => panic!("the session ended before the expected event: {end:?}"),
        }
    }

    /// The next frame the session sent, while the session itself stays running.
    async fn frame_while<F>(relay: &mut DuplexStream, session: &mut Pin<Box<F>>) -> Message
    where
        F: Future<Output = Result<CheckedEnd, AttachSessionError>>,
    {
        while_running(session, async {
            codec::read_message(relay)
                .await
                .expect("the session must send a frame")
        })
        .await
    }

    /// Prove a send started without letting it finish, and report its length.
    ///
    /// Reading the frame's length prefix is what proves the loop *started* the
    /// send; the frame is larger than the relay's buffer and nothing reads the
    /// rest, so the send stays in flight for as long as the test needs it to.
    /// The length is the frame body's, so a caller can read the rest itself.
    async fn blocked_send<F>(relay: &mut DuplexStream, session: &mut Pin<Box<F>>) -> usize
    where
        F: Future<Output = Result<CheckedEnd, AttachSessionError>>,
    {
        let mut length = [0u8; 4];
        while_running(session, async {
            relay
                .read_exact(&mut length)
                .await
                .expect("the loop must start its send")
        })
        .await;
        let length = u32::from_be_bytes(length) as usize;
        assert!(
            length > STALLED_RELAY_BYTES,
            "the frame must be larger than the relay's buffer, or the send cannot be in flight"
        );
        length
    }

    fn stdout(id: u32, data: &[u8]) -> Message {
        Message::with_payload(
            MessageType::ExecStdout,
            id,
            &ExecStdout {
                data: data.to_vec(),
            },
        )
        .expect("a guest output frame")
    }

    fn exited(id: u32, code: i32) -> Message {
        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
            .expect("a guest exit frame")
    }

    fn stdin_error(id: u32, errno: i32, name: &str) -> Message {
        Message::with_payload(
            MessageType::ExecStdinError,
            id,
            &ExecStdinError {
                errno: Some(errno),
                errno_name: Some(name.to_string()),
                message: format!("write failed: {name}"),
            },
        )
        .expect("a guest input failure frame")
    }

    fn stdin_payload(message: &Message) -> Vec<u8> {
        let frame: ExecStdin = message.payload().expect("a stdin payload");
        frame.data
    }

    //----------------------------------------------------------------------------------------------
    // Tests
    //----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn post_eio_console_input_reaches_neither_the_filter_nor_the_guest() {
        input_after_input_closure_is_discarded(5, "EIO").await;
    }

    #[tokio::test]
    async fn post_epipe_console_input_reaches_neither_the_filter_nor_the_guest() {
        input_after_input_closure_is_discarded(32, "EPIPE").await;
    }

    /// The review's regression: after the guest closed its input, the console's
    /// separate pump keeps reading keystrokes, and they must not reach the detach
    /// scan, the filter, or the guest.
    async fn input_after_input_closure_is_discarded(errno: i32, name: &str) {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(OPEN_RELAY_BYTES).await;
        let (seen, mut seen_rx) = mpsc::unbounded_channel();
        let filter: Box<dyn StdinFilter> = Box::new(TaggingFilter { seen });
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            Some(filter),
        ));

        // While the guest still accepts input, a keystroke is filtered and
        // forwarded: the filter really is wired to this session.
        console_tx
            .send(ConsoleEvent::Input(vec![b'a']))
            .expect("the console");
        assert_eq!(
            while_running(&mut run, seen_rx.recv()).await,
            Some(vec![b'a']),
            "the filter must see console input while the guest accepts it"
        );
        let frame = frame_while(&mut relay, &mut run).await;
        assert_eq!(frame.t, MessageType::ExecStdin);
        assert_eq!(stdin_payload(&frame), vec![b'f']);

        // The guest closes its input. The output frame behind it is a barrier:
        // guest events are handled in channel order.
        events
            .send(stdin_error(id, errno, name))
            .await
            .expect("the event channel");
        events
            .send(stdout(id, b"input-closed"))
            .await
            .expect("the event channel");
        while_running(&mut run, screen.wait_for(b"input-closed")).await;

        // Console input now may reach neither the filter nor the guest, while a
        // resize is still serviced.
        console_tx
            .send(ConsoleEvent::Input(vec![b'b']))
            .expect("the console");
        console_tx
            .send(ConsoleEvent::Resize {
                cols: 100,
                rows: 40,
            })
            .expect("the console");
        let frame = frame_while(&mut relay, &mut run).await;
        assert_eq!(
            frame.t,
            MessageType::ExecResize,
            "console input after the guest closed its input must not be forwarded"
        );
        let resize: ExecResize = frame.payload().expect("a resize payload");
        assert_eq!((resize.rows, resize.cols), (40, 100));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), seen_rx.recv())
                .await
                .is_err(),
            "console input after the guest closed its input still reached the filter"
        );

        // The guest's own exit still ends the session with its own status, and
        // the console is put back.
        events.send(exited(id, 7)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session");
        assert!(
            matches!(end, CheckedEnd::Exited(7)),
            "the guest's own status must come back after its input closed"
        );
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 7);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);

        // Nothing was ever sent for the discarded keystroke: the session is over,
        // so anything in the relay was written before it ended.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), codec::read_message(&mut relay))
                .await
                .is_err(),
            "console input after the guest closed its input still reached the guest"
        );
    }

    #[tokio::test]
    async fn a_console_read_error_after_input_closure_still_ends_the_session() {
        let ConsoleFixture {
            client,
            relay: _relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(OPEN_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        // The guest closed its input, and only the console's own failure ends
        // the session after that: the pump is still read, so the error is not
        // lost with the discarded keystrokes.
        events
            .send(stdin_error(id, 5, "EIO"))
            .await
            .expect("the event channel");
        events
            .send(stdout(id, b"input-closed"))
            .await
            .expect("the event channel");
        while_running(&mut run, screen.wait_for(b"input-closed")).await;
        console_tx
            .send(ConsoleEvent::Error("input: The handle is invalid.".into()))
            .expect("the console");

        let failure = within(&mut run)
            .await
            .expect_err("a console that cannot be read ends the session");
        assert_eq!(
            failure.kind(),
            AttachFailureKind::HostTerminal,
            "a console read error must be reported as a console failure: {failure}"
        );
        assert!(
            failure.to_string().contains("reading console input"),
            "the console's own error must be reported: {failure}"
        );
    }

    #[tokio::test]
    async fn ctrl_bracket_after_eio_does_not_detach() {
        ctrl_bracket_after_input_closure_waits(5, "EIO").await;
    }

    #[tokio::test]
    async fn ctrl_bracket_after_epipe_does_not_detach() {
        ctrl_bracket_after_input_closure_waits(32, "EPIPE").await;
    }

    /// Without a filter the same rule holds for the detach scan: a session whose
    /// guest closed its input waits for the guest's exit, it does not detach.
    async fn ctrl_bracket_after_input_closure_waits(errno: i32, name: &str) {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(OPEN_RELAY_BYTES).await;
        let detach = DetachKeys::default_keys();
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            Some(&detach),
            None,
        ));

        events
            .send(stdin_error(id, errno, name))
            .await
            .expect("the event channel");
        events
            .send(stdout(id, b"input-closed"))
            .await
            .expect("the event channel");
        while_running(&mut run, screen.wait_for(b"input-closed")).await;

        assert_eq!(
            detach.sequence(),
            &[0x1d][..],
            "the injected byte must be this session's detach key"
        );
        // The loop is idle, so a session that still scanned this byte would
        // detach immediately rather than after a wait.
        console_tx
            .send(ConsoleEvent::Input(b"\x1d".to_vec()))
            .expect("the console");
        let detached = tokio::time::timeout(Duration::from_millis(100), &mut run).await;
        assert!(
            detached.is_err(),
            "console input after the guest closed its input still reached the detach scan: {detached:?}"
        );

        events.send(exited(id, 8)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session");
        assert!(
            matches!(end, CheckedEnd::Exited(8)),
            "the guest's own status must come back after its input closed"
        );
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 8);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), codec::read_message(&mut relay))
                .await
                .is_err(),
            "the detach byte must not be forwarded after the guest closed its input"
        );
    }

    #[tokio::test]
    async fn an_exit_ends_the_session_while_a_direct_input_send_is_blocked() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        console_tx
            .send(ConsoleEvent::Input(vec![b'A'; 64]))
            .expect("the console");
        blocked_send(&mut relay, &mut run).await;

        // The guest's exit is available while that send still waits for the
        // transport, and it has to end the session.
        events.send(exited(id, 4)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session even with a send in flight");
        assert!(matches!(end, CheckedEnd::Exited(4)));
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 4);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }

    #[tokio::test]
    async fn an_exit_ends_the_session_while_a_filtered_send_is_blocked() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let filter: Box<dyn StdinFilter> = Box::new(Expand(64));
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            Some(filter),
        ));

        console_tx
            .send(ConsoleEvent::Input(vec![b'a']))
            .expect("the console");
        blocked_send(&mut relay, &mut run).await;

        events.send(exited(id, 5)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session even with a send in flight");
        assert!(matches!(end, CheckedEnd::Exited(5)));
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 5);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }

    #[tokio::test]
    async fn an_exit_ends_the_session_while_a_resize_send_is_blocked() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        console_tx
            .send(ConsoleEvent::Resize {
                cols: 120,
                rows: 50,
            })
            .expect("the console");
        blocked_send(&mut relay, &mut run).await;

        events.send(exited(id, 6)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session even with a send in flight");
        assert!(matches!(end, CheckedEnd::Exited(6)));
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 6);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }

    #[tokio::test]
    async fn a_closed_channel_is_reported_while_a_send_is_blocked() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        console_tx
            .send(ConsoleEvent::Input(vec![b'C'; 64]))
            .expect("the console");
        blocked_send(&mut relay, &mut run).await;
        // The connection's event channel closes while the send still waits.
        drop(events);

        let failure = within(&mut run)
            .await
            .expect_err("a closed channel is a lost session, send in flight or not");
        assert_eq!(
            failure.kind(),
            AttachFailureKind::ConnectionLost,
            "a closed channel must be reported as the lost session it is: {failure}"
        );
        drop(run);
        let failure =
            conclude(Err(failure), &mut sink).expect_err("a lost session is not a completed one");
        let CheckedFailure::Session(error) = failure else {
            panic!("a lost session stays a session failure: {failure:?}");
        };
        assert!(
            error.terminal_restored(),
            "the console is still put back when the channel closed during a send"
        );
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }

    #[tokio::test]
    async fn input_and_resize_pending_behind_a_send_are_neither_duplicated_nor_reordered() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        // A first chunk whose send cannot finish: the relay's buffer is smaller
        // than its frame and nothing reads the rest yet.
        console_tx
            .send(ConsoleEvent::Input(vec![b'a'; 64]))
            .expect("the console");
        let length = blocked_send(&mut relay, &mut run).await;

        // Both are offered while that send is still in flight. The loop must
        // hold them until it finishes, not drop, duplicate or reorder them.
        console_tx
            .send(ConsoleEvent::Input(vec![b'b'; 64]))
            .expect("the console");
        console_tx
            .send(ConsoleEvent::Resize {
                cols: 132,
                rows: 43,
            })
            .expect("the console");

        // Only now can the first frame finish. Reading it is also what lets the
        // held events be taken in order.
        let mut rest = vec![0u8; length];
        while_running(&mut run, async {
            relay
                .read_exact(&mut rest)
                .await
                .expect("the rest of the first frame")
        })
        .await;
        let first = vec![b'a'; 64];
        assert!(
            rest.windows(first.len()).any(|window| window == first),
            "the first chunk must be forwarded once and unchanged"
        );

        let frame = frame_while(&mut relay, &mut run).await;
        assert_eq!(frame.t, MessageType::ExecStdin);
        assert_eq!(
            stdin_payload(&frame),
            vec![b'b'; 64],
            "the chunk typed during a send must be forwarded once, unchanged"
        );
        let frame = frame_while(&mut relay, &mut run).await;
        assert_eq!(frame.t, MessageType::ExecResize);
        let resize: ExecResize = frame.payload().expect("a resize payload");
        assert_eq!(
            (resize.rows, resize.cols),
            (43, 132),
            "the resize held behind the send must follow it, unchanged"
        );

        // Nothing was sent twice: the loop is idle now, so a duplicate would
        // arrive at once.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), codec::read_message(&mut relay))
                .await
                .is_err(),
            "a chunk held behind a send must not be forwarded twice"
        );

        events.send(exited(id, 9)).await.expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session");
        assert!(matches!(end, CheckedEnd::Exited(9)));
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 9);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }

    /// The same guarantee as above, with enough queued chunks to make a broken
    /// guard fail every run rather than one in a handful.
    ///
    /// `start_send` returns a lazy future, so a send is only committed to the
    /// agent client's writer task once the loop has polled it. A loop that lets
    /// a console event start a second send while one is already owned therefore
    /// **drops** the send it replaces whenever the console arm is serviced
    /// first, and the chunk that send carried is never forwarded. One queued
    /// event leaves that to `select!`'s branch order, hence the flakiness of the
    /// smaller test; each additional queued chunk is another such chance, so
    /// sixteen of them make a lost chunk the expected outcome instead of a
    /// coincidence.
    #[tokio::test]
    async fn a_burst_of_input_behind_one_blocked_send_arrives_once_and_in_order() {
        let ConsoleFixture {
            client,
            mut relay,
            events,
            mut rx,
            client_rx: _client_rx,
            id,
            console_tx,
            mut console,
            screen,
            mut sink,
        } = fixture(STALLED_RELAY_BYTES).await;
        let mut run = Box::pin(checked_bridge(
            &client,
            id,
            &mut rx,
            &mut sink,
            &mut console,
            None,
            None,
        ));

        // A first chunk whose send cannot finish: the relay's buffer is smaller
        // than its frame and nothing reads the rest yet.
        console_tx
            .send(ConsoleEvent::Input(vec![b'a'; 64]))
            .expect("the console");
        let length = blocked_send(&mut relay, &mut run).await;

        // Sixteen more, each distinguishable, all offered while that send is
        // still in flight.
        let burst: Vec<Vec<u8>> = (0u8..16).map(|index| vec![b'A' + index; 64]).collect();
        for chunk in &burst {
            console_tx
                .send(ConsoleEvent::Input(chunk.clone()))
                .expect("the console");
        }

        // Only now can the first frame finish. Reading it is also what lets the
        // held events be taken in order.
        let mut rest = vec![0u8; length];
        while_running(&mut run, async {
            relay
                .read_exact(&mut rest)
                .await
                .expect("the rest of the first frame")
        })
        .await;
        let first = vec![b'a'; 64];
        assert!(
            rest.windows(first.len()).any(|window| window == first),
            "the first chunk must be forwarded once and unchanged"
        );

        for (index, expected) in burst.iter().enumerate() {
            let frame = frame_while(&mut relay, &mut run).await;
            assert_eq!(
                frame.t,
                MessageType::ExecStdin,
                "chunk {index} of the burst must reach the guest as input"
            );
            assert_eq!(
                &stdin_payload(&frame),
                expected,
                "chunk {index} of the burst must arrive once and in order"
            );
        }

        // Nothing was sent twice: the loop is idle now, so a duplicate would
        // arrive at once.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), codec::read_message(&mut relay))
                .await
                .is_err(),
            "a chunk held behind a send must not be forwarded twice"
        );

        events
            .send(exited(id, 10))
            .await
            .expect("the event channel");
        let end = within(&mut run)
            .await
            .expect("the guest exit ends the session");
        assert!(matches!(end, CheckedEnd::Exited(10)));
        drop(run);
        assert_eq!(conclude(Ok(end), &mut sink).expect("the guest exit"), 10);
        assert_eq!(screen.steps(), vec!["flush", "restore"]);
    }
}
