use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Error};
use serde::ser::{SerializeMap, Serializer as _};
use serde_json::Serializer;
use std::os::unix::net::UnixDatagram;
use tracing::{Event, Level, Subscriber};
use tracing_serde::AsSerde;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::layer,
    layer::{Context as TracingContext, Layer, SubscriberExt},
    registry::{LookupSpan, Registry},
};

use crate::cli::Log;

// 1k is an average request log message which is a vast majority of log entries
const LOG_ENTRY_SIZE: usize = 1024;
const JOURNALD_PATH: &str = "/run/systemd/journal/socket";

// Journald protocol helper functions, stolen from tracing-journald crate
fn put_value(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value);
    buf.push(b'\n');
}

fn put_field_wellformed(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'\n');
    put_value(buf, value);
}

fn put_priority(buf: &mut Vec<u8>, meta: &tracing_core::Metadata) {
    put_field_wellformed(
        buf,
        "PRIORITY",
        match *meta.level() {
            Level::ERROR => b"3",
            Level::WARN => b"4",
            Level::INFO => b"5",
            Level::DEBUG => b"6",
            Level::TRACE => b"7",
        },
    );
}

// Prepare the JSON-serialized message from a tracing event
fn event_to_json(event: &Event) -> Result<Vec<u8>, Error> {
    let mut msg = Vec::with_capacity(LOG_ENTRY_SIZE);
    let mut ser = Serializer::new(&mut msg);
    let mut ser = ser.serialize_map(None)?;

    // Set level/timestamp
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ser.serialize_entry("timestamp", &timestamp)?;
    ser.serialize_entry("level", &event.metadata().level().as_serde())?;

    // Set other fields
    let mut visitor = tracing_serde::SerdeMapVisitor::new(ser);
    event.record(&mut visitor);
    ser = visitor.take_serializer()?;

    // Finish serializing
    ser.end()?;

    Ok(msg)
}

// tracing_subscriber Layer implementation that logs the events to Journald in JSON format
struct JournaldLayer {
    socket: UnixDatagram,
}

impl JournaldLayer {
    fn new() -> Result<Self, Error> {
        let socket = UnixDatagram::unbound()?;
        socket.connect(JOURNALD_PATH)?;
        // Ping journald to check the connection
        socket.send(&[])?;
        Ok(Self { socket })
    }
}

impl<S> Layer<S> for JournaldLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event, _ctx: TracingContext<'_, S>) {
        // Do stuff in closure to simplify error handling
        let send = || -> Result<(), Error> {
            let msg = event_to_json(event)?;

            // Prepare the Journald packet that should fit the message
            // TODO optimize to a single allocation?
            let mut buf = Vec::with_capacity(LOG_ENTRY_SIZE + 64);
            put_priority(&mut buf, event.metadata());
            put_field_wellformed(&mut buf, "MESSAGE", &msg);

            // Send it
            self.socket.send(&buf)?;

            Ok(())
        };

        // We can't really handle any of the errors here, so ignore them
        let _ = send();
    }
}

// Sets up logging
pub fn setup_logging(cli: &Log) -> Result<(), Error> {
    let level_filter = LevelFilter::from_level(cli.log_level);

    let journald_layer = if cli.log_journald {
        Some(
            JournaldLayer::new()
                .context("unable to setup JournalD")?
                .with_filter(level_filter),
        )
    } else {
        None
    };

    #[cfg(tokio_unstable)]
    let tokio_console_layer = if cli.log_tokio_console {
        Some(console_subscriber::spawn())
    } else {
        None
    };

    let subscriber = Registry::default()
        // Journald
        .with(journald_layer)
        // Stdout
        // Ugly due to different types, TODO improve?
        .with((cli.log_stdout && !cli.log_stdout_json).then(|| layer().with_filter(level_filter)))
        .with(
            (cli.log_stdout && cli.log_stdout_json)
                .then(|| layer().json().flatten_event(true).with_filter(level_filter)),
        )
        // Null
        .with(cli.log_null.then(|| {
            layer()
                .with_writer(std::io::sink)
                .json()
                .flatten_event(true)
                .with_filter(level_filter)
        }));

    #[cfg(tokio_unstable)]
    let subscriber = subscriber.with(tokio_console_layer);

    tracing::subscriber::set_global_default(subscriber).context("unable to set global subscriber")
}
