use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use async_channel::{bounded, Receiver, Sender};
use bytes::{Buf, Bytes, BytesMut};
use ic_bn_lib::http::{self, headers::CONTENT_TYPE_OCTET_STREAM};
use prometheus::{
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry, IntCounter, IntCounterVec, IntGauge, Registry,
};
use reqwest::{
    header::{self, HeaderValue},
    Method, Request,
};
use tokio::{
    select,
    sync::mpsc,
    time::{interval, sleep, Interval},
};
use tokio_util::{
    codec::{Encoder, LengthDelimitedCodec},
    sync::CancellationToken,
    task::TaskTracker,
};
use tracing::{debug, warn};
use url::Url;
use vector_lib::{codecs::encoding::NativeSerializer, config::LogNamespace, event::Event};

use crate::cli;

const CONTENT_ENCODING_ZSTD: HeaderValue = HeaderValue::from_static("zstd");

#[derive(Clone)]
struct Metrics {
    sent: IntCounter,
    sent_compressed: IntCounter,
    buffer_event_size: IntGauge,
    buffer_batch_size: IntGauge,
    batch_size: IntGauge,
    buffer_drops: IntCounter,
    encoding_failures: IntCounter,
    batch_flush_retries: IntCounter,
    batch_flushes: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            sent: register_int_counter_with_registry!(
                format!("vector_sent"),
                format!("Number of bytes sent"),
                registry
            )
            .unwrap(),

            sent_compressed: register_int_counter_with_registry!(
                format!("vector_sent_compressed"),
                format!("Number of bytes sent (compressed)"),
                registry
            )
            .unwrap(),

            buffer_event_size: register_int_gauge_with_registry!(
                format!("vector_event_buffer_size"),
                format!("Number of events in the incoming buffer"),
                registry
            )
            .unwrap(),

            buffer_batch_size: register_int_gauge_with_registry!(
                format!("vector_batch_buffer_size"),
                format!("Number of batchs in the outgoing buffer"),
                registry
            )
            .unwrap(),

            batch_size: register_int_gauge_with_registry!(
                format!("vector_batch_size"),
                format!("Number of events in the outgoing batch"),
                registry
            )
            .unwrap(),

            buffer_drops: register_int_counter_with_registry!(
                format!("vector_buffer_drops"),
                format!("Number of events that were dropped due to buffer overflow"),
                registry
            )
            .unwrap(),

            encoding_failures: register_int_counter_with_registry!(
                format!("vector_encoding_failures"),
                format!("Number of events that were dropped due to encoding failure"),
                registry
            )
            .unwrap(),

            batch_flush_retries: register_int_counter_with_registry!(
                format!("vector_batch_flush_retries"),
                format!("Number of batch flush retries"),
                registry
            )
            .unwrap(),

            batch_flushes: register_int_counter_vec_with_registry!(
                format!("vector_batch_flushes"),
                format!("Count of batch flushes"),
                &["ok"],
                registry
            )
            .unwrap(),
        }
    }
}

/// Encodes Vector events into a native format with length delimiting
#[derive(Clone)]
struct EventEncoder {
    framer: LengthDelimitedCodec,
    serializer: NativeSerializer,
}

impl EventEncoder {
    fn new() -> Self {
        Self {
            framer: LengthDelimitedCodec::new(),
            serializer: NativeSerializer,
        }
    }

    /// Encodes the event into provided buffer and adds framing
    #[inline]
    fn encode_event(&mut self, event: Event, buf: &mut BytesMut) -> Result<(), Error> {
        // Serialize
        let len = buf.len();
        let mut payload = buf.split_off(len);

        self.serializer
            .encode(event, &mut payload)
            .map_err(|e| anyhow!("unable to serialize event: {e:#}"))?;

        // Add framing
        let bytes = payload.split().freeze();
        self.framer
            .encode(bytes, &mut payload)
            .map_err(|e| anyhow!("unable to add framing: {e:#}"))?;

        buf.unsplit(payload);
        Ok(())
    }
}

pub struct Vector {
    token_batcher: CancellationToken,
    token_flushers: CancellationToken,
    token_flushers_drain: CancellationToken,
    tracker_batcher: TaskTracker,
    tracker_flushers: TaskTracker,
    tx: mpsc::Sender<Event>,
    metrics: Metrics,
}

impl Vector {
    pub fn new(cli: &cli::Vector, client: Arc<dyn http::Client>, registry: &Registry) -> Self {
        let cli = cli.clone();

        let (tx_event, rx_event) = mpsc::channel(cli.log_vector_buffer);
        let (tx_batch, rx_batch) = bounded(cli.log_vector_batch_count);

        let metrics = Metrics::new(registry);

        // Start batcher
        warn!("Vector: starting batcher");
        let batch_capacity = cli.log_vector_batch + cli.log_vector_batch / 10;
        let token_batcher = CancellationToken::new();

        let mut interval = interval(cli.log_vector_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let batcher = Batcher {
            rx: rx_event,
            tx: tx_batch,
            // Allocate an extra 10% to make sure that we don't reallocate when pushing into batch
            batch: BytesMut::with_capacity(batch_capacity),
            batch_capacity,
            batch_size: cli.log_vector_batch,
            interval,
            token: token_batcher.child_token(),
            encoder: EventEncoder::new(),
            metrics: metrics.clone(),
        };

        let tracker_batcher = TaskTracker::new();
        tracker_batcher.spawn(async move {
            batcher.run().await;
        });

        // Start flushers
        let token_flushers = CancellationToken::new();
        let token_flushers_drain = CancellationToken::new();
        let tracker_flushers = TaskTracker::new();

        // Prepare auth header
        let auth = cli
            .log_vector_user
            .map(|x| http::client::basic_auth(x, cli.log_vector_pass));

        warn!("Vector: starting flushers ({})", cli.log_vector_flushers);
        for id in 0..cli.log_vector_flushers {
            let flusher = Flusher {
                id,
                rx: rx_batch.clone(),
                client: client.clone(),
                url: cli.log_vector_url.clone().unwrap(),
                auth: auth.clone(),
                zstd_level: cli.log_vector_zstd_level,
                token: token_flushers.child_token(),
                token_drain: token_flushers_drain.child_token(),
                retry_interval: cli.log_vector_retry_interval,
                timeout: cli.log_vector_timeout,
                metrics: metrics.clone(),
            };

            tracker_flushers.spawn(async move {
                flusher.run().await;
            });
        }

        Self {
            token_batcher,
            token_flushers,
            token_flushers_drain,
            tracker_batcher,
            tracker_flushers,
            tx: tx_event,
            metrics,
        }
    }

    pub fn send(&self, v: serde_json::Value) {
        // This never fails with LogNamespace::Vector
        let event = Event::from_json_value(v, LogNamespace::Vector).unwrap();

        // If it fails we'll lose the event, but it's better than to block & eat memory.
        if self.tx.try_send(event).is_err() {
            self.metrics.buffer_drops.inc();
        } else {
            self.metrics.buffer_event_size.inc();
        };
    }

    pub async fn stop(&self) {
        // Signal the flushers to limit the retries first
        self.token_flushers_drain.cancel();

        warn!("Vector: shutting down batcher");
        self.token_batcher.cancel();
        self.tracker_batcher.close();
        self.tracker_batcher.wait().await;

        warn!("Vector: shutting down flushers");
        self.token_flushers.cancel();
        self.tracker_flushers.close();
        self.tracker_flushers.wait().await;
    }
}

struct Batcher {
    rx: mpsc::Receiver<Event>,
    tx: Sender<Bytes>,
    batch: BytesMut,
    batch_capacity: usize,
    batch_size: usize,
    encoder: EventEncoder,
    interval: Interval,
    token: CancellationToken,
    metrics: Metrics,
}

impl Display for Batcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vector: Batcher")
    }
}

impl Batcher {
    fn add_to_batch(&mut self, event: Event) {
        if let Err(e) = self.encoder.encode_event(event, &mut self.batch) {
            warn!("{self}: unable to encode event: {e:#}");
            self.metrics.encoding_failures.inc();

            // Reclaim back the space that was split off
            let additional = self.batch_capacity - self.batch.capacity();
            self.batch.reserve(additional);

            // Clear the batch since the encoding failure might leave it inconsistent
            self.batch.clear();
        };
        self.metrics.batch_size.set(self.batch.len() as i64);

        if self.batch.len() >= self.batch_size {
            // Reset the interval to cause the flushing
            self.interval.reset_immediately();
        }
    }

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        let batch = self.batch.clone().freeze();

        let start = Instant::now();
        debug!("{self}: queueing batch (len {})", batch.len());
        // In our case the Batcher is dropped before the Flusher, so no error can occur
        let _ = self.tx.send(batch).await;
        debug!("{self}: batch queued in {}s", start.elapsed().as_secs_f64());
        self.metrics.buffer_batch_size.inc();
        self.batch.clear();
    }

    async fn drain(&mut self) {
        // Close the channel
        self.rx.close();

        // Drain the buffer
        while let Some(v) = self.rx.recv().await {
            self.add_to_batch(v);

            if self.batch.len() >= self.batch_size {
                self.flush().await;
            }
        }

        // Flush the rest if anything left
        self.flush().await;
    }

    async fn run(mut self) {
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("{self}: stopping, draining");
                    self.drain().await;
                    warn!("{self}: stopped");
                    return;
                }

                _ = self.interval.tick() => {
                    self.flush().await;
                }

                Some(event) = self.rx.recv() => {
                    self.metrics.buffer_event_size.dec();
                    self.add_to_batch(event);
                }
            }
        }
    }
}

struct Flusher {
    id: usize,
    rx: Receiver<Bytes>,
    client: Arc<dyn http::Client>,
    retry_interval: Duration,
    timeout: Duration,
    url: Url,
    auth: Option<HeaderValue>,
    zstd_level: usize,
    token: CancellationToken,
    token_drain: CancellationToken,
    metrics: Metrics,
}

impl Display for Flusher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vector: Flusher{}", self.id)
    }
}

impl Flusher {
    // Sends the given body to Vector
    async fn send(&self, body: Bytes) -> Result<(), Error> {
        let mut request = Request::new(Method::POST, self.url.clone());
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM);
        request
            .headers_mut()
            .insert(header::CONTENT_ENCODING, CONTENT_ENCODING_ZSTD);

        // Add basic auth header if configured
        if let Some(v) = &self.auth {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, v.clone());
        }

        *request.body_mut() = Some(body.into());
        *request.timeout_mut() = Some(self.timeout);

        let response = self
            .client
            .execute(request)
            .await
            .context("unable to execute HTTP request")?;

        if !response.status().is_success() {
            return Err(anyhow!("incorrect HTTP code: {}", response.status()));
        }

        Ok(())
    }

    async fn flush(&self, batch: Bytes) -> Result<(), Error> {
        let raw_size = batch.len();

        let batch = zstd::encode_all(batch.reader(), self.zstd_level as i32)
            .context("unable to compress batch")?;
        let batch = Bytes::from(batch);

        // Retry
        let mut interval = self.retry_interval;
        let mut retries = 1;

        loop {
            let start = Instant::now();
            debug!(
                "{self}: sending batch (raw size {raw_size}, compressed {}, retry {})",
                batch.len(),
                retries
            );

            // Bytes is cheap to clone
            if let Err(e) = self.send(batch.clone()).await {
                self.metrics.batch_flushes.with_label_values(&["no"]).inc();
                warn!(
                    "{self}: unable to send (try {}, retry interval {}s): {e:#}",
                    retries,
                    interval.as_secs_f64()
                );
            } else {
                self.metrics.sent.inc_by(raw_size as u64);
                self.metrics.sent_compressed.inc_by(batch.len() as u64);
                self.metrics.batch_flushes.with_label_values(&["yes"]).inc();

                debug!("{self}: batch sent in {}s", start.elapsed().as_secs_f64());
                return Ok(());
            }

            // Back off a bit until some limit
            interval = (interval + self.retry_interval).min(self.retry_interval * 5);

            self.metrics.batch_flush_retries.inc();
            retries += 1;

            // Limit the retry count if we're draining.
            // Otherwise we wouldn't be able to stop with dead endpoint.
            if self.token_drain.is_cancelled() && retries > 5 {
                break;
            }

            sleep(interval).await;
        }

        Err(anyhow!("unable to flush batch: retries exhausted"))
    }

    async fn drain(&self) -> Result<(), Error> {
        // Close the channel
        self.rx.close();

        // Drain the buffer
        while let Ok(v) = self.rx.recv().await {
            self.flush(v).await.context("unable to flush")?;
        }

        Ok(())
    }

    async fn run(self) {
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("{self}: stopping, draining");

                    if let Err(e) = self.drain().await {
                        warn!("{self}: unable to drain: {e:#}");
                    }

                    warn!("{self}: stopped");
                    return;
                }

                Ok(batch) = self.rx.recv() => {
                    self.metrics.buffer_batch_size.dec();
                    debug!("{self}: received batch (len {})", batch.len());

                    if let Err(e) = self.flush(batch).await {
                        warn!("{self}: unable to flush: {e:#}");
                    };

                    debug!("{self}: received batch flushed");
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use async_trait::async_trait;
    use serde_json::json;
    use vector_lib::config::LogNamespace;

    #[derive(Debug)]
    struct TestClient(AtomicU64, AtomicU64);

    #[async_trait]
    impl http::Client for TestClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            let mut resp = ::http::Response::new(vec![]);

            // fail from time to time
            if rand::random::<f64>() < 0.05 {
                *resp.status_mut() = ::http::StatusCode::SERVICE_UNAVAILABLE;
                return Ok(resp.into());
            }

            let body = zstd::decode_all(req.body().unwrap().as_bytes().unwrap()).unwrap();
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.fetch_add(body.len() as u64, Ordering::SeqCst);

            Ok(resp.into())
        }
    }

    #[derive(Debug)]
    struct TestClientDead;

    #[async_trait]
    impl http::Client for TestClientDead {
        async fn execute(
            &self,
            _req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            let mut resp = ::http::Response::new(vec![]);
            *resp.status_mut() = ::http::StatusCode::SERVICE_UNAVAILABLE;
            Ok(resp.into())
        }
    }

    #[test]
    fn test_encoder() {
        let mut encoder = EventEncoder::new();
        let event = Event::from_json_value(
            json!({
                "foo": "bar",
            }),
            LogNamespace::Vector,
        )
        .unwrap();

        let mut buf = BytesMut::new();
        assert!(encoder.encode_event(event, &mut buf).is_ok());
        assert_eq!(
            *buf.freeze(),
            *b"\0\0\0\x1c\n\x1a\n\x18\n\x0c\n\x03foo\x12\x05\n\x03bar\x1a\x02:\0\"\x04\n\x02:\0"
        );
    }

    fn make_cli() -> cli::Vector {
        cli::Vector {
            log_vector_url: Some(Url::parse("http://127.0.0.1:1234").unwrap()),
            log_vector_user: None,
            log_vector_pass: None,
            log_vector_batch: 1500,
            log_vector_buffer: 5000,
            log_vector_interval: Duration::from_secs(100),
            log_vector_timeout: Duration::from_secs(10),
            log_vector_flushers: 4,
            log_vector_zstd_level: 3,
            log_vector_batch_count: 32,
            log_vector_retry_interval: Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn test_vector() {
        let cli = make_cli();

        let client = Arc::new(TestClient(AtomicU64::new(0), AtomicU64::new(0)));
        let vector = Vector::new(&cli, client.clone(), &Registry::new());

        for i in 0..6000 {
            let event = json!({
                format!("foo{i}"): format!("bar{i}"),
            });

            vector.send(event.clone());
        }

        vector.stop().await;

        // 6k sent, buffer 5k => 1k will be dropped
        assert_eq!(client.0.load(Ordering::SeqCst), 131);
        assert_eq!(client.1.load(Ordering::SeqCst), 197780); // Uncompressed size
    }

    /// Make sure we can drain when the endpoint is down
    #[tokio::test]
    async fn test_vector_drain() {
        let cli = make_cli();

        let client = Arc::new(TestClientDead);
        let vector = Vector::new(&cli, client, &Registry::new());

        for i in 0..6000 {
            let event = json!({
                format!("foo{i}"): format!("bar{i}"),
            });

            vector.send(event.clone());
        }

        vector.stop().await;
    }
}
