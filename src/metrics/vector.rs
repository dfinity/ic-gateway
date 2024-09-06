use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use bytes::{Bytes, BytesMut};
use ic_bn_lib::http;
use ic_bn_lib::http::headers::CONTENT_TYPE_OCTET_STREAM;
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
    sync::mpsc::{channel, Receiver, Sender},
    time::{interval, sleep, timeout},
};
use tokio_util::{
    codec::{Encoder, LengthDelimitedCodec},
    sync::CancellationToken,
    task::TaskTracker,
};
use tracing::warn;
use url::Url;
use vector_lib::{codecs::encoding::NativeSerializer, config::LogNamespace, event::Event};

use crate::cli;

const RETRY_INTERVAL: Duration = Duration::from_millis(200);
const RETRY_COUNT: usize = 5;

#[derive(Clone)]
struct Metrics {
    buffer_size: IntGauge,
    batch_size: IntGauge,
    buffer_drops: IntCounter,
    batch_encoding_failures: IntCounter,
    batch_flush_retries: IntCounter,
    batch_flushes: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            buffer_size: register_int_gauge_with_registry!(
                format!("vector_buffer_size"),
                format!("Number of events in the incoming buffer"),
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

            batch_encoding_failures: register_int_counter_with_registry!(
                format!("vector_batch_encoding_failures"),
                format!("Number of batches that were dropped due to encoding failure"),
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
        self.framer.encode(bytes, &mut payload)?;

        buf.unsplit(payload);
        Ok(())
    }

    /// Encodes the provided batch into wire format leaving the provided Vec empty
    fn encode_batch(&mut self, batch: &mut Vec<Event>) -> Result<Bytes, Error> {
        let mut body = BytesMut::new();
        for event in batch.drain(..) {
            self.encode_event(event, &mut body)?;
        }
        Ok(body.freeze())
    }
}

pub struct Vector {
    token_batcher: CancellationToken,
    token_flushers: CancellationToken,
    tracker_batcher: TaskTracker,
    tracker_flushers: TaskTracker,
    tx: Sender<Event>,
    metrics: Metrics,
}

impl Vector {
    pub fn new(cli: &cli::Vector, client: Arc<dyn http::Client>, registry: &Registry) -> Self {
        let cli = cli.clone();

        let (tx_event, rx_event) = channel(cli.log_vector_buffer);
        let (tx_batch, rx_batch) = async_channel::bounded(64);

        let metrics = Metrics::new(registry);

        // Start batcher
        warn!("Vector: starting batcher");
        let token_batcher = CancellationToken::new();
        let batcher = Batcher {
            rx: rx_event,
            tx: tx_batch,
            batch: Vec::with_capacity(cli.log_vector_batch),
            token: token_batcher.child_token(),
            encoder: EventEncoder::new(),
            metrics: metrics.clone(),
        };

        let tracker_batcher = TaskTracker::new();
        tracker_batcher.spawn(async move {
            batcher.run(cli.log_vector_interval).await;
        });

        // Start flushers
        let token_flushers = CancellationToken::new();
        let tracker_flushers = TaskTracker::new();

        // Prepare auth header
        let auth = cli
            .log_vector_user
            .map(|x| http::client::basic_auth(x, cli.log_vector_pass));

        warn!("Vector: starting flushers ({})", cli.log_vector_flushers);
        for _ in 0..cli.log_vector_flushers {
            let flusher = Flusher {
                rx: rx_batch.clone(),
                client: client.clone(),
                url: cli.log_vector_url.clone().unwrap(),
                auth: auth.clone(),
                token: token_flushers.child_token(),
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
            self.metrics.buffer_size.inc();
        };
    }

    pub async fn stop(&self) {
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
    rx: Receiver<Event>,
    tx: async_channel::Sender<Bytes>,
    batch: Vec<Event>,
    encoder: EventEncoder,
    token: CancellationToken,
    metrics: Metrics,
}

impl Batcher {
    async fn add_to_batch(&mut self, event: Event) {
        self.batch.push(event);
        self.metrics.batch_size.set(self.batch.len() as i64);

        if self.batch.len() == self.batch.capacity() {
            self.flush().await;
        }
    }

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        // Encode the batch
        let mut encoder = self.encoder.clone();
        let Ok(batch) = encoder.encode_batch(&mut self.batch) else {
            self.metrics.batch_encoding_failures.inc();
            self.batch.clear();
            return;
        };

        // In our case the Batcher is dropped before the Flusher, so no error can occur
        let _ = self.tx.send(batch).await;
    }

    async fn drain(&mut self) {
        // Close the channel
        self.rx.close();

        // Drain the buffer
        while let Some(v) = self.rx.recv().await {
            self.add_to_batch(v).await;
        }

        // Flush the rest if anything left
        self.flush().await;
    }

    async fn run(mut self, flush_interval: Duration) {
        let mut interval = interval(flush_interval);

        warn!("Vector: Batcher started");
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("Vector: Batcher: stopping, draining");
                    self.drain().await;
                    warn!("Vector: Batcher: stopped");
                    return;
                }

                _ = interval.tick() => {
                    self.flush().await;
                }

                Some(event) = self.rx.recv() => {
                    self.metrics.buffer_size.dec();
                    self.add_to_batch(event).await;
                }
            }
        }
    }
}

struct Flusher {
    rx: async_channel::Receiver<Bytes>,
    client: Arc<dyn http::Client>,
    timeout: Duration,
    url: Url,
    auth: Option<HeaderValue>,
    token: CancellationToken,
    metrics: Metrics,
}

impl Flusher {
    // Sends the given body to Vector
    async fn send(&self, body: Bytes) -> Result<(), Error> {
        let mut request = Request::new(Method::POST, self.url.clone());
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM);

        // Add basic auth header if configured
        if let Some(v) = &self.auth {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, v.clone());
        }

        *request.body_mut() = Some(body.into());
        *request.timeout_mut() = Some(self.timeout);

        let response = timeout(self.timeout, self.client.execute(request))
            .await
            .context("HTTP request timed out")?
            .context("unable to execute HTTP request")?;

        if !response.status().is_success() {
            return Err(anyhow!("Incorrect HTTP code: {}", response.status()));
        }

        Ok(())
    }

    async fn flush(&self, batch: Bytes) -> Result<(), Error> {
        // Retry
        // TODO make configurable?
        let mut interval = RETRY_INTERVAL;
        let mut retries = RETRY_COUNT;

        while retries > 0 {
            // Bytes is cheap to clone
            if let Err(e) = self.send(batch.clone()).await {
                warn!(
                    "Vector: Batcher: unable to send (try {}): {e:#}",
                    RETRY_COUNT - retries + 1
                );
            } else {
                self.metrics.batch_flushes.with_label_values(&["yes"]).inc();
                return Ok(());
            }

            self.metrics.batch_flush_retries.inc();
            sleep(interval).await;

            // Back off a bit
            retries -= 1;
            interval *= 2;
        }

        self.metrics.batch_flushes.with_label_values(&["no"]).inc();
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
        warn!("Vector: Flusher started");

        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("Vector: Flusher: stopping, draining");

                    if let Err(e) = self.drain().await {
                        warn!("Vector: Flusher: unable to drain: {e:#}");
                    }

                    warn!("Vector: Flusher: stopped");
                    return;
                }

                Ok(batch) = self.rx.recv() => {
                    if let Err(e) = self.flush(batch).await {
                        warn!("Vector: Flusher: unable to flush: {e:#}");
                    };
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

            let body = req.body().unwrap().as_bytes().unwrap();
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.fetch_add(body.len() as u64, Ordering::SeqCst);

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

    #[tokio::test]
    async fn test_vector() {
        let cli = cli::Vector {
            log_vector_url: Some(Url::parse("http://127.0.0.1:1234").unwrap()),
            log_vector_user: None,
            log_vector_pass: None,
            log_vector_batch: 50,
            log_vector_buffer: 5000,
            log_vector_interval: Duration::from_secs(100),
            log_vector_timeout: Duration::from_secs(10),
            log_vector_flushers: 4,
        };

        // 32 bytes on wire
        let event = json!({
            "foo": "bar",
        });

        let client = Arc::new(TestClient(AtomicU64::new(0), AtomicU64::new(0)));
        let vector = Vector::new(&cli, client.clone(), &Registry::new());

        for _ in 0..6000 {
            vector.send(event.clone());
        }

        vector.stop().await;

        // 6k sent, buffer 5k => 1k will be dropped
        assert_eq!(client.0.load(Ordering::SeqCst), 100);
        assert_eq!(client.1.load(Ordering::SeqCst), 5000 * 32);
    }
}
