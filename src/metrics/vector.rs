use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Error, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use ic_bn_lib::{
    http::{Client as HttpClient, client::basic_auth, headers::CONTENT_TYPE_OCTET_STREAM},
    hval, vector,
};
use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, Registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use reqwest::{Method, Request, header::HeaderValue};
use serde_json::Value;
use tokio::{
    select,
    sync::mpsc,
    time::{Interval, interval, sleep},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, warn};
use url::Url;

use crate::cli;

pub const KB: f64 = 1024.0;
pub const MB: f64 = 1024.0 * KB;

const CONTENT_ENCODING_ZSTD: HeaderValue = hval!("zstd");

#[derive(Clone)]
struct Metrics {
    sent: IntCounter,
    sent_compressed: IntCounter,
    sent_events: IntCounter,
    buffer_event_size: IntGauge,
    batch_size: IntGauge,
    buffer_drops: IntCounter,
    encoding_failures: IntCounter,
    batch_buffer_size: IntGauge,
    batch_flush_retries: IntCounter,
    batch_flushes: IntCounterVec,
    batch_queue_duration: Histogram,
    batch_encode_duration: Histogram,
    batch_flush_duration: Histogram,
    batch_sizes: Histogram,
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

            sent_events: register_int_counter_with_registry!(
                format!("vector_sent_events"),
                format!("Number of events sent"),
                registry
            )
            .unwrap(),

            buffer_event_size: register_int_gauge_with_registry!(
                format!("vector_event_buffer_size"),
                format!("Number of events in the incoming buffer"),
                registry
            )
            .unwrap(),

            batch_size: register_int_gauge_with_registry!(
                format!("vector_batch_size"),
                format!("Current size of the events queued for the next batch"),
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

            batch_buffer_size: register_int_gauge_with_registry!(
                format!("vector_batch_buffer_size"),
                format!("Number of batches in the outgoing buffer"),
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

            batch_queue_duration: register_histogram_with_registry!(
                format!("vector_batch_queue_duration"),
                format!("Time it takes to queue the batch"),
                vec![0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2],
                registry
            )
            .unwrap(),

            batch_encode_duration: register_histogram_with_registry!(
                format!("vector_batch_encode_duration"),
                format!("Time it takes to encode the batch"),
                vec![0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2],
                registry
            )
            .unwrap(),

            batch_flush_duration: register_histogram_with_registry!(
                format!("vector_batch_flush_duration"),
                format!("Time it takes to flush the batch"),
                vec![0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2],
                registry
            )
            .unwrap(),

            batch_sizes: register_histogram_with_registry!(
                format!("vector_batch_sizes"),
                format!("Batch sizes histogram"),
                vec![
                    128.0 * KB,
                    256.0 * KB,
                    1.0 * MB,
                    4.0 * MB,
                    8.0 * MB,
                    16.0 * MB
                ],
                registry
            )
            .unwrap(),
        }
    }
}

/// Encodes the event into provided buffer and adds framing
pub fn encode_event(event: Value, buf: &mut BytesMut) -> Result<(), Error> {
    // Get a pointer to the length prefix & reserve 4 bytes for it
    let mut length = buf.split_off(buf.len());
    length.reserve(4);

    // Get a pointer to the data & encode the event there
    let mut data = length.split_off(4);
    vector::encode_event(event, &mut data).context("unable to encode the event")?;

    // Write the length prefix in Big Endian
    length.put_u32(data.len() as u32);

    // Return the buffer to its original state
    buf.unsplit(length);
    buf.unsplit(data);

    Ok(())
}

/// Encodes the given vec of events into Vector protobuf format
pub fn encode_batch(batch: Vec<Value>) -> Result<Bytes, Error> {
    let mut buf = BytesMut::with_capacity(512 * 1024);
    for v in batch {
        encode_event(v, &mut buf)?;
    }

    Ok(buf.freeze())
}

pub struct Vector {
    token_batcher: CancellationToken,
    token_flushers: CancellationToken,
    token_flushers_drain: CancellationToken,
    tracker_batcher: TaskTracker,
    tracker_flushers: TaskTracker,
    tx: mpsc::Sender<Value>,
    metrics: Metrics,
}

impl Vector {
    pub fn new(cli: &cli::Vector, client: Arc<dyn HttpClient>, registry: &Registry) -> Self {
        let cli = cli.clone();

        let (tx_event, rx_event) = mpsc::channel(cli.log_vector_buffer);
        let (tx_batch, rx_batch) = async_channel::bounded(cli.log_vector_batch_queue);

        let metrics = Metrics::new(registry);

        // Start batcher
        warn!("Vector: starting batcher");
        let token_batcher = CancellationToken::new();

        let mut interval = interval(cli.log_vector_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.reset();

        let batcher = Batcher {
            rx: rx_event,
            tx: tx_batch,
            batch: Vec::with_capacity(cli.log_vector_batch),
            interval,
            token: token_batcher.child_token(),
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
            .map(|x| basic_auth(x, cli.log_vector_pass));

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

    pub fn send(&self, event: Value) {
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

struct Batch {
    events: Vec<Value>,
}

struct Batcher {
    rx: mpsc::Receiver<Value>,
    tx: async_channel::Sender<Batch>,
    batch: Vec<Value>,
    interval: Interval,
    token: CancellationToken,
    metrics: Metrics,
}

impl Display for Batcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vector(Batcher)")
    }
}

impl Batcher {
    async fn add_to_batch(&mut self, event: Value) {
        self.batch.push(event);
        self.metrics.batch_size.set(self.batch.len() as i64);

        // If we've reached the capacity - it's time to flush
        if self.batch.len() == self.batch.capacity() {
            self.flush().await;
            // Reset the timer so that we don't flush again too soon
            self.interval.reset();
        }
    }

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        let len = self.batch.len();
        // Drain all elements from the batch without deallocating backing memory
        let batch = self.batch.drain(..).collect::<Vec<_>>();
        debug!("{self}: queueing batch ({len} events)");

        let start = Instant::now();
        // In our case the Batcher is dropped before the Flusher, so no error can occur
        let _ = self.tx.send(Batch { events: batch }).await;
        let dur = start.elapsed().as_secs_f64();

        debug!("{self}: batch ({len} events) queued in {dur}s");

        self.metrics.batch_queue_duration.observe(dur);
        self.metrics.batch_buffer_size.inc();
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

    async fn run(mut self) {
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("{self}: stopping, draining");
                    self.drain().await;
                    warn!("{self}: stopped");
                    return;
                },

                _ = self.interval.tick() => {
                    self.flush().await;
                },

                Some(event) = self.rx.recv() => {
                    self.metrics.buffer_event_size.dec();
                    self.add_to_batch(event).await;
                }
            }
        }
    }
}

struct Flusher {
    id: usize,
    rx: async_channel::Receiver<Batch>,
    client: Arc<dyn HttpClient>,
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
        write!(f, "Vector(Flusher{})", self.id)
    }
}

impl Flusher {
    // Sends the given body to Vector
    async fn send_batch(&self, body: Bytes, timeout: Duration) -> Result<(), Error> {
        let mut request = Request::new(Method::POST, self.url.clone());
        request
            .headers_mut()
            .insert(CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM);
        request
            .headers_mut()
            .insert(CONTENT_ENCODING, CONTENT_ENCODING_ZSTD);

        // Add basic auth header if configured
        if let Some(v) = &self.auth {
            request.headers_mut().insert(AUTHORIZATION, v.clone());
        }

        *request.body_mut() = Some(body.into());
        *request.timeout_mut() = Some(timeout);

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

    async fn send_batch_retry(&self, batch: Bytes) -> Result<(), Error> {
        let raw_size = batch.len();

        let batch = zstd::encode_all(batch.reader(), self.zstd_level as i32)
            .context("unable to compress batch")?;
        let batch = Bytes::from(batch);

        // Retry
        let mut interval = self.retry_interval;
        let mut retries = 1;
        let mut timeout = self.timeout;

        loop {
            let start = Instant::now();
            debug!(
                "{self}: sending batch (raw size {raw_size}, compressed {}, retry {})",
                batch.len(),
                retries
            );

            // Bytes is cheap to clone
            if let Err(e) = self.send_batch(batch.clone(), timeout).await {
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

            // Back off until some limit
            interval = (interval + self.retry_interval).min(self.retry_interval * 5);
            timeout = (timeout + self.timeout).min(self.timeout * 10);

            self.metrics.batch_flush_retries.inc();
            retries += 1;

            // Limit the retry count and reset the interval/timeout if we're draining.
            // Otherwise we wouldn't be able to stop with a dead endpoint.
            if self.token_drain.is_cancelled() {
                warn!("{self}: draining...");
                interval = self.retry_interval;
                timeout = self.timeout;

                if retries > 3 {
                    break;
                }
            }

            sleep(interval).await;
        }

        Err(anyhow!("unable to flush batch: retries exhausted"))
    }

    async fn process_batch(&self, batch: Batch) {
        let len = batch.events.len();
        self.metrics.batch_buffer_size.dec();

        debug!("{self}: received batch ({len} events)");

        // Encode the batch into wire format
        let start = Instant::now();
        match encode_batch(batch.events) {
            Ok(v) => {
                self.metrics
                    .batch_encode_duration
                    .observe(start.elapsed().as_secs_f64());
                self.metrics.batch_sizes.observe(v.len() as f64);

                // Send it
                let start = Instant::now();
                if let Err(e) = self.send_batch_retry(v).await {
                    warn!("{self}: unable to flush: {e:#}");
                } else {
                    self.metrics.sent_events.inc_by(len as u64);
                };
                self.metrics
                    .batch_flush_duration
                    .observe(start.elapsed().as_secs_f64());

                debug!("{self}: {len} events flushed");
            }

            Err(e) => {
                self.metrics.encoding_failures.inc();
                warn!("{self}: unable to encode batch: {e:#}")
            }
        };
    }

    async fn drain(&self) -> Result<(), Error> {
        // Close the channel
        self.rx.close();

        // Drain the buffer
        while let Ok(v) = self.rx.recv().await {
            self.process_batch(v).await;
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
                    self.process_batch(batch).await;
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

    #[derive(Debug)]
    struct TestClient(AtomicU64, AtomicU64);

    #[async_trait]
    impl HttpClient for TestClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            let mut resp = http::Response::new(vec![]);

            // fail from time to time
            if rand::random::<f64>() < 0.05 {
                *resp.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
                return Ok(resp.into());
            }

            let body = zstd::decode_all(req.body().unwrap().as_bytes().unwrap()).unwrap();
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.fetch_add(body.len() as u64, Ordering::SeqCst);

            Ok(resp.into())
        }
    }

    #[derive(Debug)]
    struct TestClientOk;

    #[async_trait]
    impl HttpClient for TestClientOk {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            let resp = http::Response::new(vec![]);
            Ok(resp.into())
        }
    }

    #[derive(Debug)]
    struct TestClientDead;

    #[async_trait]
    impl HttpClient for TestClientDead {
        async fn execute(
            &self,
            _req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            let mut resp = http::Response::new(vec![]);
            *resp.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
            Ok(resp.into())
        }
    }

    #[test]
    fn test_encoder() {
        let event = json!({
            "foo": "bar",
        });

        let mut buf = BytesMut::new();
        assert!(encode_event(event.clone(), &mut buf).is_ok());
        assert!(encode_event(event, &mut buf).is_ok());
        assert_eq!(
            &buf.freeze().to_vec(),
            &[
                0, 0, 0, 31, 10, 29, 10, 27, 10, 7, 10, 1, 46, 18, 2, 72, 0, 18, 16, 58, 14, 10,
                12, 10, 3, 102, 111, 111, 18, 5, 10, 3, 98, 97, 114, 0, 0, 0, 31, 10, 29, 10, 27,
                10, 7, 10, 1, 46, 18, 2, 72, 0, 18, 16, 58, 14, 10, 12, 10, 3, 102, 111, 111, 18,
                5, 10, 3, 98, 97, 114
            ],
        );
    }

    fn make_cli() -> cli::Vector {
        cli::Vector {
            log_vector_url: Some(Url::parse("http://127.0.0.1:1234").unwrap()),
            log_vector_user: None,
            log_vector_pass: None,
            log_vector_batch: 50,
            log_vector_buffer: 5000,
            log_vector_interval: Duration::from_secs(100),
            log_vector_timeout: Duration::from_secs(10),
            log_vector_flushers: 4,
            log_vector_zstd_level: 3,
            log_vector_batch_queue: 32,
            log_vector_retry_interval: Duration::from_millis(1),
        }
    }

    #[tokio::test]
    async fn test_vector() {
        let cli = make_cli();

        let client = Arc::new(TestClient(AtomicU64::new(0), AtomicU64::new(0)));
        let vector = Vector::new(&cli, client.clone(), &Registry::new());

        for i in 0..5000 {
            let event = json!({
                format!("foo{i}"): format!("bar{i}"),
            });

            vector.send(event.clone());
        }

        vector.stop().await;

        assert_eq!(client.0.load(Ordering::SeqCst), 100); // Batches
        assert_eq!(client.1.load(Ordering::SeqCst), 212780); // Uncompressed size
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_vector_drain_alive() {
        let mut cli = make_cli();
        cli.log_vector_buffer = 10000;
        cli.log_vector_batch = 1000;
        cli.log_vector_interval = Duration::from_secs(1);
        cli.log_vector_flushers = 32;

        let client = Arc::new(TestClientOk);
        let vector = Vector::new(&cli, client, &Registry::new());

        for _ in 0..cli.log_vector_buffer {
            let event = json!({
                "env": "prod",
                "hostname": "da11-bnp00",
                "msec": 1000,
                "request_id": "69f9acca-6321-4d03-905b-d2424cba4ba2",
                "request_method": "PUT",
                "server_protocol": "HTTP/2.0",
                "status": 200,
                "status_upstream": 200,
                "http_host": "foobar.com",
                "http_origin": "foobar2.com",
                "http_referer": "foobar3.com/foo/bar",
                "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
                "content_type": "text/plain",
                "geo_country_code": "CH",
                "request_uri": "https://foobar.com/foo/bar/baz/dead/beef",
                "query_string": "?foo=1&bar=2&baz=3",
                "ic_node_id": "upg5h-ggk5u-6qxp7-ksz3r-osynn-z2wou-65klx-cuala-sd6y3-3lorr-dae",
                "ic_subnet_id": "yqbqe-whgvn-teyic-zvtln-rcolf-yztin-ecal6-smlwy-6imph-6isdn-qqe",
                "ic_method_name": "http_request",
                "ic_request_type": "query",
                "ic_sender": "4fssn-4vi43-2qufr-hlrfz-hfohd-jgrwc-7l7ok-uatwb-ukau7-lwmoz-tae",
                "ic_canister_id": "canister_id",
                "ic_canister_id_cbor": "4fssn-4vi43-2qufr-hlrfz",
                "ic_error_cause": "foobar",
                "retries": 0,
                "error_cause": "no_error",
                "ssl_protocol": "TLSv1_3",
                "ssl_cipher": "TLS13_AES_256_GCM_SHA384",
                "request_length": 1000,
                "body_bytes_sent": 2000,
                "bytes_sent": 2500,
                "remote_addr": "5fcfafd1a139fc995662feea66e52ae7",
                "request_time": 1.5,
                "request_time_headers": 0,
                "cache_status": "MISS",
                "cache_status_nginx": "MISS",
                "cache_bypass_reason": "unable_to_extract_key",
                "upstream": "or1-dll01.gntlficpnode.com",
            });

            vector.send(event);
        }

        vector.stop().await;

        assert_eq!(
            vector.metrics.sent_events.get(),
            cli.log_vector_buffer as u64,
        );
    }

    /// Make sure we can drain when the endpoint is down
    #[tokio::test]
    async fn test_vector_drain_dead() {
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
