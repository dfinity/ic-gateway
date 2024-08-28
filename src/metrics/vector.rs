use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use bytes::{Bytes, BytesMut};
use ic_bn_lib::http;
use ic_bn_lib::http::headers::CONTENT_TYPE_OCTET_STREAM;
use reqwest::{
    header::{self, HeaderValue},
    Method, Request,
};
use tokio::{
    select,
    sync::mpsc::{channel, Receiver, Sender},
    time::{interval, sleep},
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
    token: CancellationToken,
    tracker: TaskTracker,
    tx: Sender<Event>,
}

impl Vector {
    pub fn new(cli: &cli::Vector, client: Arc<dyn http::Client>) -> Self {
        let cli = cli.clone();

        let (tx, rx) = channel(cli.log_vector_buffer);
        let token = CancellationToken::new();

        // Prepare auth header
        let auth = cli
            .log_vector_user
            .map(|x| http::client::basic_auth(x, cli.log_vector_pass));

        let actor = VectorActor {
            client,
            url: cli.log_vector_url.unwrap(),
            batch: Vec::with_capacity(cli.log_vector_batch),
            auth,
            rx,
            token: token.child_token(),
            encoder: EventEncoder::new(),
            timeout: cli.log_vector_timeout,
        };

        let tracker = TaskTracker::new();
        tracker.spawn(async move {
            actor.run(cli.log_vector_interval).await;
        });

        Self { token, tracker, tx }
    }

    pub fn send(&self, v: serde_json::Value) {
        // This never fails with LogNamespace::Vector
        let event = Event::from_json_value(v, LogNamespace::Vector).unwrap();
        // If it fails we'll lose the message, but it's better than to block & eat memory.
        let _ = self.tx.try_send(event);
    }

    pub async fn stop(&self) {
        warn!("Vector: shutting down actor");
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

struct VectorActor {
    rx: Receiver<Event>,
    batch: Vec<Event>,

    client: Arc<dyn http::Client>,
    timeout: Duration,
    url: Url,
    auth: Option<HeaderValue>,

    encoder: EventEncoder,
    token: CancellationToken,
}

impl VectorActor {
    async fn add_to_batch(&mut self, event: Event) -> Result<(), Error> {
        self.batch.push(event);

        if self.batch.len() == self.batch.capacity() {
            self.flush().await?;
        }

        Ok(())
    }

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

        let response = self
            .client
            .execute(request)
            .await
            .context("unable to execute HTTP request")?;

        if !response.status().is_success() {
            return Err(anyhow!("Incorrect HTTP code: {}", response.status()));
        }

        Ok(())
    }

    async fn flush(&mut self) -> Result<(), Error> {
        if self.batch.is_empty() {
            return Ok(());
        }

        // Encode the batch
        let mut encoder = self.encoder.clone();
        let Ok(body) = encoder.encode_batch(&mut self.batch) else {
            self.batch.clear();
            return Err(anyhow!("unable to encode batch, dropping it"));
        };

        // Retry
        // TODO make configurable?
        let mut interval = Duration::from_millis(200);
        let mut retries = 5;

        while retries > 0 {
            // Bytes is cheap to clone
            if let Err(e) = self.send(body.clone()).await {
                warn!("Vector: unable to flush batch: {e:#}");
            } else {
                return Ok(());
            }

            sleep(interval).await;

            // Back off a bit
            retries -= 1;
            interval *= 2;
        }

        Err(anyhow!("unable to flush batch: retries exhausted"))
    }

    async fn drain(&mut self) -> Result<(), Error> {
        // Close the channel
        self.rx.close();

        // Drain the buffer
        while let Some(v) = self.rx.recv().await {
            self.add_to_batch(v).await.context("unable to flush")?;
        }

        // Flush the rest if anything left
        self.flush().await.context("unable to flush")
    }

    async fn run(mut self, flush_interval: Duration) {
        let mut interval = interval(flush_interval);

        warn!("Vector: started");
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("Vector: stopping, draining");
                    if let Err(e) = self.drain().await {
                        warn!("Vector: unable to drain: {e:#}");
                    }

                    warn!("Vector: stopped");
                    return;
                }

                _ = interval.tick() => {
                    if let Err(e) = self.flush().await {
                        warn!("Vector: unable to flush: {e:#}");
                    }
                }

                event = self.rx.recv() => {
                    if let Some(v) = event {
                        if let Err(e) = self.add_to_batch(v).await {
                            warn!("Vector: unable to flush: {e:#}");
                        }
                    }
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
        };

        // 32 bytes on wire
        let event = json!({
            "foo": "bar",
        });

        let client = Arc::new(TestClient(AtomicU64::new(0), AtomicU64::new(0)));
        let vector = Vector::new(&cli, client.clone());

        let mut i = 6000;
        while i > 0 {
            vector.send(event.clone());
            i -= 1;
        }

        vector.stop().await;

        // 6k sent, buffer 5k => 1k will be dropped
        assert_eq!(client.0.load(Ordering::SeqCst), 100);
        assert_eq!(client.1.load(Ordering::SeqCst), 5000 * 32);
    }
}
