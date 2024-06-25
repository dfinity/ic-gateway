use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use bytes::{Bytes, BytesMut};
use reqwest::{
    header::{self, HeaderValue},
    Method, Request,
};
use tokio::{
    select,
    sync::mpsc::{channel, Receiver, Sender},
    time::interval,
};
use tokio_util::{
    codec::{Encoder, LengthDelimitedCodec},
    sync::CancellationToken,
    task::TaskTracker,
};
use tracing::warn;
use url::Url;
use vector_lib::{codecs::encoding::NativeSerializer, config::LogNamespace, event::Event};

use crate::{cli, http};

#[allow(clippy::declare_interior_mutable_const)]
const CONTENT_TYPE_OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet-stream");

// Encodes Vector events into a native format with length delimiting
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

    // Encodes the event into provided buffer and adds framing
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
        };

        let tracker = TaskTracker::new();
        tracker.spawn(async move {
            let _ = actor.run(cli.log_vector_interval).await;
        });

        Self { tx, tracker, token }
    }

    pub fn send(&self, v: serde_json::Value) {
        // This never fails with LogNamespace::Vector
        let event = Event::from_json_value(v, LogNamespace::Vector).unwrap();
        // If it fails we'll lose the message, but it's better than to block & eat memory.
        let _ = self.tx.try_send(event);
    }

    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

struct VectorActor {
    rx: Receiver<Event>,
    batch: Vec<Event>,

    client: Arc<dyn http::Client>,
    url: Url,
    auth: Option<HeaderValue>,

    encoder: EventEncoder,
    token: CancellationToken,
}

impl VectorActor {
    async fn buffer_event(&mut self, event: Event) -> Result<(), Error> {
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

        let mut encoder = self.encoder.clone();
        let body = encoder
            .encode_batch(&mut self.batch)
            .context("unable to encode batch")?;

        // Retry until we succeed or token is cancelled
        let mut interval = interval(Duration::from_secs(3));
        let mut retries = 3;
        let drain = self.token.is_cancelled();

        loop {
            select! {
                biased;

                _ = interval.tick() => {
                    if let Err(e) = self.send(body.clone()).await {
                        warn!("Vector: unable to flush batch: {e:#}");

                        // Limit the number of retries when draining
                        if drain {
                            retries -= 1;
                            if retries == 0 {
                                return Err(e);
                            }
                        }

                        continue
                    }

                    return Ok(())
                }

                () = self.token.cancelled(), if !drain => {
                    warn!("Vector: exiting, aborting batch sending");
                    return Ok(());
                }
            }
        }
    }

    async fn run(mut self, flush_interval: Duration) {
        let mut interval = interval(flush_interval);

        warn!("Vector: started");
        loop {
            select! {
                biased;

                () = self.token.cancelled() => {
                    warn!("Vector: stopping, draining");
                    // Close the channel
                    self.rx.close();

                    // Drain the buffer
                    while let Some(v) = self.rx.recv().await {
                        if let Err(e) = self.buffer_event(v).await {
                            warn!("Vector: unable to drain: {e:#}");
                            return;
                        }
                    }

                    if let Err(e) = self.flush().await {
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
                        if let Err(e) = self.buffer_event(v).await {
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
    use super::*;
    use serde_json::json;
    use vector_lib::config::LogNamespace;

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
}
