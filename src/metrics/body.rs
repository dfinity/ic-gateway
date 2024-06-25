use std::{
    pin::{pin, Pin},
    task::{Context, Poll},
};

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use tokio::sync::oneshot::{self, Receiver, Sender};

use crate::http::calc_headers_size;

pub type BodyResult = Result<u64, String>;

// Body that counts the bytes streamed
pub struct CountingBody<D, E> {
    inner: Pin<Box<dyn Body<Data = D, Error = E> + Send + 'static>>,
    tx: Option<Sender<BodyResult>>,
    expected_size: Option<u64>,
    bytes_sent: u64,
}

impl<D, E> CountingBody<D, E> {
    pub fn new<B>(inner: B) -> (Self, Receiver<BodyResult>)
    where
        B: Body<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        let expected_size = inner.size_hint().exact();
        let (tx, rx) = oneshot::channel();

        let mut body = Self {
            inner: Box::pin(inner),
            tx: Some(tx),
            expected_size,
            bytes_sent: 0,
        };

        // If the size is known and zero - finish now,
        // otherwise it won't be called anywhere else
        if expected_size == Some(0) {
            body.finish(Ok(0));
        }

        (body, rx)
    }

    pub fn finish(&mut self, res: Result<u64, String>) {
        if let Some(v) = self.tx.take() {
            let _ = v.send(res);
        }
    }
}

impl<D, E> Body for CountingBody<D, E>
where
    D: Buf,
    E: std::string::ToString,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = pin!(&mut self.inner).poll_frame(cx);

        match &poll {
            // There is still some data available
            Poll::Ready(Some(v)) => match v {
                Ok(buf) => {
                    // Normal data frame
                    if buf.is_data() {
                        self.bytes_sent += buf.data_ref().unwrap().remaining() as u64;
                    } else if buf.is_trailers() {
                        // Trailers are very uncommon, for the sake of completeness
                        self.bytes_sent += calc_headers_size(buf.trailers_ref().unwrap()) as u64;
                    }

                    // Check if we already got what was expected
                    if Some(self.bytes_sent) >= self.expected_size {
                        // Make borrow checker happy
                        let x = self.bytes_sent;
                        self.finish(Ok(x));
                    }
                }

                // Error occured
                Err(e) => {
                    self.finish(Err(e.to_string()));
                }
            },

            // Nothing left
            Poll::Ready(None) => {
                // Make borrow checker happy
                let x = self.bytes_sent;
                self.finish(Ok(x));
            }

            // Do nothing
            Poll::Pending => {}
        }

        poll
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn test_body_stream() {
        let data = b"foobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbl\
        ahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahbla\
        hfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoob\
        arblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarbla\
        blahfoobarblahblah";

        let stream = tokio_util::io::ReaderStream::new(&data[..]);
        let body = axum::body::Body::from_stream(stream);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_body_full() {
        let data = vec![0; 512];
        let buf = bytes::Bytes::from_iter(data.clone());
        let body = http_body_util::Full::new(buf);

        let (body, rx) = CountingBody::new(body);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let size = rx.await.unwrap().unwrap();
        assert_eq!(size, data.len() as u64);
    }
}
