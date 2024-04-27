use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use std::{
    pin::{pin, Pin},
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

// Body that counts the bytes streamed
pub struct CountingBody<D, E> {
    inner: Pin<Box<dyn Body<Data = D, Error = E> + Send + 'static>>,
    callback: Box<dyn Fn(u64, Result<(), String>) + Send + 'static>,
    callback_done: AtomicBool,
    expected_size: Option<u64>,
    bytes_sent: u64,
}

impl<D, E> CountingBody<D, E> {
    pub fn new<B>(inner: B, callback: impl Fn(u64, Result<(), String>) + Send + 'static) -> Self
    where
        B: Body<Data = D, Error = E> + Send + 'static,
        D: Buf,
    {
        let expected_size = inner.size_hint().exact();

        let mut body = Self {
            inner: Box::pin(inner),
            callback: Box::new(callback),
            callback_done: AtomicBool::new(false),
            expected_size,
            bytes_sent: 0,
        };

        // If the size is known and zero - just execute the callback now,
        // otherwise it won't be called anywhere else
        if expected_size == Some(0) {
            body.do_callback(Ok(()));
        }

        body
    }

    // It seems that in certain cases the users of Body trait can cause us to run callbacks more than once.
    // Use AtomicBool to prevent that and run it at most once.
    pub fn do_callback(&mut self, res: Result<(), String>) {
        // Make locking scope shorter
        {
            let done = self.callback_done.get_mut();
            if *done {
                return;
            }
            *done = true;
        }

        (self.callback)(self.bytes_sent, res);
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
                    // Ignore if it's not a data frame for now.
                    // It can also be trailers that are uncommon
                    if buf.is_data() {
                        self.bytes_sent += buf.data_ref().unwrap().remaining() as u64;

                        // Check if we already got what was expected
                        if Some(self.bytes_sent) >= self.expected_size {
                            self.do_callback(Ok(()));
                        }
                    }
                }

                // Error occured, execute callback
                Err(e) => {
                    // Error is not Copy/Clone so use string instead
                    self.do_callback(Err(e.to_string()));
                }
            },

            // Nothing left, execute callback
            Poll::Ready(None) => {
                self.do_callback(Ok(()));
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
        let data = b"foobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblahfoobarblahblah";
        let mut stream = tokio_util::io::ReaderStream::new(&data[..]);
        let body = axum::body::Body::from_stream(stream);

        let (tx, rx) = std::sync::mpsc::channel();

        let callback = move |response_size: u64, _body_result: Result<(), String>| {
            let _ = tx.send(response_size);
        };

        let body = CountingBody::new(body, callback);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let count = rx.recv().unwrap();
        assert_eq!(count, data.len() as u64);
    }

    #[tokio::test]
    async fn test_body_full() {
        let data = vec![0; 512];

        let buf = bytes::Bytes::from_iter(data.clone());
        let body = http_body_util::Full::new(buf);

        let (tx, rx) = std::sync::mpsc::channel();

        let callback = move |response_size: u64, _body_result: Result<(), String>| {
            let _ = tx.send(response_size);
        };

        let body = CountingBody::new(body, callback);

        // Check that the body streams the same data back
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        assert_eq!(body, data);

        // Check that the counting body got right number
        let count = rx.recv().unwrap();
        assert_eq!(count, data.len() as u64);
    }
}
