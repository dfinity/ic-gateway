use std::{
    pin::{pin, Pin},
    task::{Context, Poll},
};

use axum::{body::Body, Error};
use bytes::Bytes;
use futures::Stream;
use http_body::Body as _;
use sync_wrapper::SyncWrapper;

/// Wrapper for Axum body that makes it `Sync` to be usable with Request.
/// TODO find a better way?
pub struct SyncBodyDataStream {
    inner: SyncWrapper<Body>,
}

impl SyncBodyDataStream {
    pub const fn new(body: Body) -> Self {
        Self {
            inner: SyncWrapper::new(body),
        }
    }
}

impl Stream for SyncBodyDataStream {
    type Item = Result<Bytes, Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let mut pinned = pin!(self.inner.get_mut());
            match futures_util::ready!(pinned.as_mut().poll_frame(cx)?) {
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                None => return Poll::Ready(None),
            }
        }
    }
}
