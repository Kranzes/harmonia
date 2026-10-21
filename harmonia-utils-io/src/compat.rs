use std::task::{Poll, ready};

use bytes::{Buf as _, Bytes};
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead};

use super::{AsyncBytesRead, DrainInto};

pin_project! {
    #[derive(Debug)]
    pub struct AsyncBufReadCompat<R> {
        #[pin]
        reader: R,
        buffer: Bytes,
    }
}

impl<R> AsyncBufReadCompat<R>
where
    R: AsyncBytesRead,
{
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Bytes::new(),
        }
    }
}

impl<R> AsyncRead for AsyncBufReadCompat<R>
where
    R: AsyncBytesRead,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let rem = ready!(AsyncBufRead::poll_fill_buf(self.as_mut(), cx))?;
        if !rem.is_empty() {
            let amt = std::cmp::min(rem.len(), buf.remaining());
            buf.put_slice(&rem[0..amt]);
            AsyncBufRead::consume(self, amt);
        }
        Poll::Ready(Ok(()))
    }
}

impl<R> AsyncBufRead for AsyncBufReadCompat<R>
where
    R: AsyncBytesRead,
{
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let this = self.project();
        if this.buffer.is_empty() {
            *this.buffer = ready!(this.reader.poll_fill_buf(cx))?;
        }
        Poll::Ready(Ok(&this.buffer[..]))
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        let this = self.project();
        // After a fill through `AsyncBytesRead`, the caller holds the bytes
        // and `buffer` is empty.
        if !this.buffer.is_empty() {
            this.buffer.advance(amt);
            if this.buffer.is_empty() {
                // Release the buffer when empty so that the reader can reclaim it
                // on the next call to poll_fill_buf
                *this.buffer = Bytes::new();
            }
        }
        this.reader.consume(amt);
    }
}

/// Hands out the inner reader's bytes as they are, so a reader can use
/// either interface, or switch between them.
impl<R> AsyncBytesRead for AsyncBufReadCompat<R>
where
    R: AsyncBytesRead,
{
    fn poll_force_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<Bytes>> {
        let this = self.project();
        *this.buffer = Bytes::new();
        this.reader.poll_force_fill_buf(cx)
    }

    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<Bytes>> {
        let this = self.project();
        if this.buffer.is_empty() {
            this.reader.poll_fill_buf(cx)
        } else {
            Poll::Ready(Ok(this.buffer.clone()))
        }
    }

    fn prepare(self: std::pin::Pin<&mut Self>, additional: usize) {
        self.project().reader.prepare(additional);
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        AsyncBufRead::consume(self, amt);
    }
}

impl<R, R2> DrainInto<R2> for AsyncBufReadCompat<R>
where
    R: DrainInto<R2>,
{
    fn poll_drain(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        *this.buffer = Bytes::new();
        this.reader.poll_drain(cx)
    }

    fn into_inner(self) -> R2 {
        self.reader.into_inner()
    }
}

#[cfg(test)]
mod unittests {
    use std::future::poll_fn;
    use std::pin::Pin;

    use bytes::Bytes;
    use futures_util::stream;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    use super::AsyncBufReadCompat;
    use crate::{AsyncBytesRead, BytesStreamReader};

    async fn fill<R: AsyncBytesRead + Unpin>(reader: &mut R) -> std::io::Result<Bytes> {
        poll_fn(|cx| Pin::new(&mut *reader).poll_fill_buf(cx)).await
    }

    /// Reads can switch between the two interfaces, and the `Bytes` one
    /// hands out the inner reader's buffer instead of a copy.
    #[tokio::test]
    async fn bytes_read_shares_the_buffer() {
        let chunks = [Bytes::from_static(b"hello "), Bytes::from_static(b"world")];
        let source = stream::iter(chunks.clone().map(Ok));
        let mut reader = AsyncBufReadCompat::new(BytesStreamReader::new(source));

        assert_eq!(reader.fill_buf().await.unwrap(), b"hello ");
        reader.consume(2);
        let rest = fill(&mut reader).await.unwrap();
        assert_eq!(rest, &b"llo "[..]);
        assert_eq!(rest.as_ptr(), chunks[0][2..].as_ptr());

        AsyncBytesRead::consume(Pin::new(&mut reader), rest.len());
        let next = fill(&mut reader).await.unwrap();
        assert_eq!(next.as_ptr(), chunks[1].as_ptr());
        let mut tail = String::new();
        reader.read_to_string(&mut tail).await.unwrap();
        assert_eq!(tail, "world");
    }
}
