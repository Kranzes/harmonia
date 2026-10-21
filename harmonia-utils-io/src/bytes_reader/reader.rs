#![allow(unsafe_code)]

use std::future::poll_fn;
use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Poll, ready};

use bytes::{Buf, BufMut as _, Bytes};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};

use super::buffer::BufferMut;
use crate::AsyncBytesRead;

pub const DEFAULT_RESERVED_BUF_SIZE: usize = 8192;
pub const DEFAULT_MAX_BUF_SIZE: usize = 1024 * 1024 * 8;

pub struct BytesReaderBuilder {
    reserved_buf_size: usize,
    max_buf_size: usize,
}

impl Default for BytesReaderBuilder {
    fn default() -> Self {
        Self {
            reserved_buf_size: DEFAULT_RESERVED_BUF_SIZE,
            max_buf_size: DEFAULT_MAX_BUF_SIZE,
        }
    }
}

impl BytesReaderBuilder {
    pub fn set_reserved_buf_size(mut self, size: usize) -> Self {
        self.reserved_buf_size = size;
        self
    }

    pub fn set_max_buf_size(mut self, size: usize) -> Self {
        self.max_buf_size = size;
        self
    }

    pub fn build<R>(self, reader: R) -> BytesReader<R> {
        let size = self.reserved_buf_size.saturating_mul(2);
        let buf = BufferMut::with_capacity(size.min(self.max_buf_size));
        BytesReader {
            inner: reader,
            reserved_buf_size: self.reserved_buf_size,
            max_buf_size: self.max_buf_size,
            buf,
            view: None,
        }
    }
}

pin_project! {
    #[derive(Debug)]
    pub struct BytesReader<R> {
        #[pin]
        inner: R,
        buf: BufferMut,
        // A `Bytes` over the filled part of `buf`. `poll_fill_buf` hands out
        // clones of it instead of building a new `Bytes` on every call. When
        // set, it covers exactly the bytes in `buf`. Clear it before reading
        // into `buf`, which makes it stale, and before growing `buf`, which
        // can't reuse its allocation while this is alive.
        view: Option<Bytes>,
        reserved_buf_size: usize,
        max_buf_size: usize,
    }
}

impl BytesReader<Cursor<Vec<u8>>> {
    pub fn builder() -> BytesReaderBuilder {
        BytesReaderBuilder::default()
    }
}

impl<R> BytesReader<R>
where
    R: AsyncRead,
{
    pub fn new(reader: R) -> BytesReader<R> {
        BytesReader::builder().build(reader)
    }

    fn poll_force_fill_buf_internal(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<usize>> {
        let me = self.project();
        *me.view = None;
        // Make room for `reserved_buf_size` bytes, or for as many as
        // `max_buf_size` still allows. Fail only if that is none.
        if me.buf.remaining_mut() < *me.reserved_buf_size {
            me.buf.reserve(*me.reserved_buf_size, *me.max_buf_size);
            if me.buf.remaining_mut() == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("buffer is full at {} bytes", me.buf.len()),
                )));
            }
        }
        let n = {
            let dst = me.buf.spare_capacity_mut();
            let mut buf = ReadBuf::uninit(dst);
            let ptr = buf.filled().as_ptr();
            ready!(me.inner.poll_read(cx, &mut buf)?);

            // Ensure the pointer does not change from under us
            assert_eq!(ptr, buf.filled().as_ptr());
            buf.filled().len()
        };

        // SAFETY: This is guaranteed to be the number of initialized (and read)
        // bytes due to the invariants provided by `ReadBuf::filled`.
        unsafe {
            me.buf.advance_mut(n);
        }
        Poll::Ready(Ok(n))
    }
}

impl<R> BytesReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn force_fill(&mut self) -> io::Result<bytes::Bytes> {
        let mut p = Pin::new(self);
        let read = poll_fn(|cx| p.as_mut().poll_force_fill_buf(cx)).await?;
        Ok(read)
    }
}

impl<R> BytesReader<R> {
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
        self.project().inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    pub fn buffer_capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn filled(&self) -> Bytes {
        self.buf.filled()
    }

    fn view(self: Pin<&mut Self>) -> Bytes {
        let me = self.project();
        me.view.get_or_insert_with(|| me.buf.filled()).clone()
    }

    /// Remaining capacity in internal buffer
    pub fn remaining_mut(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }
}

impl<R> AsyncBytesRead for BytesReader<R>
where
    R: AsyncRead,
{
    fn poll_force_fill_buf(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<bytes::Bytes>> {
        let read = ready!(self.as_mut().poll_force_fill_buf_internal(cx))?;
        if read == 0 {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while force reading",
            )))
        } else {
            Poll::Ready(Ok(self.view()))
        }
    }

    fn poll_fill_buf(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<bytes::Bytes>> {
        if self.buf.is_empty() {
            ready!(self.as_mut().poll_force_fill_buf_internal(cx))?;
        }
        Poll::Ready(Ok(self.view()))
    }

    fn prepare(self: std::pin::Pin<&mut Self>, additional: usize) {
        let me = self.project();
        let len = me.buf.len();
        // Also reserve the spare room `poll_force_fill_buf` requires before
        // each read, so reading the rest of the string doesn't grow the
        // buffer again.
        let reserved = *me.reserved_buf_size;
        // `additional` comes from a length on the wire, so a total that
        // doesn't fit in `usize` is over `max_buf_size` as well.
        let fits = additional
            .checked_add(reserved)
            .is_some_and(|total| total <= *me.max_buf_size);
        if additional > len && fits {
            let wanted = additional - len + reserved;
            if me.buf.capacity() - len < wanted {
                *me.view = None;
                me.buf.reserve(wanted, *me.max_buf_size);
            }
        }
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        let me = self.project();
        me.buf.advance(amt);
        if let Some(view) = me.view {
            view.advance(amt);
        }
    }
}

impl<R> AsyncRead for BytesReader<R>
where
    R: AsyncRead,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let rem = ready!(self.as_mut().poll_fill_buf(cx))?;
        if !rem.is_empty() {
            let amt = std::cmp::min(rem.len(), buf.remaining());
            buf.put_slice(&rem[0..amt]);
            self.consume(amt);
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod unittests {
    use std::future::poll_fn;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use hex_literal::hex;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};
    use tokio_test::io::Builder;

    use crate::{AsyncBytesRead as _, BytesReader, TryReadBytesLimited, TryReadU64};

    /// The cached view of the filled bytes must not stop the buffer from
    /// reusing its allocation once everything in it is consumed.
    #[tokio::test]
    async fn test_reuses_buffer_after_consume() {
        let mock = Builder::new()
            .read(b"abcdefgh")
            .read(b"ijklmnop")
            .read(b"qrstuvwx")
            .build();
        // The buffer starts with room for exactly the first two reads.
        let mut reader = BytesReader::builder().set_reserved_buf_size(8).build(mock);

        let start = reader.force_fill().await.unwrap().as_ptr();
        Pin::new(&mut reader).consume(8);
        reader.force_fill().await.unwrap();
        Pin::new(&mut reader).consume(8);
        assert_eq!(reader.force_fill().await.unwrap().as_ptr(), start);
    }

    /// Returns at most `chunk` bytes per read.
    struct Chunked {
        data: Bytes,
        chunk: usize,
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = self.chunk.min(self.data.len()).min(buf.remaining());
            buf.put_slice(&self.data.split_to(n));
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Fill,
        ForceFill,
        Consume(Index),
        Prepare(usize),
        Release,
    }

    /// In any order of calls, every `Bytes` the reader hands out is its
    /// current buffer and keeps its contents. The buffer holds the next
    /// unconsumed part of the stream and never grows past `max_buf_size`.
    #[test]
    fn proptest_buffer_matches_stream() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        proptest!(|(
            data in prop::collection::vec(any::<u8>(), 0..512),
            chunk in 1..64usize,
            max in 1..1024usize,
            ops in prop::collection::vec(prop_oneof![
                Just(Op::Fill),
                Just(Op::ForceFill),
                any::<Index>().prop_map(Op::Consume),
                (0..256usize).prop_map(Op::Prepare),
                Just(Op::Release),
            ], 0..64),
        )| {
            rt.block_on(async {
                let source = Chunked { data: Bytes::from(data.clone()), chunk };
                let mut reader = BytesReader::builder()
                    .set_reserved_buf_size(16)
                    .set_max_buf_size(max)
                    .build(source);
                let mut pos = 0;
                // The last `Bytes` handed out, which shares the buffer until
                // released, and where it starts in the stream.
                let mut held = None;
                for op in ops {
                    match op {
                        Op::Fill => {
                            let buf = poll_fn(|cx| Pin::new(&mut reader).poll_fill_buf(cx)).await?;
                            prop_assert!(std::ptr::eq(&buf[..], reader.buffer()));
                            prop_assert!(!buf.is_empty() || pos == data.len());
                            held = Some((pos, buf));
                        }
                        Op::ForceFill => {
                            let before = reader.buffer().len();
                            match reader.force_fill().await {
                                Ok(buf) => {
                                    prop_assert!(std::ptr::eq(&buf[..], reader.buffer()));
                                    prop_assert!(buf.len() > before);
                                    held = Some((pos, buf));
                                }
                                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                                    prop_assert_eq!(before, max);
                                }
                                Err(err) => {
                                    prop_assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
                                    prop_assert_eq!(pos + before, data.len());
                                }
                            }
                        }
                        Op::Consume(amt) => {
                            let amt = amt.index(reader.buffer().len() + 1);
                            Pin::new(&mut reader).consume(amt);
                            pos += amt;
                        }
                        Op::Prepare(additional) => Pin::new(&mut reader).prepare(additional),
                        Op::Release => held = None,
                    }
                    let buffered = reader.buffer();
                    prop_assert_eq!(buffered, &data[pos..pos + buffered.len()]);
                    prop_assert!(reader.buffer_capacity() <= max);
                    if let Some((start, buf)) = &held {
                        prop_assert_eq!(&buf[..], &data[*start..*start + buf.len()]);
                    }
                }
                Ok::<_, TestCaseError>(())
            })?;
        });
    }

    #[tokio::test]
    async fn test_read_u64_partial() {
        let mock = Builder::new()
            .read(&hex!("0100 0000"))
            .read(&hex!("0000 0000 0123 4567 89AB CDEF"))
            .read(&hex!("0100 0000"))
            .build();
        let mut reader = BytesReader::new(mock);

        assert_eq!(
            1,
            TryReadU64::new().read(&mut reader).await.unwrap().unwrap()
        );
        assert_eq!(hex!("0123 4567 89AB CDEF"), reader.buffer());

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(hex!("0123 4567 89AB CDEF 0100 0000"), &buf[..]);
    }

    #[tokio::test]
    async fn test_read_twice() {
        let mock = Builder::new()
            .read(&hex!("0100 0000"))
            .read(&hex!("0000 0000 0123 4567 89AB CDEF"))
            .read(&hex!("0100 0000"))
            .build();
        let mut reader = BytesReader::new(mock);

        let mut buf = [0u8; 8];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(4, n);
        let n1 = reader.read(&mut buf[n..]).await.unwrap();
        assert_eq!(4, n1);
        assert_eq!(hex!("0100 0000 0000 0000"), buf);

        let mut buf = [0u8; 12];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(8, n);
        let n1 = reader.read(&mut buf[n..]).await.unwrap();
        assert_eq!(4, n1);
        assert_eq!(hex!("0123 4567 89AB CDEF 0100 0000"), buf);
        assert_eq!(0, reader.read(&mut buf[..]).await.unwrap());
    }

    /// After `prepare(n)`, reading until the buffer holds `n` bytes must not
    /// grow it again. `n` counts the bytes already buffered.
    #[tokio::test]
    async fn test_prepare_reserves_whole_string() {
        let mut mock = Builder::new();
        mock.read(&[1; 12]);
        for _ in 0..7 {
            mock.read(&[2; 4]);
        }
        let mut reader = BytesReader::builder()
            .set_reserved_buf_size(8)
            .build(mock.build());
        assert_eq!(reader.force_fill().await.unwrap().len(), 12);

        Pin::new(&mut reader).prepare(40);
        let start = reader.buffer().as_ptr();
        while reader.buffer().len() < 40 {
            reader.force_fill().await.unwrap();
        }
        assert_eq!(reader.buffer().as_ptr(), start);
    }

    /// A length near `usize::MAX` from the wire must not overflow `prepare`'s
    /// size check. It is over `max_buf_size`, so nothing gets reserved.
    #[tokio::test]
    async fn test_prepare_huge_length() {
        let mut mock = Builder::new();
        mock.read(&[1; 12]);
        let mut reader = BytesReader::new(mock.build());
        assert_eq!(reader.force_fill().await.unwrap().len(), 12);

        let capacity = reader.buf.capacity();
        for additional in [usize::MAX, usize::MAX - 4] {
            Pin::new(&mut reader).prepare(additional);
            assert_eq!(reader.buf.capacity(), capacity);
        }
    }

    /// `prepare` reserves room for any string that fits in `max_buf_size`
    /// with `reserved_buf_size` to spare, whatever the buffer's capacity.
    #[tokio::test]
    async fn test_prepare_up_to_max_buf_size() {
        let mut mock = Builder::new();
        mock.read(&[1; 12]);
        for _ in 0..3 {
            mock.read(&[2; 4]);
        }
        let mut reader = BytesReader::builder()
            .set_reserved_buf_size(8)
            .set_max_buf_size(32)
            .build(mock.build());
        assert_eq!(reader.force_fill().await.unwrap().len(), 12);

        Pin::new(&mut reader).prepare(24);
        let start = reader.buffer().as_ptr();
        while reader.buffer().len() < 24 {
            reader.force_fill().await.unwrap();
        }
        assert_eq!(reader.buffer().as_ptr(), start);
    }

    /// Holding each force fill's result while reading more, as the NAR
    /// parser does, shares the buffer. Growing it must still double it
    /// rather than copy everything on every read.
    #[tokio::test]
    async fn test_shared_buffer_grows_geometrically() {
        let data = Bytes::from(vec![7; 1 << 20]);
        let source = Chunked {
            data: data.clone(),
            chunk: 1024,
        };
        let mut reader = BytesReader::builder()
            .set_reserved_buf_size(1024)
            .set_max_buf_size(4 << 20)
            .build(source);

        let mut buf = reader.force_fill().await.unwrap();
        let mut copies = 0;
        while buf.len() < data.len() {
            let before = buf.as_ptr();
            buf = reader.force_fill().await.unwrap();
            copies += usize::from(buf.as_ptr() != before);
        }
        assert_eq!(buf, data);
        assert!(copies <= 12, "copied the buffer {copies} times");
    }

    /// The buffer grows to `max_buf_size` and no further, even when doubling
    /// would go past it.
    #[tokio::test]
    async fn test_force_fill_up_to_max_buf_size() {
        let data = Bytes::from(vec![7; 48 * 1024]);
        let source = Chunked {
            data: data.clone(),
            chunk: 4096,
        };
        let mut reader = BytesReader::builder()
            .set_max_buf_size(data.len())
            .build(source);

        while reader.buffer().len() < data.len() {
            reader.force_fill().await.unwrap();
        }
        assert_eq!(reader.buffer(), &data[..]);
        assert_eq!(reader.buffer_capacity(), data.len());
        let err = reader.force_fill().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_force_fill() {
        let mock = Builder::new()
            .read(&hex!("0100"))
            .read(&hex!("0000 0000 0000"))
            .build();
        let mut reader = BytesReader::new(mock);

        //assert!(reader.filled().is_unique());
        let buf = reader.force_fill().await.unwrap();
        assert_eq!(2, buf.len());
        drop(buf);

        assert_eq!(8, reader.force_fill().await.unwrap().len());
    }

    #[tokio::test]
    async fn test_try_read_bytes_missing_padding() {
        let mock = Builder::new()
            .read(&hex!("0200 0000 0000 0000"))
            .read(&hex!("1234"))
            .build();
        let mut reader = BytesReader::new(mock);

        let ret = TryReadBytesLimited::new(0..=usize::MAX)
            .read(&mut reader)
            .await;

        assert_eq!(std::io::ErrorKind::UnexpectedEof, ret.unwrap_err().kind());
    }

    /// A string that fits in `max_buf_size` can be read, even when there is
    /// no room left for a full `reserved_buf_size` after it.
    #[tokio::test]
    async fn test_try_read_bytes_up_to_max_buf_size() {
        let len = 60 * 1024;
        let mut data = (len as u64).to_le_bytes().to_vec();
        data.resize(8 + len, 7);
        let source = Chunked {
            data: data.into(),
            chunk: 4096,
        };
        let mut reader = BytesReader::builder()
            .set_max_buf_size(64 * 1024)
            .build(source);

        let read = TryReadBytesLimited::new(0..=len)
            .read(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, vec![7; len]);
    }

    /// `TryReadBytesLimited` must release the reader's buffer before reading
    /// the rest of a string, so the reader can move the part already read to
    /// the front of its buffer instead of copying it to a new one.
    #[tokio::test]
    async fn test_try_read_bytes_reuses_buffer() {
        let mock = Builder::new()
            .read(&hex!("0C00 0000 0000 0000 0102 0304"))
            .read(&hex!("0506 0708 090A 0B0C 0000 0000"))
            .build();
        // The 16-byte padded string fits in the 16-byte buffer, but
        // `max_buf_size` leaves no room to also reserve 8 bytes after it, so
        // `prepare` reserves nothing and reading the rest has to make room.
        let mut reader = BytesReader::builder()
            .set_reserved_buf_size(8)
            .set_max_buf_size(20)
            .build(mock);
        let start = reader.buffer().as_ptr();

        let read = TryReadBytesLimited::new(0..=20)
            .read(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, hex!("0102 0304 0506 0708 090A 0B0C")[..]);
        assert_eq!(read.as_ptr(), start);
    }
}
