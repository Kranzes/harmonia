use crate::ByteString;

mod byte_stream;
mod dumper;
mod parser;
pub(crate) mod radix_tree;
mod read_nar;
mod restorer;
pub mod test_data;
mod writer;

pub use byte_stream::NarByteStream;
pub use dumper::{DumpOptions, DumpedFile, NarDumper, dump};
#[cfg(any(test, feature = "test"))]
pub use parser::read_nar;
pub use parser::{NarParser, ParsedFile, parse_nar, parse_nar_stream};
pub use read_nar::{NarBytesReader, NarReader};
pub use restorer::{NarRestorer, NarWriteError, RestoreOptions, restore};
pub use writer::NarWriter;
#[cfg(any(test, feature = "test"))]
pub use writer::write_nar;

pub const CASE_HACK_SUFFIX: &str = "~nix~case~hack~";

/// Whether `name` can name an entry in a directory. Like Nix, this refuses
/// empty names, `.`, `..`, and names with a slash or NUL, so that restoring
/// an entry can't leave its directory.
// Both callers are generic and get compiled in other crates, which can
// only inline this with `#[inline]`.
#[inline]
pub(crate) fn is_valid_entry_name(name: &[u8]) -> bool {
    // Names are short, which leaves `memchr2` little to speed up, so this
    // is a plain loop.
    !matches!(name, b"" | b"." | b"..") && !name.iter().any(|&b| b == b'/' || b == 0)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum NarEvent<R> {
    File {
        name: ByteString,
        executable: bool,
        size: u64,
        reader: R,
    },
    Symlink {
        name: ByteString,
        target: ByteString,
    },
    StartDirectory {
        name: ByteString,
    },
    EndDirectory,
}

impl<R> NarEvent<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    #[cfg(any(test, feature = "test"))]
    pub async fn read_file(self) -> std::io::Result<test_data::TestNarEvent> {
        use tokio::io::AsyncReadExt as _;
        match self {
            NarEvent::StartDirectory { name } => Ok(NarEvent::StartDirectory { name }),
            NarEvent::EndDirectory => Ok(NarEvent::EndDirectory),
            NarEvent::Symlink { name, target } => Ok(NarEvent::Symlink { name, target }),
            NarEvent::File {
                name,
                executable,
                size,
                mut reader,
            } => {
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await?;
                let reader = std::io::Cursor::new(bytes::Bytes::from(buf));
                Ok(NarEvent::File {
                    name,
                    executable,
                    size,
                    reader,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::is_valid_entry_name;

    #[rstest]
    #[case::empty(b"", false)]
    #[case::dot(b".", false)]
    #[case::dot_dot(b"..", false)]
    #[case::slash(b"a/b", false)]
    #[case::trailing_slash(b"a/", false)]
    #[case::nul(b"a\0", false)]
    #[case::plain(b"a", true)]
    #[case::three_dots(b"...", true)]
    #[case::hidden(b".a", true)]
    #[case::dot_dot_prefix(b"..a", true)]
    #[case::not_utf8(b"\xff", true)]
    fn test_is_valid_entry_name(#[case] name: &[u8], #[case] valid: bool) {
        assert_eq!(is_valid_entry_name(name), valid);
    }
}
