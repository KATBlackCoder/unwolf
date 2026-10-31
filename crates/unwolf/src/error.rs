use std::path::{Path, PathBuf};

/// Errors returned by the library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The archive structure is inconsistent. With a plaintext DXA v8 header
    /// this is also how a wrong key shows up.
    #[error("invalid archive data: {0}")]
    Format(String),

    #[error("not a DX archive")]
    NotDxArchive,

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("no decryption mode matches {0}")]
    NoMatchingMode(PathBuf),

    #[error("configuration file {path}: {message}")]
    Config { path: PathBuf, message: String },

    #[error("unsafe path in archive: {0:?}")]
    UnsafePath(String),

    #[error("{0}")]
    Game(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn format(msg: impl Into<String>) -> Self {
        Self::Format(msg.into())
    }

    pub(crate) fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

/// Attach a path to I/O errors.
pub(crate) trait IoContext<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn at(self, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|e| Error::io(path, e))
    }
}
