use std::{error, fmt};

/// The error type.
#[derive(Debug)]
pub enum ErrorKind {
    /// Internal
    Crx,
    /// crate::std::io::Error.
    Io,
    /// crate::pkcs8::error::Error.
    Pkcs8,
}

struct ErrorImpl {
    kind: ErrorKind,
    source: Box<dyn error::Error + Send + Sync>,
}

/// A list specifying general categories of error.
pub struct Error {
    inner: ErrorImpl,
}

impl Error {
    pub fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self {
            inner: ErrorImpl {
                kind,
                source: error.into(),
            },
        }
    }

    #[inline]
    pub(crate) fn from_crx<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Crx, error)
    }

    pub fn from_pkcs8<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Pkcs8, error)
    }

    pub fn from_io<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Io, error)
    }

    fn description(&self) -> &str {
        match &self.inner.kind {
            ErrorKind::Crx => "crx error",
            ErrorKind::Io => "io error",
            ErrorKind::Pkcs8 => "pkcs8 error",
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("crx::Error");
        f.field(&self.inner.kind);
        f.field(&self.inner.source);

        f.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.description(), self.inner.source)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self.inner.source.as_ref() as &(dyn error::Error + 'static))
    }
}
