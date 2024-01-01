//! Error types.

use core::fmt;
use pkcs8::der::asn1::ObjectIdentifier;

/// Alias for [`core::result::Result`] with the `crx` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Invalid CRX size error.
    InvalidSize,

    /// Invalid CRX magic number error.
    InvalidMagicNumber,

    /// Unsupported CRX version.
    UnsupportedVersion,

    /// Invalid CRX file header size error.
    InvalidFileHeaderSize,

    /// Protobuf decode error.
    ProtobufDecodeError(prost::DecodeError),

    /// Invalid CRX ID size error.
    InvalidIdSize,

    /// Missing asymmetric proofs error.
    MissingAsymmetricProofs,

    /// Empty asymmetric keys error.
    EmptyAsymmetricKeys,

    /// I/O errors.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),

    /// PKCS#8 errors.
    Pkcs8(pkcs8::Error),

    /// X.509 SubjectPublicKeyInfo (SPKI) errors.
    Spki(pkcs8::spki::Error),

    /// RSA errors.
    Rsa(rsa::Error),

    /// Digital signature errors.
    Signature(signature::Error),

    /// Unknown algorithm OID.
    OidUnknown {
        /// Unrecognized OID value found.
        oid: ObjectIdentifier,
    },
}

impl From<prost::DecodeError> for Error {
    fn from(err: prost::DecodeError) -> Self {
        Self::ProtobufDecodeError(err)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind())
    }
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        Self::Pkcs8(err)
    }
}

impl From<pkcs8::spki::Error> for Error {
    fn from(err: pkcs8::spki::Error) -> Self {
        Self::Spki(err)
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Self::Rsa(err)
    }
}

impl From<signature::Error> for Error {
    fn from(err: signature::Error) -> Self {
        Self::Signature(err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidSize => f.write_str("invalid CRX size"),
            Error::InvalidFileHeaderSize => f.write_str("invalid CRX file header size"),
            Error::InvalidMagicNumber => f.write_str("invalid CRX magic number"),
            Error::UnsupportedVersion => f.write_str("unsupported CRX version"),
            Error::ProtobufDecodeError(err) => write!(f, "Protocol buffer decode error: {}", err),
            Error::InvalidIdSize => f.write_str("invalid CRX ID size"),
            Error::MissingAsymmetricProofs => f.write_str("missing asymmetric proofs"),
            Error::EmptyAsymmetricKeys => f.write_str("empty asymmetric keys"),
            #[cfg(feature = "std")]
            Error::Io(err) => write!(f, "{}", err),
            Error::Pkcs8(err) => write!(f, "{}", err),
            Error::Spki(err) => write!(f, "{}", err),
            Error::Rsa(err) => write!(f, "{}", err),
            Error::Signature(err) => write!(f, "{}", err),
            Error::OidUnknown { oid } => {
                write!(f, "unknown/unsupported algorithm OID: {}", oid)
            }
        }
    }
}
