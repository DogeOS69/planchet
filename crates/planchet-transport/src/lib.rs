//! Host transport seam. The optional HTTP implementation has no TLS/native dependencies.
#![forbid(unsafe_code)]
use std::{fmt, future::Future, pin::Pin, sync::Arc};

/// Bodies and credentials deliberately do not appear in Debug output.
pub struct Request {
    pub body: Vec<u8>,
    pub max_response_bytes: usize,
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("body_bytes", &self.body.len())
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidConfiguration(&'static str),
    UnsupportedScheme,
    Timeout,
    Io,
    ResponseTooLarge { limit: usize },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => {
                write!(f, "invalid transport configuration: {reason}")
            }
            Self::UnsupportedScheme => {
                f.write_str("only explicit http:// endpoints are supported; TLS is not available")
            }
            Self::Timeout => f.write_str("RPC transport deadline exceeded"),
            Self::Io => f.write_str("RPC transport I/O failed"),
            Self::ResponseTooLarge { limit } => write!(f, "RPC response exceeds {limit} bytes"),
        }
    }
}
impl std::error::Error for Error {}
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'a>>;
/// Implementations must enforce the byte budget and must not automatically replay requests.
/// Dropping the returned future cancels observation; it cannot undo a submitted transaction.
pub trait Transport: Send + Sync {
    fn send(&self, request: Request) -> TransportFuture<'_>;
}
impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn send(&self, request: Request) -> TransportFuture<'_> {
        (**self).send(request)
    }
}
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "http")]
pub use http::{BasicAuth, HttpConfig, HttpTransport};
