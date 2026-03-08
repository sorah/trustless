/// Error types for protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error occurred on the underlying stream.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The provider returned an error response.
    #[error(transparent)]
    Provider(#[from] crate::message::ErrorCode),

    /// The response ID did not match the request ID.
    #[error("unexpected response id: expected {expected}, got {got}")]
    UnexpectedResponseId { expected: u64, got: u64 },

    /// The response method did not match what was expected.
    #[error("unexpected response method")]
    UnexpectedResponseMethod,

    /// The provider process exited (stdin/stdout reached EOF).
    #[error("provider process exited unexpectedly")]
    ProcessExited,
}

impl From<crate::message::ErrorPayload> for Error {
    fn from(p: crate::message::ErrorPayload) -> Self {
        Error::Provider(crate::message::ErrorCode::from(p))
    }
}
