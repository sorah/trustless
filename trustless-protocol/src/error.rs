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
    #[error("provider error (code={code}): {message}")]
    Provider { code: i64, message: String },

    /// The response ID did not match the request ID.
    #[error("unexpected response id: expected {expected}, got {got}")]
    UnexpectedResponseId { expected: u64, got: u64 },

    /// The provider process exited (stdin/stdout reached EOF).
    #[error("provider process exited unexpectedly")]
    ProcessExited,
}
