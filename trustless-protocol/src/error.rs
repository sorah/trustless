#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("provider error (code={code}): {message}")]
    Provider { code: i64, message: String },

    #[error("unexpected response id: expected {expected}, got {got}")]
    UnexpectedResponseId { expected: u64, got: u64 },

    #[error("provider process exited unexpectedly")]
    ProcessExited,
}
