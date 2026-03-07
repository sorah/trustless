#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("S3 error: {0}")]
    S3(String),

    #[error("SSM error: {0}")]
    Ssm(String),

    #[error("provider error: {0}")]
    Provider(#[from] trustless_protocol::provider_helpers::ProviderHelperError),
}

impl From<AppError> for trustless_protocol::message::ErrorPayload {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Provider(pe) => pe.into(),
            other => trustless_protocol::message::ErrorPayload {
                code: -1,
                message: other.to_string(),
            },
        }
    }
}
