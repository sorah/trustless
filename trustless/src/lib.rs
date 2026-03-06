pub mod cmd;
pub mod config;
pub mod provider;
pub mod signer;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Protocol(#[from] trustless_protocol::error::Error),
    #[error("provider already exists: {0}")]
    ProviderAlreadyExists(String),
    #[error("no valid certificates in provider response")]
    NoCertificates,
    #[error("provider not found: {0}")]
    ProviderNotFound(String),
    #[error("provider supervisor gone: {0}")]
    ProviderSupervisorGone(String),
}
