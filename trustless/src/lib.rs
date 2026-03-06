pub mod cmd;
pub mod config;
pub mod control;
pub mod provider;
pub mod proxy;
pub mod route;
pub mod signer;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Protocol(#[from] trustless_protocol::error::Error),
    #[error("{0}")]
    Control(String),
    #[error("silently exit")]
    SilentlyExitWithCode(std::process::ExitCode),
    #[error("provider already exists: {0}")]
    ProviderAlreadyExists(String),
    #[error("no valid certificates in provider response")]
    NoCertificates,
    #[error("provider not found: {0}")]
    ProviderNotFound(String),
    #[error("provider supervisor gone: {0}")]
    ProviderSupervisorGone(String),
}
