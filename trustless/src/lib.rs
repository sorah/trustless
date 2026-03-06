pub mod cmd;
pub mod config;
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
}
