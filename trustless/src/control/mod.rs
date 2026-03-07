pub mod client;
pub mod server;
pub mod state;

pub use client::Client;
pub use state::ProxyState;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReloadProviderResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReloadResponse {
    pub ok: bool,
    pub results: std::collections::HashMap<String, ReloadProviderResult>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatusResponse {
    pub pid: u32,
    pub port: u16,
    pub providers: Vec<crate::provider::ProviderStatusInfo>,
    pub routes: std::collections::HashMap<String, String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
