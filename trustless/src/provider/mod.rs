pub mod orchestrator;
pub mod process;
pub mod registry;
mod supervisor;

pub use orchestrator::ProviderOrchestrator;
pub use registry::ProviderRegistry;

use crate::signer::SigningHandle;

// --- Error tracking ---

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Crash,
    InitFailure,
    ProtocolError,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProviderError {
    #[serde(
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub timestamp: std::time::SystemTime,
    pub kind: ProviderErrorKind,
    pub message: String,
    pub stderr_snapshot: Option<Vec<String>>,
}

fn serialize_system_time<S: serde::Serializer>(
    t: &std::time::SystemTime,
    s: S,
) -> Result<S::Ok, S::Error> {
    let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    s.serialize_u64(duration.as_secs())
}

fn deserialize_system_time<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<std::time::SystemTime, D::Error> {
    let secs: u64 = serde::Deserialize::deserialize(d)?;
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

// --- Provider state ---

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Running,
    Restarting,
    Failed,
}

impl std::fmt::Display for ProviderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Restarting => write!(f, "restarting"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl std::fmt::Display for ProviderErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crash => write!(f, "crash"),
            Self::InitFailure => write!(f, "init_failure"),
            Self::ProtocolError => write!(f, "protocol_error"),
        }
    }
}

// --- Status info ---

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CertificateStatusInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub serial: String,
    pub not_after: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProviderStatusInfo {
    pub name: String,
    pub state: ProviderState,
    pub certificates: Vec<CertificateStatusInfo>,
    pub errors: Vec<ProviderError>,
}

// --- ProviderSession ---

/// Represents one lifecycle of a spawned provider process.
pub struct ProviderSession {
    pub client: std::sync::Arc<process::ProviderClient>,
    pub signing_handle: SigningHandle,
    pub stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}
