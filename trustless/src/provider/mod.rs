pub mod orchestrator;
pub mod registry;
mod supervisor;

pub use orchestrator::ProviderOrchestrator;
pub use registry::ProviderRegistry;

use crate::signer::SigningHandle;

// --- Error tracking ---

#[derive(Clone, Debug)]
pub enum ProviderErrorKind {
    Crash,
    InitFailure,
    ProtocolError,
}

#[derive(Clone, Debug)]
pub struct ProviderError {
    pub timestamp: std::time::SystemTime,
    pub kind: ProviderErrorKind,
    pub message: String,
    pub stderr_snapshot: Option<Vec<String>>,
}

// --- Provider state ---

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderState {
    Running,
    Restarting,
    Failed,
}

// --- ProviderSession ---

/// Represents one lifecycle of a spawned provider process.
pub struct ProviderSession {
    pub client: std::sync::Arc<trustless_protocol::client::ProviderClient>,
    pub signing_handle: SigningHandle,
    pub stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}
