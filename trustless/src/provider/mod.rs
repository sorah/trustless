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
    SignFailure,
}

/// The error payload: what went wrong.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message: String,
}

/// A timestamped error report stored in the ring buffer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProviderErrorReport {
    #[serde(
        serialize_with = "serialize_system_time",
        deserialize_with = "deserialize_system_time"
    )]
    pub timestamp: std::time::SystemTime,
    #[serde(flatten)]
    pub error: ProviderError,
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
            Self::SignFailure => write!(f, "sign_failure"),
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    pub certificates: Vec<CertificateStatusInfo>,
    pub errors: Vec<ProviderErrorReport>,
}

/// Format a `SystemTime` as a human-friendly relative time string (e.g. "5s ago", "2m ago").
pub fn format_relative_time(t: std::time::SystemTime) -> String {
    let elapsed = t.elapsed().unwrap_or_default();
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

impl ProviderStatusInfo {
    /// Combined header + errors for use in diagnostic output.
    pub fn format_diagnostics(&self, stderr_lines: usize) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "trustless: note: provider '{}' is {} ({})\n",
            self.name,
            self.state,
            if self.command.is_empty() {
                "unknown command".to_owned()
            } else {
                shell_words::join(&self.command)
            }
        ));
        if let Some(report) = self.errors.last() {
            let ts = format_relative_time(report.timestamp);
            out.push_str(&format!(
                "trustless: note: last error ({}) [{}]: {}\n",
                report.error.kind, ts, report.error.message
            ));
            if let Some(ref lines) = report.stderr_snapshot {
                let total = lines.len();
                let skip = total.saturating_sub(stderr_lines);
                if skip > 0 {
                    out.push_str(&format!("  | ... ({} more lines)\n", skip));
                }
                for line in lines.iter().skip(skip) {
                    out.push_str(&format!("  | {}\n", line));
                }
            }
        }
        out.push_str("trustless: note: run `trustless status` for details\n");
        out
    }
}

// --- ProviderErrorSink ---

/// A handle for pushing errors into a provider's error ring buffer.
/// Intentionally general-purpose — not tied to any specific operation kind.
#[derive(Clone)]
pub struct ProviderErrorSink {
    registry: registry::ProviderRegistry,
    provider_name: String,
}

impl ProviderErrorSink {
    pub fn new(registry: registry::ProviderRegistry, provider_name: String) -> Self {
        Self {
            registry,
            provider_name,
        }
    }

    pub fn push(&self, error: ProviderError) {
        self.registry.push_error(
            &self.provider_name,
            ProviderErrorReport {
                timestamp: std::time::SystemTime::now(),
                error,
                stderr_snapshot: None,
            },
        );
    }
}

// --- ProviderSession ---

/// Represents one lifecycle of a spawned provider process.
pub struct ProviderSession {
    pub client: std::sync::Arc<process::ProviderClient>,
    pub signing_handle: SigningHandle,
    pub stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}
