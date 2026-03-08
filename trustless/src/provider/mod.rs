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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    pub certificates: Vec<CertificateStatusInfo>,
    pub errors: Vec<ProviderError>,
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
    /// Format the provider header line: `"name [command]: state"`
    pub fn format_header(&self) -> String {
        if self.command.is_empty() {
            format!("{}: {}", self.name, self.state)
        } else {
            format!(
                "{} [{}]: {}",
                self.name,
                shell_words::join(&self.command),
                self.state
            )
        }
    }

    /// Format error lines with timestamps and optional stderr tail.
    /// `stderr_lines` controls how many stderr lines to show per error (0 = none).
    pub fn format_errors(&self, stderr_lines: usize) -> String {
        let mut out = String::new();
        for error in &self.errors {
            let ts = format_relative_time(error.timestamp);
            out.push_str(&format!(
                "    error ({}) [{}]: {}\n",
                error.kind, ts, error.message
            ));
            if stderr_lines > 0
                && let Some(ref lines) = error.stderr_snapshot
            {
                let total = lines.len();
                let skip = total.saturating_sub(stderr_lines);
                if skip > 0 {
                    out.push_str(&format!("      | ... ({} more lines)\n", skip));
                }
                for line in lines.iter().skip(skip) {
                    out.push_str(&format!("      | {}\n", line));
                }
            }
        }
        out
    }

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
        if let Some(error) = self.errors.last() {
            let ts = format_relative_time(error.timestamp);
            out.push_str(&format!(
                "trustless: note: last error ({}) [{}]: {}\n",
                error.kind, ts, error.message
            ));
            if let Some(ref lines) = error.stderr_snapshot {
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

// --- ProviderSession ---

/// Represents one lifecycle of a spawned provider process.
pub struct ProviderSession {
    pub client: std::sync::Arc<process::ProviderClient>,
    pub signing_handle: SigningHandle,
    pub stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}
