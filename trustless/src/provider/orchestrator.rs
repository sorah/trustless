use super::registry::ProviderRegistry;
use super::supervisor::Supervisor;
use crate::signer::SigningHandle;

#[derive(Clone)]
pub struct ProviderOrchestrator {
    inner: std::sync::Arc<OrchestratorInner>,
}

struct OrchestratorInner {
    registry: ProviderRegistry,
    supervisors: std::sync::Mutex<std::collections::HashMap<String, SupervisorHandle>>,
    cancel: tokio_util::sync::CancellationToken,
}

impl ProviderOrchestrator {
    pub fn new(registry: ProviderRegistry) -> Self {
        Self {
            inner: std::sync::Arc::new(OrchestratorInner {
                registry,
                supervisors: std::sync::Mutex::new(std::collections::HashMap::new()),
                cancel: tokio_util::sync::CancellationToken::new(),
            }),
        }
    }

    /// Spawn a provider, initialize it, and register it. Returns only after the first
    /// successful initialization. On failure, returns Err — no automatic retry.
    pub async fn add_provider(
        &self,
        name: &str,
        profile: crate::config::Profile,
    ) -> Result<(), crate::Error> {
        {
            let supervisors = self.inner.supervisors.lock().unwrap();
            if supervisors.contains_key(name) {
                return Err(crate::Error::ProviderAlreadyExists(name.to_owned()));
            }
        }

        let result = spawn_init_register(name, &profile, &self.inner.registry).await?;

        let cancel = self.inner.cancel.child_token();
        let (command_tx, command_rx) = tokio::sync::mpsc::channel::<SupervisorCommand>(4);

        let supervisor = Supervisor {
            name: name.to_owned(),
            profile,
            registry: self.inner.registry.clone(),
            cancel,
            command_rx,
            child: result.child,
            stderr_task: result.stderr_task,
            stderr_lines: result.stderr_lines,
            backoff: super::supervisor::BACKOFF_INITIAL,
            healthy_since: Some(std::time::Instant::now()),
        };

        let task = tokio::spawn(supervisor.run());

        let mut supervisors = self.inner.supervisors.lock().unwrap();
        supervisors.insert(name.to_owned(), SupervisorHandle { command_tx, task });

        Ok(())
    }

    /// Kill the current provider process and restart it, bypassing backoff.
    pub async fn restart_provider(&self, name: &str) -> Result<(), crate::Error> {
        let command_tx = {
            let supervisors = self.inner.supervisors.lock().unwrap();
            let handle = supervisors
                .get(name)
                .ok_or_else(|| crate::Error::ProviderNotFound(name.to_owned()))?;
            handle.command_tx.clone()
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        command_tx
            .send(SupervisorCommand::Restart { reply: reply_tx })
            .await
            .map_err(|_| crate::Error::ProviderSupervisorGone(name.to_owned()))?;

        reply_rx
            .await
            .map_err(|_| crate::Error::ProviderSupervisorGone(name.to_owned()))?
    }

    /// Restart all providers. Returns per-provider results.
    pub async fn restart_all(&self) -> Vec<(String, Result<(), crate::Error>)> {
        let names = {
            let supervisors = self.inner.supervisors.lock().unwrap();
            supervisors.keys().cloned().collect::<Vec<_>>()
        };

        let mut results = Vec::new();
        for name in names {
            let result = self.restart_provider(&name).await;
            results.push((name, result));
        }
        results
    }

    /// Shutdown all providers. Sends SIGTERM, waits up to 20s, then SIGKILL.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();

        let tasks: Vec<_> = {
            let mut supervisors = self.inner.supervisors.lock().unwrap();
            supervisors.drain().map(|(_, h)| h.task).collect()
        };

        for task in tasks {
            let _ = task.await;
        }
    }
}

struct SupervisorHandle {
    command_tx: tokio::sync::mpsc::Sender<SupervisorCommand>,
    task: tokio::task::JoinHandle<()>,
}

pub(super) enum SupervisorCommand {
    Restart {
        reply: tokio::sync::oneshot::Sender<Result<(), crate::Error>>,
    },
}

pub(super) struct SpawnResult {
    pub(super) child: tokio::process::Child,
    #[allow(dead_code)]
    pub(super) client: std::sync::Arc<trustless_protocol::client::ProviderClient>,
    #[allow(dead_code)]
    pub(super) signing_handle: SigningHandle,
    pub(super) stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    pub(super) stderr_task: tokio::task::JoinHandle<()>,
}

const STDERR_RING_CAPACITY: usize = 100;
const MAX_STDERR_LINE_LENGTH: usize = 8192;

/// Spawn a provider process, start stderr reader, initialize, and register in the registry.
pub(super) async fn spawn_init_register(
    name: &str,
    profile: &crate::config::Profile,
    registry: &ProviderRegistry,
) -> Result<SpawnResult, crate::Error> {
    let process = trustless_protocol::process::ProviderProcess::spawn(&profile.command).await?;
    let (client, stderr, child) = process.into_parts();
    let client = std::sync::Arc::new(client);

    // Start stderr reader
    let stderr_lines =
        std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<String>::with_capacity(STDERR_RING_CAPACITY),
        ));
    let stderr_task = {
        let lines = stderr_lines.clone();
        let pname = name.to_owned();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt as _;
            let mut line_reader = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = line_reader.next_line().await {
                let line = if line.len() > MAX_STDERR_LINE_LENGTH {
                    let mut truncated = line;
                    truncated.truncate(MAX_STDERR_LINE_LENGTH);
                    truncated.push_str("...(truncated)");
                    truncated
                } else {
                    line
                };
                tracing::warn!(provider = %pname, "{}", line);
                let mut buf = lines.lock().unwrap();
                if buf.len() >= STDERR_RING_CAPACITY {
                    buf.pop_front();
                }
                buf.push_back(line);
            }
        })
    };

    let init = client.initialize().await?;

    let handle = crate::signer::SigningWorker::start(
        client.clone(),
        std::time::Duration::from_secs(profile.sign_timeout_seconds),
    );

    registry.replace_provider(name, init, handle.clone())?;

    Ok(SpawnResult {
        child,
        client,
        signing_handle: handle,
        stderr_lines,
        stderr_task,
    })
}
