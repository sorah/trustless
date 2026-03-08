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
        self.add_provider_inner(name, profile, false).await
    }

    /// Like `add_provider`, but on initial spawn failure, logs the error and spawns a
    /// recovery supervisor that retries in the background instead of returning an error.
    pub async fn add_provider_resilient(
        &self,
        name: &str,
        profile: crate::config::Profile,
    ) -> Result<(), crate::Error> {
        self.add_provider_inner(name, profile, true).await
    }

    async fn add_provider_inner(
        &self,
        name: &str,
        profile: crate::config::Profile,
        resilient: bool,
    ) -> Result<(), crate::Error> {
        self.check_not_exists(name)?;

        let cancel = self.inner.cancel.child_token();
        let (command_tx, command_rx) = tokio::sync::mpsc::channel::<SupervisorCommand>(4);

        let task = match spawn_init_register(name, &profile, &self.inner.registry).await {
            Ok(result) => {
                let supervisor = Supervisor::new(
                    name.to_owned(),
                    profile.clone(),
                    self.inner.registry.clone(),
                    cancel.clone(),
                    command_rx,
                    result,
                );
                tokio::spawn(supervisor.run())
            }
            Err(spawn_err) if resilient => {
                tracing::error!(provider = %name, "initial startup failed, will retry in background: {}", spawn_err.error);
                self.inner
                    .registry
                    .register_placeholder(name, super::ProviderState::Restarting);
                self.inner.registry.push_error(
                    name,
                    super::ProviderError {
                        timestamp: std::time::SystemTime::now(),
                        kind: super::ProviderErrorKind::InitFailure,
                        message: format!("initial startup failed: {}", spawn_err.error),
                        stderr_snapshot: spawn_err.stderr_snapshot,
                    },
                );
                tokio::spawn(super::supervisor::run_recovering(
                    name.to_owned(),
                    profile.clone(),
                    self.inner.registry.clone(),
                    cancel.clone(),
                    command_rx,
                ))
            }
            Err(spawn_err) => return Err(spawn_err.error),
        };

        self.register_supervisor(name, command_tx, task, cancel, profile);
        Ok(())
    }

    fn check_not_exists(&self, name: &str) -> Result<(), crate::Error> {
        let supervisors = self.inner.supervisors.lock().unwrap();
        if supervisors.contains_key(name) {
            return Err(crate::Error::ProviderAlreadyExists(name.to_owned()));
        }
        Ok(())
    }

    fn register_supervisor(
        &self,
        name: &str,
        command_tx: tokio::sync::mpsc::Sender<SupervisorCommand>,
        task: tokio::task::JoinHandle<()>,
        cancel: tokio_util::sync::CancellationToken,
        profile: crate::config::Profile,
    ) {
        let mut supervisors = self.inner.supervisors.lock().unwrap();
        supervisors.insert(
            name.to_owned(),
            SupervisorHandle {
                command_tx,
                task,
                cancel,
                profile,
            },
        );
    }

    /// Kill the current provider process and restart it, bypassing backoff.
    pub async fn restart_provider(&self, name: &str) -> Result<(), crate::Error> {
        tracing::info!(provider = %name, "restarting provider");
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

    pub fn provider_profiles(&self) -> std::collections::HashMap<String, crate::config::Profile> {
        let supervisors = self.inner.supervisors.lock().unwrap();
        supervisors
            .iter()
            .map(|(name, h)| (name.clone(), h.profile.clone()))
            .collect()
    }

    /// Remove a provider: cancel its supervisor, await task completion, and remove from registry.
    pub async fn remove_provider(&self, name: &str) -> Result<(), crate::Error> {
        let handle = {
            let mut supervisors = self.inner.supervisors.lock().unwrap();
            supervisors
                .remove(name)
                .ok_or_else(|| crate::Error::ProviderNotFound(name.to_owned()))?
        };
        handle.cancel.cancel();
        let _ = handle.task.await;
        self.inner.registry.remove_provider(name);
        Ok(())
    }

    /// Shutdown all providers. Sends SIGTERM, waits up to 20s, then SIGKILL.
    pub async fn shutdown(&self) {
        tracing::info!("shutting down all providers");
        self.inner.cancel.cancel();

        let tasks: Vec<_> = {
            let mut supervisors = self.inner.supervisors.lock().unwrap();
            supervisors.drain().map(|(_, h)| h.task).collect()
        };

        for task in tasks {
            let _ = task.await;
        }
        tracing::debug!("all provider supervisors stopped");
    }
}

struct SupervisorHandle {
    command_tx: tokio::sync::mpsc::Sender<SupervisorCommand>,
    task: tokio::task::JoinHandle<()>,
    cancel: tokio_util::sync::CancellationToken,
    profile: crate::config::Profile,
}

pub(super) enum SupervisorCommand {
    Restart {
        reply: tokio::sync::oneshot::Sender<Result<(), crate::Error>>,
    },
}

pub(super) struct SpawnResult {
    pub(super) child: tokio::process::Child,
    #[allow(dead_code)]
    pub(super) client: std::sync::Arc<super::process::ProviderClient>,
    #[allow(dead_code)]
    pub(super) signing_handle: SigningHandle,
    pub(super) stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    pub(super) stderr_task: tokio::task::JoinHandle<()>,
}

/// Error from `spawn_init_register` that carries an optional stderr snapshot.
#[derive(thiserror::Error, Debug)]
#[error("{error}")]
pub(super) struct SpawnError {
    #[source]
    pub(super) error: crate::Error,
    pub(super) stderr_snapshot: Option<Vec<String>>,
}

const STDERR_RING_CAPACITY: usize = 100;
const MAX_STDERR_LINE_LENGTH: usize = 8192;

/// Spawn a provider process, start stderr reader, initialize, and register in the registry.
pub(super) async fn spawn_init_register(
    name: &str,
    profile: &crate::config::Profile,
    registry: &ProviderRegistry,
) -> Result<SpawnResult, SpawnError> {
    let process = super::process::ProviderProcess::spawn(&profile.command)
        .await
        .map_err(|e| SpawnError {
            error: e.into(),
            stderr_snapshot: None,
        })?;
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

    let init = match client.initialize().await {
        Ok(init) => init,
        Err(e) => {
            // Wait for stderr reader to finish so we capture all output
            let _ = child.stdin; // drop stdin to signal EOF if needed
            // Give the stderr reader a moment to finish
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), stderr_task).await;
            let snapshot: Vec<String> = stderr_lines.lock().unwrap().iter().cloned().collect();
            return Err(SpawnError {
                error: e.into(),
                stderr_snapshot: if snapshot.is_empty() {
                    None
                } else {
                    Some(snapshot)
                },
            });
        }
    };

    let handle = crate::signer::SigningWorker::start(
        client.clone(),
        std::time::Duration::from_secs(profile.sign_timeout_seconds),
    );

    registry
        .replace_provider(name, init, handle.clone())
        .map_err(|e| SpawnError {
            error: e,
            stderr_snapshot: None,
        })?;

    Ok(SpawnResult {
        child,
        client,
        signing_handle: handle,
        stderr_lines,
        stderr_task,
    })
}
