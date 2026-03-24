use super::orchestrator::{
    ProviderOrchestrator, SpawnError, SpawnResult, SupervisorCommand, spawn_init_register,
};
use super::registry::ProviderRegistry;
use super::{ProviderError, ProviderErrorKind, ProviderErrorReport, ProviderState};

pub(super) struct Supervisor {
    pub(super) name: String,
    pub(super) profile: crate::config::Profile,
    pub(super) registry: ProviderRegistry,
    pub(super) orchestrator: Option<ProviderOrchestrator>,
    pub(super) cancel: tokio_util::sync::CancellationToken,
    pub(super) command_rx: tokio::sync::mpsc::Receiver<SupervisorCommand>,
    pub(super) client: std::sync::Arc<super::process::ProviderClient>,
    pub(super) child: tokio::process::Child,
    pub(super) stderr_task: tokio::task::JoinHandle<()>,
    pub(super) stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    pub(super) backoff: std::time::Duration,
    pub(super) healthy_since: Option<std::time::Instant>,
    pub(super) last_reinit: Option<std::time::Instant>,
}

impl Supervisor {
    pub(super) fn new(
        name: String,
        profile: crate::config::Profile,
        registry: ProviderRegistry,
        orchestrator: Option<ProviderOrchestrator>,
        cancel: tokio_util::sync::CancellationToken,
        command_rx: tokio::sync::mpsc::Receiver<SupervisorCommand>,
        result: SpawnResult,
    ) -> Self {
        Self {
            name,
            profile,
            registry,
            orchestrator,
            cancel,
            command_rx,
            client: result.client,
            child: result.child,
            stderr_task: result.stderr_task,
            stderr_lines: result.stderr_lines,
            backoff: BACKOFF_INITIAL,
            healthy_since: Some(std::time::Instant::now()),
            last_reinit: None,
        }
    }

    pub(super) async fn run(mut self) {
        loop {
            self.reset_backoff_if_healthy();

            let refresh_interval = self.compute_refresh_interval();
            tokio::select! {
                status = self.child.wait() => {
                    if self.handle_crash(status).await {
                        return;
                    }
                }
                _ = self.cancel.cancelled() => {
                    self.handle_shutdown().await;
                    return;
                }
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SupervisorCommand::Restart { reply } => {
                            if self.handle_restart_command(reply).await {
                                return;
                            }
                        }
                        SupervisorCommand::ReinitIfDue => {
                            self.reinitialize("reinitializing provider (certificate refresh requested)").await;
                        }
                    }
                }
                _ = tokio::time::sleep(refresh_interval) => {
                    self.reinitialize("proactive certificate refresh").await;
                }
            }
        }
    }

    fn reset_backoff_if_healthy(&mut self) {
        if let Some(since) = self.healthy_since
            && since.elapsed() >= HEALTHY_RESET_DURATION
        {
            self.backoff = BACKOFF_INITIAL;
        }
    }

    /// Handle a crashed provider process. Returns `true` if the supervisor was
    /// cancelled during the backoff/respawn loop and should exit immediately.
    async fn handle_crash(
        &mut self,
        status: Result<std::process::ExitStatus, std::io::Error>,
    ) -> bool {
        let _ = (&mut self.stderr_task).await;
        let stderr_snapshot: Vec<String> =
            self.stderr_lines.lock().unwrap().iter().cloned().collect();
        let exit_msg = match status {
            Ok(s) => format!("provider {} exited: {s}", self.name),
            Err(e) => format!("provider {} wait error: {e}", self.name),
        };
        tracing::error!("{}", exit_msg);

        self.registry
            .set_provider_state(&self.name, ProviderState::Restarting);
        self.registry.push_error(
            &self.name,
            ProviderErrorReport {
                timestamp: std::time::SystemTime::now(),
                error: ProviderError {
                    kind: ProviderErrorKind::Crash,
                    message: exit_msg,
                },
                stderr_snapshot: Some(stderr_snapshot),
            },
        );

        let _ = self.healthy_since.take();
        self.backoff_respawn_loop().await
    }

    /// Handle a manual restart command. Returns `true` if the supervisor was
    /// cancelled during the backoff/respawn loop and should exit immediately.
    async fn handle_restart_command(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Result<(), crate::Error>>,
    ) -> bool {
        tracing::debug!(provider = %self.name, "received restart command");
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        let _ = (&mut self.stderr_task).await;

        self.registry
            .set_provider_state(&self.name, ProviderState::Restarting);
        self.backoff = BACKOFF_INITIAL;

        match self.respawn().await {
            Ok(result) => {
                self.apply_spawn_result(result);
                let _ = reply.send(Ok(()));
                false
            }
            Err(spawn_err) => {
                self.record_spawn_failure("manual restart failed", spawn_err.stderr_snapshot);
                let _ = reply.send(Err(spawn_err.error));
                self.backoff_respawn_loop().await
            }
        }
    }

    async fn handle_shutdown(&mut self) {
        tracing::debug!(provider = %self.name, "shutting down provider");
        #[cfg(unix)]
        {
            if let Some(pid) = self.child.id() {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill().await;
        }

        let timeout_result = tokio::time::timeout(SHUTDOWN_TIMEOUT, self.child.wait()).await;

        if timeout_result.is_err() {
            tracing::warn!(provider = %self.name, "provider did not exit within timeout, sending SIGKILL");
            let _ = self.child.kill().await;
        }

        let _ = (&mut self.stderr_task).await;
    }

    /// Reinitialize the running provider process by calling `initialize` again
    /// and re-registering certificates, without killing the process.
    async fn reinitialize(&mut self, reason: &str) {
        if !self.is_reinit_due() {
            return;
        }
        tracing::info!(provider = %self.name, "{}", reason);
        self.last_reinit = Some(std::time::Instant::now());

        let init = match self.client.initialize().await {
            Ok(init) => init,
            Err(e) => {
                tracing::error!(provider = %self.name, "reinitialize failed: {e}");
                self.record_spawn_failure(&format!("reinitialize failed: {e}"), None);
                return;
            }
        };

        let error_sink = super::ProviderErrorSink::new(
            self.registry.clone(),
            self.name.clone(),
            Some(self.stderr_lines.clone()),
            self.orchestrator.clone(),
        );
        let handle = crate::signer::SigningWorker::start(
            self.client.clone(),
            std::time::Duration::from_secs(self.profile.sign_timeout_seconds),
            Some(error_sink),
        );
        if let Err(e) = self.registry.replace_provider(&self.name, init, handle) {
            tracing::error!(provider = %self.name, "reinitialize registration failed: {e}");
        }
    }

    /// Check whether reinit is allowed (debounce window elapsed).
    fn is_reinit_due(&self) -> bool {
        match self.last_reinit {
            Some(t) => t.elapsed() >= REINIT_DEBOUNCE,
            None => true,
        }
    }

    fn compute_refresh_interval(&self) -> std::time::Duration {
        let not_after_epoch = self.registry.earliest_not_after_epoch(&self.name);
        compute_refresh_interval(not_after_epoch)
    }

    /// Retry spawning with exponential backoff until success or cancellation.
    /// Also handles manual restart commands received during backoff sleep.
    /// Returns `true` if cancelled, `false` if a respawn succeeded.
    async fn backoff_respawn_loop(&mut self) -> bool {
        loop {
            tracing::info!(provider = %self.name, delay = ?self.backoff, "restarting after backoff");
            tokio::select! {
                _ = tokio::time::sleep(self.backoff) => {}
                _ = self.cancel.cancelled() => {
                    return true;
                }
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SupervisorCommand::Restart { reply } => {
                            self.backoff = BACKOFF_INITIAL;
                            match self.respawn().await {
                                Ok(result) => {
                                    self.apply_spawn_result(result);
                                    let _ = reply.send(Ok(()));
                                    return false;
                                }
                                Err(spawn_err) => {
                                    let _ = reply.send(Err(spawn_err.error));
                                    continue;
                                }
                            }
                        }
                        SupervisorCommand::ReinitIfDue => {
                            // Process is dead during backoff — initialize RPC would fail.
                            // The backoff loop is already working on a full respawn.
                            continue;
                        }
                    }
                }
            }

            match self.respawn().await {
                Ok(result) => {
                    self.apply_spawn_result(result);
                    return false;
                }
                Err(spawn_err) => {
                    tracing::error!(provider = %self.name, "respawn failed: {}", spawn_err.error);
                    self.record_spawn_failure(
                        &format!("respawn failed: {}", spawn_err.error),
                        spawn_err.stderr_snapshot,
                    );
                    self.backoff = next_backoff(self.backoff);
                    tracing::debug!(provider = %self.name, next_delay = ?self.backoff, "increasing backoff");
                }
            }
        }
    }

    fn apply_spawn_result(&mut self, result: SpawnResult) {
        self.client = result.client;
        self.child = result.child;
        self.stderr_task = result.stderr_task;
        self.stderr_lines = result.stderr_lines;
        self.healthy_since = Some(std::time::Instant::now());
        tracing::info!(provider = %self.name, "provider respawned successfully");
    }

    fn record_spawn_failure(&self, context: &str, stderr_snapshot: Option<Vec<String>>) {
        self.registry.push_error(
            &self.name,
            ProviderErrorReport {
                timestamp: std::time::SystemTime::now(),
                error: ProviderError {
                    kind: ProviderErrorKind::InitFailure,
                    message: context.to_owned(),
                },
                stderr_snapshot,
            },
        );
    }

    async fn respawn(&self) -> Result<SpawnResult, SpawnError> {
        tracing::info!(provider = %self.name, "spawning provider process");
        spawn_init_register(
            &self.name,
            &self.profile,
            &self.registry,
            self.orchestrator.clone(),
        )
        .await
    }
}

/// Entry point for a supervisor that failed its initial spawn. Retries with backoff,
/// then transitions into the normal supervisor loop once successful.
pub(super) async fn run_recovering(
    name: String,
    profile: crate::config::Profile,
    registry: ProviderRegistry,
    orchestrator: Option<ProviderOrchestrator>,
    cancel: tokio_util::sync::CancellationToken,
    mut command_rx: tokio::sync::mpsc::Receiver<SupervisorCommand>,
) {
    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!(provider = %name, delay = ?backoff, "restarting after backoff");
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = cancel.cancelled() => return,
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    SupervisorCommand::Restart { reply } => {
                        backoff = BACKOFF_INITIAL;
                        match spawn_init_register(&name, &profile, &registry, orchestrator.clone()).await {
                            Ok(result) => {
                                let _ = reply.send(Ok(()));
                                Supervisor::new(name, profile, registry, orchestrator, cancel, command_rx, result)
                                    .run().await;
                                return;
                            }
                            Err(spawn_err) => {
                                registry.push_error(
                                    &name,
                                    ProviderErrorReport {
                                        timestamp: std::time::SystemTime::now(),
                                        error: ProviderError {
                                            kind: ProviderErrorKind::InitFailure,
                                            message: format!("manual restart failed: {}", spawn_err.error),
                                        },
                                        stderr_snapshot: spawn_err.stderr_snapshot,
                                    },
                                );
                                let _ = reply.send(Err(spawn_err.error));
                                continue;
                            }
                        }
                    }
                    SupervisorCommand::ReinitIfDue => {
                        // Process isn't running yet — initialize RPC would fail.
                        // The recovery loop is already attempting full respawn.
                        continue;
                    }
                }
            }
        }

        match spawn_init_register(&name, &profile, &registry, orchestrator.clone()).await {
            Ok(result) => {
                tracing::info!(provider = %name, "provider recovered successfully");
                Supervisor::new(
                    name,
                    profile,
                    registry,
                    orchestrator,
                    cancel,
                    command_rx,
                    result,
                )
                .run()
                .await;
                return;
            }
            Err(spawn_err) => {
                tracing::error!(provider = %name, "respawn failed: {}", spawn_err.error);
                registry.push_error(
                    &name,
                    ProviderErrorReport {
                        timestamp: std::time::SystemTime::now(),
                        error: ProviderError {
                            kind: ProviderErrorKind::InitFailure,
                            message: format!("respawn failed: {}", spawn_err.error),
                        },
                        stderr_snapshot: spawn_err.stderr_snapshot,
                    },
                );
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// Compute the interval until the next proactive certificate refresh.
///
/// Uses `remaining / 12` clamped to `[5min, 1hr]` with ±15% jitter.
/// Falls back to 1hr if no expiry information is available.
fn compute_refresh_interval(not_after_epoch: Option<i64>) -> std::time::Duration {
    let base = match not_after_epoch {
        Some(epoch) => {
            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let remaining = (epoch - now_epoch).max(0) as u64;
            let interval = remaining / 12;
            let interval = interval.clamp(
                REFRESH_INTERVAL_MIN.as_secs(),
                REFRESH_INTERVAL_MAX.as_secs(),
            );
            std::time::Duration::from_secs(interval)
        }
        None => REFRESH_INTERVAL_MAX,
    };

    // Apply ±15% jitter using subsec_nanos as a cheap deterministic-ish source
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // Map nanos to [-0.15, +0.15] range
    let jitter_frac = (nanos as f64 / u32::MAX as f64) * 0.30 - 0.15;
    let jittered = base.as_secs_f64() * (1.0 + jitter_frac);
    std::time::Duration::from_secs_f64(jittered.max(1.0))
}

pub(super) const BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
const BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(300);
const BACKOFF_MULTIPLIER: u32 = 2;
const HEALTHY_RESET_DURATION: std::time::Duration = std::time::Duration::from_secs(60);
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const REINIT_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(30);
const REFRESH_INTERVAL_MIN: std::time::Duration = std::time::Duration::from_secs(300);
const REFRESH_INTERVAL_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

fn next_backoff(current: std::time::Duration) -> std::time::Duration {
    std::cmp::min(current * BACKOFF_MULTIPLIER, BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_no_expiry() {
        let interval = compute_refresh_interval(None);
        // Falls back to REFRESH_INTERVAL_MAX (1hr) ±15%
        assert!(interval >= std::time::Duration::from_secs(3060)); // 3600 * 0.85
        assert!(interval <= std::time::Duration::from_secs(4140)); // 3600 * 1.15
    }

    #[test]
    fn refresh_interval_clamps_to_min() {
        // 1 hour remaining → 3600/12 = 300s = 5min (REFRESH_INTERVAL_MIN)
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let interval = compute_refresh_interval(Some(now_epoch + 3600));
        // 300s base ±15%
        assert!(interval >= std::time::Duration::from_secs(255)); // 300 * 0.85
        assert!(interval <= std::time::Duration::from_secs(345)); // 300 * 1.15
    }

    #[test]
    fn refresh_interval_clamps_to_max() {
        // 24 hours remaining → 86400/12 = 7200s, clamped to 3600s (REFRESH_INTERVAL_MAX)
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let interval = compute_refresh_interval(Some(now_epoch + 86400));
        // 3600s base ±15%
        assert!(interval >= std::time::Duration::from_secs(3060));
        assert!(interval <= std::time::Duration::from_secs(4140));
    }

    #[test]
    fn refresh_interval_mid_range() {
        // 6 hours remaining → 21600/12 = 1800s (30min), within [5min, 1hr]
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let interval = compute_refresh_interval(Some(now_epoch + 21600));
        // 1800s base ±15%
        assert!(interval >= std::time::Duration::from_secs(1530)); // 1800 * 0.85
        assert!(interval <= std::time::Duration::from_secs(2070)); // 1800 * 1.15
    }

    #[test]
    fn refresh_interval_already_expired() {
        // Cert already expired → remaining clamped to 0, then clamped to min
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let interval = compute_refresh_interval(Some(now_epoch - 3600));
        // 0/12 = 0, clamped to 300s (REFRESH_INTERVAL_MIN) ±15%
        assert!(interval >= std::time::Duration::from_secs(255));
        assert!(interval <= std::time::Duration::from_secs(345));
    }

    #[test]
    fn backoff_calculation() {
        let mut delay = BACKOFF_INITIAL;
        assert_eq!(delay, std::time::Duration::from_secs(1));

        delay = next_backoff(delay);
        assert_eq!(delay, std::time::Duration::from_secs(2));

        delay = next_backoff(delay);
        assert_eq!(delay, std::time::Duration::from_secs(4));

        delay = next_backoff(delay);
        assert_eq!(delay, std::time::Duration::from_secs(8));

        // Keep going until we hit the max
        for _ in 0..20 {
            delay = next_backoff(delay);
        }
        assert_eq!(delay, BACKOFF_MAX);
    }
}
