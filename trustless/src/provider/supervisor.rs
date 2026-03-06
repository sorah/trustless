use super::orchestrator::{SpawnResult, SupervisorCommand, spawn_init_register};
use super::registry::ProviderRegistry;
use super::{ProviderError, ProviderErrorKind, ProviderState};

pub(super) struct Supervisor {
    pub(super) name: String,
    pub(super) profile: crate::config::Profile,
    pub(super) registry: ProviderRegistry,
    pub(super) cancel: tokio_util::sync::CancellationToken,
    pub(super) command_rx: tokio::sync::mpsc::Receiver<SupervisorCommand>,
    pub(super) child: tokio::process::Child,
    pub(super) stderr_task: tokio::task::JoinHandle<()>,
    pub(super) stderr_lines: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    pub(super) backoff: std::time::Duration,
    pub(super) healthy_since: Option<std::time::Instant>,
}

impl Supervisor {
    pub(super) async fn run(mut self) {
        loop {
            self.reset_backoff_if_healthy();

            tokio::select! {
                status = self.child.wait() => {
                    self.handle_crash(status).await;
                }
                _ = self.cancel.cancelled() => {
                    self.handle_shutdown().await;
                    return;
                }
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SupervisorCommand::Restart { reply } => {
                            self.handle_restart_command(reply).await;
                        }
                    }
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

    async fn handle_crash(&mut self, status: Result<std::process::ExitStatus, std::io::Error>) {
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
            ProviderError {
                timestamp: std::time::SystemTime::now(),
                kind: ProviderErrorKind::Crash,
                message: exit_msg,
                stderr_snapshot: Some(stderr_snapshot),
            },
        );

        let _ = self.healthy_since.take();
        self.backoff_respawn_loop().await;
    }

    async fn handle_restart_command(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Result<(), crate::Error>>,
    ) {
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
            }
            Err(e) => {
                self.record_init_failure(&format!("manual restart failed: {e}"));
                let _ = reply.send(Err(e));
                self.backoff_respawn_loop().await;
            }
        }
    }

    async fn handle_shutdown(&mut self) {
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

    /// Retry spawning with exponential backoff until success or cancellation.
    /// Also handles manual restart commands received during backoff sleep.
    async fn backoff_respawn_loop(&mut self) {
        loop {
            tracing::info!(provider = %self.name, delay = ?self.backoff, "restarting after backoff");
            tokio::select! {
                _ = tokio::time::sleep(self.backoff) => {}
                _ = self.cancel.cancelled() => {
                    // Cancelled during backoff — exit the supervisor entirely.
                    // We can't return from run() here directly, but the caller
                    // (handle_crash / handle_restart_command) returns to run(),
                    // which will see cancel on the next select! iteration.
                    return;
                }
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SupervisorCommand::Restart { reply } => {
                            self.backoff = BACKOFF_INITIAL;
                            match self.respawn().await {
                                Ok(result) => {
                                    self.apply_spawn_result(result);
                                    let _ = reply.send(Ok(()));
                                    return;
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            match self.respawn().await {
                Ok(result) => {
                    self.apply_spawn_result(result);
                    return;
                }
                Err(e) => {
                    tracing::error!(provider = %self.name, "respawn failed: {e}");
                    self.record_init_failure(&format!("respawn failed: {e}"));
                    self.backoff = next_backoff(self.backoff);
                }
            }
        }
    }

    fn apply_spawn_result(&mut self, result: SpawnResult) {
        self.child = result.child;
        self.stderr_task = result.stderr_task;
        self.stderr_lines = result.stderr_lines;
        self.healthy_since = Some(std::time::Instant::now());
    }

    fn record_init_failure(&self, message: &str) {
        self.registry.push_error(
            &self.name,
            ProviderError {
                timestamp: std::time::SystemTime::now(),
                kind: ProviderErrorKind::InitFailure,
                message: message.to_owned(),
                stderr_snapshot: None,
            },
        );
    }

    async fn respawn(&self) -> Result<SpawnResult, crate::Error> {
        tracing::info!(provider = %self.name, "spawning provider process");
        spawn_init_register(&self.name, &self.profile, &self.registry).await
    }
}

pub(super) const BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
const BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(300);
const BACKOFF_MULTIPLIER: u32 = 2;
const HEALTHY_RESET_DURATION: std::time::Duration = std::time::Duration::from_secs(60);
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

fn next_backoff(current: std::time::Duration) -> std::time::Duration {
    std::cmp::min(current * BACKOFF_MULTIPLIER, BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

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
