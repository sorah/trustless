pub type ProviderClient = trustless_protocol::client::ProviderClient<
    tokio::process::ChildStdout,
    tokio::process::ChildStdin,
>;

pub struct ProviderProcess {
    pub client: ProviderClient,
    pub stderr: tokio::process::ChildStderr,
    child: tokio::process::Child,
}

impl ProviderProcess {
    pub async fn spawn(command: &[String]) -> Result<Self, trustless_protocol::error::Error> {
        let mut cmd = tokio::process::Command::new(&command[0]);
        cmd.args(&command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Detach provider from controlling TTY so it cannot read from or open /dev/tty.
        // TODO: replace with std CommandExt::setsid() when stabilized
        //       https://github.com/rust-lang/rust/issues/105376
        #[cfg(unix)]
        {
            // SAFETY: setsid() is async-signal-safe
            unsafe {
                cmd.pre_exec(|| {
                    nix::unistd::setsid()?;
                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn()?;

        let stdout = child.stdout.take().expect("stdout is piped");
        let stdin = child.stdin.take().expect("stdin is piped");
        let stderr = child.stderr.take().expect("stderr is piped");

        let pid = child.id();
        tracing::debug!(command = %command[0], pid = ?pid, "provider process spawned");

        let client = ProviderClient::new(stdout, stdin);

        Ok(Self {
            client,
            stderr,
            child,
        })
    }

    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    #[cfg(unix)]
    pub fn signal(&self, sig: nix::sys::signal::Signal) -> nix::Result<()> {
        let pid = self.child.id().ok_or(nix::errno::Errno::ESRCH)?;
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig)
    }

    pub async fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill().await
    }

    /// Decompose into parts for cases where the client needs separate ownership (e.g., wrapping in Arc).
    pub fn into_parts(
        self,
    ) -> (
        ProviderClient,
        tokio::process::ChildStderr,
        tokio::process::Child,
    ) {
        (self.client, self.stderr, self.child)
    }
}
