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
        let mut child = tokio::process::Command::new(&command[0])
            .args(&command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().expect("stdout is piped");
        let stdin = child.stdin.take().expect("stdin is piped");
        let stderr = child.stderr.take().expect("stderr is piped");

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
