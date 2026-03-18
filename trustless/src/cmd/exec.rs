// Fork+execvp sidecar pattern ported from https://github.com/sorah/mairu/blob/main/src/cmd/exec.rs

#[derive(clap::Args, Debug, Clone)]
pub struct ExecArgs {
    /// Subdomain name for the route
    subdomain: String,

    /// Profile name to select which provider's domains to use
    #[arg(long, env = "TRUSTLESS_PROFILE")]
    profile: Option<String>,

    /// Domain suffix to use (when provider has multiple wildcard domains)
    #[arg(long)]
    domain: Option<String>,

    /// Use a fixed port instead of ephemeral allocation
    #[arg(long)]
    port: Option<u16>,

    /// Disable framework-specific flag injection (e.g. --port, --host for Vite/Astro)
    #[arg(long)]
    no_framework: bool,

    /// Command line to execute.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

use crate::domain::HostnameSpec;

#[derive(Debug, Clone)]
pub(crate) struct ExecParams {
    pub hostname_spec: HostnameSpec,
    pub profile: Option<String>,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub no_framework: bool,
    pub command: Vec<std::ffi::OsString>,
}

impl From<ExecArgs> for ExecParams {
    fn from(args: ExecArgs) -> Self {
        Self {
            hostname_spec: HostnameSpec::Label(args.subdomain),
            profile: args.profile,
            domain: args.domain,
            port: args.port,
            no_framework: args.no_framework,
            command: args.command,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum ExecIpcMessage {
    Ready {
        hostname: String,
        port: u16,
        proxy_port: u16,
        domain_suffix: Option<String>,
    },
    Error {
        message: String,
    },
}

#[cfg(unix)]
pub fn run(args: &ExecArgs) -> anyhow::Result<()> {
    if should_skip() {
        return skip_exec(&args.command);
    }
    run_exec(ExecParams::from(args.clone()))
}

pub(crate) fn should_skip() -> bool {
    matches!(
        std::env::var("TRUSTLESS").ok().as_deref(),
        Some("0") | Some("skip")
    )
}

pub(crate) fn skip_exec(command: &[std::ffi::OsString]) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;

    let arg0 = command
        .first()
        .ok_or_else(|| anyhow::anyhow!("command cannot be empty"))?;

    eprintln!("trustless: skipping (TRUSTLESS=skip)");
    let err = std::process::Command::new(arg0).args(&command[1..]).exec();
    anyhow::bail!("couldn't exec the command line: {}", err);
}

#[cfg(unix)]
pub(crate) fn run_exec(params: ExecParams) -> anyhow::Result<()> {
    let (ipc_i, ipc_o) = make_pipe()?;
    let pid = nix::unistd::Pid::this();
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { .. } => {
            drop(ipc_o);
            executor::run(ipc_i, params)
        }
        nix::unistd::ForkResult::Child => {
            drop(ipc_i);
            start_ignoring_signals();
            run_sidecar(pid, ipc_o, params)
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))] {
        fn make_pipe() -> anyhow::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
            Ok(nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?)
        }
    } else {
        use std::os::fd::AsRawFd;
        fn make_pipe() -> anyhow::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
            let (i, o) = nix::unistd::pipe()?;
            nix::fcntl::fcntl(i.as_raw_fd(), nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
            nix::fcntl::fcntl(o.as_raw_fd(), nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
            Ok((i, o))
        }
    }
}

#[tokio::main]
async fn run_sidecar(
    parent: nix::unistd::Pid,
    ipc: std::os::fd::OwnedFd,
    params: ExecParams,
) -> anyhow::Result<()> {
    let main = do_sidecar(ipc, params);
    let _result = tokio::spawn(main);
    crate::ppid::wait_for_parent_process_die(parent).await?;
    tracing::debug!("sidecar exiting");
    Ok(())
}

struct RouteGuard {
    route_table: crate::route::RouteTable,
    hostname: String,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = self.route_table.remove_route(&self.hostname) {
            tracing::warn!(hostname = %self.hostname, err = ?e, "failed to remove route on cleanup");
        } else {
            tracing::debug!(hostname = %self.hostname, "route removed");
        }
    }
}

async fn do_sidecar(ipc: std::os::fd::OwnedFd, params: ExecParams) -> anyhow::Result<RouteGuard> {
    match do_sidecar_inner(&params).await {
        Ok((msg, guard)) => {
            inform_executor(ipc, &msg)?;
            Ok(guard)
        }
        Err(e) => {
            let msg = ExecIpcMessage::Error {
                message: e.to_string(),
            };
            let _ = inform_executor(ipc, &msg);
            Err(e)
        }
    }
}

fn inform_executor(ipc_fd: std::os::fd::OwnedFd, message: &ExecIpcMessage) -> anyhow::Result<()> {
    use std::io::Write;
    let mut ipc = std::fs::File::from(ipc_fd);
    let payload = serde_json::to_vec(message)?;
    ipc.write_all(&payload)?;
    ipc.flush()?;
    drop(ipc);
    tracing::debug!("informed executor");
    Ok(())
}

#[tracing::instrument(name = "exec_sidecar", skip_all)]
async fn do_sidecar_inner(params: &ExecParams) -> anyhow::Result<(ExecIpcMessage, RouteGuard)> {
    let client = crate::cmd::proxy::connect_or_start().await?;
    let status = client.status().await?;

    let resolved = params.hostname_spec.resolve(
        &status,
        params.profile.as_deref(),
        params.domain.as_deref(),
    )?;
    let port = match params.port {
        Some(p) => p,
        None => allocate_ephemeral_port()?,
    };

    let route_table = crate::route::RouteTable::new(crate::config::state_dir());
    let backend: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let name = match &params.hostname_spec {
        HostnameSpec::Label(s) => Some(s.as_str()),
        HostnameSpec::LabelWithWorktree { label, .. } => Some(label.as_str()),
        HostnameSpec::Full(_) => None,
    };
    route_table.add_route(&resolved.hostname, backend, name, true, false)?;

    let guard = RouteGuard {
        route_table,
        hostname: resolved.hostname.clone(),
    };

    let msg = ExecIpcMessage::Ready {
        hostname: resolved.hostname,
        port,
        proxy_port: status.port,
        domain_suffix: resolved.domain_suffix,
    };

    Ok((msg, guard))
}

fn allocate_ephemeral_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

#[cfg(unix)]
fn start_ignoring_signals() {
    use nix::sys::signal::{SigHandler, Signal, signal};
    if let Err(e) = unsafe { signal(Signal::SIGINT, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGINT")
    }
    if let Err(e) = unsafe { signal(Signal::SIGQUIT, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGQUIT")
    }
    if let Err(e) = unsafe { signal(Signal::SIGTSTP, SigHandler::SigIgn) } {
        tracing::warn!(err = ?e, "failed to ignore SIGTSTP")
    }
}

mod executor {
    use super::*;
    use crate::framework::FrameworkBehavior as _;

    #[tracing::instrument(name = "exec_executor", skip_all)]
    pub(super) fn run(ipc_fd: std::os::fd::OwnedFd, params: ExecParams) -> anyhow::Result<()> {
        use std::io::Read;

        tracing::trace!("waiting for information from the sidecar");
        let msg = {
            let mut ipc = std::fs::File::from(ipc_fd);
            let mut buf = Vec::new();
            ipc.read_to_end(&mut buf)
                .map_err(|e| anyhow::anyhow!("failed to read data from sidecar; {}", e))?;
            serde_json::from_slice::<ExecIpcMessage>(&buf).map_err(|e| {
                anyhow::anyhow!(
                    "failed to decode data from sidecar (it may have unexpectedly crashed); {}",
                    e
                )
            })?
        };

        match msg {
            ExecIpcMessage::Ready {
                hostname,
                port,
                proxy_port,
                domain_suffix,
            } => {
                eprintln!(
                    "trustless: https://{}:{} -> localhost:{}",
                    hostname, proxy_port, port
                );
                execute(hostname, port, proxy_port, domain_suffix, params)
            }
            ExecIpcMessage::Error { message } => {
                eprintln!("trustless: error: {}", message);
                Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::FAILURE).into())
            }
        }
    }

    fn execute(
        hostname: String,
        port: u16,
        proxy_port: u16,
        domain_suffix: Option<String>,
        params: ExecParams,
    ) -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        let arg0 = params
            .command
            .first()
            .ok_or_else(|| anyhow::anyhow!("command cannot be empty"))?;

        // SAFETY: Called during exec preparation in the executor process.
        // The sidecar is in its own process, and no other threads exist here.
        unsafe {
            std::env::set_var("PORT", port.to_string());
            std::env::set_var("HOST", &hostname);
            std::env::set_var("TRUSTLESS_HOST", &hostname);
            std::env::set_var("TRUSTLESS_PORT", proxy_port.to_string());
            std::env::set_var(
                "TRUSTLESS_URL",
                format!("https://{}:{}", hostname, proxy_port),
            );
        }

        let (exec_arg0, exec_args) = if !params.no_framework
            && let Some(fw) = crate::framework::detect(&params.command)
        {
            let built = fw.build_command(&params.command, port);
            tracing::trace!(command = ?built, "framework flags injected");
            for (k, v) in fw.extra_env(domain_suffix.as_deref()) {
                // SAFETY: same single-threaded executor context as above
                unsafe { std::env::set_var(&k, &v) };
            }
            let (first, rest) = built
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("framework build_command returned empty"))?;
            (first.clone(), rest.to_vec())
        } else {
            (arg0.clone(), params.command[1..].to_vec())
        };

        let err = std::process::Command::new(&exec_arg0)
            .args(&exec_args)
            .exec();
        anyhow::bail!("couldn't exec the command line: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_skip_zero() {
        unsafe { std::env::set_var("TRUSTLESS", "0") };
        assert!(should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_should_skip_skip() {
        unsafe { std::env::set_var("TRUSTLESS", "skip") };
        assert!(should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_should_skip_unset() {
        unsafe { std::env::remove_var("TRUSTLESS") };
        assert!(!should_skip());
    }

    #[test]
    fn test_should_skip_other_value() {
        unsafe { std::env::set_var("TRUSTLESS", "1") };
        assert!(!should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_ipc_message_ready_roundtrip() {
        let msg = ExecIpcMessage::Ready {
            hostname: "api.dev.invalid".to_string(),
            port: 3000,
            proxy_port: 1443,
            domain_suffix: Some("dev.invalid".to_string()),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: ExecIpcMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            ExecIpcMessage::Ready {
                hostname,
                port,
                proxy_port,
                domain_suffix,
            } => {
                assert_eq!(hostname, "api.dev.invalid");
                assert_eq!(port, 3000);
                assert_eq!(proxy_port, 1443);
                assert_eq!(domain_suffix, Some("dev.invalid".to_string()));
            }
            _ => panic!("expected Ready"),
        }
    }

    #[test]
    fn test_ipc_message_error_roundtrip() {
        let msg = ExecIpcMessage::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: ExecIpcMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            ExecIpcMessage::Error { message } => {
                assert_eq!(message, "something went wrong");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_allocate_ephemeral_port() {
        let port = allocate_ephemeral_port().unwrap();
        assert!(port > 0);
    }
}
