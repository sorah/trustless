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

    /// Command line to execute.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum ExecIpcMessage {
    Ready {
        hostname: String,
        port: u16,
        proxy_port: u16,
    },
    Error {
        message: String,
    },
}

#[cfg(unix)]
pub fn run(args: &ExecArgs) -> anyhow::Result<()> {
    let (ipc_i, ipc_o) = make_pipe()?;
    let pid = nix::unistd::Pid::this();
    match unsafe { nix::unistd::fork() }? {
        nix::unistd::ForkResult::Parent { .. } => {
            drop(ipc_o);
            executor::run(ipc_i, args.clone())
        }
        nix::unistd::ForkResult::Child => {
            drop(ipc_i);
            start_ignoring_signals();
            run_sidecar(pid, ipc_o, args.clone())
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
    args: ExecArgs,
) -> anyhow::Result<()> {
    let main = do_sidecar(ipc, args);
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

async fn do_sidecar(ipc: std::os::fd::OwnedFd, args: ExecArgs) -> anyhow::Result<RouteGuard> {
    match do_sidecar_inner(&args).await {
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
async fn do_sidecar_inner(args: &ExecArgs) -> anyhow::Result<(ExecIpcMessage, RouteGuard)> {
    let client = crate::cmd::proxy::connect_or_start().await?;
    let status = client.status().await?;

    let hostname = resolve_hostname(&status, args)?;
    let port = match args.port {
        Some(p) => p,
        None => allocate_ephemeral_port()?,
    };

    let route_table = crate::route::RouteTable::new(crate::config::state_dir());
    let backend: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    route_table.add_route(&hostname, backend, true, false)?;

    let guard = RouteGuard {
        route_table,
        hostname: hostname.clone(),
    };

    let msg = ExecIpcMessage::Ready {
        hostname,
        port,
        proxy_port: status.port,
    };

    Ok((msg, guard))
}

fn resolve_hostname(
    status: &crate::control::StatusResponse,
    args: &ExecArgs,
) -> anyhow::Result<String> {
    let provider = match &args.profile {
        Some(name) => status
            .providers
            .iter()
            .find(|p| p.name == *name)
            .ok_or_else(|| anyhow::anyhow!("provider profile '{}' not found", name))?,
        None => {
            if status.providers.len() == 1 {
                &status.providers[0]
            } else if status.providers.is_empty() {
                anyhow::bail!("no providers configured; run 'trustless setup' first");
            } else {
                let names: Vec<&str> = status.providers.iter().map(|p| p.name.as_str()).collect();
                anyhow::bail!(
                    "multiple providers configured ({}); use --profile to select one",
                    names.join(", ")
                );
            }
        }
    };

    let wildcard_domains: Vec<&str> = provider
        .certificates
        .iter()
        .flat_map(|cert| cert.domains.iter())
        .filter_map(|d| d.strip_prefix("*."))
        .collect();

    let suffix = match &args.domain {
        Some(domain) => {
            if wildcard_domains.contains(&domain.as_str()) {
                domain.as_str()
            } else {
                anyhow::bail!(
                    "domain '{}' not found in provider '{}' certificates; available: {}",
                    domain,
                    provider.name,
                    wildcard_domains.join(", ")
                );
            }
        }
        None => {
            if wildcard_domains.len() == 1 {
                wildcard_domains[0]
            } else if wildcard_domains.is_empty() {
                anyhow::bail!(
                    "no wildcard domains in provider '{}' certificates",
                    provider.name
                );
            } else {
                anyhow::bail!(
                    "multiple wildcard domains in provider '{}'; use --domain to select one: {}",
                    provider.name,
                    wildcard_domains.join(", ")
                );
            }
        }
    };

    let hostname = format!("{}.{}", args.subdomain, suffix);
    crate::route::validate_hostname(&hostname)?;
    Ok(hostname)
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

    #[tracing::instrument(name = "exec_executor", skip_all)]
    pub(super) fn run(ipc_fd: std::os::fd::OwnedFd, args: ExecArgs) -> anyhow::Result<()> {
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
            } => {
                eprintln!(
                    "trustless: https://{}:{} -> 127.0.0.1:{}",
                    hostname, proxy_port, port
                );
                execute(hostname, port, proxy_port, args)
            }
            ExecIpcMessage::Error { message } => {
                eprintln!("trustless: error: {}", message);
                Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::FAILURE).into())
            }
        }
    }

    fn execute(hostname: String, port: u16, proxy_port: u16, args: ExecArgs) -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        let arg0 = args
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
        }

        let err = std::process::Command::new(arg0)
            .args(&args.command[1..])
            .exec();
        anyhow::bail!("couldn't exec the command line: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_message_ready_roundtrip() {
        let msg = ExecIpcMessage::Ready {
            hostname: "api.dev.invalid".to_string(),
            port: 3000,
            proxy_port: 1443,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: ExecIpcMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            ExecIpcMessage::Ready {
                hostname,
                port,
                proxy_port,
            } => {
                assert_eq!(hostname, "api.dev.invalid");
                assert_eq!(port, 3000);
                assert_eq!(proxy_port, 1443);
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

    fn make_status(
        providers: Vec<crate::provider::ProviderStatusInfo>,
    ) -> crate::control::StatusResponse {
        crate::control::StatusResponse {
            pid: 1,
            port: 1443,
            providers,
            routes: std::collections::HashMap::new(),
        }
    }

    fn make_provider(name: &str, domains: Vec<&str>) -> crate::provider::ProviderStatusInfo {
        crate::provider::ProviderStatusInfo {
            name: name.to_string(),
            state: crate::provider::ProviderState::Running,
            certificates: vec![crate::provider::CertificateStatusInfo {
                id: "test".to_string(),
                domains: domains.into_iter().map(|s| s.to_string()).collect(),
                issuer: "test".to_string(),
                serial: "00".to_string(),
                not_after: "2099-01-01".to_string(),
            }],
            errors: vec![],
        }
    }

    #[test]
    fn test_resolve_hostname_single_provider_single_wildcard() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let args = ExecArgs {
            subdomain: "api".to_string(),
            profile: None,
            domain: None,
            port: None,
            command: vec![],
        };
        let hostname = resolve_hostname(&status, &args).unwrap();
        assert_eq!(hostname, "api.dev.invalid");
    }

    #[test]
    fn test_resolve_hostname_with_profile() {
        let status = make_status(vec![
            make_provider("alpha", vec!["*.alpha.invalid"]),
            make_provider("beta", vec!["*.beta.invalid"]),
        ]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: Some("beta".to_string()),
            domain: None,
            port: None,
            command: vec![],
        };
        let hostname = resolve_hostname(&status, &args).unwrap();
        assert_eq!(hostname, "app.beta.invalid");
    }

    #[test]
    fn test_resolve_hostname_with_domain() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.a.invalid", "*.b.invalid"],
        )]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: None,
            domain: Some("b.invalid".to_string()),
            port: None,
            command: vec![],
        };
        let hostname = resolve_hostname(&status, &args).unwrap();
        assert_eq!(hostname, "app.b.invalid");
    }

    #[test]
    fn test_resolve_hostname_no_providers() {
        let status = make_status(vec![]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: None,
            domain: None,
            port: None,
            command: vec![],
        };
        let err = resolve_hostname(&status, &args).unwrap_err();
        assert!(err.to_string().contains("no providers configured"));
    }

    #[test]
    fn test_resolve_hostname_ambiguous_providers() {
        let status = make_status(vec![
            make_provider("a", vec!["*.a.invalid"]),
            make_provider("b", vec!["*.b.invalid"]),
        ]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: None,
            domain: None,
            port: None,
            command: vec![],
        };
        let err = resolve_hostname(&status, &args).unwrap_err();
        assert!(err.to_string().contains("--profile"));
    }

    #[test]
    fn test_resolve_hostname_ambiguous_domains() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.a.invalid", "*.b.invalid"],
        )]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: None,
            domain: None,
            port: None,
            command: vec![],
        };
        let err = resolve_hostname(&status, &args).unwrap_err();
        assert!(err.to_string().contains("--domain"));
    }

    #[test]
    fn test_resolve_hostname_profile_not_found() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: Some("nonexistent".to_string()),
            domain: None,
            port: None,
            command: vec![],
        };
        let err = resolve_hostname(&status, &args).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn test_resolve_hostname_domain_not_found() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let args = ExecArgs {
            subdomain: "app".to_string(),
            profile: None,
            domain: Some("other.invalid".to_string()),
            port: None,
            command: vec![],
        };
        let err = resolve_hostname(&status, &args).unwrap_err();
        assert!(err.to_string().contains("other.invalid"));
    }
}
