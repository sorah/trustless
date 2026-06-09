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

    /// Additional alias subdomain label (repeatable)
    #[arg(long = "alias")]
    alias: Vec<String>,

    /// Additional alias FQDN (repeatable)
    #[arg(long = "alias-domain")]
    alias_domain: Vec<String>,

    /// Use a fixed port instead of ephemeral allocation
    #[arg(long)]
    port: Option<u16>,

    /// The command's backend speaks HTTPS (and may use HTTP/2); forward over TLS
    #[arg(long)]
    tls: bool,

    /// Disable framework-specific flag injection (e.g. --port, --host for Vite/Astro)
    #[arg(long)]
    no_framework: bool,

    #[command(flatten)]
    url_mode: UrlModeArgs,

    /// Command line to execute.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<std::ffi::OsString>,
}

/// URL/scheme behavior flags shared by `trustless exec` and `trustless run`.
/// The flags are mutually exclusive: `--require-https-url` already implies `--no-localhost`,
/// and `--prefer-cleartext-url` is the opposite of both.
#[derive(clap::Args, Debug, Clone)]
#[group(multiple = false)]
pub(crate) struct UrlModeArgs {
    /// Do not also register a `<name>.localhost` route
    #[arg(long, env = "TRUSTLESS_NO_LOCALHOST", action = clap::ArgAction::SetTrue)]
    pub no_localhost: bool,

    /// Fail (instead of falling back to the cleartext URL) when no HTTPS domain is available
    #[arg(long, env = "TRUSTLESS_REQUIRE_HTTPS_URL", action = clap::ArgAction::SetTrue)]
    pub require_https_url: bool,

    /// Display and export the plaintext `http://<name>.localhost` URL even when HTTPS is available
    #[arg(long, env = "TRUSTLESS_PREFER_CLEARTEXT_URL", action = clap::ArgAction::SetTrue)]
    pub prefer_cleartext_url: bool,
}

use crate::domain::HostnameSpec;

#[derive(Debug, Clone)]
pub(crate) struct ExecParams {
    pub hostname_spec: HostnameSpec,
    pub aliases: Vec<HostnameSpec>,
    pub profile: Option<String>,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub tls: bool,
    pub no_framework: bool,
    pub url_mode: UrlModeArgs,
    pub command: Vec<std::ffi::OsString>,
}

impl From<ExecArgs> for ExecParams {
    fn from(args: ExecArgs) -> Self {
        let mut aliases: Vec<HostnameSpec> =
            args.alias.into_iter().map(HostnameSpec::Label).collect();
        aliases.extend(args.alias_domain.into_iter().map(HostnameSpec::Full));
        Self {
            hostname_spec: HostnameSpec::Label(args.subdomain),
            aliases,
            profile: args.profile,
            domain: args.domain,
            port: args.port,
            tls: args.tls,
            no_framework: args.no_framework,
            url_mode: args.url_mode,
            command: args.command,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
enum ExecIpcMessage {
    Ready {
        /// Local backend port the command listens on.
        backend_port: u16,
        /// The chosen primary URL (HTTPS, or the cleartext fallback). `None` when no
        /// reachable URL is available. Drives both display and the `HOST`/`TRUSTLESS_*` env vars.
        service: Option<UrlChoice>,
        /// Additional alias URLs to display (chosen scheme).
        #[serde(default)]
        alias_urls: Vec<String>,
        /// Provider diagnostic to surface before continuing (cleartext fallback only).
        #[serde(default)]
        warning: Option<String>,
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
        fn make_pipe() -> anyhow::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
            let (i, o) = nix::unistd::pipe()?;
            nix::fcntl::fcntl(&i, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
            nix::fcntl::fcntl(&o, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
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
    backend: std::net::SocketAddr,
    hostnames: Vec<String>,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for hostname in &self.hostnames {
            match self
                .route_table
                .remove_route_if_backend(hostname, self.backend)
            {
                Ok(true) => tracing::debug!(hostname = %hostname, "route removed"),
                Ok(false) => {
                    tracing::debug!(hostname = %hostname, "route already overridden, skipping removal")
                }
                Err(e) => {
                    tracing::warn!(hostname = %hostname, err = ?e, "failed to remove route on cleanup")
                }
            }
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

/// A resolved, reachable URL for a service, in a single scheme. Carries everything the
/// executor needs to set env vars (`HOST`, `TRUSTLESS_PORT`, `TRUSTLESS_URL`) and display
/// the URL.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UrlChoice {
    host: String,
    port: u16,
    url: String,
    domain_suffix: Option<String>,
}

#[tracing::instrument(name = "exec_sidecar", skip_all)]
async fn do_sidecar_inner(params: &ExecParams) -> anyhow::Result<(ExecIpcMessage, RouteGuard)> {
    let client = crate::cmd::proxy::connect_or_start().await?;
    let status = client.status().await?;
    let profile = params.profile.as_deref();
    let domain = params.domain.as_deref();

    // Resolve the HTTPS hostname. When no wildcard domain is available we fall back to the
    // plaintext `*.localhost` URL instead of failing — unless --require-https-url is set.
    // The provider diagnostic is surfaced as a warning, but stays silent when no provider
    // is configured at all (nothing to diagnose).
    let (resolved, warning) = match params.hostname_spec.resolve(&status, profile, domain) {
        Ok(r) => (Some(r), None),
        Err(e) if params.url_mode.require_https_url => return Err(e),
        Err(e) => {
            let warning = (!status.providers.is_empty()).then(|| e.to_string());
            (None, warning)
        }
    };

    let port = match params.port {
        Some(p) => p,
        None => allocate_ephemeral_port()?,
    };
    let backend: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let name = match &params.hostname_spec {
        HostnameSpec::Label(s) => Some(s.as_str()),
        HostnameSpec::LabelWithWorktree { label, .. } => Some(label.as_str()),
        HostnameSpec::Full(_) => None,
    };

    let mut guard = RouteGuard {
        route_table: crate::route::RouteTable::new(crate::config::state_dir()),
        backend,
        hostnames: Vec::new(),
    };

    // Register a route once, deduplicating by hostname. Returns whether it was newly added
    // (so an alias or `*.localhost` companion that coincides with an already-registered name
    // — e.g. when resolution naturally picks a `*.localhost` domain — isn't added twice).
    let tls = params.tls;
    let mut register = |host: &str, route_name: Option<&str>| -> anyhow::Result<bool> {
        if guard.hostnames.iter().any(|h| h == host) {
            return Ok(false);
        }
        guard
            .route_table
            .add_route(host, backend, route_name, tls, true, false)?;
        guard.hostnames.push(host.to_owned());
        Ok(true)
    };

    // Register the HTTPS route (when a domain resolved). This may itself be a `*.localhost`
    // name when that's what resolution picked or what the user configured.
    if let Some(r) = &resolved {
        register(&r.hostname, name)?;
    }

    // Register the `*.localhost` companion. Always in fallback (it is the only route);
    // otherwise unless opted out. `--require-https-url` implies `--no-localhost` (a
    // plaintext-only companion would contradict "HTTPS or fail"); a `*.localhost` name that
    // resolves over HTTPS is registered above and survives via dedup regardless.
    let localhost_host = params.hostname_spec.localhost_hostname();
    let no_localhost = params.url_mode.no_localhost || params.url_mode.require_https_url;
    let register_localhost = !no_localhost || resolved.is_none();
    if register_localhost && let Some(lh) = &localhost_host {
        let lh_name = if resolved.is_some() { None } else { name };
        register(lh, lh_name)?;
    }

    // Register alias routes (same backend, no name) and collect their hostnames per scheme.
    let mut alias_https: Vec<String> = Vec::new();
    let mut alias_localhost: Vec<String> = Vec::new();
    for alias_spec in &params.aliases {
        if let Ok(ar) = alias_spec.resolve(&status, profile, domain)
            && register(&ar.hostname, None)?
        {
            alias_https.push(ar.hostname);
        }
        if register_localhost
            && let Some(alh) = alias_spec.localhost_hostname()
            && register(&alh, None)?
        {
            alias_localhost.push(alh);
        }
    }

    let cleartext_port = status.cleartext_port;
    // The localhost companion is reachable whenever its host ended up registered — either
    // added above, or because it coincided with the resolved HTTPS name.
    let localhost_registered = localhost_host
        .as_deref()
        .is_some_and(|lh| guard.hostnames.iter().any(|h| h == lh));

    // Pick the single URL to display and export. HTTPS by default; the cleartext URL when
    // HTTPS is unavailable or when --prefer-cleartext-url is set.
    let https_choice = resolved.as_ref().map(|r| UrlChoice {
        host: r.hostname.clone(),
        port: status.port,
        url: format!("https://{}:{}", r.hostname, status.port),
        domain_suffix: r.domain_suffix.clone(),
    });
    let cleartext_choice = match (
        localhost_registered.then_some(localhost_host).flatten(),
        cleartext_port,
    ) {
        (Some(lh), Some(cp)) => Some(UrlChoice {
            host: lh.clone(),
            port: cp,
            url: format!("http://{lh}:{cp}"),
            domain_suffix: Some("localhost".to_owned()),
        }),
        _ => None,
    };
    let chose_cleartext = cleartext_choice.is_some()
        && (params.url_mode.prefer_cleartext_url || https_choice.is_none());
    let primary = if chose_cleartext {
        cleartext_choice
    } else {
        https_choice
    };

    let alias_urls: Vec<String> = if chose_cleartext {
        let cp = cleartext_port.expect("cleartext chosen implies a cleartext port");
        alias_localhost
            .iter()
            .map(|h| format!("http://{h}:{cp}"))
            .collect()
    } else if primary.is_some() {
        alias_https
            .iter()
            .map(|h| format!("https://{h}:{}", status.port))
            .collect()
    } else {
        Vec::new()
    };

    let msg = ExecIpcMessage::Ready {
        backend_port: port,
        service: primary,
        alias_urls,
        warning,
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
                backend_port,
                service,
                alias_urls,
                warning,
            } => {
                if let Some(warning) = &warning {
                    eprintln!("trustless: error: {}", warning);
                }
                match &service {
                    Some(s) => eprintln!("trustless: {} -> localhost:{}", s.url, backend_port),
                    None => eprintln!(
                        "trustless: no reachable URL available, running on localhost:{}",
                        backend_port
                    ),
                }
                for alias in &alias_urls {
                    eprintln!("trustless:   alias {}", alias);
                }
                execute(backend_port, service, params)
            }
            ExecIpcMessage::Error { message } => {
                eprintln!("trustless: error: {}", message);
                Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::FAILURE).into())
            }
        }
    }

    fn execute(port: u16, service: Option<UrlChoice>, params: ExecParams) -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        let arg0 = params
            .command
            .first()
            .ok_or_else(|| anyhow::anyhow!("command cannot be empty"))?;

        // SAFETY: Called during exec preparation in the executor process.
        // The sidecar is in its own process, and no other threads exist here.
        unsafe {
            std::env::set_var("PORT", port.to_string());
            if let Some(s) = &service {
                std::env::set_var("HOST", &s.host);
                std::env::set_var("TRUSTLESS_HOST", &s.host);
                std::env::set_var("TRUSTLESS_PORT", s.port.to_string());
                std::env::set_var("TRUSTLESS_URL", &s.url);
            }
        }

        let domain_suffix = service.as_ref().and_then(|s| s.domain_suffix.clone());
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

    /// Env-var-mutating tests must not run concurrently with each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_should_skip_zero() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TRUSTLESS", "0") };
        assert!(should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_should_skip_skip() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TRUSTLESS", "skip") };
        assert!(should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_should_skip_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("TRUSTLESS") };
        assert!(!should_skip());
    }

    #[test]
    fn test_should_skip_other_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("TRUSTLESS", "1") };
        assert!(!should_skip());
        unsafe { std::env::remove_var("TRUSTLESS") };
    }

    #[test]
    fn test_ipc_message_ready_roundtrip() {
        let msg = ExecIpcMessage::Ready {
            backend_port: 3000,
            service: Some(UrlChoice {
                host: "api.dev.invalid".to_string(),
                port: 1443,
                url: "https://api.dev.invalid:1443".to_string(),
                domain_suffix: Some("dev.invalid".to_string()),
            }),
            alias_urls: vec!["https://api-v2.dev.invalid:1443".to_string()],
            warning: None,
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: ExecIpcMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            ExecIpcMessage::Ready {
                backend_port,
                service,
                alias_urls,
                warning,
            } => {
                assert_eq!(backend_port, 3000);
                let service = service.unwrap();
                assert_eq!(service.host, "api.dev.invalid");
                assert_eq!(service.port, 1443);
                assert_eq!(service.url, "https://api.dev.invalid:1443");
                assert_eq!(service.domain_suffix, Some("dev.invalid".to_string()));
                assert_eq!(alias_urls, vec!["https://api-v2.dev.invalid:1443"]);
                assert_eq!(warning, None);
            }
            _ => panic!("expected Ready"),
        }
    }

    #[test]
    fn test_ipc_message_ready_cleartext_fallback() {
        let msg = ExecIpcMessage::Ready {
            backend_port: 3000,
            service: Some(UrlChoice {
                host: "hello.localhost".to_string(),
                port: 1355,
                url: "http://hello.localhost:1355".to_string(),
                domain_suffix: Some("localhost".to_string()),
            }),
            alias_urls: vec![],
            warning: Some("no wildcard domains".to_string()),
        };
        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: ExecIpcMessage = serde_json::from_slice(&json).unwrap();
        match decoded {
            ExecIpcMessage::Ready {
                service, warning, ..
            } => {
                assert_eq!(service.unwrap().url, "http://hello.localhost:1355");
                assert_eq!(warning, Some("no wildcard domains".to_string()));
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
    fn test_ipc_message_ready_optional_fields_default() {
        // alias_urls and warning default when omitted.
        let json = r#"{"type":"Ready","backend_port":3000,"service":null}"#;
        let decoded: ExecIpcMessage = serde_json::from_str(json).unwrap();
        match decoded {
            ExecIpcMessage::Ready {
                alias_urls,
                warning,
                ..
            } => {
                assert!(alias_urls.is_empty());
                assert!(warning.is_none());
            }
            _ => panic!("expected Ready"),
        }
    }

    #[test]
    fn test_allocate_ephemeral_port() {
        let port = allocate_ephemeral_port().unwrap();
        assert!(port > 0);
    }
}
