use std::sync::Arc;

#[derive(clap::Subcommand)]
pub enum ProxyCommand {
    /// Start the proxy server
    Start(ProxyStartArgs),
    /// Stop the running proxy server
    Stop(ProxyStopArgs),
}

#[derive(clap::Args)]
pub struct ProxyStartArgs {
    /// Listen port (overrides config)
    #[arg(long)]
    port: Option<u16>,

    /// Run as a daemon process
    #[arg(long, default_value_t = false)]
    daemonize: bool,

    /// Log to file instead of stderr
    #[arg(long, default_value_t = false)]
    pub log_to_file: bool,

    /// Force start even if another proxy is detected
    #[arg(long, default_value_t = false)]
    force: bool,

    /// Enable TLS 1.2 (default: TLS 1.3 only)
    #[arg(long, default_value_t = false)]
    tls12: bool,
}

#[derive(clap::Args)]
pub struct ProxyStopArgs {}

pub fn run(cmd: &ProxyCommand) -> anyhow::Result<()> {
    match cmd {
        ProxyCommand::Start(args) => run_start(args),
        ProxyCommand::Stop(args) => run_stop(args),
    }
}

fn run_start(args: &ProxyStartArgs) -> anyhow::Result<()> {
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
    crate::config::state_dir_mkpath()?;

    if args.daemonize {
        daemonize()?;
    }

    run_start_async(args)
}

#[tokio::main]
async fn run_start_async(args: &ProxyStartArgs) -> anyhow::Result<()> {
    let config = crate::config::Config::load()?;
    let port = args.port.unwrap_or(config.port);
    let port = if port == 0 { 1443 } else { port };

    // Check for existing proxy
    check_existing_proxy(args.force).await?;

    // Generate self-signed certificate
    let (certified_key, cert_pem) = generate_self_signed_cert()?;

    // Set up provider registry with control cert
    let registry = crate::provider::ProviderRegistry::new();
    registry.register_control_cert(Arc::new(certified_key), vec!["trustless".to_owned()]);

    // Initialize providers from configured profiles
    let orchestrator = crate::provider::ProviderOrchestrator::new(registry.clone());
    let profile_names = config.list_profiles()?;
    for name in &profile_names {
        let profile = config.load_profile(name)?;
        tracing::info!(provider = %name, "Starting provider");
        orchestrator.add_provider(name, profile).await?;
        tracing::info!(provider = %name, "Provider initialized");
    }
    if profile_names.is_empty() {
        tracing::info!("No profiles configured");
    }

    // Build TLS params (per-connection config built during LazyConfigAcceptor)
    let tls12 = args.tls12 || config.tls12;
    let tls_params = TlsParams {
        registry,
        tls12,
        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    // Bind TCP listener
    let listener = bind_listener(port).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(port = local_addr.port(), "Proxy listening");

    // Write proxy state
    let state = crate::control::ProxyState {
        pid: std::process::id(),
        port: local_addr.port(),
        control_cert_pem: cert_pem,
    };
    state.write_atomic()?;
    tracing::info!(path = %crate::control::ProxyState::path().display(), "State file written");

    // Route table and proxy router
    let route_table = crate::route::RouteTable::new(crate::config::state_dir());
    let proxy_state = crate::proxy::ProxyState {
        route_table,
        client: reqwest::Client::new(),
    };
    let proxy_app = crate::proxy::proxy_router(proxy_state);

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_state = crate::control::server::ServerState::new(shutdown_tx);
    let app = crate::control::server::dispatch_router(server_state, proxy_app);

    // Serve
    let result = serve(listener, tls_params, app, shutdown_rx).await;

    // Shutdown providers
    orchestrator.shutdown().await;

    // Cleanup
    crate::control::ProxyState::remove();
    tracing::info!("State file removed, proxy stopped");

    result
}

struct TlsParams {
    registry: crate::provider::ProviderRegistry,
    tls12: bool,
    alpn_protocols: Vec<Vec<u8>>,
}

static PROTOCOL_VERSIONS_TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static PROTOCOL_VERSIONS_TLS12: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

impl TlsParams {
    fn protocol_versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        if self.tls12 {
            PROTOCOL_VERSIONS_TLS12
        } else {
            PROTOCOL_VERSIONS_TLS13
        }
    }
}

async fn serve(
    listener: tokio::net::TcpListener,
    tls_params: TlsParams,
    app: axum::Router,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let tls_params = Arc::new(tls_params);

    let shutdown = async {
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = sigint.recv() => tracing::info!("Received SIGINT"),
            _ = shutdown_rx => tracing::info!("Shutdown requested via control API"),
        }
    };

    let accept_loop = async {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to accept connection");
                    continue;
                }
            };
            tokio::spawn(handle_connection(
                tls_params.clone(),
                stream,
                addr,
                app.clone(),
                graceful.watcher(),
            ));
        }
    };

    tokio::select! {
        _ = shutdown => {}
        _ = accept_loop => unreachable!(),
    }

    // Drain with timeout
    tracing::info!("Shutting down, draining connections...");
    if tokio::time::timeout(std::time::Duration::from_secs(30), graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("Drain timeout reached, dropping remaining connections");
    }

    Ok(())
}

async fn handle_connection(
    tls_params: Arc<TlsParams>,
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    app: axum::Router,
    watcher: hyper_util::server::graceful::Watcher,
) {
    let acceptor =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    tokio::pin!(acceptor);

    let start = match acceptor.as_mut().await {
        Ok(start) => start,
        Err(e) => {
            tracing::debug!(addr = %addr, error = %e, "TLS accept failed");
            return;
        }
    };

    let sni = start.client_hello().server_name().map(|s| s.to_owned());
    let certified_key = match tls_params.registry.resolve_by_sni(sni.as_deref()) {
        Some(ck) => ck,
        None => {
            tracing::debug!(addr = %addr, sni = ?sni, "No certificate for SNI");
            return;
        }
    };

    let resolver = Arc::new(crate::signer::FixedCertResolver::new(certified_key));
    let mut server_config =
        rustls::ServerConfig::builder_with_protocol_versions(tls_params.protocol_versions())
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    server_config.alpn_protocols = tls_params.alpn_protocols.clone();

    let tls_stream = match start.into_stream(Arc::new(server_config)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(addr = %addr, error = %e, "TLS handshake failed");
            return;
        }
    };

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let app = app.layer(axum::Extension(crate::proxy::ClientAddr(addr)));
    let service = hyper_util::service::TowerToHyperService::new(app);

    let conn = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .into_owned();

    if let Err(e) = watcher.watch(conn).await {
        tracing::debug!(addr = %addr, error = %e, "Connection error");
    }
}

async fn check_existing_proxy(force: bool) -> anyhow::Result<()> {
    let client = match crate::control::Client::from_state() {
        Ok(c) => c,
        Err(_) => return Ok(()), // No state file or invalid — fine to proceed
    };

    if client.ping().await.is_err() {
        tracing::info!("Stale proxy state detected, cleaning up");
        crate::control::ProxyState::remove();
        return Ok(());
    }

    if !force {
        anyhow::bail!(
            "Another proxy is already running (pid in proxy.json). Use --force to override."
        );
    }

    tracing::warn!("Existing proxy is running, --force specified, continuing");
    let _ = client.stop().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}

fn generate_self_signed_cert() -> anyhow::Result<(rustls::sign::CertifiedKey, String)> {
    use rcgen::{CertificateParams, KeyPair};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::new(vec!["trustless".to_owned()])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("trustless".to_owned()),
    );

    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();

    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("failed to parse private key DER: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der)?;

    let certified_key = rustls::sign::CertifiedKey::new(vec![cert_der], signing_key);

    Ok((certified_key, cert_pem))
}

async fn bind_listener(port: u16) -> anyhow::Result<tokio::net::TcpListener> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    socket.listen(128)?;

    let listener = tokio::net::TcpListener::from_std(std::net::TcpListener::from(socket))?;
    Ok(listener)
}

fn daemonize() -> anyhow::Result<()> {
    // Get executable path before fork (needed for macOS re-exec)
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let arg0 = process_path::get_executable_path().expect("can't get executable path");

    let d = daemonize::Daemonize::new()
        .working_directory(crate::config::state_dir())
        .stderr(daemonize::Stdio::keep());

    match d.execute() {
        daemonize::Outcome::Parent(Ok(o)) => {
            return Err(
                crate::Error::SilentlyExitWithCode(std::process::ExitCode::from(
                    o.first_child_exit_code as u8,
                ))
                .into(),
            );
        }
        daemonize::Outcome::Parent(Err(e)) => return Err(e.into()),
        daemonize::Outcome::Child(Ok(_)) => {}
        daemonize::Outcome::Child(Err(e)) => return Err(e.into()),
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // Re-exec to avoid Objective-C fork safety issues
        use std::os::unix::process::CommandExt;
        let args: Vec<String> = std::env::args()
            .skip(1)
            .filter(|x| x.as_str() != "--daemonize")
            .collect();
        tracing::debug!(?arg0, ?args, "Re-exec(2)-ing after daemonize");
        let err = std::process::Command::new(arg0).args(args).exec();
        panic!("exec(2) failed after daemonize: {err}");
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Connect to existing proxy or auto-start one.
/// Respects TRUSTLESS_NO_AUTO_PROXY env var.
pub async fn connect_or_start() -> anyhow::Result<crate::control::Client> {
    if let Ok(client) = crate::control::Client::from_state()
        && client.ping().await.is_ok()
    {
        return Ok(client);
    }

    if std::env::var_os("TRUSTLESS_NO_AUTO_PROXY").is_some() {
        anyhow::bail!("no running proxy and TRUSTLESS_NO_AUTO_PROXY is set");
    }

    tracing::info!("Starting the proxy");
    spawn_proxy().await?;

    let fut = attempt_connect_to_proxy_loop();
    match tokio::time::timeout(std::time::Duration::from_secs(20), fut).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(_)) => unreachable!(),
        Err(_) => {
            anyhow::bail!("timed out waiting for proxy to start");
        }
    }
}

async fn attempt_connect_to_proxy_loop() -> anyhow::Result<crate::control::Client> {
    loop {
        if let Ok(client) = crate::control::Client::from_state()
            && client.ping().await.is_ok()
        {
            return Ok(client);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Spawn proxy as a daemon process.
async fn spawn_proxy() -> anyhow::Result<()> {
    let arg0 = process_path::get_executable_path().expect("can't get executable path");

    tokio::process::Command::new(arg0)
        .args(["proxy", "start", "--log-to-file", "--daemonize"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(false)
        .status()
        .await?;
    Ok(())
}

#[tokio::main]
async fn run_stop(_args: &ProxyStopArgs) -> anyhow::Result<()> {
    let client = crate::control::Client::from_state()
        .map_err(|_| anyhow::anyhow!("no proxy is running (proxy.json not found or invalid)"))?;
    client.stop().await?;
    eprintln!("trustless: proxy stop requested");
    Ok(())
}
