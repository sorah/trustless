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
    log_to_file: bool,

    /// Force start even if another proxy is detected
    #[arg(long, default_value_t = false)]
    force: bool,
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
    if args.daemonize {
        daemonize()?;
    }

    init_logging(args.log_to_file);
    run_start_async(args)
}

#[tokio::main]
async fn run_start_async(args: &ProxyStartArgs) -> anyhow::Result<()> {
    let config = crate::config::Config::load()?;
    let port = args.port.unwrap_or(config.port);
    let port = if port == 0 { 1443 } else { port };

    // Check for existing proxy
    check_existing_proxy(args.force).await?;

    // Create state directory
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
    crate::config::state_dir_mkpath()?;

    // Generate self-signed certificate
    let (certified_key, cert_pem) = generate_self_signed_cert()?;

    // Set up provider registry with control cert
    let registry = crate::provider::ProviderRegistry::new();
    registry.register_control_cert(Arc::new(certified_key), vec!["trustless".to_owned()]);

    // Build TLS config
    let cert_resolver = Arc::new(crate::signer::CertResolver::new(registry));
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

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

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_state = crate::control::server::ServerState::new(shutdown_tx);
    let app = crate::control::server::dispatch_router(server_state);

    // Serve
    let result = serve(listener, tls_acceptor, app, shutdown_rx).await;

    // Cleanup
    crate::control::ProxyState::remove();
    tracing::info!("State file removed, proxy stopped");

    result
}

async fn serve(
    listener: tokio::net::TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    app: axum::Router,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let (close_tx, close_rx) = tokio::sync::watch::channel(());
    let mut connections = tokio::task::JoinSet::new();

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

            let acceptor = tls_acceptor.clone();
            let app = app.clone();
            let close_rx = close_rx.clone();

            connections.spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(addr = %addr, error = %e, "TLS handshake failed");
                        return;
                    }
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let service = hyper_util::service::TowerToHyperService::new(app);

                let builder = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );
                let conn = builder.serve_connection(io, service);

                // Use graceful shutdown on connection
                let conn = conn.into_owned();
                tokio::pin!(conn);

                let mut close_rx = close_rx;
                loop {
                    tokio::select! {
                        result = conn.as_mut() => {
                            if let Err(e) = result {
                                tracing::debug!(addr = %addr, error = %e, "Connection error");
                            }
                            break;
                        }
                        _ = close_rx.changed() => {
                            conn.as_mut().graceful_shutdown();
                        }
                    }
                }
            });
        }
    };

    tokio::select! {
        _ = shutdown => {}
        _ = accept_loop => unreachable!(),
    }

    // Drain: signal all connections to graceful shutdown, wait up to 30s
    tracing::info!("Shutting down, draining connections...");
    drop(close_rx);
    let _ = close_tx.send(());

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(std::time::Duration::from_secs(30), drain)
        .await
        .is_err()
    {
        tracing::warn!("Drain timeout reached, dropping remaining connections");
    }

    Ok(())
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

    let d = daemonize::Daemonize::new().stderr(daemonize::Stdio::keep());

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

fn init_logging(log_to_file: bool) {
    let rust_log = std::env::var_os("RUST_LOG");

    // SAFETY: Called during program initialization in single-threaded context
    // before any threads are spawned.
    #[cfg(not(debug_assertions))]
    unsafe {
        std::env::remove_var("RUST_LOG");
    }

    if let Ok(l) = std::env::var("TRUSTLESS_LOG") {
        // SAFETY: Called during program initialization in single-threaded context
        unsafe {
            std::env::set_var("RUST_LOG", l);
        }
    }

    if log_to_file {
        if std::env::var_os("RUST_LOG").is_none() {
            // SAFETY: single-threaded init
            unsafe {
                std::env::set_var("RUST_LOG", "trustless=info");
            }
        }
        let log_dir = crate::config::log_dir_mkpath().expect("can't create log directory");
        let w = tracing_appender::rolling::daily(log_dir, "trustless.log");
        tracing_subscriber::fmt()
            .with_writer(w)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        if std::env::var_os("RUST_LOG").is_none() {
            // SAFETY: single-threaded init
            unsafe {
                std::env::set_var("RUST_LOG", "trustless=info");
            }
        }
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    // Restore original RUST_LOG
    if let Some(v) = rust_log {
        // SAFETY: single-threaded init
        unsafe {
            std::env::set_var("RUST_LOG", v);
        }
    } else {
        // SAFETY: single-threaded init
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
    }
}

#[tokio::main]
async fn run_stop(_args: &ProxyStopArgs) -> anyhow::Result<()> {
    let client = crate::control::Client::from_state()
        .map_err(|_| anyhow::anyhow!("no proxy is running (proxy.json not found or invalid)"))?;
    client.stop().await?;
    eprintln!("trustless: proxy stop requested");
    Ok(())
}
