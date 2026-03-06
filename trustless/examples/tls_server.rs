#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = trustless::config::Config::load()?;
    let profile = config.load_profile("default")?;

    eprintln!("spawning provider: {:?}", profile.command);
    let registry = trustless::provider::ProviderRegistry::new();
    let orchestrator = trustless::provider::ProviderOrchestrator::new(registry.clone());

    orchestrator.add_provider("default", profile).await?;
    eprintln!("provider initialized");

    let addr = format!("127.0.0.1:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let registry = registry.clone();

        tokio::spawn(async move {
            let acceptor =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
            tokio::pin!(acceptor);

            let start = match acceptor.as_mut().await {
                Ok(start) => start,
                Err(e) => {
                    eprintln!("{peer}: TLS accept failed: {e}");
                    return;
                }
            };

            let sni = start.client_hello().server_name().map(|s| s.to_owned());
            let sni_display = sni.as_deref().unwrap_or("<none>").to_owned();

            let certified_key = match registry.resolve_by_sni(sni.as_deref()) {
                Some(ck) => ck,
                None => {
                    eprintln!("{peer}: no certificate for SNI {sni_display}");
                    return;
                }
            };

            let resolver =
                std::sync::Arc::new(trustless::signer::FixedCertResolver::new(certified_key));
            let server_config = std::sync::Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(resolver),
            );

            let mut tls_stream = match start.into_stream(server_config).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{peer}: TLS handshake failed: {e}");
                    return;
                }
            };

            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            // Read request (discard)
            let mut buf = [0u8; 4096];
            let _ = tls_stream.read(&mut buf).await;

            let body = format!("Hello from trustless TLS server!\nSNI: {sni_display}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );

            let _ = tls_stream.write_all(response.as_bytes()).await;
            let _ = tls_stream.shutdown().await;
            eprintln!("{peer}: sni={sni_display} -> 200 OK");
        });
    }
}
