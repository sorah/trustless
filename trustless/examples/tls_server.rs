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
    let client = std::sync::Arc::new(
        trustless_protocol::client::ProviderClient::spawn(&profile.command).await?,
    );

    let handle = trustless::signer::SigningThread::start(
        tokio::runtime::Handle::current(),
        client.clone(),
        std::time::Duration::from_secs(profile.sign_timeout_seconds),
    );

    eprintln!("calling initialize...");
    let init = client.initialize().await?;
    eprintln!("default certificate: {}", init.default);
    for cert in &init.certificates {
        eprintln!(
            "  id={} domains={:?} schemes={:?}",
            cert.id, cert.domains, cert.schemes,
        );
    }

    let registry = trustless::signer::ProviderRegistry::new();
    registry.add_provider(init, handle)?;

    let resolver = trustless::signer::CertResolver::new(registry);
    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(std::sync::Arc::new(resolver)),
    );

    let addr = format!("127.0.0.1:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

                    let sni = tls_stream
                        .get_ref()
                        .1
                        .server_name()
                        .unwrap_or("<none>")
                        .to_owned();

                    // Read request (discard)
                    let mut buf = [0u8; 4096];
                    let _ = tls_stream.read(&mut buf).await;

                    let body = format!("Hello from trustless TLS server!\nSNI: {sni}\n");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );

                    let _ = tls_stream.write_all(response.as_bytes()).await;
                    let _ = tls_stream.shutdown().await;
                    eprintln!("{peer}: sni={sni} -> 200 OK");
                }
                Err(e) => {
                    eprintln!("{peer}: TLS handshake failed: {e}");
                }
            }
        });
    }
}
