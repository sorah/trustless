use rustls_pki_types::pem::PemObject as _;

#[derive(clap::Args)]
pub struct TestProviderArgs {
    /// Domain (SNI) to select a certificate for testing
    #[arg(long)]
    domain: Option<String>,

    /// Provider command line
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub async fn run(args: &TestProviderArgs) -> Result<(), anyhow::Error> {
    // Spawn provider
    eprintln!("Spawning provider: {:?}", args.command);
    let process = trustless_protocol::process::ProviderProcess::spawn(&args.command).await?;
    let (client, stderr, child) = process.into_parts();

    // Forward provider stderr to parent stderr
    tokio::spawn(async move {
        let mut stderr = stderr;
        let mut parent_stderr = tokio::io::stderr();
        let _ = tokio::io::copy(&mut stderr, &mut parent_stderr).await;
    });

    // Ensure child process is killed on all exit paths
    struct ChildGuard(Option<tokio::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(ref mut c) = self.0 {
                let _ = c.start_kill();
            }
        }
    }
    let _child_guard = ChildGuard(Some(child));

    let client = std::sync::Arc::new(client);

    // Initialize
    eprintln!("Initializing provider...");
    let init = client.initialize().await?;

    eprintln!("Provider initialized:");
    eprintln!("  default: {}", init.default);
    for cert in &init.certificates {
        eprintln!("  certificate: {}", cert.id);
        eprintln!("    domains: {}", cert.domains.join(", "));
        eprintln!("    schemes: {}", cert.schemes.join(", "));
    }

    // Select SNI domain (before consuming init)
    let domain = match &args.domain {
        Some(d) => {
            let d_lower = d.to_ascii_lowercase();
            let matched = init
                .certificates
                .iter()
                .any(|cert| crate::provider::registry::matches_sni(&d_lower, &cert.domains));
            if !matched {
                anyhow::bail!(
                    "domain {:?} does not match any certificate from the provider",
                    d,
                );
            }
            d.clone()
        }
        None => {
            let cert = init
                .certificates
                .iter()
                .find(|c| c.id == init.default)
                .or_else(|| init.certificates.first())
                .ok_or_else(|| anyhow::anyhow!("no certificates from provider"))?;
            cert.domains
                .iter()
                .find(|d| !d.starts_with("*."))
                .cloned()
                .or_else(|| {
                    cert.domains
                        .first()
                        .and_then(|d| d.strip_prefix("*."))
                        .map(|suffix| format!("test.{suffix}"))
                })
                .ok_or_else(|| anyhow::anyhow!("no domains in default certificate"))?
        }
    };

    // Collect PEM data for building client trust store (before consuming init)
    let pem_data: Vec<String> = init.certificates.iter().map(|c| c.pem.clone()).collect();

    // Register in a temporary registry
    let handle = crate::signer::SigningWorker::start(
        client.clone(),
        std::time::Duration::from_secs(crate::config::default_sign_timeout_seconds()),
    );
    let registry = crate::provider::ProviderRegistry::new();
    registry.add_provider(init, handle)?;

    eprintln!("Testing TLS handshake with SNI: {domain}");

    // Resolve CertifiedKey
    let certified_key = registry
        .resolve_by_sni(Some(&domain))
        .ok_or_else(|| anyhow::anyhow!("no certificate resolved for domain {:?}", domain))?;

    // Build server config
    let resolver = crate::signer::FixedCertResolver::new(certified_key);
    let server_config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(std::sync::Arc::new(resolver)),
    );

    // Build client config trusting the provider's cert
    let mut root_store = rustls::RootCertStore::empty();
    for pem in &pem_data {
        for cert_der in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert_der = cert_der?;
            let _ = root_store.add(cert_der);
        }
    }

    let client_config = std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    // Bind ephemeral TCP listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let test_payload = b"trustless-test-provider-ok";

    // Server task
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let mut tls_stream = acceptor.accept(stream).await?;

        use tokio::io::AsyncWriteExt as _;
        tls_stream.write_all(test_payload).await?;
        tls_stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    // Client task
    let domain_clone = domain.clone();
    let client_task = tokio::spawn(async move {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name = rustls_pki_types::ServerName::try_from(domain_clone.as_str())
            .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?
            .to_owned();
        let mut tls_stream = connector.connect(server_name, stream).await?;

        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf).await?;
        anyhow::ensure!(
            buf == test_payload,
            "unexpected payload: expected {:?}, got {:?}",
            String::from_utf8_lossy(test_payload),
            String::from_utf8_lossy(&buf),
        );
        Ok::<(), anyhow::Error>(())
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);

    let mut ok = true;
    match server_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("TLS server error: {e}");
            ok = false;
        }
        Err(e) => {
            eprintln!("TLS server task panicked: {e}");
            ok = false;
        }
    }
    match client_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("TLS client error: {e}");
            ok = false;
        }
        Err(e) => {
            eprintln!("TLS client task panicked: {e}");
            ok = false;
        }
    }

    if ok {
        eprintln!("OK: provider is working correctly");
        Ok(())
    } else {
        Err(anyhow::anyhow!("TLS handshake test failed"))
    }
}
