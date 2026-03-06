fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn setup_cert_dir(domain: &str, sans: Vec<String>) -> (tempfile::TempDir, rcgen::Certificate) {
    let dir = tempfile::tempdir().unwrap();
    let domain_path = dir.path().join("certs").join(domain);
    let version_path = domain_path.join("v1");
    std::fs::create_dir_all(&version_path).unwrap();
    std::fs::write(domain_path.join("current"), "v1").unwrap();

    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(sans).unwrap();
    std::fs::write(version_path.join("fullchain.pem"), cert.pem()).unwrap();
    std::fs::write(version_path.join("key.pem"), key_pair.serialize_pem()).unwrap();

    (dir, cert)
}

fn stub_provider_binary() -> std::path::PathBuf {
    // The test binary lives in target/debug/deps/; the stub provider binary is in target/debug/
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove the test binary name
    path.pop(); // remove "deps"
    path.push("trustless-provider-stub");
    assert!(
        path.exists(),
        "stub provider binary not found at {}; run `cargo build -p trustless-provider-stub` first",
        path.display()
    );
    path
}

fn stub_provider_command(cert_dir: &std::path::Path) -> Vec<String> {
    vec![
        stub_provider_binary().to_str().unwrap().to_owned(),
        "--cert-dir".to_owned(),
        cert_dir.to_str().unwrap().to_owned(),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_provider_and_resolve_sni() {
    let (dir, _cert) = setup_cert_dir(
        "example.com",
        vec!["example.com".to_owned(), "*.example.com".to_owned()],
    );

    let command = stub_provider_command(dir.path());
    let process = trustless::provider::process::ProviderProcess::spawn(&command)
        .await
        .unwrap();
    let (client, _stderr, mut child) = process.into_parts();
    let client = std::sync::Arc::new(client);

    let handle = trustless::signer::SigningWorker::start(
        client.clone(),
        std::time::Duration::from_secs(trustless::config::default_sign_timeout_seconds()),
    );

    let init = client.initialize().await.unwrap();
    let registry = trustless::provider::ProviderRegistry::new();
    registry.add_provider(init, handle).unwrap();

    // Exact match
    let resolved = registry.resolve_by_sni(Some("example.com"));
    assert!(resolved.is_some());

    // Wildcard match
    let resolved = registry.resolve_by_sni(Some("api.example.com"));
    assert!(resolved.is_some());

    // No match — falls back to default
    let resolved = registry.resolve_by_sni(Some("other.invalid"));
    assert!(resolved.is_some()); // default fallback

    // No SNI — falls back to default
    let resolved = registry.resolve_by_sni(None);
    assert!(resolved.is_some());

    child.kill().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_tls_handshake() {
    install_crypto_provider();
    use rustls_pki_types::pem::PemObject as _;

    let (dir, cert) = setup_cert_dir("localhost", vec!["localhost".to_owned()]);

    let command = stub_provider_command(dir.path());
    let process = trustless::provider::process::ProviderProcess::spawn(&command)
        .await
        .unwrap();
    let (client, _stderr, mut child) = process.into_parts();
    let client = std::sync::Arc::new(client);

    let handle = trustless::signer::SigningWorker::start(
        client.clone(),
        std::time::Duration::from_secs(trustless::config::default_sign_timeout_seconds()),
    );

    let init = client.initialize().await.unwrap();
    let registry = trustless::provider::ProviderRegistry::new();
    registry.add_provider(init, handle).unwrap();

    let certified_key = registry.resolve_by_sni(Some("localhost")).unwrap();
    let resolver = trustless::signer::FixedCertResolver::new(certified_key);

    // Build server config
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(resolver));

    // Build client config with the self-signed cert as trust anchor
    let cert_der = rustls_pki_types::CertificateDer::from_pem_slice(cert.pem().as_bytes()).unwrap();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set up a TCP listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_config = std::sync::Arc::new(server_config);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        use tokio::io::AsyncWriteExt as _;
        tls_stream.write_all(b"hello from server").await.unwrap();
        tls_stream.shutdown().await.unwrap();
    });

    let client_config = std::sync::Arc::new(client_config);
    let client_task = tokio::spawn(async move {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        tls_stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello from server");
    });

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    server_result.unwrap();
    client_result.unwrap();

    child.kill().await.unwrap();
}
