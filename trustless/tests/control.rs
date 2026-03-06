use std::sync::Arc;

fn generate_test_cert() -> (
    Arc<rustls::sign::CertifiedKey>,
    rustls_pki_types::CertificateDer<'static>,
    String,
) {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["trustless".to_owned()]).unwrap();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("trustless".to_owned()),
    );
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der).unwrap();
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
        vec![cert_der.clone()],
        signing_key,
    ));
    (certified_key, cert_der, cert_pem)
}

fn start_test_server(
    certified_key: Arc<rustls::sign::CertifiedKey>,
) -> (
    tokio::task::JoinHandle<()>,
    u16,
    tokio::sync::oneshot::Receiver<()>,
) {
    let cert_resolver = Arc::new(trustless::signer::FixedCertResolver::new(certified_key));
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_state = trustless::control::server::ServerState::new(shutdown_tx);
    let stub_proxy = axum::Router::new()
        .fallback(|| async { (axum::http::StatusCode::BAD_GATEWAY, "no backend") });
    let app = trustless::control::server::dispatch_router(server_state, stub_proxy);

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };

            let acceptor = tls_acceptor.clone();
            let app = app.clone();

            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let service = hyper_util::service::TowerToHyperService::new(app);

                let builder = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );
                let _ = builder.serve_connection(io, service).await;
            });
        }
    });

    (handle, port, shutdown_rx)
}

/// Start a proxy in-process, connect with Client, ping, stop, verify shutdown signal.
#[tokio::test]
async fn proxy_lifecycle_in_process() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (certified_key, _cert_der, cert_pem) = generate_test_cert();
    let (server_handle, port, shutdown_rx) = start_test_server(certified_key);

    // Give server a moment to start accepting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Build client directly from proxy state (no filesystem dependency)
    let state = trustless::control::ProxyState {
        pid: std::process::id(),
        port,
        control_cert_pem: cert_pem,
    };
    let client = trustless::control::Client::from_proxy_state(&state).unwrap();

    // Ping
    client.ping().await.unwrap();

    // Stop
    client.stop().await.unwrap();

    // Verify shutdown signal was sent
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(shutdown_rx.await.is_ok());

    server_handle.abort();
}

/// Verify TLS handshake with the self-signed cert for SNI=trustless
#[tokio::test]
async fn tls_handshake_with_control_cert() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (certified_key, cert_der, _cert_pem) = generate_test_cert();

    let cert_resolver = Arc::new(trustless::signer::FixedCertResolver::new(certified_key));
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _tls_stream = tls_acceptor.accept(stream).await.unwrap();
    });

    // Connect with TLS client that trusts the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("trustless").unwrap();
    let _tls = connector.connect(server_name, tcp).await.unwrap();

    accept_handle.await.unwrap();
}
