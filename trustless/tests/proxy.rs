/// Start a mock backend HTTP server, returning its socket address.
async fn start_mock_backend(
    handler: axum::Router,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, handler).await.unwrap();
    });
    (addr, handle)
}

/// Start the proxy server, returning its socket address.
async fn start_proxy(
    route_table: trustless::route::RouteTable,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let state = trustless::proxy::ProxyState::new(
        route_table,
        trustless::provider::ProviderRegistry::new(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = trustless::proxy::proxy_router(state)
        .layer(axum::Extension(trustless::proxy::ClientAddr(addr)))
        .layer(axum::Extension(trustless::proxy::RequestScheme::Https));
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn test_end_to_end_forwarding() {
    let backend = axum::Router::new().route(
        "/hello",
        axum::routing::get(|| async { "Hello from backend" }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "test.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/hello"))
        .header("Host", "test.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "Hello from backend");
}

#[tokio::test]
async fn test_redirect_passed_through() {
    let backend = axum::Router::new().route(
        "/old",
        axum::routing::get(|| async { axum::response::Redirect::to("/new") }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "redir.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    // Use a client that does NOT follow redirects so we can inspect the 3xx
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = client
        .get(format!("http://{proxy_addr}/old"))
        .header("Host", "redir.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        303,
        "Proxy must pass redirect responses through, not follow them"
    );
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/new"
    );
}

#[tokio::test]
async fn test_no_route_returns_404() {
    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/"))
        .header("Host", "unknown.host")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("no route for host: unknown.host"),
        "plain text body: {body}"
    );
    assert!(
        body.contains("trustless exec"),
        "should include usage hint: {body}"
    );
}

#[tokio::test]
async fn test_no_route_html_for_browser() {
    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "existing.lo.dev.invalid",
            "127.0.0.1:3000".parse().unwrap(),
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/"))
        .header("Host", "unknown.host")
        .header("Accept", "text/html,application/xhtml+xml")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("text/html"),
        "content-type: {content_type}"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("<!DOCTYPE html>"), "should be HTML: {body}");
    assert!(
        body.contains("unknown.host"),
        "should mention the host: {body}"
    );
    assert!(
        body.contains("existing.lo.dev.invalid"),
        "should list active routes: {body}"
    );
}

#[tokio::test]
async fn test_backend_refused_returns_502() {
    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    // Point to a port that is not listening
    let dead_addr: std::net::SocketAddr = "127.0.0.1:19999".parse().unwrap();
    route_table
        .add_route("dead.lo.dev.invalid", dead_addr, None, false, false, false)
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/"))
        .header("Host", "dead.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("failed to connect to backend 127.0.0.1:19999"),
        "body: {body}"
    );
}

#[tokio::test]
async fn test_reserved_host_returns_503() {
    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/"))
        .header("Host", "trustless")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 503);
    let body = resp.text().await.unwrap();
    assert!(body.contains("reserved hostname"), "body: {body}");
}

#[tokio::test]
async fn test_forwarded_headers_present() {
    let backend = axum::Router::new().route(
        "/headers",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let xff = headers
                .get("X-Forwarded-For")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            let xfp = headers
                .get("X-Forwarded-Proto")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            let xfh = headers
                .get("X-Forwarded-Host")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            let fwd = headers
                .get("Forwarded")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            let host = headers
                .get("Host")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            format!("xff={xff}\nxfp={xfp}\nxfh={xfh}\nfwd={fwd}\nhost={host}")
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "headers.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/headers"))
        .header("Host", "headers.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    let body = resp.text().await.unwrap();
    assert!(body.contains("xff=127.0.0.1"), "body: {body}");
    assert!(body.contains("xfp=https"), "body: {body}");
    assert!(body.contains("xfh=headers.lo.dev.invalid"), "body: {body}");
    assert!(body.contains("proto=https"), "body: {body}");
    // Original Host preserved
    assert!(body.contains("host=headers.lo.dev.invalid"), "body: {body}");
}

#[tokio::test]
async fn test_websocket_upgrade() {
    // Start a WebSocket echo backend using axum's websocket extractor
    let backend = axum::Router::new().route("/ws", axum::routing::get(ws_echo_handler));
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route("ws.lo.dev.invalid", backend_addr, None, false, false, false)
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    // Connect via the proxy using tokio-tungstenite
    let url = format!("ws://{proxy_addr}/ws");
    let request = http::Request::builder()
        .uri(&url)
        .header("Host", "ws.lo.dev.invalid")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .unwrap();

    let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket handshake failed");

    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    // Send a message
    ws.send(Message::Text("hello proxy".into())).await.unwrap();

    // Receive echoed message
    let msg = ws.next().await.unwrap().unwrap();
    match msg {
        Message::Text(text) => assert_eq!(text, "hello proxy"),
        other => panic!("unexpected message: {other:?}"),
    }

    ws.close(None).await.ok();
}

#[tokio::test]
async fn test_hop_by_hop_headers_stripped_from_request() {
    let backend = axum::Router::new().route(
        "/check",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let has_te = headers.contains_key("te");
            let has_proxy_auth = headers.contains_key("proxy-authorization");
            let has_via = headers
                .get("via")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            format!("te={has_te}\nproxy_auth={has_proxy_auth}\nvia={has_via}")
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "hop.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let resp = client
        .get(format!("http://{proxy_addr}/check"))
        .header("Host", "hop.lo.dev.invalid")
        .header("TE", "trailers")
        .header("Proxy-Authorization", "Basic dXNlcjpwYXNz")
        .send()
        .await
        .unwrap();

    let body = resp.text().await.unwrap();
    assert!(body.contains("te=false"), "TE should be stripped: {body}");
    assert!(
        body.contains("proxy_auth=false"),
        "Proxy-Authorization should be stripped: {body}"
    );
    assert!(
        body.contains("via=1.1 trustless"),
        "Via header should be present: {body}"
    );
}

#[tokio::test]
async fn test_hop_by_hop_headers_stripped_from_response() {
    let backend = axum::Router::new().route(
        "/resp",
        axum::routing::get(|| async {
            let mut resp = axum::response::Response::new(axum::body::Body::from("ok"));
            resp.headers_mut()
                .insert("trailer", "X-Checksum".parse().unwrap());
            resp.headers_mut()
                .insert("x-custom-keep", "kept".parse().unwrap());
            resp
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "resp.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/resp"))
        .header("Host", "resp.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    assert!(
        resp.headers().get("trailer").is_none(),
        "Trailer header should be stripped from response"
    );
    assert_eq!(
        resp.headers()
            .get("x-custom-keep")
            .unwrap()
            .to_str()
            .unwrap(),
        "kept"
    );
    assert_eq!(
        resp.headers().get("via").unwrap().to_str().unwrap(),
        "1.1 trustless"
    );
}

#[tokio::test]
async fn test_loop_detection_returns_508() {
    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    let backend_addr: std::net::SocketAddr = "127.0.0.1:19999".parse().unwrap();
    route_table
        .add_route(
            "loop.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/"))
        .header("Host", "loop.lo.dev.invalid")
        .header("x-trustless-hops", "5")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 508);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("loop detected for loop.lo.dev.invalid"),
        "body: {body}"
    );
}

#[tokio::test]
async fn test_hops_below_threshold_allowed() {
    let backend = axum::Router::new().route(
        "/hops",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            headers
                .get("x-trustless-hops")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default()
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "hops.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/hops"))
        .header("Host", "hops.lo.dev.invalid")
        .header("x-trustless-hops", "3")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    // Hops should be incremented to 4
    let body = resp.text().await.unwrap();
    assert_eq!(body, "4", "hops should be incremented: {body}");
}

#[tokio::test]
async fn test_cookie_header_forwarded() {
    let backend = axum::Router::new().route(
        "/cookies",
        axum::routing::get(|headers: axum::http::HeaderMap| async move {
            let cookies: Vec<String> = headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect();
            cookies.join("\n")
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "cookie.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    // Single cookie header passes through unchanged
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/cookies"))
        .header("Host", "cookie.lo.dev.invalid")
        .header(http::header::COOKIE, "a=1; b=2")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "a=1; b=2", "cookie header should be forwarded as-is");
}

#[tokio::test]
async fn test_websocket_upgrade_uses_origin_form() {
    // Backend that records the request line and replies with a minimal 101.
    // A raw TCP listener is used so we observe the actual wire bytes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let (request_line_tx, request_line_rx) = tokio::sync::oneshot::channel::<String>();

    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).await.unwrap();
        let _ = request_line_tx.send(request_line.trim_end().to_string());

        let mut line = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let response = "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
             \r\n";
        write_half.write_all(response.as_bytes()).await.unwrap();
        let _ = write_half.shutdown().await;
    });

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "ws-form.lo.dev.invalid",
            backend_addr,
            None,
            false,
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let url = format!("ws://{proxy_addr}/some/path?x=1");
    let request = http::Request::builder()
        .uri(&url)
        .header("Host", "ws-form.lo.dev.invalid")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();

    let _ = tokio_tungstenite::connect_async(request).await;

    let request_line = tokio::time::timeout(std::time::Duration::from_secs(5), request_line_rx)
        .await
        .expect("backend never received a request")
        .expect("request-line channel dropped");

    assert!(
        request_line.starts_with("GET /some/path?x=1 HTTP/1.1"),
        "expected origin-form request line, got: {request_line:?}"
    );
}

async fn ws_echo_handler(ws: axum::extract::WebSocketUpgrade) -> impl axum::response::IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        use axum::extract::ws::Message;
        while let Some(Ok(msg)) = socket.recv().await {
            match msg {
                Message::Text(text) => {
                    if socket.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    })
}

/// Start a mock HTTPS backend serving `handler` with a self-signed cert. ALPN offers both
/// HTTP/2 and HTTP/1.1 so the proxy's negotiated version is observable by the handler.
async fn start_mock_tls_backend(
    handler: axum::Router,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(move |req: http::Request<_>| {
                    let handler = handler.clone();
                    async move {
                        use tower::ServiceExt as _;
                        handler.oneshot(req.map(axum::body::Body::new)).await
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls), service)
                .await;
            });
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn test_tls_backend_forwarding_negotiates_http2() {
    // The handler echoes back the HTTP version it observed, so we can assert the proxy
    // both spoke TLS and negotiated HTTP/2 with the backend via ALPN.
    let backend = axum::Router::new().route(
        "/proto",
        axum::routing::get(|req: http::Request<axum::body::Body>| async move {
            format!("{:?}", req.version())
        }),
    );
    let (backend_addr, _backend_handle) = start_mock_tls_backend(backend).await;

    let dir = tempfile::tempdir().unwrap();
    let route_table = trustless::route::RouteTable::new(dir.path().to_path_buf());
    route_table
        .add_route(
            "tls.lo.dev.invalid",
            backend_addr,
            None,
            true, // tls
            false,
            false,
        )
        .unwrap();

    let (proxy_addr, _proxy_handle) = start_proxy(route_table).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/proto"))
        .header("Host", "tls.lo.dev.invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.text().await.unwrap(),
        "HTTP/2.0",
        "TLS backend with h2 ALPN should be reached over HTTP/2"
    );
}
