const VIA_VALUE: &str = "1.1 trustless";

#[derive(thiserror::Error, Debug)]
enum ProxyError {
    #[error("no Host header")]
    NoHostHeader,
    #[error("proxy control API not yet implemented")]
    ControlApiNotImplemented,
    #[error(
        "loop detected for {host}: request has passed through trustless {hops} times. \
         This usually means a backend is proxying back through trustless without \
         rewriting the Host header."
    )]
    LoopDetected { host: String, hops: u32 },
    #[error("no route for host: {0}")]
    NoRoute(String),
    #[error("route resolution error: {0}")]
    RouteResolution(crate::route::RouteError),
    #[error("failed to connect to backend {backend}: {source}")]
    BackendConnect {
        backend: std::net::SocketAddr,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("failed to send request to backend {backend}: {source}")]
    BackendRequest {
        backend: std::net::SocketAddr,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl ProxyError {
    fn status(&self) -> http::StatusCode {
        match self {
            Self::NoRoute(_) => http::StatusCode::NOT_FOUND,
            Self::ControlApiNotImplemented => http::StatusCode::SERVICE_UNAVAILABLE,
            Self::LoopDetected { .. } => http::StatusCode::LOOP_DETECTED,
            _ => http::StatusCode::BAD_GATEWAY,
        }
    }
}

struct ErrorResponse {
    error: ProxyError,
    accepts_html: bool,
    routes: Option<std::collections::HashMap<String, crate::route::RouteEntry>>,
}

impl axum::response::IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        let status = self.error.status();

        if !self.accepts_html {
            let body = match &self.error {
                ProxyError::NoRoute(host) => {
                    let routes = self.routes.as_ref().cloned().unwrap_or_default();
                    crate::error_page::render_404_text(host, &routes)
                }
                ProxyError::LoopDetected { .. } => {
                    format!(
                        "{}\nIf you use Vite/webpack proxy, set changeOrigin: true.\n",
                        self.error,
                    )
                }
                _ => format!("{}\n", self.error),
            };
            return (status, [(http::header::CONTENT_TYPE, "text/plain")], body).into_response();
        }

        let html = match &self.error {
            ProxyError::NoRoute(host) => {
                let routes = self.routes.as_ref().cloned().unwrap_or_default();
                crate::error_page::render_404_page(host, &routes)
            }
            ProxyError::BackendConnect { backend, .. } => {
                crate::error_page::render_502_page(*backend, "is not responding")
            }
            ProxyError::BackendRequest { backend, .. } => {
                crate::error_page::render_502_page(*backend, "failed to send request")
            }
            ProxyError::LoopDetected { host, hops } => {
                crate::error_page::render_508_page(host, *hops)
            }
            _ => {
                // For other errors (NoHostHeader, ControlApiNotImplemented, RouteResolution),
                // fall back to plain text
                return (
                    status,
                    [(http::header::CONTENT_TYPE, "text/plain")],
                    format!("{}\n", self.error),
                )
                    .into_response();
            }
        };

        (
            status,
            [(http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response()
    }
}

/// Custom header tracking how many times a request has passed through the
/// trustless proxy. Used to detect forwarding loops (e.g. a dev server proxying
/// back through trustless without rewriting the Host header).
const HOPS_HEADER: &str = "x-trustless-hops";

/// Maximum number of proxy hops before rejecting the request as a loop.
/// Two hops is normal when a frontend proxies API calls to a separate backend;
/// five gives headroom for multi-tier setups while catching loops quickly.
const MAX_PROXY_HOPS: u32 = 5;

#[derive(Clone, Copy, Debug)]
pub struct ClientAddr(pub std::net::SocketAddr);

#[derive(Clone)]
pub struct ProxyState {
    pub route_table: crate::route::RouteTable,
    pub client: reqwest::Client,
}

pub fn proxy_router(state: ProxyState) -> axum::Router {
    axum::Router::new()
        .fallback(proxy_handler)
        .with_state(std::sync::Arc::new(state))
}

fn accepts_html(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<ProxyState>>,
    axum::Extension(ClientAddr(client_addr)): axum::Extension<ClientAddr>,
    req: axum::extract::Request,
) -> Result<axum::response::Response, ErrorResponse> {
    let start = std::time::Instant::now();

    let wants_html = accepts_html(req.headers());
    let route_table = state.route_table.clone();

    let mk_err = move |error: ProxyError| {
        let routes = match &error {
            ProxyError::NoRoute(_) => route_table.list_routes().ok(),
            _ => None,
        };
        ErrorResponse {
            error,
            accepts_html: wants_html,
            routes,
        }
    };

    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.uri().host().map(|h| match req.uri().port_u16() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        })
        .ok_or_else(|| mk_err(ProxyError::NoHostHeader))?;

    let host_without_port = crate::route::strip_port(&host);

    // Reserved hostname
    if host_without_port.eq_ignore_ascii_case("trustless") {
        return Err(mk_err(ProxyError::ControlApiNotImplemented));
    }

    // Loop prevention
    let hops: u32 = req
        .headers()
        .get(HOPS_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if hops >= MAX_PROXY_HOPS {
        tracing::warn!(host = %host, hops = hops, "loop detected");
        return Err(mk_err(ProxyError::LoopDetected {
            host: host.clone(),
            hops,
        }));
    }

    let backend = match state.route_table.resolve(&host) {
        Ok(Some(addr)) => addr,
        Ok(None) => {
            tracing::warn!(host = %host, "no route found");
            return Err(mk_err(ProxyError::NoRoute(host)));
        }
        Err(e) => {
            tracing::error!(host = %host, error = %e, "route resolution error");
            return Err(mk_err(ProxyError::RouteResolution(e)));
        }
    };

    let is_upgrade = req
        .headers()
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_lowercase().contains("upgrade"));

    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map_or("/".to_string(), |pq| pq.to_string());

    let response = if is_upgrade {
        handle_upgrade(state, client_addr, req, backend, &host, hops)
            .await
            .map_err(&mk_err)?
    } else {
        handle_request(state, client_addr, req, backend, &host, hops)
            .await
            .map_err(&mk_err)?
    };

    let status = response.status();
    let duration = start.elapsed();
    tracing::info!(
        method = %method,
        host = %host,
        path = %path,
        backend = %backend,
        status = status.as_u16(),
        duration_ms = duration.as_millis() as u64,
        "proxied request"
    );

    Ok(response)
}

fn build_forwarded_headers(
    client_addr: std::net::SocketAddr,
    original_host: &str,
    proto: &str,
) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "X-Forwarded-For",
        client_addr.ip().to_string().parse().unwrap(),
    );
    headers.insert("X-Forwarded-Proto", proto.parse().unwrap());
    headers.insert("X-Forwarded-Host", original_host.parse().unwrap());
    headers.insert(
        "Forwarded",
        format!(
            "for={};host=\"{}\";proto={}",
            client_addr.ip(),
            original_host,
            proto
        )
        .parse()
        .unwrap(),
    );
    headers
}

/// Well-known hop-by-hop headers that must not be forwarded by proxies (RFC 7230 §6.1).
const HOP_BY_HOP_HEADERS: &[http::header::HeaderName] = &[
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
];

/// Strip hop-by-hop headers from a header map.
///
/// Removes well-known hop-by-hop headers and any headers listed in the `Connection` header value.
/// When `preserve_upgrade` is true, keeps `Connection: upgrade` and `Upgrade` intact for WebSocket.
fn strip_hop_by_hop_headers(headers: &mut http::HeaderMap, preserve_upgrade: bool) {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }

    // Parse Connection header to find additional headers to remove
    let connection_tokens: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_lowercase()))
        .collect();

    for token in &connection_tokens {
        if preserve_upgrade && token == "upgrade" {
            continue;
        }
        if let Ok(name) = http::header::HeaderName::from_bytes(token.as_bytes()) {
            headers.remove(&name);
        }
    }

    if preserve_upgrade {
        // Keep Connection header but only with "upgrade" value
        let has_upgrade = connection_tokens.iter().any(|t| t == "upgrade");
        headers.remove(http::header::CONNECTION);
        if has_upgrade {
            headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("upgrade"),
            );
        }
    } else {
        headers.remove(http::header::CONNECTION);
    }
}

async fn handle_request(
    state: std::sync::Arc<ProxyState>,
    client_addr: std::net::SocketAddr,
    req: axum::extract::Request,
    backend: std::net::SocketAddr,
    original_host: &str,
    hops: u32,
) -> Result<axum::response::Response, ProxyError> {
    let (mut parts, body) = req.into_parts();
    let url = format!(
        "http://{}{}",
        backend,
        parts.uri.path_and_query().map_or("/", |pq| pq.as_str())
    );

    strip_hop_by_hop_headers(&mut parts.headers, false);
    parts.headers.remove(HOPS_HEADER);

    let forwarded = build_forwarded_headers(client_addr, original_host, "https");

    let mut request_builder = state
        .client
        .request(parts.method, &url)
        .headers(parts.headers.clone());

    // Set forwarded headers (after cloning original headers so they take precedence)
    for (key, value) in &forwarded {
        request_builder = request_builder.header(key, value);
    }

    // Preserve the original Host header, add Via, and increment hops
    request_builder = request_builder.header(http::header::HOST, original_host);
    request_builder = request_builder.header(http::header::VIA, VIA_VALUE);
    request_builder = request_builder.header(HOPS_HEADER, (hops + 1).to_string());

    request_builder = request_builder.body(reqwest::Body::wrap_stream(body.into_data_stream()));

    let upstream_response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(backend = %backend, error = %e, "failed to send request to backend");
            return Err(ProxyError::BackendConnect {
                backend,
                source: Box::new(e),
            });
        }
    };

    let mut response_headers = upstream_response.headers().clone();
    strip_hop_by_hop_headers(&mut response_headers, false);

    let mut response_builder =
        axum::response::Response::builder().status(upstream_response.status());
    for (key, value) in &response_headers {
        response_builder = response_builder.header(key, value);
    }
    response_builder = response_builder.header(http::header::VIA, VIA_VALUE);
    let body = axum::body::Body::from_stream(upstream_response.bytes_stream());
    Ok(response_builder.body(body).unwrap())
}

async fn handle_upgrade(
    _state: std::sync::Arc<ProxyState>,
    client_addr: std::net::SocketAddr,
    req: axum::extract::Request,
    backend: std::net::SocketAddr,
    original_host: &str,
    hops: u32,
) -> Result<axum::response::Response, ProxyError> {
    let forwarded = build_forwarded_headers(client_addr, original_host, "https");

    // Build the request to the backend
    let (mut parts, _body) = req.into_parts();

    let backend_url = format!(
        "http://{}{}",
        backend,
        parts.uri.path_and_query().map_or("/", |pq| pq.as_str())
    );

    strip_hop_by_hop_headers(&mut parts.headers, true);
    parts.headers.remove(HOPS_HEADER);

    // We need to use hyper directly for upgrade support
    let uri: http::Uri = backend_url.parse().unwrap();
    let mut backend_req = http::Request::builder().method(&parts.method).uri(&uri);

    // Copy headers
    for (key, value) in &parts.headers {
        backend_req = backend_req.header(key, value);
    }
    // Add forwarded headers
    for (key, value) in &forwarded {
        backend_req = backend_req.header(key, value);
    }
    // Preserve original Host, add Via, and increment hops
    backend_req = backend_req.header(http::header::HOST, original_host);
    backend_req = backend_req.header(http::header::VIA, VIA_VALUE);
    backend_req = backend_req.header(HOPS_HEADER, (hops + 1).to_string());

    let backend_req = backend_req
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();

    let stream = match tokio::net::TcpStream::connect(backend.to_string()).await {
        Ok(s) => s,
        Err(e) => {
            return Err(ProxyError::BackendConnect {
                backend,
                source: Box::new(e),
            });
        }
    };

    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await {
            Ok(r) => r,
            Err(e) => {
                return Err(ProxyError::BackendConnect {
                    backend,
                    source: Box::new(e),
                });
            }
        };

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::error!(error = %e, "backend connection error");
        }
    });

    let backend_response = match sender.send_request(backend_req).await {
        Ok(r) => r,
        Err(e) => {
            return Err(ProxyError::BackendRequest {
                backend,
                source: Box::new(e),
            });
        }
    };

    if backend_response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        // Upgrade the client connection
        let mut response_headers = backend_response.headers().clone();
        strip_hop_by_hop_headers(&mut response_headers, true);

        let mut client_response =
            axum::response::Response::builder().status(http::StatusCode::SWITCHING_PROTOCOLS);
        for (key, value) in &response_headers {
            client_response = client_response.header(key, value);
        }
        client_response = client_response.header(http::header::VIA, VIA_VALUE);

        // Spawn the bidirectional copy after client upgrade completes
        let client_req = http::Request::from_parts(parts, axum::body::Body::empty());
        let backend_upgraded = hyper::upgrade::on(backend_response).await;

        tokio::spawn(async move {
            let client_upgraded = hyper::upgrade::on(client_req).await;
            match (client_upgraded, backend_upgraded) {
                (Ok(client_io), Ok(backend_io)) => {
                    let mut client_io = hyper_util::rt::TokioIo::new(client_io);
                    let mut backend_io = hyper_util::rt::TokioIo::new(backend_io);
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut client_io, &mut backend_io).await
                    {
                        tracing::debug!(error = %e, "upgrade connection closed");
                    }
                }
                (Err(e), _) => {
                    tracing::error!(error = %e, "client upgrade failed");
                }
                (_, Err(e)) => {
                    tracing::error!(error = %e, "backend upgrade failed");
                }
            }
        });

        Ok(client_response.body(axum::body::Body::empty()).unwrap())
    } else {
        // Not an upgrade response, return as-is
        let mut response_headers = backend_response.headers().clone();
        strip_hop_by_hop_headers(&mut response_headers, false);

        let mut response_builder =
            axum::response::Response::builder().status(backend_response.status());
        for (key, value) in &response_headers {
            response_builder = response_builder.header(key, value);
        }
        response_builder = response_builder.header(http::header::VIA, VIA_VALUE);
        use http_body_util::BodyExt as _;
        let body = backend_response
            .into_body()
            .collect()
            .await
            .map(|collected: http_body_util::Collected<bytes::Bytes>| collected.to_bytes())
            .unwrap_or_default();
        Ok(response_builder.body(axum::body::Body::from(body)).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarded_headers() {
        let addr: std::net::SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let headers = build_forwarded_headers(addr, "api.example.com", "http");

        assert_eq!(
            headers.get("X-Forwarded-For").unwrap().to_str().unwrap(),
            "192.168.1.100"
        );
        assert_eq!(
            headers.get("X-Forwarded-Proto").unwrap().to_str().unwrap(),
            "http"
        );
        assert_eq!(
            headers.get("X-Forwarded-Host").unwrap().to_str().unwrap(),
            "api.example.com"
        );
        let forwarded = headers.get("Forwarded").unwrap().to_str().unwrap();
        assert!(forwarded.contains("for=192.168.1.100"));
        assert!(forwarded.contains("host=\"api.example.com\""));
        assert!(forwarded.contains("proto=http"));
    }

    #[test]
    fn test_strip_hop_by_hop_removes_known_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::PROXY_AUTHENTICATE, "Basic".parse().unwrap());
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            "Bearer tok".parse().unwrap(),
        );
        headers.insert(http::header::TE, "trailers".parse().unwrap());
        headers.insert(http::header::TRAILER, "X-Checksum".parse().unwrap());
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers, false);

        assert!(headers.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(headers.get(http::header::PROXY_AUTHORIZATION).is_none());
        assert!(headers.get(http::header::TE).is_none());
        assert!(headers.get(http::header::TRAILER).is_none());
        assert!(headers.get(http::header::TRANSFER_ENCODING).is_none());
        assert!(headers.get(http::header::CONTENT_TYPE).is_some());
    }

    #[test]
    fn test_strip_hop_by_hop_removes_connection_linked_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, x-custom".parse().unwrap(),
        );
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-custom", "value".parse().unwrap());
        headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers, false);

        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("x-custom").is_none());
        assert!(headers.get(http::header::CONTENT_TYPE).is_some());
    }

    #[test]
    fn test_strip_hop_by_hop_preserves_upgrade() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::TE, "trailers".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers, true);

        assert_eq!(
            headers
                .get(http::header::CONNECTION)
                .unwrap()
                .to_str()
                .unwrap(),
            "upgrade"
        );
        assert_eq!(
            headers
                .get(http::header::UPGRADE)
                .unwrap()
                .to_str()
                .unwrap(),
            "websocket"
        );
        assert!(headers.get(http::header::TE).is_none());
    }

    #[test]
    fn test_strip_hop_by_hop_preserves_regular_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(http::header::AUTHORIZATION, "Bearer tok".parse().unwrap());
        headers.insert(http::header::ACCEPT, "text/html".parse().unwrap());

        strip_hop_by_hop_headers(&mut headers, false);

        assert_eq!(
            headers
                .get(http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
        assert_eq!(
            headers
                .get(http::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer tok"
        );
        assert_eq!(
            headers.get(http::header::ACCEPT).unwrap().to_str().unwrap(),
            "text/html"
        );
    }

    #[tokio::test]
    async fn test_host_header_preserved() {
        let backend = axum::Router::new().route(
            "/host-check",
            axum::routing::get(|headers: http::HeaderMap| async move {
                headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("missing")
                    .to_string()
            }),
        );
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(backend_listener, backend).await.unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let route_table = crate::route::RouteTable::new(dir.path().to_path_buf());
        route_table
            .add_route("my-app.lo.dev.invalid", backend_addr, None, false, false)
            .unwrap();

        let state = ProxyState {
            route_table,
            client: reqwest::Client::new(),
        };
        let app =
            proxy_router(state).layer(axum::Extension(ClientAddr("127.0.0.1:0".parse().unwrap())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{proxy_addr}/host-check"))
            .header("Host", "my-app.lo.dev.invalid")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert_eq!(
            body, "my-app.lo.dev.invalid",
            "Host header should be preserved as the original hostname, not rewritten to backend address"
        );
    }

    #[test]
    fn test_forwarded_headers_https() {
        let addr: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
        let headers = build_forwarded_headers(addr, "secure.example.com", "https");

        assert_eq!(
            headers.get("X-Forwarded-Proto").unwrap().to_str().unwrap(),
            "https"
        );
        let forwarded = headers.get("Forwarded").unwrap().to_str().unwrap();
        assert!(forwarded.contains("proto=https"));
    }
}
