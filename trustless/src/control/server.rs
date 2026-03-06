use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

#[derive(Clone)]
pub struct ServerState {
    shutdown_tx: std::sync::Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    orchestrator: crate::provider::ProviderOrchestrator,
    registry: crate::provider::ProviderRegistry,
    route_table: crate::route::RouteTable,
    port: u16,
}

impl ServerState {
    pub fn new(
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        orchestrator: crate::provider::ProviderOrchestrator,
        registry: crate::provider::ProviderRegistry,
        route_table: crate::route::RouteTable,
        port: u16,
    ) -> Self {
        Self {
            shutdown_tx: std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx))),
            orchestrator,
            registry,
            route_table,
            port,
        }
    }
}

fn control_router(state: ServerState) -> axum::Router {
    axum::Router::new()
        .route("/ping", get(ping))
        .route("/stop", post(stop))
        .route("/reload", post(reload))
        .route("/status", get(status))
        .fallback(not_found)
        .with_state(state)
}

async fn ping() -> Json<super::OkResponse> {
    Json(super::OkResponse { ok: true })
}

async fn stop(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Json<super::OkResponse> {
    if let Some(tx) = state.shutdown_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }
    Json(super::OkResponse { ok: true })
}

async fn reload(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Json<super::ReloadResponse> {
    let results = state.orchestrator.restart_all().await;
    let mut per_provider = std::collections::HashMap::new();
    let mut all_ok = true;
    for (name, result) in results {
        match result {
            Ok(()) => {
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: true,
                        error: None,
                    },
                );
            }
            Err(e) => {
                all_ok = false;
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: false,
                        error: Some(e.to_string()),
                    },
                );
            }
        }
    }
    Json(super::ReloadResponse {
        ok: all_ok,
        results: per_provider,
    })
}

async fn status(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Json<super::StatusResponse> {
    let providers = state.registry.list_providers();
    let routes = state
        .route_table
        .list_routes()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();

    Json(super::StatusResponse {
        pid: std::process::id(),
        port: state.port,
        providers,
        routes,
    })
}

async fn not_found() -> (StatusCode, Json<super::ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(super::ErrorResponse {
            error: "not found".to_owned(),
        }),
    )
}

fn extract_host(req: &axum::http::Request<axum::body::Body>) -> Option<String> {
    req.headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            // Strip port if present
            h.split(':').next().unwrap_or(h).to_owned()
        })
}

/// Build the top-level dispatch router.
/// Host: trustless → control API
/// All other hosts → proxy router
pub fn dispatch_router(state: ServerState, proxy: axum::Router) -> axum::Router {
    use tower::ServiceExt as _;

    let control = control_router(state);

    axum::Router::new().fallback(
        move |req: axum::http::Request<axum::body::Body>| async move {
            let host = extract_host(&req);
            let is_control = host.as_deref() == Some("trustless");

            if is_control {
                let resp: Response = control.oneshot(req).await.into_response();
                resp
            } else {
                let resp: Response = proxy.oneshot(req).await.into_response();
                resp
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn test_state() -> (ServerState, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let registry = crate::provider::ProviderRegistry::new();
        let orchestrator = crate::provider::ProviderOrchestrator::new(registry.clone());
        let dir = tempfile::tempdir().unwrap();
        let route_table = crate::route::RouteTable::new(dir.path().to_path_buf());
        (
            ServerState::new(tx, orchestrator, registry, route_table, 1443),
            rx,
        )
    }

    fn stub_proxy() -> axum::Router {
        axum::Router::new().fallback(|| async { (StatusCode::BAD_GATEWAY, "no backend") })
    }

    #[tokio::test]
    async fn ping_returns_ok() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .uri("/ping")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::OkResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);
    }

    #[tokio::test]
    async fn stop_returns_ok_and_triggers_shutdown() {
        let (state, rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .method("POST")
            .uri("/stop")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::OkResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);

        // Shutdown signal should have been sent
        assert!(rx.await.is_ok());
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .uri("/nonexistent")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.error, "not found");
    }

    #[tokio::test]
    async fn non_control_host_returns_502() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .uri("/ping")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn no_host_returns_502() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder().uri("/ping").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn status_returns_pid_and_port() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .uri("/status")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: super::super::StatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.port, 1443);
        assert!(json.pid > 0);
        assert!(json.providers.is_empty());
        assert!(json.routes.is_empty());
    }

    #[tokio::test]
    async fn reload_returns_ok_with_no_providers() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = Request::builder()
            .method("POST")
            .uri("/reload")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: super::super::ReloadResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);
        assert!(json.results.is_empty());
    }
}
