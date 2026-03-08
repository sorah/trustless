#[derive(Clone)]
pub struct ServerState {
    shutdown_tx: std::sync::Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    orchestrator: crate::provider::ProviderOrchestrator,
    registry: crate::provider::ProviderRegistry,
    route_table: crate::route::RouteTable,
    port: u16,
    config_dir: std::path::PathBuf,
}

impl ServerState {
    pub fn new(
        shutdown_tx: tokio::sync::oneshot::Sender<()>,
        orchestrator: crate::provider::ProviderOrchestrator,
        registry: crate::provider::ProviderRegistry,
        route_table: crate::route::RouteTable,
        port: u16,
        config_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            shutdown_tx: std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx))),
            orchestrator,
            registry,
            route_table,
            port,
            config_dir,
        }
    }
}

fn control_router(state: ServerState) -> axum::Router {
    axum::Router::new()
        .route("/ping", axum::routing::get(ping))
        .route("/stop", axum::routing::post(stop))
        .route("/reload", axum::routing::post(reload))
        .route("/status", axum::routing::get(status))
        .fallback(not_found)
        .with_state(state)
}

async fn ping() -> axum::Json<super::OkResponse> {
    axum::Json(super::OkResponse { ok: true })
}

async fn stop(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> axum::Json<super::OkResponse> {
    tracing::info!("stop requested via control API");
    if let Some(tx) = state.shutdown_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }
    axum::Json(super::OkResponse { ok: true })
}

async fn reload(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> axum::Json<super::ReloadResponse> {
    let config = match crate::config::Config::load_from(state.config_dir.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("reload: failed to load config: {e}");
            return axum::Json(super::ReloadResponse {
                ok: false,
                results: std::collections::HashMap::from([(
                    "_config".to_owned(),
                    super::ReloadProviderResult {
                        ok: false,
                        error: Some(format!("failed to load config: {e}")),
                        action: None,
                    },
                )]),
            });
        }
    };

    let current_profiles = state.orchestrator.provider_profiles();
    let diff = match config.diff_profiles(&current_profiles) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("reload: failed to diff profiles: {e}");
            return axum::Json(super::ReloadResponse {
                ok: false,
                results: std::collections::HashMap::from([(
                    "_config".to_owned(),
                    super::ReloadProviderResult {
                        ok: false,
                        error: Some(format!("failed to diff profiles: {e}")),
                        action: None,
                    },
                )]),
            });
        }
    };

    let mut per_provider = std::collections::HashMap::new();
    let mut all_ok = true;

    // Added profiles
    for (name, profile) in diff.added {
        match state
            .orchestrator
            .add_provider_resilient(&name, profile)
            .await
        {
            Ok(()) => {
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: true,
                        error: None,
                        action: Some("added".to_owned()),
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
                        action: Some("added".to_owned()),
                    },
                );
            }
        }
    }

    // Removed profiles
    for name in diff.removed {
        match state.orchestrator.remove_provider(&name).await {
            Ok(()) => {
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: true,
                        error: None,
                        action: Some("removed".to_owned()),
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
                        action: Some("removed".to_owned()),
                    },
                );
            }
        }
    }

    // Changed profiles: remove and re-add
    for (name, new_profile) in diff.changed {
        if let Err(e) = state.orchestrator.remove_provider(&name).await {
            all_ok = false;
            per_provider.insert(
                name,
                super::ReloadProviderResult {
                    ok: false,
                    error: Some(format!("failed to remove for restart: {e}")),
                    action: Some("restarted".to_owned()),
                },
            );
            continue;
        }

        match state
            .orchestrator
            .add_provider_resilient(&name, new_profile)
            .await
        {
            Ok(()) => {
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: true,
                        error: None,
                        action: Some("restarted".to_owned()),
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
                        action: Some("restarted".to_owned()),
                    },
                );
            }
        }
    }

    // Unchanged profiles: restart to bypass any backoff
    for name in diff.unchanged {
        match state.orchestrator.restart_provider(&name).await {
            Ok(()) => {
                per_provider.insert(
                    name,
                    super::ReloadProviderResult {
                        ok: true,
                        error: None,
                        action: Some("restarted".to_owned()),
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
                        action: Some("restarted".to_owned()),
                    },
                );
            }
        }
    }

    tracing::info!(ok = all_ok, "reload completed via control API");
    axum::Json(super::ReloadResponse {
        ok: all_ok,
        results: per_provider,
    })
}

async fn status(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> axum::Json<super::StatusResponse> {
    let profiles = state.orchestrator.provider_profiles();
    let mut providers = state.registry.list_providers();
    for provider in &mut providers {
        if let Some(profile) = profiles.get(&provider.name) {
            provider.command.clone_from(&profile.command);
        }
    }
    let routes = state
        .route_table
        .list_routes()
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();

    axum::Json(super::StatusResponse {
        pid: std::process::id(),
        port: state.port,
        providers,
        routes,
    })
}

async fn not_found() -> (axum::http::StatusCode, axum::Json<super::ErrorResponse>) {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(super::ErrorResponse {
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
            use axum::response::IntoResponse as _;
            let host = extract_host(&req);
            let is_control = host.as_deref() == Some("trustless");

            if is_control {
                let resp: axum::response::Response = control.oneshot(req).await.into_response();
                resp
            } else {
                let resp: axum::response::Response = proxy.oneshot(req).await.into_response();
                resp
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt as _;

    fn test_state() -> (
        ServerState,
        tokio::sync::oneshot::Receiver<()>,
        tempfile::TempDir,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let registry = crate::provider::ProviderRegistry::new();
        let orchestrator = crate::provider::ProviderOrchestrator::new(registry.clone());
        let dir = tempfile::tempdir().unwrap();
        let route_table = crate::route::RouteTable::new(dir.path().to_path_buf());
        (
            ServerState::new(
                tx,
                orchestrator,
                registry,
                route_table,
                1443,
                dir.path().to_path_buf(),
            ),
            rx,
            dir,
        )
    }

    fn stub_proxy() -> axum::Router {
        axum::Router::new()
            .fallback(|| async { (axum::http::StatusCode::BAD_GATEWAY, "no backend") })
    }

    #[tokio::test]
    async fn ping_returns_ok() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .uri("/ping")
            .header("host", "trustless")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::OkResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);
    }

    #[tokio::test]
    async fn stop_returns_ok_and_triggers_shutdown() {
        let (state, rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/stop")
            .header("host", "trustless")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::OkResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);

        // Shutdown signal should have been sent
        assert!(rx.await.is_ok());
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .uri("/nonexistent")
            .header("host", "trustless")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: super::super::ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.error, "not found");
    }

    #[tokio::test]
    async fn non_control_host_returns_502() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .uri("/ping")
            .header("host", "example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn no_host_returns_502() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .uri("/ping")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn status_returns_pid_and_port() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .uri("/status")
            .header("host", "trustless")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: super::super::StatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.port, 1443);
        assert!(json.pid > 0);
        assert!(json.providers.is_empty());
        assert!(json.routes.is_empty());
    }

    #[tokio::test]
    async fn reload_returns_ok_with_no_providers() {
        let (state, _rx, _dir) = test_state();
        let app = dispatch_router(state, stub_proxy());

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/reload")
            .header("host", "trustless")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: super::super::ReloadResponse = serde_json::from_slice(&body).unwrap();
        assert!(json.ok);
        assert!(json.results.is_empty());
    }
}
