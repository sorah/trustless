use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

#[derive(Clone)]
pub struct ServerState {
    shutdown_tx: std::sync::Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
}

impl ServerState {
    pub fn new(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            shutdown_tx: std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx))),
        }
    }
}

fn control_router(state: ServerState) -> axum::Router {
    axum::Router::new()
        .route("/ping", get(ping))
        .route("/stop", post(stop))
        .fallback(not_found)
        .with_state(state)
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

async fn stop(
    axum::extract::State(state): axum::extract::State<ServerState>,
) -> Json<serde_json::Value> {
    if let Some(tx) = state.shutdown_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }
    Json(serde_json::json!({"ok": true}))
}

async fn not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "not found"})),
    )
}

fn bad_gateway() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({"error": "no backend available"})),
    )
        .into_response()
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
/// All other hosts → 502 placeholder
pub fn dispatch_router(state: ServerState) -> axum::Router {
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
                bad_gateway()
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
        (ServerState::new(tx), rx)
    }

    #[tokio::test]
    async fn ping_returns_ok() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state);

        let req = Request::builder()
            .uri("/ping")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({"ok": true}));
    }

    #[tokio::test]
    async fn stop_returns_ok_and_triggers_shutdown() {
        let (state, rx) = test_state();
        let app = dispatch_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/stop")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({"ok": true}));

        // Shutdown signal should have been sent
        assert!(rx.await.is_ok());
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state);

        let req = Request::builder()
            .uri("/nonexistent")
            .header("host", "trustless")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({"error": "not found"}));
    }

    #[tokio::test]
    async fn non_control_host_returns_502() {
        let (state, _rx) = test_state();
        let app = dispatch_router(state);

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
        let app = dispatch_router(state);

        let req = Request::builder().uri("/ping").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
