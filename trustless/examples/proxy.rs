/// Plain HTTP reverse proxy example.
///
/// Starts an HTTP listener on the specified port (default 8080) and forwards
/// requests based on the route table in the state directory.
///
/// Usage: cargo run --example proxy -- [--port 8080]

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::args()
        .position(|a| a == "--port")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state_dir = trustless::config::state_dir();
    tracing::info!(state_dir = %state_dir.display(), port = port, "starting proxy");

    let route_table = trustless::route::RouteTable::new(state_dir);
    let client = reqwest::Client::new();
    let state = trustless::proxy::ProxyState {
        route_table,
        registry: trustless::provider::ProviderRegistry::new(),
        client,
    };
    let app = trustless::proxy::proxy_router(state);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(addr = %addr, "listening");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}
