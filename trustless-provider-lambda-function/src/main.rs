mod config;
mod error;
mod handler;
mod state;

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config = crate::config::AppConfig::from_env().expect("failed to parse configuration");
    tracing::info!(method = %config.method, s3_url_count = config.s3_urls.len(), "starting Lambda function");

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);
    let ssm_client = aws_sdk_ssm::Client::new(&aws_config);

    let state = crate::state::AppState::new(config, s3_client, ssm_client);
    let state_ref = &state;

    lambda_runtime::run(lambda_runtime::service_fn(|event| async move {
        crate::handler::handle(state_ref, event).await
    }))
    .await
}
