use clap::Parser as _;

/// A failure-injecting proxy provider for testing.
///
/// Wraps another provider process and injects errors when specified trigger files exist on disk.
#[derive(clap::Parser)]
struct Args {
    /// Path to a file whose existence triggers sign errors.
    #[clap(long)]
    sign_error_file: Option<std::path::PathBuf>,

    /// Path to a file whose existence triggers initialize errors.
    #[clap(long)]
    initialize_error_file: Option<std::path::PathBuf>,

    /// The wrapped provider command (after `--`).
    #[clap(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

struct FailureProxy {
    client: trustless::provider::process::ProviderClient,
    sign_error_file: Option<std::path::PathBuf>,
    initialize_error_file: Option<std::path::PathBuf>,
}

impl trustless_protocol::handler::Handler for FailureProxy {
    async fn initialize(
        &self,
    ) -> Result<trustless_protocol::message::InitializeResult, trustless_protocol::message::ErrorCode>
    {
        if let Some(path) = &self.initialize_error_file
            && path.exists()
        {
            return Err(trustless_protocol::message::ErrorCode::Internal(format!(
                "failure injected: {} exists",
                path.display()
            )));
        }
        self.client
            .initialize()
            .await
            .map_err(|e| trustless_protocol::message::ErrorCode::Internal(e.to_string()))
    }

    async fn sign(
        &self,
        params: trustless_protocol::message::SignParams,
    ) -> Result<trustless_protocol::message::SignResult, trustless_protocol::message::ErrorCode>
    {
        if let Some(path) = &self.sign_error_file
            && path.exists()
        {
            return Err(trustless_protocol::message::ErrorCode::SigningFailed(
                format!("failure injected: {} exists", path.display()),
            ));
        }
        let signature = self
            .client
            .sign(&params.certificate_id, &params.scheme, &params.blob)
            .await
            .map_err(|e| trustless_protocol::message::ErrorCode::Internal(e.to_string()))?;
        Ok(trustless_protocol::message::SignResult { signature })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let process = trustless::provider::process::ProviderProcess::spawn(&args.command).await?;
    let (client, _stderr, _child) = process.into_parts();

    let proxy = FailureProxy {
        client,
        sign_error_file: args.sign_error_file,
        initialize_error_file: args.initialize_error_file,
    };

    tracing::info!("failure proxy started");

    trustless_protocol::handler::run(proxy).await?;

    Ok(())
}
