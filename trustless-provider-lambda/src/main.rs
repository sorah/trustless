struct LambdaHandler {
    client: aws_sdk_lambda::Client,
    function_name: String,
}

impl LambdaHandler {
    async fn invoke_lambda(
        &self,
        request: trustless_protocol::message::Request,
    ) -> Result<trustless_protocol::message::Response, trustless_protocol::message::ErrorPayload>
    {
        let payload = serde_json::to_vec(&request).map_err(|e| {
            trustless_protocol::message::ErrorPayload {
                code: -1,
                message: format!("failed to serialize request: {e}"),
            }
        })?;

        let result = self
            .client
            .invoke()
            .function_name(&self.function_name)
            .payload(aws_sdk_lambda::primitives::Blob::new(payload))
            .send()
            .await
            .map_err(|e| trustless_protocol::message::ErrorPayload {
                code: -1,
                message: format!("Lambda invocation failed: {e}"),
            })?;

        if let Some(func_error) = result.function_error() {
            let error_message = result
                .payload()
                .and_then(|p| String::from_utf8(p.as_ref().to_vec()).ok())
                .unwrap_or_else(|| func_error.to_owned());
            return Err(trustless_protocol::message::ErrorPayload {
                code: -1,
                message: format!("Lambda function error: {error_message}"),
            });
        }

        let response_payload =
            result
                .payload()
                .ok_or_else(|| trustless_protocol::message::ErrorPayload {
                    code: -1,
                    message: "Lambda returned no payload".to_owned(),
                })?;

        let response: trustless_protocol::message::Response =
            serde_json::from_slice(response_payload.as_ref()).map_err(|e| {
                trustless_protocol::message::ErrorPayload {
                    code: -1,
                    message: format!("failed to deserialize Lambda response: {e}"),
                }
            })?;

        Ok(response)
    }
}

impl trustless_protocol::handler::Handler for LambdaHandler {
    async fn initialize(
        &self,
    ) -> Result<
        trustless_protocol::message::InitializeResult,
        trustless_protocol::message::ErrorPayload,
    > {
        let request = trustless_protocol::message::Request::Initialize {
            id: 0,
            params: trustless_protocol::message::InitializeParams {},
        };
        let response = self.invoke_lambda(request).await?;
        match response {
            trustless_protocol::message::Response::Success(
                trustless_protocol::message::SuccessResponse::Initialize { result, .. },
            ) => Ok(result),
            trustless_protocol::message::Response::Success(_) => {
                Err(trustless_protocol::message::ErrorPayload {
                    code: -1,
                    message: "unexpected response method".to_owned(),
                })
            }
            trustless_protocol::message::Response::Error(
                trustless_protocol::message::ErrorResponse { error, .. },
            ) => Err(error),
        }
    }

    async fn sign(
        &self,
        params: trustless_protocol::message::SignParams,
    ) -> Result<trustless_protocol::message::SignResult, trustless_protocol::message::ErrorPayload>
    {
        let request = trustless_protocol::message::Request::Sign { id: 0, params };
        let response = self.invoke_lambda(request).await?;
        match response {
            trustless_protocol::message::Response::Success(
                trustless_protocol::message::SuccessResponse::Sign { result, .. },
            ) => Ok(result),
            trustless_protocol::message::Response::Success(_) => {
                Err(trustless_protocol::message::ErrorPayload {
                    code: -1,
                    message: "unexpected response method".to_owned(),
                })
            }
            trustless_protocol::message::Response::Error(
                trustless_protocol::message::ErrorResponse { error, .. },
            ) => Err(error),
        }
    }
}

#[derive(clap::Parser)]
struct Args {
    #[clap(long)]
    function_name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser as _;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let lambda_client = aws_sdk_lambda::Client::new(&aws_config);

    let handler = LambdaHandler {
        client: lambda_client,
        function_name: args.function_name,
    };

    tracing::info!(
        function_name = %handler.function_name,
        "starting Lambda provider"
    );

    trustless_protocol::handler::run(handler).await?;

    Ok(())
}
