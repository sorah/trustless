use crate::state::AppState;

#[allow(clippy::disallowed_types)]
pub(crate) async fn handle(
    state: &AppState,
    event: lambda_runtime::LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    let (payload, _context) = event.into_parts();

    let request: trustless_protocol::message::Request = serde_json::from_value(payload)?;
    let id = request.id();

    tracing::info!(?request, "handling request");

    let response = match request {
        trustless_protocol::message::Request::Initialize { .. } => {
            trustless_protocol::message::Response::initialize(
                id,
                state.initialize().await.map_err(Into::into),
            )
        }
        trustless_protocol::message::Request::Sign { params, .. } => {
            trustless_protocol::message::Response::sign(
                id,
                state.sign(&params).await.map_err(Into::into),
            )
        }
    };

    Ok(serde_json::to_value(response)?)
}
