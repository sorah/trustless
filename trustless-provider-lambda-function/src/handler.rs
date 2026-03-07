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
            match state.do_initialize().await {
                Ok(result) => trustless_protocol::message::Response::Success(
                    trustless_protocol::message::SuccessResponse::Initialize { id, result },
                ),
                Err(e) => trustless_protocol::message::Response::Error(
                    trustless_protocol::message::ErrorResponse {
                        id,
                        error: e.into(),
                    },
                ),
            }
        }
        trustless_protocol::message::Request::Sign { params, .. } => {
            match state.do_sign(&params).await {
                Ok(result) => trustless_protocol::message::Response::Success(
                    trustless_protocol::message::SuccessResponse::Sign { id, result },
                ),
                Err(e) => trustless_protocol::message::Response::Error(
                    trustless_protocol::message::ErrorResponse {
                        id,
                        error: e.into(),
                    },
                ),
            }
        }
    };

    Ok(serde_json::to_value(response)?)
}
