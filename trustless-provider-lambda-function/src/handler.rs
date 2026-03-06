use crate::state::AppState;

#[allow(clippy::disallowed_types)] // Dynamic dispatch over method field requires Value
pub(crate) async fn handle(
    state: &AppState,
    event: lambda_runtime::LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, lambda_runtime::Error> {
    let (payload, _context) = event.into_parts();

    let method = payload
        .get("params")
        .and_then(|p| p.get("method"))
        .and_then(|m| m.as_str())
        .unwrap_or("");

    tracing::info!(method, "handling request");

    match method {
        "initialize" => {
            let req: trustless_protocol::message::Request<
                trustless_protocol::message::InitializeParams,
            > = serde_json::from_value(payload)?;

            let response = match state.do_initialize().await {
                Ok(result) => trustless_protocol::message::Response {
                    id: req.id,
                    body: trustless_protocol::message::ResponseBody::Result { result },
                },
                Err(e) => trustless_protocol::message::Response {
                    id: req.id,
                    body: trustless_protocol::message::ResponseBody::Error { error: e.into() },
                },
            };
            Ok(serde_json::to_value(response)?)
        }
        "sign" => {
            let req: trustless_protocol::message::Request<trustless_protocol::message::SignParams> =
                serde_json::from_value(payload)?;

            let response = match state.do_sign(&req.params).await {
                Ok(result) => trustless_protocol::message::Response {
                    id: req.id,
                    body: trustless_protocol::message::ResponseBody::Result { result },
                },
                Err(e) => trustless_protocol::message::Response {
                    id: req.id,
                    body: trustless_protocol::message::ResponseBody::Error { error: e.into() },
                },
            };
            Ok(serde_json::to_value(response)?)
        }
        _ => {
            let id = payload.get("id").and_then(|v| v.as_u64()).unwrap_or(0);

            let response: trustless_protocol::message::Response<()> =
                trustless_protocol::message::Response {
                    id,
                    body: trustless_protocol::message::ResponseBody::Error {
                        error: trustless_protocol::message::ErrorPayload {
                            code: -1,
                            message: format!("unknown method: {method}"),
                        },
                    },
                };
            Ok(serde_json::to_value(response)?)
        }
    }
}
