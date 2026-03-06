/// Trait for implementing a key provider.
///
/// Implement this trait and pass it to [`run`] to start the provider event loop.
/// See `trustless-provider-stub` for a complete example.
pub trait Handler: Send + Sync {
    /// Handle an `initialize` request. Return all available certificates.
    fn initialize(
        &self,
    ) -> impl std::future::Future<
        Output = Result<crate::message::InitializeResult, crate::message::ErrorPayload>,
    > + Send;

    /// Handle a `sign` request. Sign the blob using the specified certificate and scheme.
    fn sign(
        &self,
        params: crate::message::SignParams,
    ) -> impl std::future::Future<
        Output = Result<crate::message::SignResult, crate::message::ErrorPayload>,
    > + Send;
}

/// Main event loop for a key provider process.
///
/// Reads requests from stdin, dispatches to the [`Handler`], and writes responses to stdout.
/// Returns `Ok(())` when stdin reaches EOF (i.e., the proxy closed the connection).
pub async fn run(handler: impl Handler) -> Result<(), crate::error::Error> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let mut reader = crate::codec::framed_read(stdin);
    let mut writer = crate::codec::framed_write(stdout);

    loop {
        let request: crate::message::ReceivedRequest =
            match crate::codec::recv_message(&mut reader).await {
                Ok(req) => req,
                Err(crate::error::Error::ProcessExited) => break,
                Err(e) => return Err(e),
            };

        let id = request.id;

        if let Some(_params) = request
            .params
            .as_any()
            .downcast_ref::<crate::message::InitializeParams>()
        {
            match handler.initialize().await {
                Ok(result) => {
                    let response = crate::message::Response {
                        id,
                        body: crate::message::ResponseBody::Result { result },
                    };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
                Err(error) => {
                    let response: crate::message::Response<crate::message::InitializeResult> =
                        crate::message::Response {
                            id,
                            body: crate::message::ResponseBody::Error { error },
                        };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
            }
        } else if let Some(params) = request
            .params
            .as_any()
            .downcast_ref::<crate::message::SignParams>()
        {
            match handler.sign(params.clone()).await {
                Ok(result) => {
                    let response = crate::message::Response {
                        id,
                        body: crate::message::ResponseBody::Result { result },
                    };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
                Err(error) => {
                    let response: crate::message::Response<crate::message::SignResult> =
                        crate::message::Response {
                            id,
                            body: crate::message::ResponseBody::Error { error },
                        };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
            }
        } else {
            let response: crate::message::Response<()> = crate::message::Response {
                id,
                body: crate::message::ResponseBody::Error {
                    error: crate::message::ErrorPayload {
                        code: -1,
                        message: "unknown method".to_owned(),
                    },
                },
            };
            crate::codec::send_message(&mut writer, &response).await?;
        }
    }

    Ok(())
}
