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
        let request: crate::message::Request = match crate::codec::recv_message(&mut reader).await {
            Ok(req) => req,
            Err(crate::error::Error::ProcessExited) => break,
            Err(e) => return Err(e),
        };

        let id = request.id();

        let response = match request {
            crate::message::Request::Initialize { .. } => {
                crate::message::Response::initialize(id, handler.initialize().await)
            }
            crate::message::Request::Sign { params, .. } => {
                crate::message::Response::sign(id, handler.sign(params).await)
            }
        };

        crate::codec::send_message(&mut writer, &response).await?;
    }

    Ok(())
}
