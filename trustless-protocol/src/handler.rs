pub trait Handler: Send + Sync {
    fn initialize(
        &self,
    ) -> impl std::future::Future<
        Output = Result<crate::message::InitializeResult, crate::message::ErrorPayload>,
    > + Send;

    fn sign(
        &self,
        params: crate::message::SignParams,
    ) -> impl std::future::Future<
        Output = Result<crate::message::SignResult, crate::message::ErrorPayload>,
    > + Send;
}

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

        let id = request.id;

        match request.body {
            crate::message::RequestBody::Initialize(_params) => match handler.initialize().await {
                Ok(result) => {
                    let response = crate::message::RawResponse {
                        id,
                        body: crate::message::RawResponseBody::Result { result },
                    };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
                Err(error) => {
                    let response: crate::message::RawResponse<crate::message::InitializeResult> =
                        crate::message::RawResponse {
                            id,
                            body: crate::message::RawResponseBody::Error { error },
                        };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
            },
            crate::message::RequestBody::Sign(params) => match handler.sign(params).await {
                Ok(result) => {
                    let response = crate::message::RawResponse {
                        id,
                        body: crate::message::RawResponseBody::Result { result },
                    };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
                Err(error) => {
                    let response: crate::message::RawResponse<crate::message::SignResult> =
                        crate::message::RawResponse {
                            id,
                            body: crate::message::RawResponseBody::Error { error },
                        };
                    crate::codec::send_message(&mut writer, &response).await?;
                }
            },
        }
    }

    Ok(())
}
