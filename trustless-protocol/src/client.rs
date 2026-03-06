pub struct ProviderClient {
    inner: tokio::sync::Mutex<ProviderClientInner>,
}

struct ProviderClientInner {
    reader: tokio_util::codec::FramedRead<
        tokio::process::ChildStdout,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    writer: tokio_util::codec::FramedWrite<
        tokio::process::ChildStdin,
        tokio_util::codec::LengthDelimitedCodec,
    >,
    next_id: u64,
}

impl ProviderClient {
    pub fn from_child_io(
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
    ) -> Self {
        let reader = crate::codec::framed_read(stdout);
        let writer = crate::codec::framed_write(stdin);

        Self {
            inner: tokio::sync::Mutex::new(ProviderClientInner {
                reader,
                writer,
                next_id: 1,
            }),
        }
    }

    pub async fn initialize(
        &self,
    ) -> Result<crate::message::InitializeResult, crate::error::Error> {
        self.call(crate::message::RequestBody::Initialize(
            crate::message::InitializeParams {},
        ))
        .await
    }

    pub async fn sign(
        &self,
        certificate_id: &str,
        scheme: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>, crate::error::Error> {
        let result: crate::message::SignResult = self
            .call(crate::message::RequestBody::Sign(
                crate::message::SignParams {
                    certificate_id: certificate_id.to_owned(),
                    scheme: scheme.to_owned(),
                    blob: blob.to_vec(),
                },
            ))
            .await?;
        Ok(result.signature)
    }

    async fn call<R: serde::de::DeserializeOwned>(
        &self,
        body: crate::message::RequestBody,
    ) -> Result<R, crate::error::Error> {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;

        let request = crate::message::Request { id, body };
        crate::codec::send_message(&mut inner.writer, &request).await?;

        let response: crate::message::RawResponse<R> =
            crate::codec::recv_message(&mut inner.reader).await?;

        if response.id != id {
            return Err(crate::error::Error::UnexpectedResponseId {
                expected: id,
                got: response.id,
            });
        }

        match response.body {
            crate::message::RawResponseBody::Result { result } => Ok(result),
            crate::message::RawResponseBody::Error { error } => {
                Err(crate::error::Error::Provider {
                    code: error.code,
                    message: error.message,
                })
            }
        }
    }
}
