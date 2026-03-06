pub struct ProviderClient<R, W> {
    inner: tokio::sync::Mutex<ProviderClientInner<R, W>>,
}

struct ProviderClientInner<R, W> {
    reader: tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec>,
    writer: tokio_util::codec::FramedWrite<W, tokio_util::codec::LengthDelimitedCodec>,
    next_id: u64,
}

impl<R, W> ProviderClient<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(reader: R, writer: W) -> Self {
        let reader = crate::codec::framed_read(reader);
        let writer = crate::codec::framed_write(writer);

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

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        body: crate::message::RequestBody,
    ) -> Result<T, crate::error::Error> {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;

        let request = crate::message::Request { id, body };
        crate::codec::send_message(&mut inner.writer, &request).await?;

        let response: crate::message::RawResponse<T> =
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
