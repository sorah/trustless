/// Async client for communicating with a key provider process.
///
/// Thread-safe via an interior `Mutex` — multiple tasks can share a single client,
/// but requests are serialized (one at a time on the wire).
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
    /// Create a new client from an `AsyncRead` (provider's stdout) and `AsyncWrite` (provider's stdin).
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

    /// Send an `initialize` request and return the provider's certificates.
    pub async fn initialize(
        &self,
    ) -> Result<crate::message::InitializeResult, crate::error::Error> {
        self.call(crate::message::InitializeParams {}).await
    }

    /// Send a `sign` request and return the raw signature bytes.
    pub async fn sign(
        &self,
        certificate_id: &str,
        scheme: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>, crate::error::Error> {
        let result: crate::message::SignResult = self
            .call(crate::message::SignParams {
                certificate_id: certificate_id.to_owned(),
                scheme: scheme.to_owned(),
                blob: blob.to_vec(),
            })
            .await?;
        Ok(result.signature)
    }

    async fn call<P, T>(&self, params: P) -> Result<T, crate::error::Error>
    where
        P: crate::message::RequestParams + serde::Serialize,
        T: serde::de::DeserializeOwned,
    {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;

        let request = crate::message::Request { id, params };
        crate::codec::send_message(&mut inner.writer, &request).await?;

        let response: crate::message::Response<T> =
            crate::codec::recv_message(&mut inner.reader).await?;

        if response.id != id {
            return Err(crate::error::Error::UnexpectedResponseId {
                expected: id,
                got: response.id,
            });
        }

        match response.body {
            crate::message::ResponseBody::Result { result } => Ok(result),
            crate::message::ResponseBody::Error { error } => Err(crate::error::Error::Provider {
                code: error.code,
                message: error.message,
            }),
        }
    }
}
