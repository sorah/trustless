// --- SigningWorker ---

pub struct SigningWorker;

struct SignRequest {
    certificate_id: String,
    scheme: String,
    blob: Vec<u8>,
    response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, rustls::Error>>,
}

impl SigningWorker {
    pub fn start(
        client: std::sync::Arc<crate::provider::process::ProviderClient>,
        sign_timeout: std::time::Duration,
    ) -> SigningHandle {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SignRequest>();

        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let result = client
                    .sign(&req.certificate_id, &req.scheme, &req.blob)
                    .await;
                let mapped =
                    result.map_err(|e| rustls::Error::General(format!("remote sign failed: {e}")));
                // Ignore send error — caller may have dropped
                let _ = req.response_tx.send(mapped);
            }
        });

        SigningHandle {
            tx,
            timeout: sign_timeout,
        }
    }
}

#[derive(Clone)]
pub struct SigningHandle {
    tx: tokio::sync::mpsc::UnboundedSender<SignRequest>,
    timeout: std::time::Duration,
}

impl std::fmt::Debug for SigningHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningHandle").finish_non_exhaustive()
    }
}

impl SigningHandle {
    /// Create a disconnected handle for use in tests and placeholder entries.
    /// Any sign request will fail with "signing worker gone".
    pub fn disconnected() -> Self {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            tx,
            timeout: std::time::Duration::from_secs(1),
        }
    }

    pub fn sign(
        &self,
        certificate_id: &str,
        scheme: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>, rustls::Error> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let req = SignRequest {
            certificate_id: certificate_id.to_owned(),
            scheme: scheme.to_owned(),
            blob: blob.to_vec(),
            response_tx,
        };
        self.tx.send(req).map_err(|_| {
            rustls::Error::General("remote sign failed: signing worker gone".to_owned())
        })?;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match tokio::time::timeout(self.timeout, response_rx).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(_)) => Err(rustls::Error::General(
                        "remote sign failed: signing worker gone".to_owned(),
                    )),
                    Err(_) => Err(rustls::Error::General(format!(
                        "remote sign failed: timed out after {}s",
                        self.timeout.as_secs(),
                    ))),
                }
            })
        })
    }
}

// --- RemoteSigningKey ---

#[derive(Debug)]
pub struct RemoteSigningKey {
    handle: SigningHandle,
    certificate_id: String,
    algorithm: rustls::SignatureAlgorithm,
    supported_schemes: Vec<rustls::SignatureScheme>,
}

impl RemoteSigningKey {
    pub fn new(
        handle: SigningHandle,
        certificate_id: String,
        algorithm: rustls::SignatureAlgorithm,
        supported_schemes: Vec<rustls::SignatureScheme>,
    ) -> Self {
        Self {
            handle,
            certificate_id,
            algorithm,
            supported_schemes,
        }
    }
}

impl rustls::sign::SigningKey for RemoteSigningKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.supported_schemes
            .iter()
            .find(|s| offered.contains(s))
            .map(|&scheme| {
                Box::new(RemoteSigner {
                    handle: self.handle.clone(),
                    certificate_id: self.certificate_id.clone(),
                    scheme,
                }) as Box<dyn rustls::sign::Signer>
            })
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.algorithm
    }
}

// --- RemoteSigner ---

#[derive(Debug)]
struct RemoteSigner {
    handle: SigningHandle,
    certificate_id: String,
    scheme: rustls::SignatureScheme,
}

impl rustls::sign::Signer for RemoteSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let scheme_name = trustless_protocol::scheme::scheme_to_string(self.scheme);
        self.handle.sign(&self.certificate_id, scheme_name, message)
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

// --- FixedCertResolver ---

/// A trivial `ResolvesServerCert` that always returns a pre-resolved `CertifiedKey`.
///
/// Used because `ServerConfig` requires a cert resolver — there's no API to pass
/// `CertifiedKey` directly. The actual SNI-based resolution happens before the
/// handshake via `LazyConfigAcceptor` + `ProviderRegistry::resolve_by_sni`.
#[derive(Debug)]
pub struct FixedCertResolver(std::sync::Arc<rustls::sign::CertifiedKey>);

impl FixedCertResolver {
    pub fn new(key: std::sync::Arc<rustls::sign::CertifiedKey>) -> Self {
        Self(key)
    }
}

impl rustls::server::ResolvesServerCert for FixedCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
