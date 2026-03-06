// --- SigningThread ---

pub struct SigningThread;

struct SignRequest {
    certificate_id: String,
    scheme: String,
    blob: Vec<u8>,
    response_tx: std::sync::mpsc::Sender<Result<Vec<u8>, rustls::Error>>,
}

impl SigningThread {
    pub fn start(
        rt: tokio::runtime::Handle,
        client: std::sync::Arc<trustless_protocol::client::ProviderClient>,
        sign_timeout: std::time::Duration,
    ) -> SigningThreadHandle {
        let (tx, rx) = std::sync::mpsc::channel::<SignRequest>();

        std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                let result = rt.block_on(client.sign(&req.certificate_id, &req.scheme, &req.blob));
                let mapped =
                    result.map_err(|e| rustls::Error::General(format!("remote sign failed: {e}")));
                // Ignore send error — caller may have dropped
                let _ = req.response_tx.send(mapped);
            }
        });

        SigningThreadHandle {
            tx,
            timeout: sign_timeout,
        }
    }
}

#[derive(Clone)]
pub struct SigningThreadHandle {
    tx: std::sync::mpsc::Sender<SignRequest>,
    timeout: std::time::Duration,
}

impl std::fmt::Debug for SigningThreadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningThreadHandle")
            .finish_non_exhaustive()
    }
}

impl SigningThreadHandle {
    /// Create a disconnected handle for use in tests and placeholder entries.
    /// Any sign request will fail with "signing thread gone".
    pub fn disconnected() -> Self {
        let (tx, _rx) = std::sync::mpsc::channel();
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
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let req = SignRequest {
            certificate_id: certificate_id.to_owned(),
            scheme: scheme.to_owned(),
            blob: blob.to_vec(),
            response_tx,
        };
        self.tx.send(req).map_err(|_| {
            rustls::Error::General("remote sign failed: signing thread gone".to_owned())
        })?;
        response_rx
            .recv_timeout(self.timeout)
            .map_err(|e| match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => rustls::Error::General(format!(
                    "remote sign failed: timed out after {}s",
                    self.timeout.as_secs(),
                )),
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    rustls::Error::General("remote sign failed: signing thread gone".to_owned())
                }
            })?
    }
}

// --- RemoteSigningKey ---

#[derive(Debug)]
pub struct RemoteSigningKey {
    handle: SigningThreadHandle,
    certificate_id: String,
    algorithm: rustls::SignatureAlgorithm,
    supported_schemes: Vec<rustls::SignatureScheme>,
}

impl RemoteSigningKey {
    pub fn new(
        handle: SigningThreadHandle,
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
    handle: SigningThreadHandle,
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
