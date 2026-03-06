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

// --- ProviderRegistry ---

#[derive(Clone, Debug)]
pub struct ProviderRegistry {
    inner: std::sync::Arc<std::sync::RwLock<ProviderRegistryInner>>,
}

#[derive(Debug)]
struct ProviderRegistryInner {
    providers: Vec<ProviderEntry>,
}

#[derive(Debug)]
struct ProviderEntry {
    #[allow(dead_code)]
    signing_handle: SigningThreadHandle,
    certificates: Vec<CertResolverEntry>,
    default_id: Option<String>,
}

struct CertResolverEntry {
    id: String,
    domains: Vec<String>,
    certified_key: std::sync::Arc<rustls::sign::CertifiedKey>,
}

impl std::fmt::Debug for CertResolverEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolverEntry")
            .field("id", &self.id)
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(ProviderRegistryInner {
                providers: Vec::new(),
            })),
        }
    }

    pub fn add_provider(
        &self,
        init: trustless_protocol::message::InitializeResult,
        handle: SigningThreadHandle,
    ) -> anyhow::Result<()> {
        use rustls_pki_types::pem::PemObject as _;

        let mut certificates = Vec::new();

        for cert_info in &init.certificates {
            // Parse schemes
            let mut schemes = Vec::new();
            for scheme_name in &cert_info.schemes {
                match trustless_protocol::scheme::parse_scheme(scheme_name) {
                    Some(s) => schemes.push(s),
                    None => {
                        tracing::warn!(
                            certificate_id = %cert_info.id,
                            scheme = %scheme_name,
                            "skipping unknown signature scheme",
                        );
                    }
                }
            }

            if schemes.is_empty() {
                tracing::warn!(
                    certificate_id = %cert_info.id,
                    "skipping certificate with no valid signature schemes",
                );
                continue;
            }

            // Infer algorithm
            let algorithm = match trustless_protocol::scheme::algorithm_for_schemes(&schemes) {
                Some(a) => a,
                None => {
                    tracing::warn!(
                        certificate_id = %cert_info.id,
                        "skipping certificate: cannot infer signature algorithm",
                    );
                    continue;
                }
            };

            // Parse PEM certificate chain
            let cert_chain: Vec<rustls_pki_types::CertificateDer<'static>> =
                match rustls_pki_types::CertificateDer::pem_slice_iter(cert_info.pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(chain) if !chain.is_empty() => chain,
                    Ok(_) => {
                        tracing::warn!(
                            certificate_id = %cert_info.id,
                            "skipping certificate with empty PEM chain",
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            certificate_id = %cert_info.id,
                            error = %e,
                            "skipping certificate with invalid PEM",
                        );
                        continue;
                    }
                };

            let signing_key: std::sync::Arc<dyn rustls::sign::SigningKey> = std::sync::Arc::new(
                RemoteSigningKey::new(handle.clone(), cert_info.id.clone(), algorithm, schemes),
            );

            let certified_key =
                std::sync::Arc::new(rustls::sign::CertifiedKey::new(cert_chain, signing_key));

            certificates.push(CertResolverEntry {
                id: cert_info.id.clone(),
                domains: cert_info
                    .domains
                    .iter()
                    .map(|d| d.to_ascii_lowercase())
                    .collect(),
                certified_key,
            });
        }

        if certificates.is_empty() {
            anyhow::bail!("no valid certificates found in provider initialize response");
        }

        let default_id = if init.default.is_empty() {
            None
        } else {
            Some(init.default.clone())
        };

        let mut inner = self.inner.write().unwrap();
        inner.providers.push(ProviderEntry {
            signing_handle: handle,
            certificates,
            default_id,
        });

        Ok(())
    }

    pub fn resolve_by_sni(
        &self,
        sni: Option<&str>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        let inner = self.inner.read().unwrap();

        if let Some(sni) = sni {
            let sni_lower = sni.to_ascii_lowercase();
            // Try to find a matching certificate across all providers
            for provider in &inner.providers {
                for entry in &provider.certificates {
                    if matches_sni(&sni_lower, &entry.domains) {
                        return Some(entry.certified_key.clone());
                    }
                }
            }
        }

        // Fallback: return the default certificate of the first provider
        // TODO: multi-provider default selection (future spec)
        for provider in &inner.providers {
            if let Some(ref default_id) = provider.default_id
                && let Some(entry) = provider.certificates.iter().find(|e| e.id == *default_id)
            {
                return Some(entry.certified_key.clone());
            }
            // If no default_id or default cert not found, fall back to first cert
            if let Some(entry) = provider.certificates.first() {
                return Some(entry.certified_key.clone());
            }
        }

        None
    }
}

fn matches_sni(sni: &str, domains: &[String]) -> bool {
    for domain in domains {
        if domain == sni {
            return true;
        }
        if let Some(suffix) = domain.strip_prefix("*.") {
            // Wildcard: *.example.com matches foo.example.com but not bar.foo.example.com
            if let Some(prefix) = sni.strip_suffix(suffix)
                && prefix.ends_with('.')
                && !prefix[..prefix.len() - 1].contains('.')
            {
                return true;
            }
        }
    }
    false
}

// --- CertResolver ---

#[derive(Debug)]
pub struct CertResolver {
    registry: ProviderRegistry,
}

impl CertResolver {
    pub fn new(registry: ProviderRegistry) -> Self {
        Self { registry }
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        self.registry.resolve_by_sni(client_hello.server_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_single_label() {
        assert!(matches_sni(
            "foo.example.com",
            &["*.example.com".to_owned()]
        ));
    }

    #[test]
    fn wildcard_does_not_match_nested() {
        assert!(!matches_sni(
            "bar.foo.example.com",
            &["*.example.com".to_owned()]
        ));
    }

    #[test]
    fn wildcard_does_not_match_base() {
        assert!(!matches_sni("example.com", &["*.example.com".to_owned()]));
    }

    #[test]
    fn exact_match() {
        assert!(matches_sni(
            "foo.example.com",
            &["foo.example.com".to_owned()]
        ));
    }

    #[test]
    fn exact_no_match() {
        assert!(!matches_sni(
            "bar.example.com",
            &["foo.example.com".to_owned()]
        ));
    }

    #[test]
    fn matches_sni_case_insensitive() {
        // matches_sni expects pre-normalized (lowercase) domains;
        // the registry normalises on insert and lowercases the SNI query.
        assert!(matches_sni(
            "foo.example.com",
            &["*.example.com".to_owned()]
        ));
        assert!(matches_sni(
            "foo.example.com",
            &["FOO.EXAMPLE.COM".to_ascii_lowercase().to_owned()]
        ));
    }

    #[test]
    fn multiple_domains_match() {
        let domains = vec!["exact.example.com".to_owned(), "*.example.com".to_owned()];
        assert!(matches_sni("exact.example.com", &domains));
        assert!(matches_sni("other.example.com", &domains));
        assert!(!matches_sni("deep.sub.example.com", &domains));
    }
}
