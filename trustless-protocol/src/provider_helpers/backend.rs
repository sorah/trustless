/// A source of certificates for [`CachingBackend`].
///
/// Implementors define how to enumerate, identify, and load certificates from an external store
/// (e.g. S3, filesystem).
pub trait CertificateSource: Send + Sync {
    /// Identifies a certificate source (e.g. an S3 prefix, a filesystem directory).
    type SourceId: Sync;
    /// Error type. Must convert into [`crate::message::ErrorCode`] for protocol responses,
    /// and from [`super::ProviderHelperError`] for signing errors propagated by [`CachingBackend`].
    type Error: Into<crate::message::ErrorCode> + From<super::ProviderHelperError>;

    /// Ordered list of certificate sources. The first entry determines the default certificate.
    fn sources(&self) -> &[Self::SourceId];

    /// Fetch the current certificate ID for the given source.
    fn fetch_current_id(
        &self,
        source: &Self::SourceId,
    ) -> impl std::future::Future<Output = Result<String, Self::Error>> + Send;

    /// Load a certificate (fullchain + key) for the given source and cert ID.
    fn load_certificate(
        &self,
        source: &Self::SourceId,
        cert_id: &str,
    ) -> impl std::future::Future<Output = Result<super::Certificate, Self::Error>> + Send;
}

/// Generic caching backend that wraps a [`CertificateSource`].
///
/// Provides cold/warm initialization logic and cache-first signing with on-demand fallback.
/// Implements [`crate::handler::Handler`] so it can be used directly with
/// [`crate::handler::run`].
pub struct CachingBackend<S: CertificateSource> {
    source: S,
    cache: tokio::sync::RwLock<CertCache>,
}

struct CertCache {
    certs: std::collections::HashMap<String, super::Certificate>,
    current_ids: Vec<(usize, String)>,
    initialized: bool,
}

impl CertCache {
    fn new() -> Self {
        Self {
            certs: std::collections::HashMap::new(),
            current_ids: Vec::new(),
            initialized: false,
        }
    }
}

impl<S: CertificateSource> CachingBackend<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            cache: tokio::sync::RwLock::new(CertCache::new()),
        }
    }

    /// Cold/warm initialization.
    ///
    /// On cold start, fetches current IDs and certificates from all sources.
    /// On warm call, checks for current ID changes and refreshes only updated certificates.
    pub async fn initialize(&self) -> Result<crate::message::InitializeResult, S::Error> {
        let mut cache = self.cache.write().await;

        if cache.initialized {
            tracing::debug!("warm initialize: checking for current ID changes");
            let mut changed = false;
            for (idx, old_id) in cache.current_ids.clone() {
                let source_id = &self.source.sources()[idx];
                let new_id = self.source.fetch_current_id(source_id).await?;
                if new_id != old_id {
                    tracing::info!(
                        idx,
                        old_id,
                        new_id,
                        "current ID changed, fetching new certificate"
                    );
                    let cert = self.source.load_certificate(source_id, &new_id).await?;
                    cache.certs.remove(&old_id);
                    cache.certs.insert(new_id.clone(), cert);

                    if let Some(entry) = cache.current_ids.iter_mut().find(|(i, _)| *i == idx) {
                        entry.1 = new_id;
                    }
                    changed = true;
                }
            }
            if !changed {
                tracing::debug!("warm initialize: no changes detected");
            }
        } else {
            tracing::info!("cold initialize: fetching all certificates");
            for (idx, source_id) in self.source.sources().iter().enumerate() {
                let cert_id = self.source.fetch_current_id(source_id).await?;
                let cert = self.source.load_certificate(source_id, &cert_id).await?;
                cache.certs.insert(cert_id.clone(), cert);
                cache.current_ids.push((idx, cert_id));
            }
            cache.initialized = true;
        }

        let default_id = cache
            .current_ids
            .first()
            .map(|(_, id)| id.clone())
            .ok_or_else(|| {
                super::ProviderHelperError::CertificateNotFound(
                    "no certificates configured".to_owned(),
                )
            })?;

        let certificates: Vec<crate::message::CertificateInfo> = cache
            .current_ids
            .iter()
            .filter_map(|(_, id)| cache.certs.get(id))
            .map(|c| c.to_certificate_info())
            .collect();

        Ok(crate::message::InitializeResult {
            default: default_id,
            certificates,
        })
    }

    /// Sign a blob, using the cache first with on-demand fallback.
    ///
    /// If the requested certificate is not in cache (e.g. sign-before-initialize race on cold
    /// start), searches through all sources to find and load it.
    pub async fn sign(
        &self,
        params: &crate::message::SignParams,
    ) -> Result<crate::message::SignResult, S::Error> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            if let Some(cert) = cache.certs.get(&params.certificate_id) {
                return Ok(cert.sign(params)?);
            }
        }

        // Not in cache — try to load on demand
        tracing::info!(
            certificate_id = %params.certificate_id,
            "certificate not in cache, attempting on-demand load"
        );

        for (idx, source_id) in self.source.sources().iter().enumerate() {
            let current_id = match self.source.fetch_current_id(source_id).await {
                Ok(id) => id,
                Err(_) => continue,
            };
            if current_id == params.certificate_id {
                let cert = self.source.load_certificate(source_id, &current_id).await?;
                let result = cert.sign(params)?;

                // Cache it
                let mut cache = self.cache.write().await;
                if !cache.current_ids.iter().any(|(i, _)| *i == idx) {
                    cache.current_ids.push((idx, current_id.clone()));
                }
                cache.certs.insert(current_id, cert);

                return Ok(result);
            }
        }

        Err(super::ProviderHelperError::CertificateNotFound(
            params.certificate_id.clone(),
        ))?
    }
}

impl<S: CertificateSource> crate::handler::Handler for CachingBackend<S> {
    async fn initialize(
        &self,
    ) -> Result<crate::message::InitializeResult, crate::message::ErrorCode> {
        self.initialize().await.map_err(Into::into)
    }

    async fn sign(
        &self,
        params: crate::message::SignParams,
    ) -> Result<crate::message::SignResult, crate::message::ErrorCode> {
        self.sign(&params).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    fn generate_cert(sans: Vec<String>) -> (String, String) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(sans).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[derive(Debug, thiserror::Error)]
    enum MockError {
        #[error("provider error: {0}")]
        Provider(#[from] super::super::ProviderHelperError),
        #[error("source error: {0}")]
        Source(String),
    }

    impl From<MockError> for crate::message::ErrorCode {
        fn from(e: MockError) -> Self {
            match e {
                MockError::Provider(pe) => pe.into(),
                other => crate::message::ErrorCode::Internal(other.to_string()),
            }
        }
    }

    struct MockSource {
        sources: Vec<String>,
        current_ids: std::sync::Mutex<Vec<String>>,
        certs: std::collections::HashMap<String, (String, String)>, // cert_id -> (fullchain, key)
    }

    impl CertificateSource for MockSource {
        type SourceId = String;
        type Error = MockError;

        fn sources(&self) -> &[String] {
            &self.sources
        }

        async fn fetch_current_id(&self, source: &String) -> Result<String, MockError> {
            let ids = self.current_ids.lock().unwrap();
            let idx = self
                .sources
                .iter()
                .position(|s| s == source)
                .ok_or_else(|| MockError::Source(format!("unknown source: {source}")))?;
            Ok(ids[idx].clone())
        }

        async fn load_certificate(
            &self,
            _source: &String,
            cert_id: &str,
        ) -> Result<super::super::Certificate, MockError> {
            let (fullchain, key) = self
                .certs
                .get(cert_id)
                .ok_or_else(|| MockError::Source(format!("cert not found: {cert_id}")))?;
            Ok(super::super::Certificate::from_pem(
                cert_id.to_owned(),
                fullchain.clone(),
                key.as_bytes(),
            )?)
        }
    }

    fn make_mock_source(
        domains: &[(&str, &str, Vec<String>)], // (source_name, cert_id, sans)
    ) -> MockSource {
        let mut sources = Vec::new();
        let mut current_ids = Vec::new();
        let mut certs = std::collections::HashMap::new();

        for (source_name, cert_id, sans) in domains {
            sources.push(source_name.to_string());
            current_ids.push(cert_id.to_string());
            let (fullchain, key) = generate_cert(sans.clone());
            certs.insert(cert_id.to_string(), (fullchain, key));
        }

        MockSource {
            sources,
            current_ids: std::sync::Mutex::new(current_ids),
            certs,
        }
    }

    #[tokio::test]
    async fn cold_initialize_fetches_all_certs() {
        let source =
            make_mock_source(&[("source-a", "cert-v1", vec!["test.example.com".to_owned()])]);
        let backend = CachingBackend::new(source);

        let result = backend.initialize().await.unwrap();
        assert_eq!(result.default, "cert-v1");
        assert_eq!(result.certificates.len(), 1);
        assert_eq!(result.certificates[0].id, "cert-v1");
        assert_eq!(result.certificates[0].domains, vec!["test.example.com"]);
    }

    #[tokio::test]
    async fn warm_initialize_unchanged() {
        let source =
            make_mock_source(&[("source-a", "cert-v1", vec!["test.example.com".to_owned()])]);
        let backend = CachingBackend::new(source);

        let result1 = backend.initialize().await.unwrap();
        assert_eq!(result1.default, "cert-v1");

        let result2 = backend.initialize().await.unwrap();
        assert_eq!(result2.default, "cert-v1");
        assert_eq!(result2.certificates.len(), 1);
    }

    #[tokio::test]
    async fn warm_initialize_detects_change() {
        let (fullchain1, key1) = generate_cert(vec!["v1.example.com".to_owned()]);
        let (fullchain2, key2) = generate_cert(vec!["v2.example.com".to_owned()]);
        let mut certs_map = std::collections::HashMap::new();
        certs_map.insert("cert-v1".to_owned(), (fullchain1, key1));
        certs_map.insert("cert-v2".to_owned(), (fullchain2, key2));

        let source = MockSource {
            sources: vec!["source-a".to_owned()],
            current_ids: std::sync::Mutex::new(vec!["cert-v1".to_owned()]),
            certs: certs_map,
        };

        let backend = CachingBackend::new(source);

        let result1 = backend.initialize().await.unwrap();
        assert_eq!(result1.certificates[0].domains, vec!["v1.example.com"]);

        // Simulate current ID change
        {
            let mut ids = backend.source.current_ids.lock().unwrap();
            ids[0] = "cert-v2".to_owned();
        }

        let result2 = backend.initialize().await.unwrap();
        assert_eq!(result2.default, "cert-v2");
        assert_eq!(result2.certificates[0].domains, vec!["v2.example.com"]);
    }

    #[tokio::test]
    async fn sign_with_cached_cert() {
        let source =
            make_mock_source(&[("source-a", "cert-v1", vec!["test.example.com".to_owned()])]);
        let backend = CachingBackend::new(source);

        let init_result = backend.initialize().await.unwrap();
        let scheme = init_result.certificates[0].schemes[0].clone();

        let sign_result = backend
            .sign(&crate::message::SignParams {
                certificate_id: "cert-v1".to_owned(),
                scheme,
                blob: crate::message::Base64Bytes::from(vec![1, 2, 3, 4]).into_secret(),
            })
            .await
            .unwrap();

        assert!(!sign_result.signature.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn sign_on_demand_loads_cert() {
        let source =
            make_mock_source(&[("source-a", "cert-v1", vec!["test.example.com".to_owned()])]);
        let backend = CachingBackend::new(source);

        // Sign without initialize — triggers on-demand load.
        // We need to know the scheme. Since it's ECDSA P256 from rcgen, use that.
        let sign_result = backend
            .sign(&crate::message::SignParams {
                certificate_id: "cert-v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: crate::message::Base64Bytes::from(vec![1, 2, 3, 4]).into_secret(),
            })
            .await
            .unwrap();

        assert!(!sign_result.signature.expose_secret().is_empty());
    }

    #[tokio::test]
    async fn sign_missing_cert_returns_error() {
        let source = make_mock_source(&[(
            "source-a",
            "other-cert",
            vec!["test.example.com".to_owned()],
        )]);
        let backend = CachingBackend::new(source);

        let err = backend
            .sign(&crate::message::SignParams {
                certificate_id: "nonexistent".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: crate::message::Base64Bytes::from(vec![1, 2, 3]).into_secret(),
            })
            .await
            .unwrap_err();

        let code: crate::message::ErrorCode = err.into();
        assert!(matches!(
            code,
            crate::message::ErrorCode::CertificateNotFound(_)
        ));
    }

    #[tokio::test]
    async fn multiple_sources() {
        let source = make_mock_source(&[
            ("source-a", "cert-a", vec!["a.example.com".to_owned()]),
            ("source-b", "cert-b", vec!["b.example.com".to_owned()]),
        ]);
        let backend = CachingBackend::new(source);

        let result = backend.initialize().await.unwrap();
        assert_eq!(result.default, "cert-a");
        assert_eq!(result.certificates.len(), 2);
        assert_eq!(result.certificates[0].domains, vec!["a.example.com"]);
        assert_eq!(result.certificates[1].domains, vec!["b.example.com"]);
    }

    #[tokio::test]
    async fn handler_trait_implementation() {
        let source =
            make_mock_source(&[("source-a", "cert-v1", vec!["test.example.com".to_owned()])]);
        let backend = CachingBackend::new(source);

        let result = crate::handler::Handler::initialize(&backend).await.unwrap();
        assert_eq!(result.default, "cert-v1");

        let scheme = result.certificates[0].schemes[0].clone();
        let sign_result = crate::handler::Handler::sign(
            &backend,
            crate::message::SignParams {
                certificate_id: "cert-v1".to_owned(),
                scheme,
                blob: crate::message::Base64Bytes::from(vec![1, 2, 3]).into_secret(),
            },
        )
        .await
        .unwrap();
        assert!(!sign_result.signature.expose_secret().is_empty());
    }
}
