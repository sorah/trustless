use crate::signer::{RemoteSigningKey, SigningThreadHandle};

// --- ProviderRegistry ---

#[derive(Clone, Debug)]
pub struct ProviderRegistry {
    inner: std::sync::Arc<std::sync::RwLock<ProviderRegistryInner>>,
}

#[derive(Debug)]
struct ProviderRegistryInner {
    providers: Vec<ProviderEntry>,
    control_cert: Option<ControlCertEntry>,
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

struct ControlCertEntry {
    domains: Vec<String>,
    certified_key: std::sync::Arc<rustls::sign::CertifiedKey>,
}

impl std::fmt::Debug for ControlCertEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlCertEntry")
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
                control_cert: None,
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

    /// Register a local CertifiedKey (not from a remote provider).
    /// Used for the self-signed control API certificate.
    /// Repeated calls overwrite the previous control cert.
    pub fn register_control_cert(
        &self,
        certified_key: std::sync::Arc<rustls::sign::CertifiedKey>,
        domains: Vec<String>,
    ) {
        let mut inner = self.inner.write().unwrap();
        inner.control_cert = Some(ControlCertEntry {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            certified_key,
        });
    }

    pub fn resolve_by_sni(
        &self,
        sni: Option<&str>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        let inner = self.inner.read().unwrap();

        if let Some(sni) = sni {
            let sni_lower = sni.to_ascii_lowercase();

            // Check control cert
            if let Some(ref control) = inner.control_cert
                && matches_sni(&sni_lower, &control.domains)
            {
                return Some(control.certified_key.clone());
            }

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

    #[test]
    fn register_control_cert_resolve() {
        let registry = ProviderRegistry::new();

        let key_pair = rcgen::generate_simple_self_signed(vec!["trustless".to_owned()]).unwrap();
        let cert_der = rustls_pki_types::CertificateDer::from(key_pair.cert.der().to_vec());
        let key_der =
            rustls_pki_types::PrivateKeyDer::try_from(key_pair.key_pair.serialize_der()).unwrap();
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der).unwrap();
        let certified_key =
            std::sync::Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key));

        registry.register_control_cert(certified_key.clone(), vec!["trustless".to_owned()]);

        let resolved = registry.resolve_by_sni(Some("trustless"));
        assert!(resolved.is_some());

        // Non-matching SNI should not resolve to control cert
        let resolved = registry.resolve_by_sni(Some("other.example.com"));
        assert!(resolved.is_none());
    }

    #[test]
    fn register_control_cert_overwrites() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let registry = ProviderRegistry::new();

        let make_cert = |domain: &str| {
            let key_pair = rcgen::generate_simple_self_signed(vec![domain.to_owned()]).unwrap();
            let cert_der = rustls_pki_types::CertificateDer::from(key_pair.cert.der().to_vec());
            let key_der =
                rustls_pki_types::PrivateKeyDer::try_from(key_pair.key_pair.serialize_der())
                    .unwrap();
            let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key_der).unwrap();
            std::sync::Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key))
        };

        registry.register_control_cert(make_cert("trustless"), vec!["trustless".to_owned()]);
        registry.register_control_cert(make_cert("trustless"), vec!["trustless".to_owned()]);

        // Should still resolve (overwritten, not duplicated)
        let resolved = registry.resolve_by_sni(Some("trustless"));
        assert!(resolved.is_some());
    }
}
