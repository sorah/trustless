#[derive(Debug, thiserror::Error)]
enum StubError {
    #[error("provider error: {0}")]
    Provider(#[from] trustless_protocol::provider_helpers::ProviderHelperError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<StubError> for trustless_protocol::message::ErrorCode {
    fn from(e: StubError) -> Self {
        match e {
            StubError::Provider(pe) => pe.into(),
            other => trustless_protocol::message::ErrorCode::Internal(other.to_string()),
        }
    }
}

struct CertSourceEntry {
    path: std::path::PathBuf,
    domain_name: String,
}

struct FilesystemSource {
    sources: Vec<CertSourceEntry>,
    passphrase: Option<String>,
}

impl FilesystemSource {
    fn scan(cert_dir: &std::path::Path, passphrase: Option<String>) -> anyhow::Result<Self> {
        let certs_dir = cert_dir.join("certs");
        let mut sources = Vec::new();

        let mut entries: Vec<_> = std::fs::read_dir(&certs_dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let domain_name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-utf8 directory name"))?
                .to_owned();

            sources.push(CertSourceEntry { path, domain_name });
        }

        if sources.is_empty() {
            anyhow::bail!("no certificates found");
        }

        Ok(Self {
            sources,
            passphrase,
        })
    }
}

impl trustless_protocol::provider_helpers::CertificateSource for FilesystemSource {
    type SourceId = CertSourceEntry;
    type Error = StubError;

    fn sources(&self) -> &[CertSourceEntry] {
        &self.sources
    }

    async fn fetch_current_id(&self, source: &CertSourceEntry) -> Result<String, StubError> {
        let current_path = source.path.join("current");
        let version = std::fs::read_to_string(&current_path)?.trim().to_owned();
        let id = format!("{}/{version}", source.domain_name);
        Ok(id)
    }

    async fn load_certificate(
        &self,
        source: &CertSourceEntry,
        cert_id: &str,
    ) -> Result<trustless_protocol::provider_helpers::Certificate, StubError> {
        // cert_id is "{domain_name}/{version}", extract version
        let version = cert_id
            .strip_prefix(&source.domain_name)
            .and_then(|s| s.strip_prefix('/'))
            .unwrap_or(cert_id);

        let version_dir = source.path.join(version);

        let fullchain_pem = match std::fs::read_to_string(version_dir.join("fullchain.pem")) {
            Ok(pem) => pem,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::read_to_string(version_dir.join("cert.pem"))?
            }
            Err(e) => return Err(e.into()),
        };
        let key_pem = std::fs::read(version_dir.join("key.pem"))?;

        let cert = trustless_protocol::provider_helpers::Certificate::from_pem_with_passphrase(
            cert_id.to_owned(),
            fullchain_pem,
            &key_pem,
            self.passphrase.as_deref(),
        )?;

        Ok(cert)
    }
}

#[derive(clap::Parser)]
struct Args {
    #[clap(long)]
    cert_dir: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser as _;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let passphrase = std::env::var("TRUSTLESS_KEY_PASSPHRASE").ok();
    let source = FilesystemSource::scan(&args.cert_dir, passphrase)?;

    tracing::info!(count = source.sources.len(), "loaded certificate sources");

    let backend = trustless_protocol::provider_helpers::CachingBackend::new(source);
    trustless_protocol::handler::run(backend).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    fn setup_cert_dir(domain_dir: &str, version: &str, sans: Vec<String>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let domain_path = dir.path().join("certs").join(domain_dir);
        let version_path = domain_path.join(version);
        std::fs::create_dir_all(&version_path).unwrap();

        std::fs::write(domain_path.join("current"), version).unwrap();

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(sans).unwrap();
        std::fs::write(version_path.join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(version_path.join("key.pem"), key_pair.serialize_pem()).unwrap();

        dir
    }

    #[test]
    fn scan_finds_certificate_sources() {
        let dir = setup_cert_dir(
            "example.com",
            "2026-01-01",
            vec![
                "example.com".to_owned(),
                "*.example.com".to_owned(),
                "other.example.net".to_owned(),
            ],
        );

        let source = FilesystemSource::scan(dir.path(), None).unwrap();

        assert_eq!(source.sources.len(), 1);
        assert_eq!(source.sources[0].domain_name, "example.com");
    }

    #[tokio::test]
    async fn initialize_loads_certs_from_filesystem() {
        let dir = setup_cert_dir(
            "example.com",
            "2026-01-01",
            vec![
                "example.com".to_owned(),
                "*.example.com".to_owned(),
                "other.example.net".to_owned(),
            ],
        );

        let source = FilesystemSource::scan(dir.path(), None).unwrap();
        let backend = trustless_protocol::provider_helpers::CachingBackend::new(source);

        let result = backend.initialize().await.unwrap();

        assert_eq!(result.default, "example.com/2026-01-01");
        assert_eq!(result.certificates.len(), 1);
        assert_eq!(result.certificates[0].id, "example.com/2026-01-01");
        assert_eq!(
            result.certificates[0].domains,
            vec!["example.com", "*.example.com", "other.example.net"],
        );
    }

    #[tokio::test]
    async fn sign_via_caching_backend() {
        let dir = setup_cert_dir("example.com", "v1", vec!["example.com".to_owned()]);

        let source = FilesystemSource::scan(dir.path(), None).unwrap();
        let backend = trustless_protocol::provider_helpers::CachingBackend::new(source);

        let init_result = backend.initialize().await.unwrap();
        let scheme = init_result.certificates[0].schemes[0].clone();

        let sign_result = backend
            .sign(&trustless_protocol::message::SignParams {
                certificate_id: "example.com/v1".to_owned(),
                scheme,
                blob: trustless_protocol::message::Base64Bytes::from(vec![1, 2, 3, 4])
                    .into_secret(),
            })
            .await
            .unwrap();

        assert!(!sign_result.signature.expose_secret().is_empty());
    }

    #[test]
    fn scan_empty_certs_dir_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("certs")).unwrap();
        assert!(FilesystemSource::scan(dir.path(), None).is_err());
    }

    #[test]
    fn cert_entry_from_pem_constructs_entry() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["test.example.com".to_owned()]).unwrap();

        let entry = trustless_protocol::provider_helpers::Certificate::from_pem(
            "test/v1".to_owned(),
            cert.pem(),
            key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();

        assert_eq!(entry.id, "test/v1");
        assert_eq!(entry.domains, vec!["test.example.com"]);
    }

    #[tokio::test]
    async fn load_handles_certificate_without_sans() {
        let dir = tempfile::tempdir().unwrap();
        let domain_path = dir.path().join("certs").join("bare.test");
        let version_path = domain_path.join("v1");
        std::fs::create_dir_all(&version_path).unwrap();
        std::fs::write(domain_path.join("current"), "v1").unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![];
        let cert = params.self_signed(&key_pair).unwrap();
        std::fs::write(version_path.join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(version_path.join("key.pem"), key_pair.serialize_pem()).unwrap();

        let source = FilesystemSource::scan(dir.path(), None).unwrap();
        let backend = trustless_protocol::provider_helpers::CachingBackend::new(source);

        let result = backend.initialize().await.unwrap();
        assert!(result.certificates[0].domains.is_empty());
    }
}
