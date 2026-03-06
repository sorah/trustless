struct CertEntry {
    id: String,
    domains: Vec<String>,
    fullchain_pem: String,
    signing_key: std::sync::Arc<dyn rustls::sign::SigningKey>,
}

struct StubHandler {
    default: String,
    certs: Vec<CertEntry>,
}

impl StubHandler {
    fn load(cert_dir: &std::path::Path) -> anyhow::Result<Self> {
        let certs_dir = cert_dir.join("certs");
        let mut certs = Vec::new();
        let mut default = None;

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

            let current_path = path.join("current");
            let version = std::fs::read_to_string(&current_path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", current_path.display()))?
                .trim()
                .to_owned();

            let version_dir = path.join(&version);

            let fullchain_pem = std::fs::read_to_string(version_dir.join("fullchain.pem"))?;

            let key_der = {
                use rustls_pki_types::pem::PemObject as _;
                rustls_pki_types::PrivateKeyDer::from_pem_file(version_dir.join("key.pem"))
                    .map_err(|e| anyhow::anyhow!("failed to load key.pem: {e}"))?
            };

            let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
                .map_err(|e| anyhow::anyhow!("failed to parse signing key: {e}"))?;

            let id = format!("{domain_name}/{version}");
            let domains = {
                use rustls_pki_types::pem::PemObject as _;
                let leaf_der = rustls_pki_types::CertificateDer::pem_file_iter(
                    version_dir.join("fullchain.pem"),
                )
                .map_err(|e| anyhow::anyhow!("failed to read fullchain.pem for DER parsing: {e}"))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("fullchain.pem is empty"))?
                .map_err(|e| anyhow::anyhow!("failed to parse leaf cert PEM: {e}"))?;

                let (_, cert) = x509_parser::parse_x509_certificate(&leaf_der)
                    .map_err(|e| anyhow::anyhow!("failed to parse leaf certificate: {e}"))?;

                let mut dns_names = Vec::new();
                if let Some(san) = cert
                    .subject_alternative_name()
                    .map_err(|e| anyhow::anyhow!("failed to parse SAN extension: {e}"))?
                {
                    for name in &san.value.general_names {
                        if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                            dns_names.push((*dns).to_owned());
                        }
                    }
                }
                dns_names
            };

            if default.is_none() {
                default = Some(id.clone());
            }

            certs.push(CertEntry {
                id,
                domains,
                fullchain_pem,
                signing_key,
            });
        }

        let default = default.ok_or_else(|| anyhow::anyhow!("no certificates found"))?;

        Ok(Self { default, certs })
    }
}

impl trustless_protocol::handler::Handler for StubHandler {
    async fn initialize(
        &self,
    ) -> Result<
        trustless_protocol::message::InitializeResult,
        trustless_protocol::message::ErrorPayload,
    > {
        let certificates = self
            .certs
            .iter()
            .map(|c| trustless_protocol::message::CertificateInfo {
                id: c.id.clone(),
                domains: c.domains.clone(),
                pem: c.fullchain_pem.clone(),
            })
            .collect();

        Ok(trustless_protocol::message::InitializeResult {
            default: self.default.clone(),
            certificates,
        })
    }

    async fn sign(
        &self,
        params: trustless_protocol::message::SignParams,
    ) -> Result<trustless_protocol::message::SignResult, trustless_protocol::message::ErrorPayload>
    {
        let cert = self
            .certs
            .iter()
            .find(|c| c.id == params.certificate_id)
            .ok_or_else(|| trustless_protocol::message::ErrorPayload {
                code: 1,
                message: format!("certificate not found: {}", params.certificate_id),
            })?;

        // Offer all common schemes; the signing key picks the first it supports
        let schemes = &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ];

        let signer = cert.signing_key.choose_scheme(schemes).ok_or_else(|| {
            trustless_protocol::message::ErrorPayload {
                code: 2,
                message: "no compatible signature scheme".to_owned(),
            }
        })?;

        let signature =
            signer
                .sign(&params.blob)
                .map_err(|e| trustless_protocol::message::ErrorPayload {
                    code: 3,
                    message: format!("signing failed: {e}"),
                })?;

        Ok(trustless_protocol::message::SignResult { signature })
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
    let handler = StubHandler::load(&args.cert_dir)?;

    tracing::info!(
        default = %handler.default,
        count = handler.certs.len(),
        "loaded certificates"
    );

    trustless_protocol::handler::run(handler).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
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
    fn load_extracts_dns_sans_from_certificate() {
        let dir = setup_cert_dir(
            "example.com",
            "2026-01-01",
            vec![
                "example.com".to_owned(),
                "*.example.com".to_owned(),
                "other.example.net".to_owned(),
            ],
        );

        let handler = StubHandler::load(dir.path()).unwrap();

        assert_eq!(handler.certs.len(), 1);
        assert_eq!(handler.default, "example.com/2026-01-01");

        let cert = &handler.certs[0];
        assert_eq!(cert.id, "example.com/2026-01-01");
        assert_eq!(
            cert.domains,
            vec!["example.com", "*.example.com", "other.example.net"],
        );
    }

    #[test]
    fn load_handles_certificate_without_sans() {
        let dir = tempfile::tempdir().unwrap();
        let domain_path = dir.path().join("certs").join("bare.test");
        let version_path = domain_path.join("v1");
        std::fs::create_dir_all(&version_path).unwrap();
        std::fs::write(domain_path.join("current"), "v1").unwrap();

        // Generate a cert with no SANs using CertificateParams directly
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![];
        let cert = params.self_signed(&key_pair).unwrap();
        std::fs::write(version_path.join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(version_path.join("key.pem"), key_pair.serialize_pem()).unwrap();

        let handler = StubHandler::load(dir.path()).unwrap();
        assert!(handler.certs[0].domains.is_empty());
    }
}
