use secrecy::ExposeSecret as _;

use super::ProviderHelperError;

/// A loaded certificate with its signing key and metadata.
pub struct Certificate {
    pub id: String,
    pub domains: Vec<String>,
    pub fullchain_pem: String,
    pub signing_key: std::sync::Arc<dyn rustls::sign::SigningKey>,
    pub schemes: Vec<rustls::SignatureScheme>,
}

/// Extract DNS Subject Alternative Names from the leaf certificate in a PEM chain.
pub fn dns_sans_from_pem(fullchain_pem: &str) -> Result<Vec<String>, ProviderHelperError> {
    use rustls_pki_types::pem::PemObject as _;

    let leaf_der = rustls_pki_types::CertificateDer::pem_slice_iter(fullchain_pem.as_bytes())
        .next()
        .ok_or_else(|| ProviderHelperError::PemParse("fullchain PEM is empty".to_owned()))?
        .map_err(|e| {
            ProviderHelperError::PemParse(format!("failed to parse leaf cert PEM: {e}"))
        })?;

    let (_, cert) = x509_parser::parse_x509_certificate(&leaf_der).map_err(|e| {
        ProviderHelperError::X509Parse(format!("failed to parse leaf certificate: {e}"))
    })?;

    let mut dns_names = Vec::new();
    if let Some(san) = cert.subject_alternative_name().map_err(|e| {
        ProviderHelperError::X509Parse(format!("failed to parse SAN extension: {e}"))
    })? {
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                dns_names.push((*dns).to_owned());
            }
        }
    }
    Ok(dns_names)
}

const ALL_SCHEMES: &[rustls::SignatureScheme] = &[
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

impl Certificate {
    /// Construct a Certificate from PEM-encoded fullchain and key.
    pub fn from_pem(
        id: String,
        fullchain_pem: String,
        key_pem: &[u8],
    ) -> Result<Self, ProviderHelperError> {
        use rustls_pki_types::pem::PemObject as _;

        let domains = dns_sans_from_pem(&fullchain_pem)?;

        let key_der = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| ProviderHelperError::KeyParse(format!("failed to parse key PEM: {e}")))?;

        Self::from_pem_and_key_der(id, fullchain_pem, domains, key_der)
    }

    /// Construct a Certificate from PEM-encoded fullchain and a possibly-encrypted key.
    ///
    /// If `passphrase` is `Some`, attempts to decrypt the key using
    /// [`super::decrypt_key_if_encrypted`]. If the key is not encrypted, the passphrase is ignored.
    #[cfg(feature = "encrypted-key")]
    pub fn from_pem_with_passphrase(
        id: String,
        fullchain_pem: String,
        key_pem: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Self, ProviderHelperError> {
        if let Some(passphrase) = passphrase
            && let Some(key_der_bytes) = super::decrypt_key_if_encrypted(key_pem, passphrase)?
        {
            let domains = dns_sans_from_pem(&fullchain_pem)?;
            let key_der =
                rustls_pki_types::PrivateKeyDer::try_from(key_der_bytes).map_err(|e| {
                    ProviderHelperError::KeyDecryption(format!(
                        "failed to parse decrypted key DER: {e}"
                    ))
                })?;
            return Self::from_pem_and_key_der(id, fullchain_pem, domains, key_der);
        }
        Self::from_pem(id, fullchain_pem, key_pem)
    }

    /// Construct a Certificate from PEM-encoded fullchain and a DER-encoded private key.
    pub fn from_pem_and_key_der(
        id: String,
        fullchain_pem: String,
        domains: Vec<String>,
        key_der: rustls_pki_types::PrivateKeyDer<'_>,
    ) -> Result<Self, ProviderHelperError> {
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der).map_err(|e| {
                ProviderHelperError::KeyParse(format!("failed to parse signing key: {e}"))
            })?;

        let schemes: Vec<rustls::SignatureScheme> = ALL_SCHEMES
            .iter()
            .filter(|s| signing_key.choose_scheme(&[**s]).is_some())
            .copied()
            .collect();

        Ok(Self {
            id,
            domains,
            fullchain_pem,
            signing_key,
            schemes,
        })
    }

    /// Sign a blob using the specified scheme.
    pub fn sign(
        &self,
        params: &crate::message::SignParams,
    ) -> Result<crate::message::SignResult, ProviderHelperError> {
        super::blob_check::check_and_log_blob(params)?;

        let requested_scheme = crate::scheme::parse_scheme(&params.scheme).ok_or_else(|| {
            ProviderHelperError::UnsupportedScheme(format!(
                "unknown signature scheme: {}",
                params.scheme,
            ))
        })?;

        let signer = self
            .signing_key
            .choose_scheme(&[requested_scheme])
            .ok_or_else(|| {
                ProviderHelperError::UnsupportedScheme(format!(
                    "unsupported signature scheme for this certificate: {}",
                    params.scheme,
                ))
            })?;

        let signature = signer
            .sign(params.blob.expose_secret())
            .map_err(|e| ProviderHelperError::SigningFailed(format!("signing failed: {e}")))?;

        Ok(crate::message::SignResult {
            signature: crate::message::Base64Bytes::from(signature).into_secret(),
        })
    }

    /// Build a `CertificateInfo` protocol message from this certificate.
    pub fn to_certificate_info(&self) -> crate::message::CertificateInfo {
        crate::message::CertificateInfo {
            id: self.id.clone(),
            domains: self.domains.clone(),
            pem: self.fullchain_pem.clone(),
            schemes: self
                .schemes
                .iter()
                .map(|s| crate::scheme::scheme_to_string(*s).to_owned())
                .collect(),
        }
    }
}

/// Build an `InitializeResult` from a default certificate ID and a slice of certificates.
pub fn build_initialize_result(
    default: &str,
    certs: &[Certificate],
) -> crate::message::InitializeResult {
    crate::message::InitializeResult {
        default: default.to_owned(),
        certificates: certs.iter().map(|c| c.to_certificate_info()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::blob_check::test_tls13_blob;
    use super::*;

    fn generate_cert(sans: Vec<String>) -> (String, String) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(sans).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn dns_sans_from_pem_extracts_names() {
        let (pem, _) = generate_cert(vec![
            "example.com".to_owned(),
            "*.example.com".to_owned(),
            "other.example.net".to_owned(),
        ]);
        let sans = dns_sans_from_pem(&pem).unwrap();
        assert_eq!(
            sans,
            vec!["example.com", "*.example.com", "other.example.net"]
        );
    }

    #[test]
    fn dns_sans_from_pem_empty_sans() {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![];
        let cert = params.self_signed(&key_pair).unwrap();

        let sans = dns_sans_from_pem(&cert.pem()).unwrap();
        assert!(sans.is_empty());
    }

    #[test]
    fn dns_sans_from_pem_empty_input() {
        let result = dns_sans_from_pem("");
        assert!(result.is_err());
    }

    #[test]
    fn certificate_from_pem_constructs_entry() {
        let (pem, key) = generate_cert(vec!["test.example.com".to_owned()]);
        let cert = Certificate::from_pem("test/v1".to_owned(), pem, key.as_bytes()).unwrap();

        assert_eq!(cert.id, "test/v1");
        assert_eq!(cert.domains, vec!["test.example.com"]);
        assert!(!cert.schemes.is_empty());
    }

    #[test]
    fn certificate_sign_succeeds() {
        let (pem, key) = generate_cert(vec!["test.example.com".to_owned()]);
        let cert = Certificate::from_pem("test/v1".to_owned(), pem, key.as_bytes()).unwrap();

        let scheme_name = crate::scheme::scheme_to_string(cert.schemes[0]);
        let params = crate::message::SignParams {
            certificate_id: "test/v1".to_owned(),
            scheme: scheme_name.to_owned(),
            blob: crate::message::Base64Bytes::from(test_tls13_blob()).into_secret(),
        };
        let result = cert.sign(&params).unwrap();
        assert!(!result.signature.expose_secret().is_empty());
    }

    #[test]
    fn certificate_sign_unknown_scheme() {
        let (pem, key) = generate_cert(vec!["test.example.com".to_owned()]);
        let cert = Certificate::from_pem("test/v1".to_owned(), pem, key.as_bytes()).unwrap();

        let params = crate::message::SignParams {
            certificate_id: "test/v1".to_owned(),
            scheme: "NONEXISTENT_SCHEME".to_owned(),
            blob: crate::message::Base64Bytes::from(test_tls13_blob()).into_secret(),
        };
        let err = cert.sign(&params).unwrap_err();
        assert!(matches!(err, ProviderHelperError::UnsupportedScheme(_)));
    }

    #[test]
    fn certificate_to_certificate_info() {
        let (pem, key) = generate_cert(vec!["test.example.com".to_owned()]);
        let cert =
            Certificate::from_pem("test/v1".to_owned(), pem.clone(), key.as_bytes()).unwrap();

        let info = cert.to_certificate_info();
        assert_eq!(info.id, "test/v1");
        assert_eq!(info.domains, vec!["test.example.com"]);
        assert_eq!(info.pem, pem);
        assert!(!info.schemes.is_empty());
    }

    #[test]
    fn build_initialize_result_constructs_response() {
        let (pem, key) = generate_cert(vec!["a.example.com".to_owned()]);
        let cert = Certificate::from_pem("cert-a".to_owned(), pem, key.as_bytes()).unwrap();

        let result = build_initialize_result("cert-a", &[cert]);
        assert_eq!(result.default, "cert-a");
        assert_eq!(result.certificates.len(), 1);
        assert_eq!(result.certificates[0].id, "cert-a");
    }
}
