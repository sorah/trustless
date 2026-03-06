mod certificate;
#[cfg(feature = "encrypted-key")]
mod encrypted_key;

pub use certificate::*;
#[cfg(feature = "encrypted-key")]
pub use encrypted_key::*;

/// Error type for provider helper operations.
#[derive(Debug, thiserror::Error)]
pub enum ProviderHelperError {
    #[error("failed to parse PEM: {0}")]
    PemParse(String),

    #[error("failed to parse X.509 certificate: {0}")]
    X509Parse(String),

    #[error("failed to parse signing key: {0}")]
    KeyParse(String),

    #[error("certificate not found: {0}")]
    CertificateNotFound(String),

    #[error("unsupported signature scheme: {0}")]
    UnsupportedScheme(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("key decryption error: {0}")]
    KeyDecryption(String),
}

impl From<ProviderHelperError> for crate::message::ErrorPayload {
    fn from(e: ProviderHelperError) -> Self {
        let (code, message) = match &e {
            ProviderHelperError::CertificateNotFound(_) => (1, e.to_string()),
            ProviderHelperError::UnsupportedScheme(_) => (2, e.to_string()),
            ProviderHelperError::SigningFailed(_) => (3, e.to_string()),
            ProviderHelperError::KeyDecryption(_) => (3, e.to_string()),
            _ => (3, e.to_string()),
        };
        crate::message::ErrorPayload { code, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_to_error_payload_codes() {
        let cert_err: crate::message::ErrorPayload =
            ProviderHelperError::CertificateNotFound("x".to_owned()).into();
        assert_eq!(cert_err.code, 1);

        let scheme_err: crate::message::ErrorPayload =
            ProviderHelperError::UnsupportedScheme("x".to_owned()).into();
        assert_eq!(scheme_err.code, 2);

        let sign_err: crate::message::ErrorPayload =
            ProviderHelperError::SigningFailed("x".to_owned()).into();
        assert_eq!(sign_err.code, 3);
    }
}
