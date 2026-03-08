mod backend;
mod certificate;
#[cfg(feature = "encrypted-key")]
mod encrypted_key;

pub use backend::*;
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

impl From<ProviderHelperError> for crate::message::ErrorCode {
    fn from(e: ProviderHelperError) -> Self {
        match e {
            ProviderHelperError::CertificateNotFound(m) => {
                crate::message::ErrorCode::CertificateNotFound(m)
            }
            ProviderHelperError::UnsupportedScheme(m) => {
                crate::message::ErrorCode::UnsupportedScheme(m)
            }
            ProviderHelperError::SigningFailed(m) | ProviderHelperError::KeyDecryption(m) => {
                crate::message::ErrorCode::SigningFailed(m)
            }
            other => crate::message::ErrorCode::SigningFailed(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_to_error_code() {
        let cert_err: crate::message::ErrorCode =
            ProviderHelperError::CertificateNotFound("x".to_owned()).into();
        assert!(matches!(
            cert_err,
            crate::message::ErrorCode::CertificateNotFound(_)
        ));

        let scheme_err: crate::message::ErrorCode =
            ProviderHelperError::UnsupportedScheme("x".to_owned()).into();
        assert!(matches!(
            scheme_err,
            crate::message::ErrorCode::UnsupportedScheme(_)
        ));

        let sign_err: crate::message::ErrorCode =
            ProviderHelperError::SigningFailed("x".to_owned()).into();
        assert!(matches!(
            sign_err,
            crate::message::ErrorCode::SigningFailed(_)
        ));
    }
}
