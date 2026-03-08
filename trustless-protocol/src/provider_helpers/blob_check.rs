use std::sync::OnceLock;

use secrecy::ExposeSecret as _;

use super::ProviderHelperError;

const TLS13_PADDING: &[u8] = &[0x20; 64];
const TLS13_SERVER_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";

fn is_tls13_server_verify_blob(blob: &[u8]) -> bool {
    if blob.len() < TLS13_PADDING.len() + TLS13_SERVER_CONTEXT.len() {
        return false;
    }
    if !blob.starts_with(TLS13_PADDING) {
        return false;
    }
    let after_padding = &blob[TLS13_PADDING.len()..];
    after_padding.starts_with(TLS13_SERVER_CONTEXT)
}

fn blob_check_disabled() -> bool {
    static DISABLED: OnceLock<bool> = OnceLock::new();
    *DISABLED
        .get_or_init(|| std::env::var("TRUSTLESS_DISABLE_BLOB_CHECK_TLS").as_deref() == Ok("1"))
}

fn blob_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TRUSTLESS_LOG_BLOB").as_deref() == Ok("1"))
}

/// Validate that a signing blob looks like a TLS 1.3 server CertificateVerify message.
///
/// Only server CertificateVerify is accepted because Trustless only operates as a TLS server.
/// Disabled when `TRUSTLESS_DISABLE_BLOB_CHECK_TLS=1`.
pub fn check_blob(blob: &[u8]) -> Result<(), ProviderHelperError> {
    if blob_check_disabled() {
        return Ok(());
    }
    if !is_tls13_server_verify_blob(blob) {
        return Err(ProviderHelperError::BlobCheckFailed(
            "blob does not look like a TLS 1.3 server CertificateVerify message".to_owned(),
        ));
    }
    Ok(())
}

/// Log blob contents when `TRUSTLESS_LOG_BLOB=1`.
pub fn log_blob(blob: &[u8], certificate_id: &str, scheme: &str) {
    if !blob_log_enabled() {
        return;
    }
    let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(
        certificate_id,
        scheme,
        blob_len = blob.len(),
        blob_hex = %hex,
        "sign blob"
    );
}

/// Build a valid TLS 1.3 server CertificateVerify blob for testing.
#[cfg(test)]
pub fn test_tls13_blob() -> Vec<u8> {
    let mut blob = vec![0x20; 64];
    blob.extend_from_slice(TLS13_SERVER_CONTEXT);
    blob.extend_from_slice(&[0xaa; 32]); // mock handshake hash
    blob
}

/// Call [`check_blob`] and [`log_blob`] for a sign request.
pub fn check_and_log_blob(params: &crate::message::SignParams) -> Result<(), ProviderHelperError> {
    let blob = params.blob.expose_secret();
    log_blob(blob, &params.certificate_id, &params.scheme);
    check_blob(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tls13_server_blob() {
        let blob = test_tls13_blob();
        assert!(is_tls13_server_verify_blob(&blob));
        check_blob(&blob).unwrap();
    }

    #[test]
    fn rejects_tls13_client_blob() {
        let mut blob = vec![0x20; 64];
        blob.extend_from_slice(b"TLS 1.3, client CertificateVerify\x00");
        blob.extend_from_slice(&[0xbb; 48]);
        assert!(!is_tls13_server_verify_blob(&blob));
        check_blob(&blob).unwrap_err();
    }

    #[test]
    fn rejects_non_tls13_blob() {
        let blob = vec![1, 2, 3, 4];
        assert!(!is_tls13_server_verify_blob(&blob));
        let err = check_blob(&blob).unwrap_err();
        assert!(matches!(err, ProviderHelperError::BlobCheckFailed(_)));
    }

    #[test]
    fn rejects_too_short_blob() {
        let blob = vec![0x20; 60];
        assert!(!is_tls13_server_verify_blob(&blob));
        check_blob(&blob).unwrap_err();
    }

    #[test]
    fn rejects_wrong_padding() {
        let mut blob = vec![0x00; 64];
        blob.extend_from_slice(TLS13_SERVER_CONTEXT);
        blob.extend_from_slice(&[0xaa; 32]);
        assert!(!is_tls13_server_verify_blob(&blob));
        check_blob(&blob).unwrap_err();
    }
}
