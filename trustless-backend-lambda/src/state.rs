use crate::config::{AppConfig, S3Prefix};
use crate::error::AppError;

pub(crate) struct S3Source {
    config: AppConfig,
    s3_client: aws_sdk_s3::Client,
    ssm_client: aws_sdk_ssm::Client,
    ssm_passphrase: tokio::sync::OnceCell<secrecy::SecretString>,
}

impl S3Source {
    async fn get_passphrase(&self) -> Result<&secrecy::SecretString, AppError> {
        self.ssm_passphrase
            .get_or_try_init(|| async {
                let arn = self.config.key_passphrase_ssm_arn.as_ref().ok_or_else(|| {
                    AppError::Config(
                        "encrypted key found but TRUSTLESS_KEY_PASSPHRASE_SSM_ARN is not set"
                            .to_owned(),
                    )
                })?;

                tracing::info!("fetching passphrase from SSM");
                let result = self
                    .ssm_client
                    .get_parameter()
                    .name(arn)
                    .with_decryption(true)
                    .send()
                    .await
                    .map_err(|e| AppError::Ssm(format!("failed to get SSM parameter: {e}")))?;

                let value = result
                    .parameter()
                    .and_then(|p| p.value())
                    .ok_or_else(|| AppError::Ssm("SSM parameter has no value".to_owned()))?;

                let secret = secrecy::SecretString::from(value.to_owned());
                tracing::info!("fetched passphrase from SSM");
                Ok(secret)
            })
            .await
    }

    async fn fetch_s3_text(&self, bucket: &str, key: &str) -> Result<Option<String>, AppError> {
        let result = self
            .s3_client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await;

        match result {
            Ok(output) => {
                let bytes = output.body.collect().await.map_err(|e| {
                    AppError::S3(format!("failed to read S3 body {bucket}/{key}: {e}"))
                })?;
                let text = String::from_utf8(bytes.to_vec()).map_err(|e| {
                    AppError::S3(format!("S3 object is not UTF-8 {bucket}/{key}: {e}"))
                })?;
                Ok(Some(text))
            }
            Err(sdk_err) => {
                if let aws_sdk_s3::error::SdkError::ServiceError(ref se) = sdk_err
                    && se.err().is_no_such_key()
                {
                    return Ok(None);
                }
                Err(AppError::S3(format!(
                    "failed to get S3 object {bucket}/{key}: {sdk_err}"
                )))
            }
        }
    }

    async fn fetch_s3_bytes(&self, bucket: &str, key: &str) -> Result<Vec<u8>, AppError> {
        let output = self
            .s3_client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AppError::S3(format!("failed to get S3 object {bucket}/{key}: {e}")))?;

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| AppError::S3(format!("failed to read S3 body {bucket}/{key}: {e}")))?;
        Ok(bytes.to_vec())
    }

    async fn get_passphrase_str(&self) -> Result<Option<String>, AppError> {
        use secrecy::ExposeSecret as _;

        if self.config.key_passphrase_ssm_arn.is_none() {
            return Ok(None);
        }
        let passphrase = self.get_passphrase().await?;
        Ok(Some(passphrase.expose_secret().to_owned()))
    }
}

impl trustless_protocol::provider_helpers::CertificateSource for S3Source {
    type SourceId = S3Prefix;
    type Error = AppError;

    fn sources(&self) -> &[S3Prefix] {
        &self.config.s3_urls
    }

    async fn fetch_current_id(&self, prefix: &S3Prefix) -> Result<String, AppError> {
        let current_key = format!("{}current", prefix.key_prefix);
        let text = self
            .fetch_s3_text(&prefix.bucket, &current_key)
            .await?
            .ok_or_else(|| {
                AppError::S3(format!(
                    "'current' object not found at {}/{}",
                    prefix.bucket, current_key,
                ))
            })?;
        Ok(text.trim().to_owned())
    }

    async fn load_certificate(
        &self,
        prefix: &S3Prefix,
        cert_id: &str,
    ) -> Result<trustless_protocol::provider_helpers::Certificate, AppError> {
        let fullchain_key = format!("{}{}/fullchain.pem", prefix.key_prefix, cert_id);
        let cert_key = format!("{}{}/cert.pem", prefix.key_prefix, cert_id);
        let key_key = format!("{}{}/key.pem", prefix.key_prefix, cert_id);

        tracing::debug!(bucket = %prefix.bucket, cert_id, "fetching certificate from S3");

        let fullchain_pem = match self.fetch_s3_text(&prefix.bucket, &fullchain_key).await? {
            Some(pem) => pem,
            None => {
                tracing::debug!(
                    bucket = %prefix.bucket,
                    cert_id,
                    "fullchain.pem not found, falling back to cert.pem"
                );
                self.fetch_s3_text(&prefix.bucket, &cert_key)
                    .await?
                    .ok_or_else(|| {
                        AppError::S3(format!(
                            "neither fullchain.pem nor cert.pem found for {cert_id} in {}/{}",
                            prefix.bucket, prefix.key_prefix
                        ))
                    })?
            }
        };

        let key_pem_raw = self.fetch_s3_bytes(&prefix.bucket, &key_key).await?;
        let passphrase = self.get_passphrase_str().await?;

        let cert = trustless_protocol::provider_helpers::Certificate::from_pem_with_passphrase(
            cert_id.to_owned(),
            fullchain_pem,
            &key_pem_raw,
            passphrase.as_deref(),
        )?;

        tracing::info!(cert_id, domains = ?cert.domains, "loaded certificate");
        Ok(cert)
    }
}

pub(crate) type AppState = trustless_protocol::provider_helpers::CachingBackend<S3Source>;

pub(crate) fn new_app_state(
    config: AppConfig,
    s3_client: aws_sdk_s3::Client,
    ssm_client: aws_sdk_ssm::Client,
) -> AppState {
    trustless_protocol::provider_helpers::CachingBackend::new(S3Source {
        config,
        s3_client,
        ssm_client,
        ssm_passphrase: tokio::sync::OnceCell::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_mocks::{RuleMode, mock, mock_client};

    fn generate_cert(sans: Vec<String>) -> (String, String) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(sans).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn make_s3_client(rules: &[&aws_smithy_mocks::Rule]) -> aws_sdk_s3::Client {
        mock_client!(aws_sdk_s3, RuleMode::Sequential, rules)
    }

    fn make_ssm_client(rules: &[&aws_smithy_mocks::Rule]) -> aws_sdk_ssm::Client {
        mock_client!(aws_sdk_ssm, RuleMode::Sequential, rules)
    }

    fn make_state(
        s3_urls: Vec<S3Prefix>,
        ssm_arn: Option<String>,
        s3_client: aws_sdk_s3::Client,
        ssm_client: aws_sdk_ssm::Client,
    ) -> AppState {
        new_app_state(
            AppConfig {
                method: "s3".to_owned(),
                s3_urls,
                key_passphrase_ssm_arn: ssm_arn,
            },
            s3_client,
            ssm_client,
        )
    }

    fn s3_get_object_output(body: &[u8]) -> aws_sdk_s3::operation::get_object::GetObjectOutput {
        aws_sdk_s3::operation::get_object::GetObjectOutput::builder()
            .body(aws_smithy_types::byte_stream::ByteStream::from_static(
                // We need to leak a copy because ByteStream::from_static needs 'static
                // In tests this is fine
                Vec::leak(body.to_vec()),
            ))
            .build()
    }

    fn s3_no_such_key() -> aws_sdk_s3::operation::get_object::GetObjectError {
        aws_sdk_s3::operation::get_object::GetObjectError::NoSuchKey(
            aws_sdk_s3::types::error::NoSuchKey::builder().build(),
        )
    }

    #[tokio::test]
    async fn cold_initialize_fetches_all_certs() {
        let (fullchain, key) = generate_cert(vec!["test.example.com".to_owned()]);

        let get_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        let get_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain.as_bytes()));
        let get_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key.as_bytes()));

        let s3_client = make_s3_client(&[&get_current, &get_fullchain, &get_key]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        let result = state.initialize().await.unwrap();
        assert_eq!(result.default, "cert-v1");
        assert_eq!(result.certificates.len(), 1);
        assert_eq!(result.certificates[0].id, "cert-v1");
        assert_eq!(result.certificates[0].domains, vec!["test.example.com"]);
        assert!(!result.certificates[0].schemes.is_empty());
    }

    #[tokio::test]
    async fn warm_initialize_unchanged() {
        let (fullchain, key) = generate_cert(vec!["test.example.com".to_owned()]);

        // Cold init calls
        let get_current_1 = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        let get_fullchain_1 = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain.as_bytes()));
        let get_key_1 = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key.as_bytes()));
        // Warm init: re-fetches current only
        let get_current_2 = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));

        let s3_client =
            make_s3_client(&[&get_current_1, &get_fullchain_1, &get_key_1, &get_current_2]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        // Cold init
        let result1 = state.initialize().await.unwrap();
        assert_eq!(result1.default, "cert-v1");

        // Warm init (unchanged)
        let result2 = state.initialize().await.unwrap();
        assert_eq!(result2.default, "cert-v1");
        assert_eq!(result2.certificates.len(), 1);
    }

    #[tokio::test]
    async fn warm_initialize_changed_current() {
        let (fullchain1, key1) = generate_cert(vec!["v1.example.com".to_owned()]);
        let (fullchain2, key2) = generate_cert(vec!["v2.example.com".to_owned()]);

        // Cold init
        let cold_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        let cold_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain1.as_bytes()));
        let cold_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key1.as_bytes()));
        // Warm init: current changed
        let warm_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v2"));
        let warm_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v2/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain2.as_bytes()));
        let warm_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v2/key.pem"))
            .then_output(move || s3_get_object_output(key2.as_bytes()));

        let s3_client = make_s3_client(&[
            &cold_current,
            &cold_fullchain,
            &cold_key,
            &warm_current,
            &warm_fullchain,
            &warm_key,
        ]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        let result1 = state.initialize().await.unwrap();
        assert_eq!(result1.certificates[0].domains, vec!["v1.example.com"]);

        let result2 = state.initialize().await.unwrap();
        assert_eq!(result2.default, "cert-v2");
        assert_eq!(result2.certificates[0].domains, vec!["v2.example.com"]);
    }

    #[tokio::test]
    async fn sign_with_cached_key() {
        let (fullchain, key) = generate_cert(vec!["test.example.com".to_owned()]);

        let get_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        let get_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain.as_bytes()));
        let get_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key.as_bytes()));

        let s3_client = make_s3_client(&[&get_current, &get_fullchain, &get_key]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        // Initialize first
        let init_result = state.initialize().await.unwrap();
        let scheme = init_result.certificates[0].schemes[0].clone();

        // Sign
        let sign_result = state
            .sign(&trustless_protocol::message::SignParams {
                certificate_id: "cert-v1".to_owned(),
                scheme,
                blob: vec![1, 2, 3, 4],
            })
            .await
            .unwrap();

        assert!(!sign_result.signature.is_empty());
    }

    #[tokio::test]
    async fn sign_missing_cert_returns_error() {
        let s3_client = {
            // Sign without initialize: on-demand load will check current for each prefix
            let get_current = mock!(aws_sdk_s3::Client::get_object)
                .match_requests(|req| req.key() == Some("prefix/current"))
                .then_output(|| s3_get_object_output(b"other-cert"));
            make_s3_client(&[&get_current])
        };
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        let err = state
            .sign(&trustless_protocol::message::SignParams {
                certificate_id: "nonexistent".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![1, 2, 3],
            })
            .await
            .unwrap_err();

        let code: trustless_protocol::message::ErrorCode = err.into();
        assert!(matches!(
            code,
            trustless_protocol::message::ErrorCode::CertificateNotFound(_)
        ));
    }

    #[tokio::test]
    async fn sign_unsupported_scheme() {
        let (fullchain, key) = generate_cert(vec!["test.example.com".to_owned()]);

        let get_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        let get_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_output(move || s3_get_object_output(fullchain.as_bytes()));
        let get_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key.as_bytes()));

        let s3_client = make_s3_client(&[&get_current, &get_fullchain, &get_key]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        state.initialize().await.unwrap();

        let err = state
            .sign(&trustless_protocol::message::SignParams {
                certificate_id: "cert-v1".to_owned(),
                scheme: "NONEXISTENT_SCHEME".to_owned(),
                blob: vec![1, 2, 3],
            })
            .await
            .unwrap_err();

        let code: trustless_protocol::message::ErrorCode = err.into();
        assert!(matches!(
            code,
            trustless_protocol::message::ErrorCode::UnsupportedScheme(_)
        ));
    }

    #[tokio::test]
    async fn fullchain_fallback_to_cert_pem() {
        let (fullchain, key) = generate_cert(vec!["test.example.com".to_owned()]);

        let get_current = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/current"))
            .then_output(|| s3_get_object_output(b"cert-v1"));
        // fullchain.pem returns NoSuchKey
        let get_fullchain = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/fullchain.pem"))
            .then_error(s3_no_such_key);
        // Falls back to cert.pem
        let get_cert = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/cert.pem"))
            .then_output(move || s3_get_object_output(fullchain.as_bytes()));
        let get_key = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.key() == Some("prefix/cert-v1/key.pem"))
            .then_output(move || s3_get_object_output(key.as_bytes()));

        let s3_client = make_s3_client(&[&get_current, &get_fullchain, &get_cert, &get_key]);
        let ssm_client = make_ssm_client(&[]);

        let state = make_state(
            vec![S3Prefix {
                bucket: "test-bucket".to_owned(),
                key_prefix: "prefix/".to_owned(),
            }],
            None,
            s3_client,
            ssm_client,
        );

        let result = state.initialize().await.unwrap();
        assert_eq!(result.certificates[0].id, "cert-v1");
        assert_eq!(result.certificates[0].domains, vec!["test.example.com"]);
    }
}
