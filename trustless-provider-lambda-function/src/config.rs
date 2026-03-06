use crate::error::AppError;

#[derive(Debug, Clone)]
pub(crate) struct S3Prefix {
    pub(crate) bucket: String,
    pub(crate) key_prefix: String,
}

impl S3Prefix {
    pub(crate) fn parse(url: &str) -> Result<Self, AppError> {
        let rest = url
            .strip_prefix("s3://")
            .ok_or_else(|| AppError::Config(format!("S3 URL must start with s3://: {url}")))?;
        let (bucket, key_prefix) = rest
            .split_once('/')
            .ok_or_else(|| AppError::Config(format!("S3 URL must contain a path: {url}")))?;
        let mut key_prefix = key_prefix.to_owned();
        if !key_prefix.is_empty() && !key_prefix.ends_with('/') {
            key_prefix.push('/');
        }
        Ok(Self {
            bucket: bucket.to_owned(),
            key_prefix,
        })
    }
}

#[derive(Debug)]
pub(crate) struct AppConfig {
    pub(crate) method: String,
    pub(crate) s3_urls: Vec<S3Prefix>,
    pub(crate) key_passphrase_ssm_arn: Option<String>,
}

impl AppConfig {
    pub(crate) fn from_env() -> Result<Self, AppError> {
        let method = std::env::var("TRUSTLESS_AWS_METHOD")
            .map_err(|_| AppError::Config("TRUSTLESS_AWS_METHOD is required".to_owned()))?;

        if method != "s3" {
            return Err(AppError::Config(format!(
                "unsupported method: {method}, only 's3' is supported"
            )));
        }

        let s3_urls_raw = std::env::var("TRUSTLESS_S3_URLS")
            .map_err(|_| AppError::Config("TRUSTLESS_S3_URLS is required".to_owned()))?;

        let s3_urls: Vec<S3Prefix> = s3_urls_raw
            .split(',')
            .filter(|s| !s.is_empty())
            .map(S3Prefix::parse)
            .collect::<Result<_, _>>()?;

        if s3_urls.is_empty() {
            return Err(AppError::Config(
                "TRUSTLESS_S3_URLS must contain at least one URL".to_owned(),
            ));
        }

        let key_passphrase_ssm_arn = std::env::var("TRUSTLESS_KEY_PASSPHRASE_SSM_ARN").ok();

        Ok(Self {
            method,
            s3_urls,
            key_passphrase_ssm_arn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_prefix_parse_basic() {
        let p = S3Prefix::parse("s3://my-bucket/my-prefix/").unwrap();
        assert_eq!(p.bucket, "my-bucket");
        assert_eq!(p.key_prefix, "my-prefix/");
    }

    #[test]
    fn s3_prefix_parse_appends_trailing_slash() {
        let p = S3Prefix::parse("s3://my-bucket/my-prefix").unwrap();
        assert_eq!(p.key_prefix, "my-prefix/");
    }

    #[test]
    fn s3_prefix_parse_nested() {
        let p = S3Prefix::parse("s3://bucket/a/b/c/").unwrap();
        assert_eq!(p.bucket, "bucket");
        assert_eq!(p.key_prefix, "a/b/c/");
    }

    #[test]
    fn s3_prefix_parse_root() {
        let p = S3Prefix::parse("s3://bucket/").unwrap();
        assert_eq!(p.bucket, "bucket");
        assert_eq!(p.key_prefix, "");
    }

    #[test]
    fn s3_prefix_parse_invalid_no_scheme() {
        assert!(S3Prefix::parse("bucket/prefix").is_err());
    }

    #[test]
    fn s3_prefix_parse_invalid_no_path() {
        assert!(S3Prefix::parse("s3://bucket").is_err());
    }
}
