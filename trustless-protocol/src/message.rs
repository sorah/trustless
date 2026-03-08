use secrecy::SecretBox;

pub use crate::base64::Base64Bytes;

/// Protocol error code with message.
///
/// Well-known codes from the key-provider protocol:
/// - `-1`: internal/infrastructure error
/// - `1`: certificate not found
/// - `2`: unsupported signature scheme
/// - `3`: signing failed
///
/// Providers may define additional codes via `Other`.
#[derive(Debug, thiserror::Error)]
pub enum ErrorCode {
    /// Internal/infrastructure error (`-1`).
    #[error("internal error: {0}")]
    Internal(String),
    /// Certificate not found (`1`).
    #[error("certificate not found: {0}")]
    CertificateNotFound(String),
    /// Unsupported signature scheme (`2`).
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    /// Signing failed (`3`).
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// A provider-defined code not covered by the well-known variants.
    #[error("error (code {code}): {message}")]
    Other { code: i64, message: String },
}

impl ErrorCode {
    pub fn as_i64(&self) -> i64 {
        match self {
            ErrorCode::Internal(_) => -1,
            ErrorCode::CertificateNotFound(_) => 1,
            ErrorCode::UnsupportedScheme(_) => 2,
            ErrorCode::SigningFailed(_) => 3,
            ErrorCode::Other { code, .. } => *code,
        }
    }
}

impl From<ErrorCode> for ErrorPayload {
    fn from(e: ErrorCode) -> Self {
        ErrorPayload {
            code: e.as_i64(),
            message: e.to_string(),
        }
    }
}

impl From<ErrorPayload> for ErrorCode {
    fn from(p: ErrorPayload) -> Self {
        match p.code {
            -1 => ErrorCode::Internal(p.message),
            1 => ErrorCode::CertificateNotFound(p.message),
            2 => ErrorCode::UnsupportedScheme(p.message),
            3 => ErrorCode::SigningFailed(p.message),
            code => ErrorCode::Other {
                code,
                message: p.message,
            },
        }
    }
}

/// A protocol request message.
///
/// Internally tagged by `method`, with `id` repeated in each variant.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "method")]
pub enum Request {
    #[serde(rename = "initialize")]
    Initialize { id: u64, params: InitializeParams },
    #[serde(rename = "sign")]
    Sign { id: u64, params: SignParams },
}

impl Request {
    pub fn id(&self) -> u64 {
        match self {
            Request::Initialize { id, .. } => *id,
            Request::Sign { id, .. } => *id,
        }
    }
}

/// Parameters for the `initialize` method. Currently empty.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct InitializeParams {}

/// Parameters for the `sign` method.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignParams {
    /// The certificate ID (from [`InitializeResult`]) identifying which key to use.
    pub certificate_id: String,
    /// The signature scheme name (e.g., `"ECDSA_NISTP256_SHA256"`).
    pub scheme: String,
    /// The data to sign. Base64-encoded on the wire. Blobs to sign are not considered sensitive,
    /// but we wrap them with `SecretBox` to avoid accidental logging or exposure in debug builds.
    pub blob: SecretBox<Base64Bytes>,
}

/// A successful protocol response, internally tagged by `method`.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "method")]
pub enum SuccessResponse {
    #[serde(rename = "initialize")]
    Initialize { id: u64, result: InitializeResult },
    #[serde(rename = "sign")]
    Sign { id: u64, result: SignResult },
}

/// An error response with no method tag.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ErrorResponse {
    pub id: u64,
    pub error: ErrorPayload,
}

/// A protocol response message — either a tagged success or an error.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

impl From<SuccessResponse> for Response {
    fn from(s: SuccessResponse) -> Self {
        Response::Success(s)
    }
}

impl From<ErrorResponse> for Response {
    fn from(e: ErrorResponse) -> Self {
        Response::Error(e)
    }
}

impl Response {
    pub fn id(&self) -> u64 {
        match self {
            Response::Success(SuccessResponse::Initialize { id, .. }) => *id,
            Response::Success(SuccessResponse::Sign { id, .. }) => *id,
            Response::Error(ErrorResponse { id, .. }) => *id,
        }
    }

    pub fn initialize(id: u64, result: Result<InitializeResult, ErrorPayload>) -> Self {
        match result {
            Ok(result) => SuccessResponse::Initialize { id, result }.into(),
            Err(error) => ErrorResponse { id, error }.into(),
        }
    }

    pub fn sign(id: u64, result: Result<SignResult, ErrorPayload>) -> Self {
        match result {
            Ok(result) => SuccessResponse::Sign { id, result }.into(),
            Err(error) => ErrorResponse { id, error }.into(),
        }
    }
}

/// An error payload with a numeric code and human-readable message.
///
/// This is the wire-format struct. Use [`ErrorCode`] for typed error handling,
/// and convert via `From`/`Into` at boundaries.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ErrorPayload {
    /// Numeric error code. See [`ErrorCode`] for well-known values.
    pub code: i64,
    /// Human-readable error description.
    pub message: String,
}

/// Result of the `initialize` method.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct InitializeResult {
    /// Certificate ID to use as the default when no SNI matches.
    pub default: String,
    /// All certificates available from this provider.
    pub certificates: Vec<CertificateInfo>,
}

/// Metadata for a single certificate returned during initialization.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct CertificateInfo {
    /// Unique identifier for this certificate. Used in `sign` requests.
    pub id: String,
    /// DNS Subject Alternative Names the certificate covers (e.g., `["*.example.com"]`).
    pub domains: Vec<String>,
    /// Full certificate chain in PEM format (leaf first, then intermediates).
    pub pem: String,
    /// Supported signature scheme names (e.g., `["ECDSA_NISTP256_SHA256"]`).
    /// Strongly recommended — certificates without valid schemes are skipped.
    #[serde(default)]
    pub schemes: Vec<String>,
}

/// Result of the `sign` method.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SignResult {
    /// The signature bytes. Base64-encoded on the wire.
    pub signature: SecretBox<Base64Bytes>,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    #[derive(serde::Deserialize, Debug)]
    struct WireRequest {
        id: u64,
        method: String,
        #[allow(dead_code)]
        params: serde_json::Value,
    }

    #[test]
    fn serialize_initialize_request() {
        let req = super::Request::Initialize {
            id: 1,
            params: super::InitializeParams {},
        };
        let json = serde_json::to_string(&req).unwrap();
        let wire: WireRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 1);
        assert_eq!(wire.method, "initialize");
    }

    #[test]
    fn serialize_sign_request() {
        let req = super::Request::Sign {
            id: 42,
            params: super::SignParams {
                certificate_id: "cert/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: super::Base64Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]).into_secret(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let wire: WireRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 42);
        assert_eq!(wire.method, "sign");
        let params: super::SignParams = serde_json::from_value(wire.params).unwrap();
        assert_eq!(params.certificate_id, "cert/v1");
        assert_eq!(params.scheme, "ECDSA_NISTP256_SHA256");
        assert_eq!(**params.blob.expose_secret(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn deserialize_initialize_request() {
        let json = r#"{"id":5,"method":"initialize","params":{}}"#;
        let req: super::Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id(), 5);
        assert!(matches!(req, super::Request::Initialize { .. }));
    }

    #[test]
    fn deserialize_sign_request() {
        let json = r#"{"id":7,"method":"sign","params":{"certificate_id":"c1","scheme":"ED25519","blob":"AQID"}}"#;
        let req: super::Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id(), 7);
        match req {
            super::Request::Sign { params, .. } => {
                assert_eq!(params.certificate_id, "c1");
                assert_eq!(params.scheme, "ED25519");
                assert_eq!(params.blob.expose_secret().as_slice(), &[1, 2, 3]);
            }
            _ => panic!("expected Sign"),
        }
    }

    #[test]
    fn request_round_trip() {
        let req = super::Request::Sign {
            id: 10,
            params: super::SignParams {
                certificate_id: "cert/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: super::Base64Bytes::from(vec![0xde, 0xad]).into_secret(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: super::Request = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id(), 10);
        match decoded {
            super::Request::Sign { params, .. } => {
                assert_eq!(params.certificate_id, "cert/v1");
                assert_eq!(params.blob.expose_secret().as_slice(), &[0xde, 0xad]);
            }
            _ => panic!("expected Sign"),
        }
    }

    #[test]
    fn serialize_initialize_result_response() {
        let resp = super::Response::Success(super::SuccessResponse::Initialize {
            id: 1,
            result: super::InitializeResult {
                default: "cert1".to_owned(),
                certificates: vec![super::CertificateInfo {
                    id: "cert1".to_owned(),
                    domains: vec!["*.example.com".to_owned()],
                    pem: "PEM DATA".to_owned(),
                    schemes: vec!["ECDSA_NISTP256_SHA256".to_owned()],
                }],
            },
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"method\":\"initialize\""));
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["method"], "initialize");
        assert_eq!(v["result"]["default"], "cert1");
    }

    #[test]
    fn serialize_sign_result_response() {
        let resp = super::Response::Success(super::SuccessResponse::Sign {
            id: 2,
            result: super::SignResult {
                signature: super::Base64Bytes::from(vec![0xff, 0x00, 0xab]).into_secret(),
            },
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"method\":\"sign\""));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["id"], 2);
        assert_eq!(v["method"], "sign");
    }

    #[test]
    fn serialize_error_response() {
        let resp = super::Response::Error(super::ErrorResponse {
            id: 3,
            error: super::ErrorPayload {
                code: 1,
                message: "not found".to_owned(),
            },
        });
        let json = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["id"], 3);
        assert_eq!(v["error"]["code"], 1);
        assert_eq!(v["error"]["message"], "not found");
        assert!(!json.contains("\"result\""));
        assert!(!json.contains("\"method\""));
    }

    #[test]
    fn deserialize_result_response() {
        let json = r#"{"id":1,"method":"initialize","result":{"default":"c1","certificates":[{"id":"c1","domains":["*.test"],"pem":"---"}]}}"#;
        let resp: super::Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id(), 1);
        match resp {
            super::Response::Success(super::SuccessResponse::Initialize { result, .. }) => {
                assert_eq!(result.default, "c1");
                assert_eq!(result.certificates.len(), 1);
            }
            _ => panic!("expected Initialize Result"),
        }
    }

    #[test]
    fn deserialize_error_response() {
        let json = r#"{"id":2,"error":{"code":99,"message":"boom"}}"#;
        let resp: super::Response = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id(), 2);
        match resp {
            super::Response::Error(super::ErrorResponse { error, .. }) => {
                assert_eq!(error.code, 99);
                assert_eq!(error.message, "boom");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn sign_params_blob_round_trip() {
        let params = super::SignParams {
            certificate_id: "x".to_owned(),
            scheme: "RSA_PSS_SHA256".to_owned(),
            blob: super::Base64Bytes::from((0..=255).collect::<Vec<u8>>()).into_secret(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let decoded: super::SignParams = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.blob.expose_secret().as_slice(),
            params.blob.expose_secret().as_slice()
        );
    }

    #[test]
    fn error_code_as_i64() {
        assert_eq!(super::ErrorCode::Internal("x".to_owned()).as_i64(), -1);
        assert_eq!(
            super::ErrorCode::CertificateNotFound("x".to_owned()).as_i64(),
            1
        );
        assert_eq!(
            super::ErrorCode::UnsupportedScheme("x".to_owned()).as_i64(),
            2
        );
        assert_eq!(super::ErrorCode::SigningFailed("x".to_owned()).as_i64(), 3);
        assert_eq!(
            super::ErrorCode::Other {
                code: 42,
                message: "x".to_owned()
            }
            .as_i64(),
            42
        );
    }

    #[test]
    fn error_code_from_error_payload() {
        let payload = super::ErrorPayload {
            code: -1,
            message: "boom".to_owned(),
        };
        let code: super::ErrorCode = payload.into();
        assert!(matches!(code, super::ErrorCode::Internal(m) if m == "boom"));

        let payload = super::ErrorPayload {
            code: 1,
            message: "gone".to_owned(),
        };
        let code: super::ErrorCode = payload.into();
        assert!(matches!(code, super::ErrorCode::CertificateNotFound(m) if m == "gone"));

        let payload = super::ErrorPayload {
            code: 99,
            message: "custom".to_owned(),
        };
        let code: super::ErrorCode = payload.into();
        assert!(
            matches!(code, super::ErrorCode::Other { code: 99, message } if message == "custom")
        );
    }

    #[test]
    fn error_code_to_error_payload() {
        let code = super::ErrorCode::CertificateNotFound("not found".to_owned());
        let payload: super::ErrorPayload = code.into();
        assert_eq!(payload.code, 1);
        assert_eq!(payload.message, "certificate not found: not found");
    }

    #[test]
    fn error_payload_serde_preserves_wire_format() {
        let payload = super::ErrorPayload {
            code: 1,
            message: "not found".to_owned(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["code"], 1);

        let decoded: super::ErrorPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.code, 1);
    }
}
