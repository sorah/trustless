use serde_with::serde_as;

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
#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignParams {
    /// The certificate ID (from [`InitializeResult`]) identifying which key to use.
    pub certificate_id: String,
    /// The signature scheme name (e.g., `"ECDSA_NISTP256_SHA256"`).
    pub scheme: String,
    /// The data to sign. Base64-encoded on the wire.
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blob: Vec<u8>,
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

impl Response {
    pub fn id(&self) -> u64 {
        match self {
            Response::Success(SuccessResponse::Initialize { id, .. }) => *id,
            Response::Success(SuccessResponse::Sign { id, .. }) => *id,
            Response::Error(ErrorResponse { id, .. }) => *id,
        }
    }
}

/// An error payload with a numeric code and human-readable message.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ErrorPayload {
    /// Error code. Conventional values: 1 = cert not found, 2 = unsupported scheme, 3 = signing failed.
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
#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SignResult {
    /// The signature bytes. Base64-encoded on the wire.
    #[serde_as(as = "serde_with::base64::Base64")]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
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
                blob: vec![0xde, 0xad, 0xbe, 0xef],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let wire: WireRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 42);
        assert_eq!(wire.method, "sign");
        let params: super::SignParams = serde_json::from_value(wire.params).unwrap();
        assert_eq!(params.certificate_id, "cert/v1");
        assert_eq!(params.scheme, "ECDSA_NISTP256_SHA256");
        assert_eq!(params.blob, vec![0xde, 0xad, 0xbe, 0xef]);
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
                assert_eq!(params.blob, vec![1, 2, 3]);
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
                blob: vec![0xde, 0xad],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: super::Request = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id(), 10);
        match decoded {
            super::Request::Sign { params, .. } => {
                assert_eq!(params.certificate_id, "cert/v1");
                assert_eq!(params.blob, vec![0xde, 0xad]);
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
                signature: vec![0xff, 0x00, 0xab],
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
            blob: (0..=255).collect(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let decoded: super::SignParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.blob, params.blob);
    }
}
