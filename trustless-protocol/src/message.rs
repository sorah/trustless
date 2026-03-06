use serde_with::serde_as;

/// Trait for request parameter types, enabling typetag-based dispatch.
#[typetag::serde(tag = "method")]
pub trait RequestParams: std::fmt::Debug + Send + Sync + 'static {
    fn as_any(&self) -> &dyn std::any::Any;
}

/// A protocol request message containing a monotonic `id` and method-specific parameters.
#[derive(Debug)]
pub struct Request<P> {
    /// Monotonically increasing request identifier. Responses must echo this value.
    pub id: u64,
    pub params: P,
}

impl<P: RequestParams + serde::Serialize> serde::Serialize for Request<P> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Request", 2)?;
        s.serialize_field("id", &self.id)?;
        let dyn_params: &dyn RequestParams = &self.params;
        s.serialize_field("params", dyn_params)?;
        s.end()
    }
}

impl<'de, P: serde::Deserialize<'de>> serde::Deserialize<'de> for Request<P> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct RequestHelper<P> {
            id: u64,
            params: P,
        }
        let helper = RequestHelper::<P>::deserialize(deserializer)?;
        Ok(Request {
            id: helper.id,
            params: helper.params,
        })
    }
}

/// A received request with dynamically-dispatched parameters (for server-side use).
#[derive(Debug, serde::Deserialize)]
pub struct ReceivedRequest {
    pub id: u64,
    pub params: Box<dyn RequestParams>,
}

/// Parameters for the `initialize` method. Currently empty.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct InitializeParams {}

#[typetag::serde(name = "initialize")]
impl RequestParams for InitializeParams {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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

#[typetag::serde(name = "sign")]
impl RequestParams for SignParams {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A protocol response message containing the echoed `id` and either a result or error.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Response<R> {
    /// The request `id` this response corresponds to.
    pub id: u64,
    #[serde(flatten)]
    pub body: ResponseBody<R>,
}

/// Untagged enum: either a successful result or an error payload.
///
/// Uses serde's `untagged` representation — the presence of `"result"` vs `"error"` key
/// determines which variant is deserialized.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum ResponseBody<R> {
    /// Successful response containing the method-specific result.
    Result { result: R },
    /// Error response.
    Error { error: ErrorPayload },
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
    struct WireRequestParams<P> {
        method: String,
        #[serde(flatten)]
        inner: P,
    }

    #[derive(serde::Deserialize, Debug)]
    struct WireRequest<P> {
        id: u64,
        params: WireRequestParams<P>,
    }

    #[derive(serde::Deserialize, Debug)]
    struct WireResultResponse<R> {
        id: u64,
        result: R,
    }

    #[derive(serde::Deserialize, Debug)]
    struct WireErrorResponse {
        id: u64,
        error: super::ErrorPayload,
    }

    #[test]
    fn serialize_initialize_request() {
        let req = super::Request {
            id: 1,
            params: super::InitializeParams {},
        };
        let json = serde_json::to_string(&req).unwrap();
        let wire: WireRequest<super::InitializeParams> = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 1);
        assert_eq!(wire.params.method, "initialize");
    }

    #[test]
    fn serialize_sign_request() {
        let req = super::Request {
            id: 42,
            params: super::SignParams {
                certificate_id: "cert/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![0xde, 0xad, 0xbe, 0xef],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let wire: WireRequest<super::SignParams> = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 42);
        assert_eq!(wire.params.method, "sign");
        assert_eq!(wire.params.inner.certificate_id, "cert/v1");
        assert_eq!(wire.params.inner.scheme, "ECDSA_NISTP256_SHA256");
        // base64 of [0xde, 0xad, 0xbe, 0xef]
        assert_eq!(wire.params.inner.blob, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn deserialize_initialize_request_concrete() {
        let json = r#"{"id":5,"params":{"method":"initialize"}}"#;
        let req: super::Request<super::InitializeParams> = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 5);
    }

    #[test]
    fn deserialize_sign_request_concrete() {
        let json = r#"{"id":7,"params":{"method":"sign","certificate_id":"c1","scheme":"ED25519","blob":"AQID"}}"#;
        let req: super::Request<super::SignParams> = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 7);
        assert_eq!(req.params.certificate_id, "c1");
        assert_eq!(req.params.scheme, "ED25519");
        assert_eq!(req.params.blob, vec![1, 2, 3]);
    }

    #[test]
    fn deserialize_received_request_initialize() {
        let json = r#"{"id":5,"params":{"method":"initialize"}}"#;
        let req: super::ReceivedRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 5);
        assert!(
            req.params
                .as_any()
                .downcast_ref::<super::InitializeParams>()
                .is_some()
        );
    }

    #[test]
    fn deserialize_received_request_sign() {
        let json = r#"{"id":7,"params":{"method":"sign","certificate_id":"c1","scheme":"ED25519","blob":"AQID"}}"#;
        let req: super::ReceivedRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 7);
        let params = req
            .params
            .as_any()
            .downcast_ref::<super::SignParams>()
            .unwrap();
        assert_eq!(params.certificate_id, "c1");
        assert_eq!(params.scheme, "ED25519");
        assert_eq!(params.blob, vec![1, 2, 3]);
    }

    #[test]
    fn request_round_trip_via_received() {
        let req = super::Request {
            id: 10,
            params: super::SignParams {
                certificate_id: "cert/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![0xde, 0xad],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let received: super::ReceivedRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(received.id, 10);
        let params = received
            .params
            .as_any()
            .downcast_ref::<super::SignParams>()
            .unwrap();
        assert_eq!(params.certificate_id, "cert/v1");
        assert_eq!(params.blob, vec![0xde, 0xad]);
    }

    #[test]
    fn serialize_initialize_result_response() {
        let resp = super::Response {
            id: 1,
            body: super::ResponseBody::Result {
                result: super::InitializeResult {
                    default: "cert1".to_owned(),
                    certificates: vec![super::CertificateInfo {
                        id: "cert1".to_owned(),
                        domains: vec!["*.example.com".to_owned()],
                        pem: "PEM DATA".to_owned(),
                        schemes: vec!["ECDSA_NISTP256_SHA256".to_owned()],
                    }],
                },
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let wire: WireResultResponse<super::InitializeResult> =
            serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 1);
        assert_eq!(wire.result.default, "cert1");
        assert_eq!(wire.result.certificates[0].id, "cert1");
        assert_eq!(wire.result.certificates[0].domains[0], "*.example.com");
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn serialize_sign_result_response() {
        let resp = super::Response {
            id: 2,
            body: super::ResponseBody::Result {
                result: super::SignResult {
                    signature: vec![0xff, 0x00, 0xab],
                },
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let wire: WireResultResponse<super::SignResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 2);
        assert_eq!(wire.result.signature, vec![0xff, 0x00, 0xab]);
    }

    #[test]
    fn serialize_error_response() {
        let resp: super::Response<super::InitializeResult> = super::Response {
            id: 3,
            body: super::ResponseBody::Error {
                error: super::ErrorPayload {
                    code: 1,
                    message: "not found".to_owned(),
                },
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        let wire: WireErrorResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(wire.id, 3);
        assert_eq!(wire.error.code, 1);
        assert_eq!(wire.error.message, "not found");
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn deserialize_result_response() {
        let json = r#"{"id":1,"result":{"default":"c1","certificates":[{"id":"c1","domains":["*.test"],"pem":"---"}]}}"#;
        let resp: super::Response<super::InitializeResult> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 1);
        match resp.body {
            super::ResponseBody::Result { result } => {
                assert_eq!(result.default, "c1");
                assert_eq!(result.certificates.len(), 1);
            }
            _ => panic!("expected Result"),
        }
    }

    #[test]
    fn deserialize_error_response() {
        let json = r#"{"id":2,"error":{"code":99,"message":"boom"}}"#;
        let resp: super::Response<super::SignResult> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 2);
        match resp.body {
            super::ResponseBody::Error { error } => {
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
