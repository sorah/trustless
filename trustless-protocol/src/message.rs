use serde_with::serde_as;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub body: RequestBody,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
pub enum RequestBody {
    #[serde(rename = "initialize")]
    Initialize(InitializeParams),
    #[serde(rename = "sign")]
    Sign(SignParams),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct InitializeParams {}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SignParams {
    pub certificate_id: String,
    pub scheme: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub blob: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RawResponse<R> {
    pub id: u64,
    #[serde(flatten)]
    pub body: RawResponseBody<R>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(untagged)]
pub enum RawResponseBody<R> {
    Result { result: R },
    Error { error: ErrorPayload },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ErrorPayload {
    pub code: i64,
    pub message: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct InitializeResult {
    pub default: String,
    pub certificates: Vec<CertificateInfo>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct CertificateInfo {
    pub id: String,
    pub domains: Vec<String>,
    pub pem: String,
    #[serde(default)]
    pub schemes: Vec<String>,
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SignResult {
    #[serde_as(as = "serde_with::base64::Base64")]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn serialize_initialize_request() {
        let req = super::Request {
            id: 1,
            body: super::RequestBody::Initialize(super::InitializeParams {}),
        };
        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "initialize");
        assert_eq!(json["params"], serde_json::json!({}));
    }

    #[test]
    fn serialize_sign_request() {
        let req = super::Request {
            id: 42,
            body: super::RequestBody::Sign(super::SignParams {
                certificate_id: "cert/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![0xde, 0xad, 0xbe, 0xef],
            }),
        };
        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["id"], 42);
        assert_eq!(json["method"], "sign");
        assert_eq!(json["params"]["certificate_id"], "cert/v1");
        assert_eq!(json["params"]["scheme"], "ECDSA_NISTP256_SHA256");
        // base64 of [0xde, 0xad, 0xbe, 0xef]
        assert_eq!(json["params"]["blob"], "3q2+7w==");
    }

    #[test]
    fn deserialize_initialize_request() {
        let json = r#"{"id":5,"method":"initialize","params":{}}"#;
        let req: super::Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 5);
        assert!(matches!(req.body, super::RequestBody::Initialize(_)));
    }

    #[test]
    fn deserialize_sign_request() {
        let json = r#"{"id":7,"method":"sign","params":{"certificate_id":"c1","scheme":"ED25519","blob":"AQID"}}"#;
        let req: super::Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 7);
        match req.body {
            super::RequestBody::Sign(params) => {
                assert_eq!(params.certificate_id, "c1");
                assert_eq!(params.scheme, "ED25519");
                assert_eq!(params.blob, vec![1, 2, 3]);
            }
            _ => panic!("expected Sign"),
        }
    }

    #[test]
    fn serialize_initialize_result_response() {
        let resp = super::RawResponse {
            id: 1,
            body: super::RawResponseBody::Result {
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
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], 1);
        assert_eq!(json["result"]["default"], "cert1");
        assert_eq!(json["result"]["certificates"][0]["id"], "cert1");
        assert_eq!(
            json["result"]["certificates"][0]["domains"][0],
            "*.example.com"
        );
        assert!(json.get("error").is_none());
    }

    #[test]
    fn serialize_sign_result_response() {
        let resp = super::RawResponse {
            id: 2,
            body: super::RawResponseBody::Result {
                result: super::SignResult {
                    signature: vec![0xff, 0x00, 0xab],
                },
            },
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], 2);
        assert_eq!(json["result"]["signature"], "/wCr");
    }

    #[test]
    fn serialize_error_response() {
        let resp: super::RawResponse<super::InitializeResult> = super::RawResponse {
            id: 3,
            body: super::RawResponseBody::Error {
                error: super::ErrorPayload {
                    code: 1,
                    message: "not found".to_owned(),
                },
            },
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], 3);
        assert_eq!(json["error"]["code"], 1);
        assert_eq!(json["error"]["message"], "not found");
        assert!(json.get("result").is_none());
    }

    #[test]
    fn deserialize_result_response() {
        let json = r#"{"id":1,"result":{"default":"c1","certificates":[{"id":"c1","domains":["*.test"],"pem":"---"}]}}"#;
        let resp: super::RawResponse<super::InitializeResult> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 1);
        match resp.body {
            super::RawResponseBody::Result { result } => {
                assert_eq!(result.default, "c1");
                assert_eq!(result.certificates.len(), 1);
            }
            _ => panic!("expected Result"),
        }
    }

    #[test]
    fn deserialize_error_response() {
        let json = r#"{"id":2,"error":{"code":99,"message":"boom"}}"#;
        let resp: super::RawResponse<super::SignResult> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, 2);
        match resp.body {
            super::RawResponseBody::Error { error } => {
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
