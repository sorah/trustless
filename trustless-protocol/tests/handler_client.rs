struct TestHandler;

impl trustless_protocol::handler::Handler for TestHandler {
    async fn initialize(
        &self,
    ) -> Result<trustless_protocol::message::InitializeResult, trustless_protocol::message::ErrorCode>
    {
        Ok(trustless_protocol::message::InitializeResult {
            default: "test/v1".to_owned(),
            certificates: vec![trustless_protocol::message::CertificateInfo {
                id: "test/v1".to_owned(),
                domains: vec!["*.test.example".to_owned()],
                pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_owned(),
                schemes: vec!["ECDSA_NISTP256_SHA256".to_owned()],
            }],
        })
    }

    async fn sign(
        &self,
        params: trustless_protocol::message::SignParams,
    ) -> Result<trustless_protocol::message::SignResult, trustless_protocol::message::ErrorCode>
    {
        if params.certificate_id == "test/v1" {
            let mut sig = params.blob.clone();
            sig.reverse();
            Ok(trustless_protocol::message::SignResult { signature: sig })
        } else {
            Err(trustless_protocol::message::ErrorCode::CertificateNotFound(
                format!("unknown cert: {}", params.certificate_id),
            ))
        }
    }
}

/// Run a handler on one side of a duplex, and a client-like caller on the other,
/// verifying the full request-response cycle without spawning a real process.
#[tokio::test]
async fn handler_round_trip() {
    let (client_stream, handler_stream) = tokio::io::duplex(8192);
    let (handler_read, handler_write) = tokio::io::split(handler_stream);
    let (client_read, client_write) = tokio::io::split(client_stream);

    let handler_task = tokio::spawn(async move {
        let mut reader = trustless_protocol::codec::framed_read(handler_read);
        let mut writer = trustless_protocol::codec::framed_write(handler_write);

        // Process exactly 3 requests, then exit
        for _ in 0..3 {
            let request: trustless_protocol::message::Request =
                trustless_protocol::codec::recv_message(&mut reader)
                    .await
                    .unwrap();
            let id = request.id();

            let response = match request {
                trustless_protocol::message::Request::Initialize { .. } => {
                    use trustless_protocol::handler::Handler as _;
                    trustless_protocol::message::Response::initialize(
                        id,
                        TestHandler
                            .initialize()
                            .await
                            .map_err(trustless_protocol::message::ErrorPayload::from),
                    )
                }
                trustless_protocol::message::Request::Sign { params, .. } => {
                    use trustless_protocol::handler::Handler as _;
                    trustless_protocol::message::Response::sign(
                        id,
                        TestHandler
                            .sign(params)
                            .await
                            .map_err(trustless_protocol::message::ErrorPayload::from),
                    )
                }
            };

            trustless_protocol::codec::send_message(&mut writer, &response)
                .await
                .unwrap();
        }
    });

    let client_task = tokio::spawn(async move {
        let mut writer = trustless_protocol::codec::framed_write(client_write);
        let mut reader = trustless_protocol::codec::framed_read(client_read);

        // 1. Initialize
        let req = trustless_protocol::message::Request::Initialize {
            id: 1,
            params: trustless_protocol::message::InitializeParams {},
        };
        trustless_protocol::codec::send_message(&mut writer, &req)
            .await
            .unwrap();
        let resp: trustless_protocol::message::Response =
            trustless_protocol::codec::recv_message(&mut reader)
                .await
                .unwrap();
        assert_eq!(resp.id(), 1);
        let init = match resp {
            trustless_protocol::message::Response::Success(
                trustless_protocol::message::SuccessResponse::Initialize { result, .. },
            ) => result,
            _ => panic!("expected Initialize Result"),
        };
        assert_eq!(init.default, "test/v1");
        assert_eq!(init.certificates.len(), 1);
        assert_eq!(init.certificates[0].domains, vec!["*.test.example"]);

        // 2. Sign (success)
        let req = trustless_protocol::message::Request::Sign {
            id: 2,
            params: trustless_protocol::message::SignParams {
                certificate_id: "test/v1".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![1, 2, 3, 4],
            },
        };
        trustless_protocol::codec::send_message(&mut writer, &req)
            .await
            .unwrap();
        let resp: trustless_protocol::message::Response =
            trustless_protocol::codec::recv_message(&mut reader)
                .await
                .unwrap();
        assert_eq!(resp.id(), 2);
        match resp {
            trustless_protocol::message::Response::Success(
                trustless_protocol::message::SuccessResponse::Sign { result, .. },
            ) => {
                assert_eq!(result.signature, vec![4, 3, 2, 1]);
            }
            _ => panic!("expected Sign Result"),
        }

        // 3. Sign (error — unknown cert)
        let req = trustless_protocol::message::Request::Sign {
            id: 3,
            params: trustless_protocol::message::SignParams {
                certificate_id: "nonexistent".to_owned(),
                scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                blob: vec![0xff],
            },
        };
        trustless_protocol::codec::send_message(&mut writer, &req)
            .await
            .unwrap();
        let resp: trustless_protocol::message::Response =
            trustless_protocol::codec::recv_message(&mut reader)
                .await
                .unwrap();
        assert_eq!(resp.id(), 3);
        match resp {
            trustless_protocol::message::Response::Error(
                trustless_protocol::message::ErrorResponse { error, .. },
            ) => {
                assert_eq!(error.code, 1);
                assert!(error.message.contains("nonexistent"));
            }
            _ => panic!("expected Error"),
        }
    });

    let (handler_result, client_result) = tokio::join!(handler_task, client_task);
    handler_result.unwrap();
    client_result.unwrap();
}
