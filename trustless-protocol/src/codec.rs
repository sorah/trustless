pub fn framed_read<R: tokio::io::AsyncRead>(
    reader: R,
) -> tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec> {
    tokio_util::codec::FramedRead::new(reader, tokio_util::codec::LengthDelimitedCodec::new())
}

pub fn framed_write<W: tokio::io::AsyncWrite>(
    writer: W,
) -> tokio_util::codec::FramedWrite<W, tokio_util::codec::LengthDelimitedCodec> {
    tokio_util::codec::FramedWrite::new(writer, tokio_util::codec::LengthDelimitedCodec::new())
}

pub async fn send_message<W>(
    writer: &mut tokio_util::codec::FramedWrite<W, tokio_util::codec::LengthDelimitedCodec>,
    msg: &impl serde::Serialize,
) -> Result<(), crate::error::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use futures::SinkExt as _;

    let json = serde_json::to_vec(msg)?;
    writer.send(bytes::Bytes::from(json)).await?;
    Ok(())
}

pub async fn recv_message<R, M>(
    reader: &mut tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec>,
) -> Result<M, crate::error::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    M: serde::de::DeserializeOwned,
{
    use futures::StreamExt as _;

    let frame = reader
        .next()
        .await
        .ok_or(crate::error::Error::ProcessExited)??;
    let msg = serde_json::from_slice(&frame)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn round_trip_message() {
        let (client, server) = tokio::io::duplex(4096);
        let (read_half, write_half) = tokio::io::split(server);
        let (client_read, client_write) = tokio::io::split(client);

        let mut writer = super::framed_write(client_write);
        let mut reader = super::framed_read(read_half);

        let request = crate::message::Request {
            id: 1,
            body: crate::message::RequestBody::Initialize(crate::message::InitializeParams {}),
        };
        super::send_message(&mut writer, &request).await.unwrap();

        let received: crate::message::Request = super::recv_message(&mut reader).await.unwrap();
        assert_eq!(received.id, 1);
        assert!(matches!(
            received.body,
            crate::message::RequestBody::Initialize(_)
        ));

        // Send a response back
        let mut server_writer = super::framed_write(write_half);
        let mut client_reader = super::framed_read(client_read);

        let response = crate::message::RawResponse {
            id: 1,
            body: crate::message::RawResponseBody::<crate::message::InitializeResult>::Result {
                result: crate::message::InitializeResult {
                    default: "cert1".to_owned(),
                    certificates: vec![],
                },
            },
        };
        super::send_message(&mut server_writer, &response)
            .await
            .unwrap();

        let received: crate::message::RawResponse<crate::message::InitializeResult> =
            super::recv_message(&mut client_reader).await.unwrap();
        assert_eq!(received.id, 1);
        match received.body {
            crate::message::RawResponseBody::Result { result } => {
                assert_eq!(result.default, "cert1");
            }
            _ => panic!("expected Result"),
        }
    }

    #[tokio::test]
    async fn eof_returns_process_exited() {
        let (client, server) = tokio::io::duplex(4096);
        drop(client);
        let mut reader = super::framed_read(server);
        let result: Result<crate::message::Request, _> = super::recv_message(&mut reader).await;
        assert!(matches!(result, Err(crate::error::Error::ProcessExited)));
    }

    #[tokio::test]
    async fn multiple_messages_in_sequence() {
        let (client, server) = tokio::io::duplex(4096);
        let (server_read, _server_write) = tokio::io::split(server);
        let (client_read, client_write) = tokio::io::split(client);
        let _ = client_read;

        let mut writer = super::framed_write(client_write);
        let mut reader = super::framed_read(server_read);

        for i in 1..=5 {
            let req = crate::message::Request {
                id: i,
                body: crate::message::RequestBody::Sign(crate::message::SignParams {
                    certificate_id: format!("cert{i}"),
                    scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                    blob: vec![i as u8; 16],
                }),
            };
            super::send_message(&mut writer, &req).await.unwrap();
        }

        for i in 1..=5 {
            let received: crate::message::Request = super::recv_message(&mut reader).await.unwrap();
            assert_eq!(received.id, i);
            match received.body {
                crate::message::RequestBody::Sign(params) => {
                    assert_eq!(params.certificate_id, format!("cert{i}"));
                    assert_eq!(params.blob, vec![i as u8; 16]);
                }
                _ => panic!("expected Sign"),
            }
        }
    }
}
