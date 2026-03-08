/// Wrap an `AsyncRead` with length-delimited codec framing for reading protocol messages.
pub fn framed_read<R: tokio::io::AsyncRead>(
    reader: R,
) -> tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec> {
    tokio_util::codec::FramedRead::new(reader, tokio_util::codec::LengthDelimitedCodec::new())
}

/// Wrap an `AsyncWrite` with length-delimited codec framing for writing protocol messages.
pub fn framed_write<W: tokio::io::AsyncWrite>(
    writer: W,
) -> tokio_util::codec::FramedWrite<W, tokio_util::codec::LengthDelimitedCodec> {
    tokio_util::codec::FramedWrite::new(writer, tokio_util::codec::LengthDelimitedCodec::new())
}

/// Serialize a message as JSON and send it over a framed writer.
pub async fn send_message<W>(
    writer: &mut tokio_util::codec::FramedWrite<W, tokio_util::codec::LengthDelimitedCodec>,
    msg: &impl serde::Serialize,
) -> Result<(), crate::error::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use futures_util::SinkExt as _;

    let json = serde_json::to_vec(msg)?;
    writer.send(bytes::Bytes::from(json)).await?;
    Ok(())
}

/// Read and deserialize a JSON message from a framed reader.
///
/// Returns [`Error::ProcessExited`](crate::error::Error::ProcessExited) when the stream reaches EOF.
pub async fn recv_message<R, M>(
    reader: &mut tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec>,
) -> Result<M, crate::error::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    M: serde::de::DeserializeOwned,
{
    use futures_util::StreamExt as _;

    let frame = reader
        .next()
        .await
        .ok_or(crate::error::Error::ProcessExited)??;
    let msg = serde_json::from_slice(&frame)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    #[tokio::test]
    async fn round_trip_message() {
        let (client, server) = tokio::io::duplex(4096);
        let (read_half, write_half) = tokio::io::split(server);
        let (client_read, client_write) = tokio::io::split(client);

        let mut writer = super::framed_write(client_write);
        let mut reader = super::framed_read(read_half);

        let request = crate::message::Request::Initialize {
            id: 1,
            params: crate::message::InitializeParams {},
        };
        super::send_message(&mut writer, &request).await.unwrap();

        let received: crate::message::Request = super::recv_message(&mut reader).await.unwrap();
        assert_eq!(received.id(), 1);
        assert!(matches!(
            received,
            crate::message::Request::Initialize { .. }
        ));

        // Send a response back
        let mut server_writer = super::framed_write(write_half);
        let mut client_reader = super::framed_read(client_read);

        let response =
            crate::message::Response::Success(crate::message::SuccessResponse::Initialize {
                id: 1,
                result: crate::message::InitializeResult {
                    default: "cert1".to_owned(),
                    certificates: vec![],
                },
            });
        super::send_message(&mut server_writer, &response)
            .await
            .unwrap();

        let received: crate::message::Response =
            super::recv_message(&mut client_reader).await.unwrap();
        assert_eq!(received.id(), 1);
        match received {
            crate::message::Response::Success(crate::message::SuccessResponse::Initialize {
                result,
                ..
            }) => {
                assert_eq!(result.default, "cert1");
            }
            _ => panic!("expected Initialize Result"),
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
            let req = crate::message::Request::Sign {
                id: i,
                params: crate::message::SignParams {
                    certificate_id: format!("cert{i}"),
                    scheme: "ECDSA_NISTP256_SHA256".to_owned(),
                    blob: crate::message::Base64Bytes::from(vec![i as u8; 16]).into_secret(),
                },
            };
            super::send_message(&mut writer, &req).await.unwrap();
        }

        for i in 1..=5 {
            let received: crate::message::Request = super::recv_message(&mut reader).await.unwrap();
            assert_eq!(received.id(), i);
            match &received {
                crate::message::Request::Sign { params, .. } => {
                    assert_eq!(params.certificate_id, format!("cert{i}"));
                    assert_eq!(
                        params.blob.expose_secret().as_slice(),
                        vec![i as u8; 16].as_slice()
                    );
                }
                _ => panic!("expected Sign"),
            }
        }
    }
}
