This page includes internal information including not implemented yet things, but important design decisions.

## Crates

### Fundamentals

- clap for CLI, with derive feature
- anyhow for CLI errors
- thiserror for internal error types
- serde and serde-json for JSON
- tracing, tracing-appender and tracing-subscriber for logging

### HTTPS

- `tokio`
- `hyper`
- `rustls` only
  - We rely on rustls extension point. We'll have no other crypto crates for implementing TLS server.


## Spawning key provider

- use `tokio::process::Command` to spawn key provider command, and connect to its stdin/stdout with `tokio_util::codec::FramedRead` and `FramedWrite` with `LengthDelimitedCodec`.

## Linking key provider and https server

### Loading certificates

- Certificates are loaded at `initialize` command of key provider protocol.
- Store all certificates and resolve via rustls::Server::ResolvesServerCert trait.
- We never lookup certificates with key provider on-the-fly for simplicity.

### Loading keys

- rustls extension point is explained at @/home/sorah/git/github.com/rustls/rustls/rustls/src/manual/howto.rs
  - We need to implement `rustls::sign::Signer` trait for loaded key provider's key.
  - This is non-async function, so we need to do something to connect to key provider in async world.

## CLI and Proxy communication

CLI communicates to proxy via its own HTTPS server. Proxy creates a self-signed certificate and ephemeral ES256 key for subject name `trustless`, and saves the certificate to state directory. CLI looks up the certificate, and uses it to verify the proxy's identity. 
