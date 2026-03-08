# Writing a Key Provider

This guide walks through implementing a custom key provider for Trustless. For the full protocol specification, see [key-provider-protocol.md](key-provider-protocol.md).

## Overview

A key provider is an external process that holds TLS private keys and performs signing operations on behalf of the Trustless proxy. The proxy never sees private keys — it only receives certificates and requests signatures. This separation allows key material to live in HSMs, cloud KMS services, vaults, or any other secure storage.

## Communication Model

The proxy spawns the key provider as a child process. Communication happens over:

- **stdin** — the proxy writes requests
- **stdout** — the provider writes responses
- **stderr** — captured by the proxy and forwarded to its logs (useful for debugging)

The provider process is long-lived. It starts when the proxy starts (or reloads) and runs until the proxy shuts down or the provider crashes. On crash, the proxy automatically restarts the provider with exponential backoff.

## Wire Format

Messages are framed using a length-delimited codec: a 4-byte big-endian length prefix followed by a JSON payload. This is the default configuration of [tokio-util's LengthDelimitedCodec](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html).

```
+----------+-------------------+
| len (4B) | JSON payload      |
+----------+-------------------+
```

Each message is a complete JSON object. The length prefix covers only the JSON payload, not itself.

## Protocol Walkthrough

A complete session looks like this:

### 1. Initialize

The proxy sends an `initialize` request immediately after spawning the provider.

**Request:**
```json
{"id": 1, "method": "initialize", "params": {}}
```

**Response:**
```json
{
    "id": 1,
    "result": {
        "default": "example.com/2026-01",
        "certificates": [
            {
                "id": "example.com/2026-01",
                "domains": ["example.com", "*.example.com"],
                "pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n",
                "schemes": ["ECDSA_NISTP256_SHA256"]
            }
        ]
    }
}
```

Key points:
- `id` in the response must match the request
- `default` names the certificate to use when no SNI matches
- `pem` contains the full certificate chain (leaf first, then intermediates)
- `schemes` lists the signature schemes the provider supports for this certificate's key (strongly recommended — certificates without valid schemes are skipped with a warning)
- `domains` lists the DNS SANs the certificate covers

### 2. Sign

For each TLS handshake, the proxy sends a `sign` request with the data to be signed.

**Request:**
```json
{
    "id": 2,
    "method": "sign",
    "params": {
        "certificate_id": "example.com/2026-01",
        "scheme": "ECDSA_NISTP256_SHA256",
        "blob": "dGhlIGRhdGEgdG8gc2lnbg=="
    }
}
```

**Response:**
```json
{
    "id": 2,
    "result": {
        "signature": "MEUCIQD..."
    }
}
```

Key points:
- `blob` is base64-encoded binary data to sign
- `signature` is the base64-encoded signature bytes
- `scheme` specifies exactly which signature scheme to use
- The provider must use the requested scheme; rejecting unsupported schemes with an error is correct behavior

> **Note:** Providers using `trustless-protocol`'s `provider_helpers` have a built-in blob check that validates blobs look like TLS 1.3 server CertificateVerify messages before signing. See [Blob Validation](#blob-validation) below for details.

### Error Response

If something goes wrong, return an error instead of a result:

```json
{
    "id": 2,
    "error": {
        "code": 1,
        "message": "certificate not found: example.com/2025-12"
    }
}
```

Conventional error codes:
- `1` — certificate not found
- `2` — unsupported signature scheme
- `3` — signing failed

These codes are not strictly standardized. Use positive integers with descriptive messages.

## Implementing in Rust

The `trustless-protocol` crate provides two levels of abstraction:

1. **`provider_helpers`** (recommended) — implement the `CertificateSource` trait to describe where your certificates live. Wrap it in `CachingBackend`, which handles caching, signing, blob validation, and the `Handler` protocol for you.
2. **`Handler` trait** (low-level) — implement `initialize` and `sign` yourself for full control.

### Using `CertificateSource` + `CachingBackend` (Recommended)

The `provider_helpers` module lets you focus on loading certificates while the framework handles caching, scheme detection, blob validation, and signing.

You implement three things:
- **`sources()`** — return a list of certificate sources (e.g., directories, S3 prefixes, vault paths). The first entry becomes the default certificate.
- **`fetch_current_id(source)`** — return the current certificate ID for a source (e.g., read a version file, query an API).
- **`load_certificate(source, cert_id)`** — load a full certificate chain and private key, returning a `Certificate`.

`CachingBackend` wraps your source and provides a complete `Handler` implementation with:
- Certificate caching across `initialize` / `sign` calls
- Automatic signature scheme detection from key type
- TLS 1.3 blob validation before signing (see [Blob Validation](#blob-validation))
- On re-initialization, only refreshes certificates whose current ID has changed

```rust
use trustless_protocol::provider_helpers::{
    CachingBackend, Certificate, CertificateSource, ProviderHelperError,
};

struct MySource {
    // your certificate locations
}

// Your source entry type — identifies one certificate source
struct MyEntry {
    name: String,
}

// Error type must convert to ErrorCode and accept ProviderHelperError
#[derive(Debug, thiserror::Error)]
enum MyError {
    #[error("provider error: {0}")]
    Provider(#[from] ProviderHelperError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<MyError> for trustless_protocol::message::ErrorCode {
    fn from(e: MyError) -> Self {
        match e {
            MyError::Provider(pe) => pe.into(),
            other => trustless_protocol::message::ErrorCode::Internal(other.to_string()),
        }
    }
}

impl CertificateSource for MySource {
    type SourceId = MyEntry;
    type Error = MyError;

    fn sources(&self) -> &[MyEntry] {
        &self.entries  // first entry is the default
    }

    async fn fetch_current_id(&self, source: &MyEntry) -> Result<String, MyError> {
        // Return the current version identifier for this source.
        // e.g., read from a file, query an API, check S3 metadata
        Ok(format!("{}/2026-01", source.name))
    }

    async fn load_certificate(
        &self,
        source: &MyEntry,
        cert_id: &str,
    ) -> Result<Certificate, MyError> {
        let fullchain_pem = std::fs::read_to_string("fullchain.pem")?;
        let key_pem = std::fs::read("key.pem")?;

        // Certificate::from_pem parses the chain, extracts DNS SANs,
        // loads the signing key, and detects supported signature schemes
        let cert = Certificate::from_pem(cert_id.to_owned(), fullchain_pem, &key_pem)?;
        Ok(cert)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let source = MySource { /* ... */ };
    let backend = CachingBackend::new(source);
    trustless_protocol::handler::run(backend).await?;
    Ok(())
}
```

`Certificate::from_pem` parses the PEM fullchain and private key, extracts DNS SANs from the leaf certificate, and detects supported signature schemes from the key type. For encrypted private keys, use `Certificate::from_pem_with_passphrase` instead (requires the `encrypted-key` feature).

### Using the `Handler` Trait Directly

For full control over initialization and signing, implement the `Handler` trait directly:

```rust
use trustless_protocol::handler::Handler;
use trustless_protocol::message::{
    CertificateInfo, ErrorPayload, InitializeResult, SignParams, SignResult,
};

struct MyProvider {
    // your key material
}

impl Handler for MyProvider {
    async fn initialize(&self) -> Result<InitializeResult, ErrorPayload> {
        Ok(InitializeResult {
            default: "my-cert-id".to_owned(),
            certificates: vec![CertificateInfo {
                id: "my-cert-id".to_owned(),
                domains: vec!["*.example.com".to_owned()],
                pem: std::fs::read_to_string("fullchain.pem").map_err(|e| ErrorPayload {
                    code: 1,
                    message: format!("failed to read cert: {e}"),
                })?,
                schemes: vec!["ECDSA_NISTP256_SHA256".to_owned()],
            }],
        })
    }

    async fn sign(&self, params: SignParams) -> Result<SignResult, ErrorPayload> {
        // Sign params.blob using the key for params.certificate_id
        // with the scheme specified in params.scheme
        let signature = do_sign(&params.certificate_id, &params.scheme, &params.blob)
            .map_err(|e| ErrorPayload {
                code: 3,
                message: format!("signing failed: {e}"),
            })?;
        Ok(SignResult { signature })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = MyProvider { /* ... */ };
    trustless_protocol::handler::run(provider).await?;
    Ok(())
}
```

The `run` function reads requests from stdin, dispatches to your `Handler`, and writes responses to stdout. It returns when stdin reaches EOF (i.e., when the proxy closes the connection).

### Reference Implementation

See `trustless-provider-filesystem` for a complete working example using `CertificateSource` + `CachingBackend` that loads certificates and keys from a directory on disk.

## Implementing in Other Languages

The protocol is language-agnostic. Any language that can read from stdin, write to stdout, and handle JSON can implement a key provider.

### Reading a Frame

```
1. Read exactly 4 bytes from stdin → interpret as big-endian u32 → this is `len`
2. Read exactly `len` bytes from stdin → parse as JSON
```

### Writing a Frame

```
1. Serialize the response as JSON bytes
2. Write the length as 4 bytes big-endian to stdout
3. Write the JSON bytes to stdout
4. Flush stdout
```

### Binary Fields

The `blob` field in sign requests and the `signature` field in sign responses use standard base64 encoding (RFC 4648). Decode `blob` before signing, and encode `signature` after signing.

### Read Loop Pseudocode

```ruby
require 'json'
require 'base64'

def read_frame
  header = $stdin.read(4)
  return nil if header.nil? || header.length < 4
  length = header.unpack1('N')
  data = $stdin.read(length)
  JSON.parse(data)
end

def write_frame(obj)
  data = JSON.generate(obj)
  $stdout.write([data.bytesize].pack('N'))
  $stdout.write(data)
  $stdout.flush
end

while (request = read_frame)
  case request["method"]
  when "initialize"
    write_frame({
      "id" => request["id"],
      "result" => {
        "default" => "my-cert",
        "certificates" => [{
          "id" => "my-cert",
          "domains" => ["*.example.com"],
          "pem" => File.read("fullchain.pem"),
          "schemes" => ["ECDSA_NISTP256_SHA256"]
        }]
      }
    })
  when "sign"
    blob = Base64.decode64(request["params"]["blob"])
    signature = sign(blob, request["params"]["scheme"])
    write_frame({
      "id" => request["id"],
      "result" => {
        "signature" => Base64.strict_encode64(signature)
      }
    })
  end
end
```

## Supported Signature Schemes

The following scheme names are recognized:

| Scheme Name | Algorithm |
|---|---|
| `RSA_PKCS1_SHA256` | RSA |
| `RSA_PKCS1_SHA384` | RSA |
| `RSA_PKCS1_SHA512` | RSA |
| `RSA_PSS_SHA256` | RSA |
| `RSA_PSS_SHA384` | RSA |
| `RSA_PSS_SHA512` | RSA |
| `ECDSA_NISTP256_SHA256` | ECDSA |
| `ECDSA_NISTP384_SHA384` | ECDSA |
| `ECDSA_NISTP521_SHA512` | ECDSA |
| `ED25519` | EdDSA |
| `ED448` | EdDSA |

All schemes declared for a single certificate must share the same algorithm family (e.g., all RSA or all ECDSA). Certificates with mixed algorithm families are rejected during registration.

## Blob Validation

Providers built with `trustless-protocol`'s `provider_helpers` (including `trustless-provider-filesystem` and `trustless-backend-lambda`) automatically validate that incoming sign blobs look like TLS 1.3 **server** CertificateVerify messages before signing. This is a defense-in-depth measure — it ensures the provider only signs legitimate TLS handshake data.

The check verifies:
- The blob starts with 64 bytes of `0x20` (the TLS 1.3 padding)
- Followed by the server context string `"TLS 1.3, server CertificateVerify\0"`
- Followed by a handshake hash

Client CertificateVerify blobs are rejected because Trustless only operates as a TLS server. Non-TLS-1.3 blobs (including TLS 1.2 ServerKeyExchange blobs) are also rejected. See [tls12.md](tls12.md) for TLS 1.2 implications.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TRUSTLESS_DISABLE_BLOB_CHECK_TLS=1` | check enabled | Disables the TLS blob check, allowing any blob to be signed. Required if you enable TLS 1.2 on the proxy (`--tls12`). |
| `TRUSTLESS_LOG_BLOB=1` | logging disabled | Logs the hex-encoded blob contents before signing via `tracing::info!`. Useful for debugging handshake issues. |

> **Important:** These environment variables are read once at process startup and cached. Changing them requires restarting the provider process (e.g., via `trustless proxy reload`).

### Custom Providers

If you implement the protocol directly (without `provider_helpers`), consider adding your own blob validation. The TLS 1.3 CertificateVerify structure is:

```
| 64 bytes of 0x20 | context string (with NUL terminator) | handshake hash (32 or 48 bytes) |
```

For a TLS server, the context string is `"TLS 1.3, server CertificateVerify\0"` (34 bytes). Reject client CertificateVerify blobs unless your provider also serves as a TLS client.

## Certificate ID Best Practices

- Include a version or timestamp in the ID (e.g., `example.com/2026-01`) so that the proxy can detect when certificates have been renewed
- The proxy caches certificates from the `initialize` response. To pick up renewed certificates, use `trustless proxy reload` which restarts all providers and re-initializes them
- If a `sign` request arrives with an outdated `certificate_id`, the provider should return an error (code 1) prompting the user to reload

## Testing

Use the `trustless test-provider` command to verify your provider implementation:

```
trustless test-provider -- /path/to/your-provider --your-flags
```

This spawns your provider, calls `initialize`, displays the certificates, and performs a test TLS handshake. Use `--domain` to select a specific certificate for the handshake test:

```
trustless test-provider --domain app.example.com -- /path/to/your-provider
```
