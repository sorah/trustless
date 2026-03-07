# 001-protocol

## Summary

Implement the key provider protocol library (`trustless-protocol` crate) and a stub provider (`trustless-provider-stub` crate) that exercises it. This bootstraps the Cargo workspace and establishes the foundation for Trustless proxy to communicate with external key providers over stdin/stdout.

## Motivation

Trustless needs a way to communicate with key providers — external processes responsible for holding TLS certificates and signing blobs on behalf of the proxy. The protocol must be simple enough for third-party providers to implement, yet structured enough for reliable machine-to-machine communication.

The key provider protocol is the core abstraction that separates key management from the proxy itself. By defining it early, we enable:

1. **Pluggable key providers** — anyone can implement the protocol to serve certificates from their infrastructure (vault, HSM, cloud KMS, etc.)
2. **A stub provider for development** — a reference implementation that reads static certificate files from disk, useful for testing and as documentation-by-example.
3. **Independent development** — proxy and provider can be developed and tested separately.

## Explanation

### Wire Protocol

The proxy spawns a key provider as a child process and communicates via stdin/stdout using [length-delimited codec](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html) framing with JSON payloads. Provider stderr is inherited (for logging). Each request carries an `id`, `method`, and `params`; the `method` tag is a sibling of `params`. Success responses carry the same `id` and `method` with a `result` object; error responses carry `id` and `error` (no `method` tag).

See `docs/key-provider-protocol.md` for the wire format specification.

### Rust API (trustless-protocol)

**Client side** (used by the proxy):

```rust
// Spawn a provider process
let client = trustless_protocol::client::ProviderClient::spawn(&command).await?;

// Retrieve certificates
let init = client.initialize().await?;
// init.default: String — default certificate ID
// init.certificates: Vec<CertificateInfo> — id, domains, fullchain PEM

// Sign a blob
let signature: Vec<u8> = client.sign(&certificate_id, &blob).await?;
```

**Provider side** (used by provider implementations):

```rust
impl trustless_protocol::handler::Handler for MyHandler {
    async fn initialize(&self) -> Result<InitializeResult, ErrorPayload> { ... }
    async fn sign(&self, params: SignParams) -> Result<SignResult, ErrorPayload> { ... }
}

// Run the handler loop (reads from stdin, writes to stdout)
trustless_protocol::handler::run(my_handler).await?;
```

### Stub Provider CLI

```
trustless-provider-stub --cert-dir /path/to/cert-registry
```

The cert directory follows Acmesmith's layout:

```
cert-dir/certs/{domain}/current           # text file containing version string
cert-dir/certs/{domain}/{version}/fullchain.pem
cert-dir/certs/{domain}/{version}/key.pem  # unencrypted PEM
```

## Drawbacks

- The protocol is synchronous request-response; the client holds a mutex and does not support concurrent requests to a single provider. This is adequate for current needs but may need rework for high-throughput scenarios.
- No `scheme` field in the sign request means the provider chooses the signature scheme autonomously. This is simpler but means the proxy cannot request a specific scheme — it must accept whatever the provider returns. This is acceptable because the proxy will determine supported schemes from the certificate's public key type.

## Considered Alternatives

### gRPC / protobuf

Would provide stronger typing and streaming, but adds significant complexity for a simple two-method protocol. JSON over length-delimited frames is easier for third parties to implement in any language.

### Unix domain sockets

Would decouple process lifecycle from the proxy, but stdin/stdout is simpler to implement and the proxy already manages the provider's lifetime. UDS could be added later if needed.

### Including `scheme` in sign request

Considered having the proxy tell the provider which signature scheme to use. Omitted because the provider knows its key type and can infer the appropriate scheme (RSA key → RSA_PSS_SHA256, ECDSA P-256 → ECDSA_NISTP256_SHA256, etc.). This keeps the protocol simpler.

## Prior Art

- [Portless](https://github.com/vercel-labs/portless) — inspiration for the overall Trustless design
- JSON-RPC 2.0 — the protocol borrows the id/params/result/error structure
- Acmesmith — the stub provider's cert directory layout follows Acmesmith's storage format

## Security and Privacy Considerations

- Private keys are held by the provider process, not the proxy. The proxy only receives signatures.
- The stub provider loads unencrypted PEM keys from disk. In production, providers should use more secure key storage (HSM, KMS, etc.).
- Certificate IDs are encouraged to be dynamic (include version/timestamp) so providers can reject signing requests for rotated keys and prompt the proxy to reload.
- Provider stderr is inherited, so logging goes to the proxy's stderr — no sensitive data should be logged by providers.

## Mission Scope

### Out of scope

- TLS proxy server implementation (future spec)
- `trustless exec` / `trustless setup` CLI commands (future spec)
- Provider restart/reload logic (future spec)
- Encrypted PEM support in the stub provider
- Concurrent request multiplexing over a single provider connection

### Expected Outcomes

- Cargo workspace with three crates: `trustless`, `trustless-protocol`, `trustless-provider-stub`
- Working protocol library with client and handler APIs
- Working stub provider that serves certificates from an Acmesmith-style directory
- End-to-end example (`provider_client`) demonstrating spawn → initialize → sign

## Implementation Plan

### Crate Structure

```
Cargo.toml                              # workspace (resolver = "3")
trustless/Cargo.toml
trustless/src/lib.rs                    # empty placeholder
trustless/src/main.rs                   # placeholder ("not yet implemented")
trustless/examples/provider_client.rs   # end-to-end demo
trustless-protocol/Cargo.toml
trustless-protocol/src/lib.rs
trustless-protocol/src/error.rs
trustless-protocol/src/message.rs
trustless-protocol/src/codec.rs
trustless-protocol/src/client.rs
trustless-protocol/src/handler.rs
trustless-provider-stub/Cargo.toml
trustless-provider-stub/src/main.rs
```

### trustless-protocol internals

**Message types** (`message.rs`):

| Type | Description |
|---|---|
| `Request` | Internally-tagged enum (`tag = "method"`): `Initialize { id, params }` or `Sign { id, params }` |
| `InitializeParams` | Empty struct |
| `SignParams` | `certificate_id: String`, `blob: Vec<u8>` (base64 via `serde_with`) |
| `Response` | Untagged enum: `Success(SuccessResponse)` or `Error(ErrorResponse)` |
| `SuccessResponse` | Internally-tagged enum (`tag = "method"`): `Initialize { id, result }` or `Sign { id, result }` |
| `ErrorResponse` | Struct with `id: u64` and `error: ErrorPayload` |
| `ErrorPayload` | `code: i64`, `message: String` |
| `InitializeResult` | `default: String`, `certificates: Vec<CertificateInfo>` |
| `CertificateInfo` | `id: String`, `domains: Vec<String>`, `pem: String` |
| `SignResult` | `signature: Vec<u8>` (base64 via `serde_with`) |

`Request` and `Response` use derived serde impls — no custom `Serialize`/`Deserialize` implementations needed.

**Codec** (`codec.rs`): Thin wrappers around `tokio_util::codec::LengthDelimitedCodec` providing `framed_read`, `framed_write`, `send_message`, and `recv_message` helpers.

**Client** (`client.rs`): `ProviderClient` wraps `Mutex<ProviderClientInner>` holding the framed reader/writer, child process, and a monotonic request ID counter. The private `send_and_recv` method assigns an ID, sends the request, reads a `Response`, validates the response ID matches, and extracts the result or error.

**Handler** (`handler.rs`): The `Handler` trait has two async methods (`initialize`, `sign`). The `run()` function reads requests from stdin in a loop, dispatches to the handler, and writes responses to stdout. EOF on stdin terminates the loop cleanly.

### trustless-provider-stub internals

Scans `cert_dir/certs/*/` directories sorted by name. For each:

1. Reads `current` file → version string
2. Loads `{version}/fullchain.pem` as a string (passed through to protocol as-is)
3. Loads `{version}/key.pem` via `rustls_pki_types::PrivateKeyDer::from_pem_file()` (PemObject trait)
4. Parses into a signing key via `rustls::crypto::ring::sign::any_supported_type()`
5. Certificate ID = `"{domain_dir_name}/{version}"`; domains = DNS SANs extracted from the leaf certificate
6. First certificate becomes the default

Signing: offers all common TLS signature schemes to `SigningKey::choose_scheme()`, which picks the first compatible one, then calls `Signer::sign()` on the blob.

### Design decisions

- **No `scheme` in sign protocol**: Provider infers signature scheme from key type. The proxy determines supported schemes from the certificate's public key.
- **PEM loading**: Uses `rustls_pki_types` PemObject trait — only unencrypted PEMs.
- **Signing**: Uses `rustls::crypto::ring::sign::any_supported_type()` which supports RSA, ECDSA (P-256, P-384), and Ed25519.
- **`SuccessResponse` enum**: Success responses include a `method` tag, allowing unified deserialization. Error responses omit the `method` tag since no result is present.

## Current Status

Implementation complete.

### Checklist

- [x] Workspace `Cargo.toml`
- [x] `trustless-protocol`: error, message, codec, client, handler modules
- [x] `trustless-provider-stub`: cert directory scanning, signing via rustls
- [x] `trustless` crate skeleton with `provider_client` example
- [x] `cargo clippy --workspace` passes
- [x] End-to-end test: spawn stub → initialize → sign (verified with real Let's Encrypt cert)

### Updates

- 2026-03-06: Initial implementation complete. All three crates build and pass clippy. End-to-end test verified against `/home/sorah/tmp/lo` cert directory with RSA 2048 key.
