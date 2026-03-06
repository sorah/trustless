# 003-remote-signer

## Summary

Implement a bridge between a key provider and the Rustls TLS server. This module provides custom `rustls::sign::SigningKey` and `rustls::sign::Signer` implementations that delegate signing to the key provider process via `ProviderClient::sign()`, and a custom `rustls::server::ResolvesServerCert` that resolves certificates by SNI with wildcard matching.

## Explanation

### Remote Signing Key (`RemoteSigningKey`)

Implements `rustls::crypto::signer::SigningKey` (rustls 0.23). Delegates actual signing to the key provider process over the protocol.

```rust
use trustless::signer::RemoteSigningKey;

// Created internally during initialization — holds a reference to the signing thread handle
// and the certificate ID for sign requests.
let key: Arc<dyn rustls::sign::SigningKey> = Arc::new(RemoteSigningKey::new(
    signing_handle.clone(),
    certificate_id.clone(),
    signature_algorithm,  // inferred from the certificate's public key type
    supported_schemes,    // determined from the certificate's public key type
));
```

### Provider Registry and Certificate Resolver

`ProviderRegistry` manages provider clients and their certificates. `CertResolver` wraps the registry and implements `rustls::server::ResolvesServerCert`.

```rust
use trustless::signer::{ProviderRegistry, CertResolver, SigningThread};

let registry = ProviderRegistry::new();

// For each provider:
let handle = SigningThread::start(tokio::runtime::Handle::current(), provider_client.clone());
let init = provider_client.initialize().await?;
registry.add_provider(init, handle)?;

// Build the resolver
let resolver = CertResolver::new(registry);
// resolver implements ResolvesServerCert — pass it to rustls ServerConfig::builder().with_cert_resolver()
```

SNI resolution matches domain patterns from certificate SANs, including wildcard certificates: SNI `api.lo.myteam.invalid` matches cert domain `*.lo.myteam.invalid`. When no SNI is provided or no certificate matches the SNI, the resolver falls back to the default certificate (as specified by `InitializeResult.default`). A future spec (005) may wrap or extend this resolver to use a self-signed certificate for proxy-CLI communication as the default.

### Async-to-Sync Bridge

Rustls's `Signer::sign()` is synchronous, but `ProviderClient::sign()` is async. A dedicated background OS thread processes sign requests received via a channel, using the caller's `tokio::runtime::Handle` to run async operations. The `ProviderClient` is `Arc`-shared so it remains usable from the main async context.

```rust
use trustless::signer::SigningThread;

// Start the signing thread — takes the runtime handle and a shared ProviderClient
let handle = SigningThread::start(
    tokio::runtime::Handle::current(),
    provider_client.clone(),  // Arc<ProviderClient>
);

// handle.sign() is sync — safe to call from rustls's Signer::sign()
let signature: Vec<u8> = handle.sign(&certificate_id, &blob)?;
```

## Drawbacks

- The dedicated signing thread adds a thread and channel overhead per sign operation. This is acceptable for a development proxy but may not be ideal for high-throughput production use.
- Signing latency increases due to the channel round-trip and thread context switch.

## Considered Alternatives

### `tokio::runtime::Handle::block_on`

Calling `Handle::current().block_on()` inside `Signer::sign()` panics when called from within a tokio runtime context, which is the expected case since TLS handshakes run inside tokio tasks. Rejected.

### `tokio::task::block_in_place`

Using `block_in_place` + `Handle::current().block_on()` works on multi-threaded tokio runtimes but panics on single-threaded runtimes. Simpler than a dedicated thread, but the runtime constraint is fragile. Rejected in favor of the more robust dedicated thread approach.

## Prior Art

- [rustls-cng](https://github.com/rustls/rustls-cng/blob/dev/src/signer.rs) — Custom `SigningKey`/`Signer` implementation for Windows CNG, referenced in rustls's howto documentation.
- rustls 0.23's `ResolvesServerCertUsingSni` — Built-in SNI resolver that maps exact domain names to `CertifiedKey` values. Our resolver extends this with wildcard matching.

## Security and Privacy Considerations

- Private keys never leave the provider process. The proxy only receives signatures via the protocol.
- The signing thread holds an `Arc<ProviderClient>` — the actual key material remains in the provider process.
- Wildcard matching follows standard TLS wildcard semantics: `*` matches a single label only (e.g., `*.example.com` matches `foo.example.com` but not `bar.foo.example.com`).

## Mission Scope

### Out of scope

- Proxy implementation. This spec covers only the TLS signing bridge and certificate resolver, not the network proxy that uses it.
  - An example in `trustless/examples/` exercises the module during this mission. Integration with the actual proxy lifecycle is deferred to spec 004/005.
- Provider process lifecycle management (spawn, restart, reload).
- Certificate refresh/rotation after initialization.

## Implementation Plan

### File structure

```
trustless/src/signer.rs          # RemoteSigningKey, RemoteSigner, SigningThread, CertResolver, ProviderRegistry
trustless/examples/tls_server.rs # Example TLS server using the remote signer (playground)
```

### Module: `trustless::signer`

**`ProviderRegistry`** — Orchestrator that manages provider clients and their certificates. Inspired by mairu's `SessionManager`. Clonable via `Arc<RwLock<...>>`.

- Holds: `Arc<RwLock<ProviderRegistryInner>>` where inner contains `Vec<ProviderEntry>`
- Each `ProviderEntry`: `signing_handle: SigningThreadHandle`, `certificates: Vec<CertResolverEntry>`
- `ProviderRegistry::new() -> Self` — Creates an empty registry
- `add_provider(&self, init: InitializeResult, handle: SigningThreadHandle) -> Result<()>` — Parses certificates and adds a provider entry. Uses the same lenient parsing logic as described for `CertResolver` (skip invalid certs/schemes with warnings, fail only if no valid certs).
- `resolve_by_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>>` — Looks up a certificate by SNI across all providers. Wildcard-aware. Falls back to the default certificate of the first provider when no SNI or no match.
- Future: `remove_provider()`, `reload_provider()`, per-provider default certs, and multi-provider default selection (noted in code comments for later missions).

`CertResolver` holds a `ProviderRegistry` and delegates `resolve()` to `registry.resolve_by_sni()`.

**`SigningThread`** — Background OS thread that processes sign requests using the caller's tokio runtime.

- `SigningThread::start(handle: tokio::runtime::Handle, client: Arc<ProviderClient>) -> SigningThreadHandle` — Spawns a `std::thread::spawn`'d thread. The thread runs a loop receiving `(certificate_id, blob, oneshot::Sender<Result>)` tuples from an `std::sync::mpsc` channel, calling `handle.block_on(client.sign(...))` for each.
- `SigningThreadHandle` — Clonable handle holding the `std::sync::mpsc::Sender`. Provides `sign(&self, certificate_id: &str, blob: &[u8]) -> Result<Vec<u8>, rustls::Error>` which creates a fresh `std::sync::mpsc::channel()` for the response, sends `(certificate_id, blob, response_sender)` to the thread, and blocks on `response_receiver.recv()`.
- Error mapping: all sign failures (provider errors, channel disconnects) map to `rustls::Error::General(format!("remote sign failed: {details}"))` with the specific error message preserved for debugging.

**`RemoteSigningKey`** — Implements `rustls::crypto::signer::SigningKey` (requires `Debug + Send + Sync`). Uses `#[derive(Debug)]`.

- Holds: `SigningThreadHandle`, `certificate_id: String`, `algorithm: SignatureAlgorithm`, `supported_schemes: Vec<SignatureScheme>`
- `algorithm()` → returns the stored `SignatureAlgorithm`
- `choose_scheme(offered)` → intersects `offered` with `supported_schemes`, returns `Some(Box::new(RemoteSigner { ... }))` for the first match, or `None`

**`RemoteSigner`** — Implements `rustls::crypto::signer::Signer` (requires `Debug + Send + Sync`). Uses `#[derive(Debug)]`.

- Holds: `SigningThreadHandle`, `certificate_id: String`, `scheme: SignatureScheme`
- `scheme()` → returns the stored scheme
- `sign(message)` → calls `handle.sign(&certificate_id, message)`, returning the signature or `rustls::Error::General`

**`SigningThreadHandle`** has a manual `Debug` impl (prints `SigningThreadHandle { .. }`) since `std::sync::mpsc::Sender` does not implement `Debug`.

The signing thread exits when all `SigningThreadHandle` clones are dropped (channel closes). No explicit shutdown mechanism needed.

**`CertResolver`** — Implements `rustls::server::ResolvesServerCert` (requires `Debug + Send + Sync`).

- Holds: `registry: ProviderRegistry`
- `CertResolver::new(registry: ProviderRegistry) -> Self`
- `resolve(client_hello)` → delegates to `registry.resolve_by_sni(client_hello.server_name())`

**`CertResolverEntry`** — Internal struct used by `ProviderRegistry`.

- `id: String`, `domains: Vec<String>`, `certified_key: Arc<CertifiedKey>`

**Certificate parsing** (in `ProviderRegistry::add_provider`):

1. Parse PEM into `Vec<CertificateDer>` using `rustls_pki_types`. If PEM parsing fails, log a warning and skip the entry.
2. Parse `schemes` strings into `SignatureScheme` values (skip unknown strings with a warning). Infer `SignatureAlgorithm` from valid schemes. If no valid schemes remain, log a warning and skip the entry.
3. Create `RemoteSigningKey` and package into `CertifiedKey::new(cert_chain, signing_key)`
4. Returns error only if no valid certificates remain after filtering (empty result).

### Determining signature algorithm and schemes

The key provider protocol is extended to include supported signature schemes per certificate. The `initialize` response gains a `schemes` field on each certificate entry:

```json
{
    "result": {
        "default": "cert1",
        "certificates": [
            {
                "id": "cert1",
                "domains": ["*.lo.myteam.invalid"],
                "pem": "PEM string(s)",
                "schemes": ["RSA_PSS_SHA256", "RSA_PSS_SHA384", "RSA_PKCS1_SHA256"]
            }
        ]
    }
}
```

Scheme names follow rustls `SignatureScheme` variant names (e.g., `RSA_PSS_SHA256`, `ECDSA_NISTP256_SHA256`, `ED25519`). The `SignatureAlgorithm` is inferred from the scheme list (RSA schemes → `SignatureAlgorithm::RSA`, ECDSA schemes → `ECDSA`, Ed25519 → `ED25519`).

This requires changes in `trustless-protocol`:
- Add `rustls = { version = "0.23", default-features = false, features = ["std"] }` to `trustless-protocol/Cargo.toml`
- Add `schemes: Vec<String>` to `CertificateInfo` in `message.rs`
- Add a `scheme` module with `parse_scheme(name: &str) -> Option<SignatureScheme>` and `scheme_to_string(scheme: SignatureScheme) -> &'static str` mappings
- Add `algorithm_for_schemes(schemes: &[SignatureScheme]) -> Option<SignatureAlgorithm>` helper

Update `trustless-provider-stub` to populate `schemes` based on the key type (same logic it already uses in `choose_scheme`).

Rationale: the provider knows its key capabilities best. Parsing SPKI from the certificate works but duplicates key-type knowledge. Explicit schemes allow future providers to advertise only the schemes they actually support (e.g., an HSM that only supports RSA-PSS but not PKCS1).

### Wildcard matching

Domain matching in `CertResolver::resolve()`:

1. Exact match: SNI `foo.example.com` matches domain `foo.example.com`
2. Wildcard match: SNI `foo.example.com` matches domain `*.example.com` — the `*` replaces exactly one DNS label

Implementation: for each domain pattern, if it starts with `*.`, strip the `*.` prefix and check if the SNI ends with `.{suffix}` and contains exactly one more label (i.e., no additional dots before the suffix).

### Example: `tls_server`

A minimal TLS server that accepts connections and responds with a fixed HTTP 200 containing the SNI name. No HTTP parsing — just enough to verify the TLS handshake works with `curl` or a browser.

1. Loads config and profile via `trustless::config`
2. Spawns the provider via `ProviderClient::spawn()`
3. Creates `SigningThread`, calls `initialize()`, adds to `ProviderRegistry`
4. Creates `CertResolver` from the registry
5. Builds a `rustls::ServerConfig` with the resolver
6. Binds a `tokio::net::TcpListener` on the configured port
7. For each connection: wraps in `tokio_rustls::TlsAcceptor`, reads a few bytes, writes a hardcoded `HTTP/1.1 200 OK` response with the SNI name in the body, then closes

### Dependencies to add to `trustless/Cargo.toml`

- `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "logging", "tls12"] }`
- `rustls-pki-types = { version = "1", features = ["std"] }`
- `tokio-rustls = "0.26"` (for the example; also useful for spec 004)

### Test plan

**Unit tests** in `trustless/src/signer.rs` (`#[cfg(test)] mod tests`):

- Wildcard matching: `*.example.com` matches `foo.example.com`, does not match `bar.foo.example.com`, does not match `example.com`
- Exact matching: `foo.example.com` matches `foo.example.com`, does not match `bar.example.com`
- Scheme string parsing round-trip: `"RSA_PSS_SHA256"` → `SignatureScheme::RSA_PSS_SHA256` → `"RSA_PSS_SHA256"`
- `algorithm_for_schemes` correctly infers algorithm from scheme lists

**Integration test** in `trustless/tests/signer.rs`:

- Spawn `trustless-provider-stub` → `initialize()` → build `CertResolver` → verify resolution for known SNI names
- Full TLS handshake: create a `rustls::ServerConfig` with `CertResolver`, accept a connection from a `rustls` client, verify the handshake completes and data can be exchanged

## Current Status

Validation complete. Implementation matches spec.

### Checklist

- [x] **Protocol extension** (`trustless-protocol`):
  - [x] Add `rustls = { version = "0.23", default-features = false, features = ["std"] }` to `trustless-protocol/Cargo.toml`
  - [x] Add `schemes: Vec<String>` to `CertificateInfo` in `message.rs`
  - [x] Add `scheme` module with `parse_scheme` / `scheme_to_string` / `algorithm_for_schemes` helpers
  - [x] Unit tests for scheme parsing round-trips
- [x] **Stub provider update** (`trustless-provider-stub`):
  - [x] Populate `schemes` field in `CertificateInfo` based on key type
- [x] **Protocol documentation**:
  - [x] Update `docs/key-provider-protocol.md` with `schemes` field in initialize response
- [x] **Signer module** (`trustless/src/signer.rs`):
  - [x] `SigningThread` + `SigningThreadHandle` (background thread, std::sync::mpsc channels)
  - [x] `RemoteSigningKey` (implements `rustls::crypto::signer::SigningKey`)
  - [x] `RemoteSigner` (implements `rustls::crypto::signer::Signer`)
  - [x] `ProviderRegistry` (Arc<RwLock> orchestrator, add_provider, resolve_by_sni)
  - [x] `CertResolver` (implements `rustls::server::ResolvesServerCert`, delegates to registry)
  - [x] Wildcard domain matching
  - [x] Unit tests: wildcard matching, exact matching, scheme parsing, algorithm inference
- [x] **Dependencies** (`trustless/Cargo.toml`):
  - [x] Add `rustls`, `rustls-pki-types`, `tokio-rustls`
- [x] **Integration test** (`trustless/tests/signer.rs`):
  - [x] Spawn stub provider → initialize → add to registry → verify SNI resolution
  - [x] Full TLS handshake with rustls client
- [x] **Example** (`trustless/examples/tls_server.rs`):
  - [x] Minimal TLS server with fixed HTTP 200 response
- [x] `cargo clippy --workspace` passes

### Discrepancies

- **Default certificate fallback ignores `InitializeResult.default` ID** — Spec prose says "Falls back to the default certificate (as specified by `InitializeResult.default`)", but `CertResolverEntry` had no `id` field. Implementation stored `default_id` on `ProviderEntry` but `resolve_by_sni` always returned the first certificate. Resolution: fixed — added `id` to `CertResolverEntry`, `resolve_by_sni` now looks up by `default_id`. Spec updated to include `id` field.

### Updates

- 2026-03-06: Completed protocol extension — added `schemes` field to `CertificateInfo`, created `scheme` module with parsing helpers and unit tests. Updated stub provider to probe signing key capabilities and populate `schemes`. Updated protocol documentation.
- 2026-03-06: Completed signer module — `SigningThread`, `RemoteSigningKey`, `RemoteSigner`, `ProviderRegistry`, `CertResolver` with wildcard matching. Added rustls/tokio-rustls/rustls-pki-types deps.
- 2026-03-06: Completed integration tests (SNI resolution + full TLS handshake) and tls_server example. Note: tests require `multi_thread` tokio runtime since `Signer::sign()` blocks the calling thread while the signing thread uses `Handle::block_on()`. All tests pass, clippy clean.
- 2026-03-06: Validation complete. One discrepancy found and fixed: `resolve_by_sni` default fallback now properly looks up by `InitializeResult.default` ID instead of always returning the first certificate. Added `id` field to `CertResolverEntry`.
