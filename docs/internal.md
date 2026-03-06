# Trustless Internals

## Workspace Structure

- **`trustless`** — CLI and proxy server
- **`trustless-protocol`** — Protocol types, codec, handler trait, and client for the key provider protocol
- **`trustless-provider-stub`** — Reference key provider implementation backed by static certificate files on disk

## Dependencies

### Fundamentals

- `clap` (with derive) for CLI
- `anyhow` for CLI error handling
- `thiserror` for library error types
- `serde` and `serde_json` for JSON serialization
- `serde_with` for base64 encoding of binary fields in protocol messages
- `tracing`, `tracing-appender`, and `tracing-subscriber` for structured logging

### TLS

- `rustls` (aws-lc-rs backend) — TLS implementation with extension points for remote signing
- `tokio-rustls` — async TLS via `LazyConfigAcceptor` for per-connection SNI resolution
- `rcgen` — self-signed certificate generation (control API)
- `rustls-pki-types` — PEM parsing for certificate chains
- `x509-parser` — extracting DNS SANs, issuer, serial, and expiry from leaf certificates

### HTTP / Proxy

- `axum` — HTTP framework for both control API and proxy handler
- `reqwest` — HTTP client for forwarding requests to backends (and control API client)
- `hyper` / `hyper-util` — low-level HTTP for WebSocket upgrade handling and graceful shutdown
- `http-body-util` — body utilities for upgrade responses
- `socket2` — dual-stack TCP listener binding
- `tower` — `ServiceExt::oneshot` for host-based dispatch between control API and proxy

### Process / Async

- `tokio` (full features) — async runtime
- `tokio-util` — `LengthDelimitedCodec` for provider wire protocol, `CancellationToken` for supervisor shutdown
- `daemonix` — daemonization for background proxy startup
- `nix` — `fork`, signal handling, `mkdir` with mode, process management
- `parking_lot` — `Mutex` for route table with mtime caching
- `cfg-if` — platform-specific pipe creation (pipe2 vs pipe+fcntl)

## Provider Communication

Key providers are spawned as child processes via `tokio::process::Command` with stdin/stdout piped. Communication uses `tokio_util::codec::LengthDelimitedCodec` (4-byte big-endian length prefix + JSON payload) over stdin (requests) and stdout (responses). Provider stderr is captured line-by-line and forwarded to the proxy's tracing logs, with a ring buffer of the last 100 lines retained for error diagnostics.

See [key-provider-protocol.md](key-provider-protocol.md) for the wire protocol specification.

## Provider Lifecycle

Three layers manage provider processes:

1. **`ProviderProcess`** (`trustless/src/provider/process.rs`) — spawns the child process, provides access to stdin/stdout via `ProviderClient` and stderr as a separate stream.

2. **`Supervisor`** (`trustless/src/provider/supervisor.rs`) — monitors a single provider process. On crash, marks the provider as `Restarting` in the registry and enters an exponential backoff respawn loop (1s initial, 2x multiplier, 300s max). Backoff resets after 60s of continuous healthy operation. On shutdown, sends SIGTERM and waits up to 20s before SIGKILL. Accepts manual restart commands (bypassing backoff).

3. **`ProviderOrchestrator`** (`trustless/src/provider/orchestrator.rs`) — manages multiple named providers. `add_provider` spawns, initializes, and registers a provider (no automatic retry on first failure). `restart_provider` / `restart_all` send restart commands to supervisors. `shutdown` cancels all supervisors via `CancellationToken`.

## Remote Signing Bridge

The proxy needs to call the async provider protocol from rustls's synchronous `Signer::sign()` trait. This is bridged through three components:

- **`SigningWorker`** (`trustless/src/signer.rs`) — a tokio task that receives sign requests via `mpsc::unbounded_channel` and calls `ProviderClient::sign()`. Each request includes a `oneshot` channel for the response.

- **`SigningHandle`** — clonable handle to the worker. Its `sign()` method sends a request and blocks on the oneshot response using `tokio::task::block_in_place` + `Handle::current().block_on()`. This works because TLS handshakes run on tokio worker threads via `LazyConfigAcceptor`.

- **`RemoteSigningKey`** / **`RemoteSigner`** — implements rustls's `SigningKey` and `Signer` traits. `RemoteSigningKey::choose_scheme` finds a matching scheme from the provider's declared list and returns a `RemoteSigner` bound to that scheme. `RemoteSigner::sign` delegates to `SigningHandle::sign`.

## Certificate Resolution

**`ProviderRegistry`** (`trustless/src/provider/registry.rs`) holds all registered certificates and resolves them by SNI. Resolution order:

1. **Control cert** — if SNI matches `trustless`, return the self-signed control API certificate
2. **Exact match** — iterate all providers' certificates checking domain lists
3. **Wildcard match** — `*.example.com` matches `foo.example.com` (single label only, not nested)
4. **Default fallback** — return the default certificate (by `InitializeResult.default` id) of the first provider

Certificates without valid signature schemes or with mixed algorithm families are skipped with a warning during registration.

TLS acceptance uses `tokio_rustls::LazyConfigAcceptor`: on each incoming connection, the SNI is extracted from the ClientHello, the registry resolves a `CertifiedKey`, and a per-connection `ServerConfig` is built with a `FixedCertResolver` wrapping that key.

## Proxy Behavior

**Route table** (`trustless/src/route.rs`) — file-based (`{state_dir}/routes.json`) with mtime-based cache invalidation. Routes map hostnames to `SocketAddr` backends. The `trustless exec` command registers a route on startup and removes it via a `RouteGuard` (Drop impl) on exit.

**HTTP forwarding** (`trustless/src/proxy.rs`) — the proxy handler:
- Extracts the `Host` header to look up the backend in the route table
- Rejects requests to the reserved hostname `trustless` (control API)
- Detects forwarding loops via `X-Trustless-Hops` header (max 5 hops)
- Forwards with `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` headers
- Preserves the original `Host` header
- Adds `Via: 1.1 trustless`
- Strips hop-by-hop headers per RFC 7230

**WebSocket upgrade** — detected by `Connection: upgrade` header. Uses raw hyper HTTP/1.1 for the backend handshake, then `tokio::io::copy_bidirectional` for the upgraded connection.

## Control API

The proxy exposes a control API on the same TLS port, dispatched by `Host: trustless`:

- `GET /ping` — liveness check
- `POST /stop` — trigger graceful shutdown
- `POST /reload` — restart all providers (re-initialize, refresh certificates)
- `GET /status` — returns pid, port, provider status (state, certificates, errors), and routes

The control API uses a self-signed ECDSA P-256 certificate generated at proxy startup for subject name `trustless`. The certificate PEM is saved to `proxy.json` in the state directory. CLI clients verify the proxy's identity by pinning against this certificate (custom `RootCertStore`, not the system trust store).

## Exec Pattern

`trustless exec` (`trustless/src/cmd/exec.rs`) uses a fork + sidecar pattern (ported from [mairu](https://github.com/sorah/mairu)):

1. **Fork** — parent becomes the executor, child becomes the sidecar
2. **Sidecar** (child process) — connects to or starts the proxy, resolves a hostname from the provider's wildcard domains, registers a route in the route table, and sends the result back to the executor via a pipe (IPC)
3. **Executor** (parent process) — reads the IPC message, sets environment variables (`PORT`, `HOST`, `TRUSTLESS_HOST`, `TRUSTLESS_PORT`), and `exec`s the user's command
4. **Cleanup** — the sidecar monitors the parent pid; when the parent exits, the sidecar's `RouteGuard` removes the route from the route table

## CLI-Proxy Communication

The proxy writes `{state_dir}/proxy.json` on startup containing the port, pid, and the self-signed control certificate PEM. CLI commands read this file and build a `reqwest` client with the pinned certificate to communicate with the proxy's control API over HTTPS. The state directory is protected with 0o700 permissions.
