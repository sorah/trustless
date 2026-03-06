# 006-proxy-lifecycle

## Summary

Implement the proxy process lifecycle: `trustless proxy start` (foreground), `trustless proxy stop`, proxy state persistence, auto-start via connect-or-start pattern, and a minimal control API for liveness and shutdown. The actual reverse proxy service and provider integration are out of scope — this spec focuses on the process lifecycle, state management, and control plane. Only the control API is served on the TLS listener in this mission; later specs add provider certs and reverse proxy routing.

## Explanation

### `trustless proxy start`

Starts the proxy as a foreground process. Generates an ephemeral self-signed certificate, binds a TLS listener on the configured port, and serves the control API until terminated. Writes proxy state to `{state_dir}/proxy.json` on startup and removes it on clean shutdown.

```
trustless proxy start
trustless proxy start --port 8443
```

If another proxy is already running (detected by connecting to the existing control API and verifying the certificate), the command refuses to start. Use `--force` to overwrite the state and start anyway.

### `trustless proxy stop`

Connects to the running proxy's control API and requests a graceful shutdown. Exits immediately after the stop request is acknowledged (fire-and-forget). Errors if no proxy is running.

```
trustless proxy stop
```

### Proxy state file

On startup, the proxy writes `{state_dir}/proxy.json`:

```json
{
  "pid": 12345,
  "port": 1443,
  "control_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

- `pid` — process ID of the proxy
- `port` — the TLS listen port
- `control_cert_pem` — PEM-encoded self-signed certificate for verifying the control API

Removed on clean shutdown. Stale state files are detected and cleaned up during connect-or-start.

### Auto-start (connect-or-start)

When a future `trustless exec` (or other commands) needs a running proxy, it uses the connect-or-start pattern:

1. Read `proxy.json` and attempt to connect to the control API (with cert verification)
2. If the connection succeeds (ping), use the existing proxy
3. If the connection fails and `TRUSTLESS_NO_AUTO_PROXY` is not set, spawn `trustless proxy start` as a background (daemonized) process
4. Poll the control API every 250ms until it responds, with a 20-second timeout

### Minimal control API

The control API is served over HTTPS on the same TLS listener (port 1443), distinguished by the `Host` header. Requests with `Host: trustless` are routed to the control API. All other hostnames are routed to the reverse proxy (which returns 502 in this mission since it's not yet implemented).

Endpoints (all return JSON with `Content-Type: application/json`):

- `GET /ping` — returns `200 OK` with `{"ok": true}`. Used for liveness checks.
- `POST /stop` — initiates graceful shutdown, returns `200 OK` with `{"ok": true}`

### Control client (`trustless::control::Client`)

Connects to the proxy's control API over HTTPS. Verifies the server certificate against `control_cert_pem` from `proxy.json` — does not rely on system trust store.

```rust
use trustless::control::Client;

let client = Client::from_state()?;  // reads proxy.json, builds TLS config with pinned cert
client.ping().await?;
client.stop().await?;
```

## Drawbacks

## Considered Alternatives

## Prior Art

- **Mairu** (`/home/sorah/git/github.com/sorah/mairu/`) — `connect_or_start()` pattern, agent process lifecycle, daemonization via `daemonix` crate, logging with `MAIRU_LOG`/`MAIRU_AGENT_LOG` env vars, rolling file logs when daemonized.

## Security and Privacy Considerations

- The ephemeral ECDSA P-256 key for the self-signed control certificate lives in the proxy process memory. No process hardening (mlockall, set_dumpable) is applied — the control cert is ephemeral and low-value.
- Control API certificate pinning prevents MITM: the client verifies the server cert matches `control_cert_pem` from `proxy.json`.
- The self-signed cert is generated fresh per process. It is never written to disk as a key file — only the certificate PEM is persisted in `proxy.json` for client verification.

## Mission Scope

### Out of scope

- __Full proxy control API.__ Route management, status, provider reload endpoints are deferred to later specs.
- __Provider integration.__ Spawning key providers and loading provider certificates into the CertResolver is deferred. This spec only registers the self-signed control cert.
- __Reverse proxy service.__ The `tower::Service` for forwarding requests to backends is implemented in spec 004. Non-control requests return 502 in this mission.
- __`trustless exec` command.__ Uses connect-or-start from this spec, but the exec command itself is a separate spec.
- __Process hardening.__ No core dump prevention, mlockall, or ptrace protection.

### Expected Outcomes

## Parallel Implementation Notes

This spec is implemented in parallel with 004 (Proxy Service) and 005 (Provider Registry). A prep commit (see `tmp/before-004-005-006.md`) has already:

- Moved `ProviderRegistry` to `trustless/src/provider.rs`
- Added `register_control_cert()` method with a separate `control_cert: Option<ControlCertEntry>` field
- Added `axum` and `reqwest` to `Cargo.toml`

**This spec does NOT touch**: `route.rs`, `proxy.rs`, `trustless-protocol/`, `examples/tls_server.rs`, `examples/provider_client.rs`

**HTTP framework**: This spec uses `axum` for the control API router and TLS listener dispatch. Non-control hosts (Host != `trustless`) return a 502 placeholder. When 004's proxy service is integrated later, it replaces this 502 fallback.

### Files owned by this spec

| File | Action |
|------|--------|
| `trustless/src/control/mod.rs` | NEW |
| `trustless/src/control/server.rs` | NEW |
| `trustless/src/control/client.rs` | NEW |
| `trustless/src/cmd/proxy.rs` | NEW |
| `trustless/src/cmd/mod.rs` | add `pub mod proxy;` |
| `trustless/src/lib.rs` | add `pub mod control;` |
| `trustless/src/main.rs` | add `Proxy` subcommand |
| `trustless/src/config.rs` | add `state_dir_mkpath()`, `log_dir_mkpath()` |
| `trustless/Cargo.toml` | add `rcgen`, `daemonix`, `nix`, `process_path`, `tracing-appender` (move `rcgen` from dev-deps to deps) |
| `trustless/tests/control.rs` | NEW |

## Implementation Plan

### File structure

```
trustless/src/control/mod.rs       # re-exports
trustless/src/control/server.rs    # control API hyper service, shutdown logic
trustless/src/control/client.rs    # Client, connect_or_start, spawn_proxy
trustless/src/cmd/proxy.rs         # ProxyStartArgs, ProxyStopArgs, CLI handlers
```

### Self-signed control certificate

Generated fresh on each proxy start using `rcgen`:
- Key type: ECDSA P-256
- Subject: CN=`trustless`
- SAN: DNS `trustless`
- Validity: 1 year (generous; the cert is only valid for the process lifetime anyway)
- Key extraction: `rcgen::KeyPair` → serialize to DER → parse as `rustls_pki_types::PrivateKeyDer` → `rustls::crypto::ring::sign::any_ecdsa_type()` to obtain a `SigningKey`
- The resulting `CertifiedKey` is registered in `ProviderRegistry` via a new `register_control_cert(certified_key, domains)` method (bypasses provider protocol). Later specs add provider certs via `add_provider()`.

### TLS listener

- Bind a `tokio::net::TcpListener` on `[::1]:{port}` with IPV6_V6ONLY=false (accepts both IPv4 and IPv6)
- Build a `rustls::ServerConfig` with the `CertResolver` wrapping the `ProviderRegistry`
- Use `tokio_rustls::TlsAcceptor` to accept TLS connections
- For each accepted connection, spawn a task that dispatches based on the `Host` header

### ProviderRegistry extension (done in prep)

`register_control_cert()` already exists on `ProviderRegistry` in `trustless/src/provider.rs` (added in prep commit). It stores the cert in a separate `control_cert: Option<ControlCertEntry>` field (not in the providers list). Repeated calls overwrite the previous value. `resolve_by_sni()` checks this field alongside provider entries.

### Control API routing

After TLS termination, the proxy dispatches requests using `axum`:
- `Host: trustless` → control API axum Router
- All other hosts → placeholder 502 response (reverse proxy service from spec 004 replaces this later)

### Control API endpoints

All responses are JSON (`Content-Type: application/json`).

- `GET /ping` — returns `200 OK` with `{"ok": true}`
- `POST /stop` — sends a shutdown signal via `tokio::sync::oneshot`, returns `200 OK` with `{"ok": true}`, then the proxy begins draining
- Unmatched routes return `404 Not Found` with `{"error": "not found"}`

### Graceful shutdown

Triggered by SIGTERM, SIGINT, or `POST /stop`:
1. Signal the accept loop to stop (via `tokio::sync::oneshot` or `tokio::signal`)
2. Wait up to 30 seconds for in-flight connections to complete
3. Force-close remaining connections after the drain timeout
4. Remove `proxy.json`
5. Exit

### Proxy state file (`{state_dir}/proxy.json`)

```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProxyState {
    pub pid: u32,
    pub port: u16,
    pub control_cert_pem: String,
}
```

Written atomically (write to temp file, then rename) on startup. Removed on clean shutdown.

### Tokio runtime

Keep `fn main()` synchronous. The tokio runtime is created only when needed:
- `proxy start` without `--daemonize`: the run function is annotated `#[tokio::main]`
- `proxy start --daemonize`: fork+setsid happens before the tokio runtime starts (critical — tokio must not be running when fork is called). After daemonize, the child calls the `#[tokio::main]` run function.
- `proxy stop`: needs async for the reqwest client; uses `#[tokio::main]` on the stop handler
- `connect_or_start`: caller is responsible for providing a tokio runtime

### Startup sequence

1. If `--daemonize`: fork+setsid via `daemonix` (before tokio starts)
2. Initialize logging (stderr or file, based on `--log-to-file`)
3. Start tokio runtime
4. Load `Config` from config directory
5. Determine listen port (`--port` flag > `config.json` > default 1443)
6. Check for existing proxy: read `proxy.json`, try connect + cert verify + ping
   - If alive: error (unless `--force`)
   - If stale or `--force`: remove `proxy.json` and continue
7. Create state and log directories (0o700 permissions via `nix::sys::stat::umask`)
8. Generate self-signed ECDSA P-256 certificate
9. Create bare `ProviderRegistry`, register self-signed cert via `register_control_cert()` (no `ProviderOrchestrator` — that integration comes when 005 is merged)
10. Build `CertResolver` and `rustls::ServerConfig`
11. Bind TCP listener
12. Write `proxy.json` (atomic: write temp file, rename)
13. Serve until shutdown

### Stale state detection

When connecting to a proxy (during connect-or-start or startup conflict check):
1. Read `proxy.json`
2. Connect to `localhost:{port}` with TLS (SNI=`trustless`)
3. Verify server certificate matches `control_cert_pem` (via custom `RootCertStore`)
4. Call `GET /ping`
5. If any step fails (no state file, connection refused, cert mismatch, ping failure), the state is stale

### Control client (`trustless::control::client`)

Uses `reqwest` with a custom TLS configuration:
- Build `rustls::ClientConfig` with a `RootCertStore` containing only the self-signed cert from `proxy.json`
- Pass to `reqwest::ClientBuilder::use_preconfigured_tls(rustls_config)`
- Use `reqwest::ClientBuilder::resolve("trustless", socket_addr)` to map `trustless` to `127.0.0.1:{port}`
- All requests go to `https://trustless/...`

```rust
pub struct Client {
    inner: reqwest::Client,
    port: u16,
}

impl Client {
    /// Load proxy state and build a client with pinned certificate.
    pub fn from_state() -> Result<Self, crate::Error>

    /// Ping the proxy. Returns Ok(()) if alive.
    pub async fn ping(&self) -> Result<(), crate::Error>

    /// Request graceful shutdown. Fire-and-forget.
    pub async fn stop(&self) -> Result<(), crate::Error>
}
```

### Connect-or-start (`trustless::control::client`)

```rust
/// Connect to existing proxy or auto-start one.
/// Respects TRUSTLESS_NO_AUTO_PROXY env var.
pub async fn connect_or_start() -> Result<Client, anyhow::Error>
```

1. Try `Client::from_state()` + `ping()`
2. If connection fails and `TRUSTLESS_NO_AUTO_PROXY` is set, return error
3. Otherwise, call `spawn_proxy()`
4. Poll `Client::from_state()` + `ping()` every 250ms, 20-second timeout
5. Return the connected client or timeout error

```rust
/// Spawn proxy as a daemon process.
async fn spawn_proxy() -> Result<(), anyhow::Error>
```

Uses `process_path::get_executable_path()` to find the trustless binary, then:
```
tokio::process::Command::new(arg0)
    .args(["proxy", "start", "--log-to-file", "--daemonize"])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit())
    .kill_on_drop(false)
    .status()
    .await
```

### Daemonization

Uses the `daemonix` crate (maintained fork of `daemonize`). Added as `daemonize = { version = "0.1.0", package = "daemonix" }`.

- `--daemonize` flag: fork+setsid via `daemonix::Daemonize`, parent exits with child exit code
- On macOS: re-exec after fork to avoid Objective-C fork safety issues (same pattern as mairu)

### Logging

Follows mairu's logging pattern:
- `TRUSTLESS_LOG` env var: if set, mapped to `RUST_LOG` for the proxy process
- `TRUSTLESS_PROXY_LOG` env var: when set on the caller, copied to `TRUSTLESS_LOG` on the spawned proxy (analogous to `MAIRU_AGENT_LOG`)
- Foreground mode: log to stderr via `tracing_subscriber::fmt().with_writer(std::io::stderr)`
- `--log-to-file` mode: rolling daily log to `{state_dir}/log/trustless.log` via `tracing_appender::rolling::daily`
- Default log level (when no RUST_LOG/TRUSTLESS_LOG): `trustless=info`

### CLI commands

```rust
// In main.rs, add to Cli enum:
#[command(subcommand)]
Proxy(cmd::proxy::ProxyCommand),

// In cmd/proxy.rs:
#[derive(clap::Subcommand)]
pub enum ProxyCommand {
    Start(ProxyStartArgs),
    Stop(ProxyStopArgs),
}

#[derive(clap::Args)]
pub struct ProxyStartArgs {
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, default_value_t = false)]
    daemonize: bool,
    #[arg(long, default_value_t = false)]
    log_to_file: bool,
    #[arg(long, default_value_t = false)]
    force: bool,
}

#[derive(clap::Args)]
pub struct ProxyStopArgs {}
```

### Directory creation

On startup, create directories with 0o700 permissions:
- Set umask to 0o077 via `nix::sys::stat::umask()`
- `std::fs::create_dir_all(state_dir)` for `proxy.json`
- `std::fs::create_dir_all(state_dir.join("log"))` when `--log-to-file`

Add helper functions to `trustless::config`:
- `state_dir_mkpath() -> io::Result<PathBuf>`
- `log_dir_mkpath() -> io::Result<PathBuf>`

### Dependencies to add to `trustless/Cargo.toml`

Already present from prep: `axum`, `reqwest`. Move `rcgen` from `[dev-dependencies]` to `[dependencies]`.

New dependencies for this spec:
- `rcgen = "0.13"` — self-signed certificate generation (move from dev-deps to deps)
- `daemonize = { version = "0.1.0", package = "daemonix" }` — fork+setsid
- `nix = { version = "0.29", features = ["fs"] }` — umask
- `process_path = "0.1"` — executable path for re-exec
- `tracing-appender = "0.2"` — rolling file logs

### Test plan

**Unit tests** in `trustless/src/control/server.rs` (`#[cfg(test)] mod tests`):
- Control API handler: `GET /ping` returns 200 with `{"ok": true}`
- Control API handler: `POST /stop` returns 200 and triggers shutdown signal
- Control API handler: unknown route returns 404
- Control API handler: non-control host returns 502

**Unit tests** in `trustless/src/control/client.rs`:
- `ProxyState` serialization round-trip
- `Client::from_state()` with missing `proxy.json` returns appropriate error

**Integration test** in `trustless/tests/control.rs`:
- Start proxy in-process (not daemonized), connect with `Client`, ping, stop, verify state file cleanup
- Full TLS handshake: verify the self-signed cert is served for SNI=`trustless`

## Current Status

Interview complete. Ready for implementation.

### Checklist

- [ ] **ProviderRegistry usage** (`trustless/src/provider.rs`, prep already added `register_control_cert()`):
  - [ ] ~~Add `register_control_cert()` method~~ (done in prep)
  - [ ] Unit test for resolving control cert by SNI (if not covered by prep)
- [ ] **Control server** (`trustless/src/control/server.rs`):
  - [ ] Control API hyper service (ping, stop, 404 fallback)
  - [ ] Host-based dispatch (control vs 502 placeholder)
  - [ ] Shutdown signal integration (oneshot channel)
  - [ ] Unit tests: ping, stop, unknown route, non-control host
- [ ] **Control client** (`trustless/src/control/client.rs`):
  - [ ] `ProxyState` struct with serde
  - [ ] `Client::from_state()` — read proxy.json, build reqwest with pinned cert
  - [ ] `Client::ping()`, `Client::stop()`
  - [ ] `connect_or_start()` — connect-or-spawn with 20s/250ms poll
  - [ ] `spawn_proxy()` — daemonized proxy launch
  - [ ] Unit tests: ProxyState round-trip, from_state with missing file
- [ ] **CLI** (`trustless/src/cmd/proxy.rs` + `trustless/src/main.rs`):
  - [ ] `ProxyCommand` subcommand enum (Start, Stop)
  - [ ] `ProxyStartArgs` (--port, --daemonize, --log-to-file, --force)
  - [ ] `ProxyStopArgs`
  - [ ] Wire into main.rs Cli enum
- [ ] **Proxy lifecycle** (`trustless/src/cmd/proxy.rs`):
  - [ ] Self-signed cert generation with rcgen
  - [ ] TLS listener setup (tokio-rustls, CertResolver)
  - [ ] Startup conflict detection (existing proxy check)
  - [ ] Atomic proxy.json write + cleanup on shutdown
  - [ ] Graceful shutdown with 30s drain timeout
  - [ ] Signal handling (SIGTERM, SIGINT)
- [ ] **Daemonization**:
  - [ ] `--daemonize` via daemonix (fork before tokio)
  - [ ] macOS re-exec after fork
- [ ] **Logging**:
  - [ ] TRUSTLESS_LOG / TRUSTLESS_PROXY_LOG env var handling
  - [ ] Foreground: stderr, daemonized: rolling file
  - [ ] Default level: `trustless=info`
- [ ] **Config helpers** (`trustless/src/config.rs`):
  - [ ] `state_dir_mkpath()` with 0o700
  - [ ] `log_dir_mkpath()` with 0o700
- [ ] **Dependencies** (`trustless/Cargo.toml`):
  - [ ] Move `rcgen` from dev-deps to deps
  - [ ] Add `daemonix`, `nix`, `process_path`, `tracing-appender`
  - [ ] (`axum`, `reqwest` already present from prep)
- [ ] **Integration test** (`trustless/tests/control.rs`):
  - [ ] Start proxy in-process, connect with Client, ping, stop, verify cleanup
  - [ ] TLS handshake verification for self-signed cert
- [ ] `cargo clippy --workspace` passes

### Updates

Implementors MUST keep this section updated as they work.
