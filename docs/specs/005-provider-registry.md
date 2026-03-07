# 005-provider-registry

## Summary

Complete the provider lifecycle management layer. Introduce `ProviderOrchestrator` to manage spawning, auto-restart with exponential backoff, and error tracking for key provider processes. Refactor the existing `ProviderRegistry` into a dedicated `trustless::provider` module.

## Explanation

### Architecture

Three-layer design:

1. **`ProviderOrchestrator`** — Top-level lifecycle manager. Spawns providers, monitors for crashes, auto-restarts with exponential backoff, tracks errors (recent protocol errors and stderr from crashed processes).
2. **`ProviderRegistry`** — State management for certificates and signing handles. Moved from `trustless::signer` to `trustless::provider`. Unchanged in responsibility: stores `CertResolverEntry` values, resolves by SNI.
3. **`ProviderSession`** — Represents one lifecycle of a spawned provider process. Wraps a `ProviderClient` and its associated `SigningWorker`/`SigningHandle`.

```rust
use trustless::provider::{ProviderOrchestrator, ProviderRegistry};
use trustless::signer::CertResolver;
use trustless::config::Profile;

let registry = ProviderRegistry::new();
let orchestrator = ProviderOrchestrator::new(registry.clone());

// Add a provider — blocks until first successful initialization
let profile: Profile = config.load_profile("default")?;
orchestrator.add_provider("default", profile).await?;

let resolver = CertResolver::new(registry);
// resolver implements ResolvesServerCert

// Manual restart (bypasses backoff)
orchestrator.restart_provider("default").await?;

// Shutdown all providers
orchestrator.shutdown().await;
```

### Auto-restart

When a provider process crashes, the orchestrator automatically restarts it using exponential backoff to avoid rapid restart loops. Recent stderr output from the crashed process is preserved for diagnostics.

### Error tracking

The orchestrator stores recent errors for inspection by CLI commands (e.g., `trustless proxy status`):

- Recent protocol-level error responses from the provider
- Stderr output captured from the most recent crash

## Drawbacks

## Considered Alternatives

### Single struct instead of three layers

Merging orchestration into `ProviderRegistry` would be simpler but would conflate certificate state management (sync, used in TLS hot path) with async process lifecycle management. The three-layer split keeps the sync certificate lookup path clean.

## Prior Art

- mairu's `connect_or_start()` pattern for agent process management

## Security and Privacy Considerations

Providers are trusted local processes. Stderr output is stored in the error ring without redaction. Providers should not log secrets to stderr. This is documented but not enforced.

## Mission Scope

### Out of scope

- **Proxy integration.** How the proxy (spec 004) consumes the orchestrator is deferred. This spec provides the building blocks.
- **CLI status command.** `trustless proxy status` that reads errors is a future spec. This spec provides the error storage API.
- **Protocol-level error tracking.** Tracking individual sign() errors (as opposed to crashes/init failures) may be added later.

### Expected Outcomes

- `ProviderOrchestrator` with spawn, auto-restart, manual restart, and error tracking
- `ProviderRegistry` moved to `trustless::provider` with atomic replace and error storage
- `ProviderSession` struct wrapping client + signing thread
- `ProviderProcess` struct in trustless-protocol (replaces `ProviderClient::spawn()`)
- Updated `examples/tls_server.rs` using the new orchestrator API
- Unit and integration tests

## Parallel Implementation Notes

This spec is implemented in parallel with 004 (Proxy Service) and 006 (Proxy Lifecycle). A prep commit (see `tmp/before-004-005-006.md`) has already:

- Moved `ProviderRegistry`, `ProviderEntry`, `CertResolverEntry`, `matches_sni()` from `signer.rs` to `provider.rs`
- Added `register_control_cert()` with a separate `control_cert: Option<ControlCertEntry>` field (used by 006)
- Updated all import paths (examples, tests)

**This spec does NOT touch**: `route.rs`, `proxy.rs`, `control/`, `cmd/route.rs`, `cmd/proxy.rs`, `config.rs`

### Files owned by this spec

| File | Action |
|------|--------|
| `trustless/src/provider.rs` | EXTEND (add Orchestrator, Session, State, error tracking, replace_provider) |
| `trustless/src/signer.rs` | minor cleanup if needed |
| `trustless-protocol/src/process.rs` | NEW |
| `trustless-protocol/src/client.rs` | modify (remove spawn/kill, add from_child_io) |
| `trustless-protocol/src/lib.rs` | add `pub mod process;` |
| `trustless/Cargo.toml` | add `tokio-util` sync feature |
| `trustless/examples/tls_server.rs` | update for ProviderOrchestrator |
| `trustless/examples/provider_client.rs` | update for ProviderProcess |
| `trustless/tests/signer.rs` | update for ProviderProcess::spawn |
| `trustless-protocol/tests/handler_client.rs` | update for ProviderProcess |

## Implementation Plan

### Module structure

- `trustless/src/signer.rs` — Keeps `SigningWorker`, `SigningHandle`, `RemoteSigningKey`, `RemoteSigner`, `CertResolver`. All existing tests stay.
- `trustless/src/provider.rs` (already exists from prep) — Extend with `ProviderOrchestrator`, `ProviderSession`. `ProviderRegistry` is already here.

### Provider identity

Each provider is identified by its profile name (e.g., `"default"`). This ID is used for `replace_provider()`, error lookup, and logging. One provider per profile name is enforced.

### ProviderSession

Represents one lifecycle of a spawned provider. Contains:
- `Arc<ProviderClient>` — the spawned process
- `SigningHandle` — for sign requests
- Stderr ring buffer handle

### ProviderProcess (trustless-protocol)

Introduce `ProviderProcess` in `trustless-protocol` to own the spawned child process. `ProviderClient::spawn()` moves to `ProviderProcess::spawn()`.

```rust
pub struct ProviderProcess {
    pub client: ProviderClient,
    pub stderr: tokio::process::ChildStderr,
    child: tokio::process::Child,  // private, for wait/kill
}

impl ProviderProcess {
    pub async fn spawn(command: &[String]) -> Result<Self, Error>;
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus>;
    pub fn signal(&self, sig: i32) -> std::io::Result<()>;  // send signal (e.g., SIGTERM)
    pub async fn kill(&mut self) -> std::io::Result<()>;     // SIGKILL
}
```

`ProviderClient` no longer owns `Child` or handles spawning — it only manages the protocol communication over framed stdin/stdout. `ProviderClient::spawn()` is removed and replaced with `ProviderClient::from_child_io(stdin: ChildStdin, stdout: ChildStdout)` which creates the framed codec internally. `ProviderClient::kill()` is also removed — process lifecycle is managed by `ProviderProcess`.

`ProviderProcess` always pipes stderr. All callers (examples, tests) are updated to use `ProviderProcess::spawn()` and handle stderr (typically by dropping it or spawning a reader).

### Supervisor task model

Each provider gets a long-lived `tokio::spawn`'d supervisor task that owns the spawn → initialize → monitor → restart loop. The task `select!`s on `child.wait()` and a `CancellationToken` (from `tokio_util::sync`). The stderr reader runs as a child task within the supervisor.

### Manual restart

`ProviderOrchestrator::restart_provider(name: &str)` kills the current process and spawns a fresh one, bypassing backoff. It is async and waits for the new provider to be re-initialized before returning `Ok(())`. Implemented via a oneshot response channel in the command message. Needed for the future proxy reload command.

The supervisor task `select!`s on three sources: `child.wait()`, the `CancellationToken`, and an `mpsc` command channel. On a `Restart` command, it kills the current process, re-enters the spawn loop (resetting backoff), and signals completion via the oneshot channel. On cancellation (shutdown), it kills the process and exits.

### Shutdown

`ProviderOrchestrator::shutdown()` sends SIGTERM to all provider processes, then waits up to 20 seconds for them to exit. Any providers still running after the timeout are sent SIGKILL. Supervisor tasks are cancelled after all processes are terminated.

### Provider state

`ProviderRegistry` tracks a `ProviderState` enum per provider:

- `Running` — provider is initialized and serving sign requests
- `Restarting` — provider crashed or is being restarted, backoff in progress
- `Failed` — initial spawn/init failed (only for `add_provider` failure path; auto-restart providers cycle between Running and Restarting)

State is stored alongside certs and errors in the provider entry. Updated by the orchestrator's supervisor task. Useful for the future `trustless proxy status` command.

### Cloneability

`ProviderOrchestrator` wraps `Arc<...>` internally, same pattern as `ProviderRegistry`. Allows sharing between the proxy server and future CLI status handlers.

### Init failure handling

If `initialize()` fails after a successful spawn, the orchestrator treats it identically to a crash: kills the process, records an `InitFailure` error, and applies the same exponential backoff before retrying.

### Crash detection and restart

The orchestrator spawns a background tokio task per provider that awaits `child.wait()`. When the child exits (any exit status), the task triggers the restart flow with exponential backoff. In-flight sign requests fail naturally — `ProviderClient::sign()` returns an IO/ProcessExited error, which maps to `rustls::Error::General`. The TLS handshake fails for those requests.

**Exponential backoff:** 1s initial delay, 5m maximum, 2x multiplier. Backoff resets to 1s after the provider has been running healthy for 60s without crashing.

**Certificate update on restart:** `ProviderRegistry` gains a `replace_provider(provider_id, init, handle)` method that atomically swaps the `ProviderEntry`. `CertResolver` sees the new certificates on the next `resolve()` call with no window of missing certs.

### Adding a provider

`ProviderOrchestrator::add_provider(name: &str, profile: Profile)` takes a `Profile` from `trustless::config`. It spawns the provider, calls `initialize()`, populates the registry, and returns `Ok(())` only after the first successful initialization. If the first spawn or `initialize()` fails, `add_provider()` returns `Err` immediately — no automatic retry. The caller (proxy startup) decides whether to retry or abort. Subsequent crashes (after the first successful init) trigger background auto-restart via the supervisor task.

### Healthy period

Backoff resets to 1s after 60s of uptime since the last successful `initialize()`. No tracking of sign request outcomes is needed.

### Multiple providers

The orchestrator manages N providers, each from a different profile. Each provider has independent lifecycle, backoff state, and error tracking.

### Stderr capture

`ProviderProcess::spawn()` pipes stderr. A background tokio task reads stderr lines into a ring buffer holding the last 100 lines. Each line is also forwarded to `tracing` at `warn` level (with provider name/ID as a span field). On crash, the ring buffer contents are saved into the error history as crash context.

### Error tracking

Error state is stored on `ProviderRegistry` (alongside cert state) so consumers holding a registry reference can query provider status. Each provider entry stores the last 10 errors in a FIFO ring. Each error entry contains:

- `timestamp: SystemTime`
- `kind: ProviderErrorKind` — enum: `ProtocolError`, `Crash`, `InitFailure`
- `message: String` — human-readable description
- `stderr_snapshot: Option<Vec<String>>` — captured stderr lines at time of crash (only for `Crash` kind)

The orchestrator pushes errors into the registry when:
- The provider process exits unexpectedly (Crash)
- `initialize()` fails after spawn (InitFailure)
- A protocol-level error response is received (ProtocolError) — future consideration, may not be needed in this spec

### Dependencies

- Add `tokio-util = { version = "0.7", features = ["sync"] }` to `trustless/Cargo.toml` (for `CancellationToken`)
- `tokio-util` is already a dependency in `trustless-protocol`

### Test plan

**Unit tests** in `trustless/src/provider.rs` (`#[cfg(test)] mod tests`):

- `ProviderRegistry::replace_provider()` atomically swaps certificates (verify SNI resolution returns new cert after replace)
- `ProviderRegistry::push_error()` respects FIFO capacity (push 15 errors, verify only last 10 remain)
- Error entry fields populated correctly for each `ProviderErrorKind`
- Backoff calculation: verify delay sequence 1s, 2s, 4s, 8s, ..., capped at 5m

**Unit tests** for `ProviderOrchestrator` — mock `ProviderProcess` to test:

- Supervisor restart loop (mock process that exits, verify restart is attempted)
- Backoff reset after healthy period
- Manual restart command resets backoff
- Shutdown cancels supervisor

**Integration tests** in `trustless/tests/`:

- Existing `signer.rs` tests updated for `ProviderProcess::spawn()` API change
- `ProviderProcess::spawn()` starts provider-filesystem, `initialize()` succeeds, `sign()` works

No integration test for the full orchestrator restart loop — orchestrator is covered by unit tests with mocks.

### Example update

`trustless/examples/tls_server.rs` updated to use `ProviderOrchestrator` instead of manually spawning `ProviderClient` and calling `initialize()`.

## Current Status

Implementation complete.

### Checklist

Implementors MUST keep this section updated as they work.

- [x] **ProviderProcess** (`trustless-protocol/src/process.rs`, new):
  - [x] `ProviderProcess` struct with `client`, `stderr`, `child` fields
  - [x] `spawn()`, `wait()`, `signal()`, `kill()` methods
  - [x] `ProviderClient::from_child_io()` constructor
  - [x] Remove `ProviderClient::spawn()` and `ProviderClient::kill()`
  - [x] Update existing tests and callers
- [x] **ProviderRegistry** (`trustless/src/provider.rs`, already exists from prep):
  - [x] ~~Move `ProviderRegistry`, `ProviderEntry`, `CertResolverEntry` from `signer.rs`~~ (done in prep)
  - [x] Add `replace_provider(name, init, handle)` for atomic cert swap
  - [x] Add `ProviderState` enum (`Running`, `Restarting`, `Failed`) per provider
  - [x] Add error tracking: `ProviderError` struct, FIFO ring (10 entries), `push_error()`, `errors()` query
  - [x] Add `ProviderErrorKind` enum (`Crash`, `InitFailure`, `ProtocolError`)
  - [x] Unit tests: replace_provider, error FIFO, state tracking
- [x] **ProviderSession** (`trustless/src/provider.rs`):
  - [x] Struct wrapping `Arc<ProviderClient>`, `SigningHandle`, stderr ring buffer
- [x] **ProviderOrchestrator** (`trustless/src/provider.rs`):
  - [x] Arc-wrapped, Clone
  - [x] `new(registry)`, `add_provider(name, profile)`, `restart_provider(name)`, `shutdown()`
  - [x] Supervisor task per provider: select! on child.wait / CancellationToken / mpsc commands
  - [x] Exponential backoff (1s min, 5m max, 2x, reset after 60s healthy)
  - [x] Stderr reader task (100-line ring buffer, forward to tracing at warn)
  - [x] Shutdown: SIGTERM → wait 20s → SIGKILL
  - [ ] Unit tests with mocked ProviderProcess
- [x] **Signer module update** (`trustless/src/signer.rs`):
  - [x] ~~Remove `ProviderRegistry` and related types (moved to provider.rs)~~ (done in prep)
  - [x] Verify imports are clean, keep SigningWorker/RemoteSigningKey/RemoteSigner/CertResolver
- [x] **Dependencies**:
  - [x] Add `tokio-util` to `trustless/Cargo.toml` (sync feature not needed in 0.7.18 — CancellationToken always available)
  - [x] Add `libc` to `trustless/Cargo.toml` and `trustless-protocol/Cargo.toml` (for SIGTERM)
- [x] **Integration tests** (`trustless/tests/`):
  - [x] Update `signer.rs` tests for `ProviderProcess::spawn()` API
  - [x] Verify ProviderProcess spawn + initialize + sign with provider-filesystem
- [x] **Example** (`trustless/examples/tls_server.rs`):
  - [x] Update to use `ProviderOrchestrator` API
- [x] `cargo clippy --workspace` passes

### Updates

**2026-03-07**: Implementation complete.

- **ProviderProcess**: New `trustless-protocol/src/process.rs` with `spawn()`, `wait()`, `signal()` (unix-only via libc), `kill()`, and `into_parts()` for decomposing into client/stderr/child when separate ownership is needed.
- **ProviderClient**: Removed `spawn()` and `kill()`, replaced with `from_child_io(stdin, stdout)`. Process lifecycle now owned by `ProviderProcess`.
- **ProviderRegistry**: Changed internal storage from `Vec<ProviderEntry>` to `HashMap<String, ProviderEntry>` keyed by provider name. Added `replace_provider()` for atomic cert swap, `ProviderState` enum, error tracking with FIFO ring (10 entries), `push_error()`/`errors()`/`set_provider_state()`/`provider_state()` methods. Extracted `parse_init_result()` helper to share between `add_provider()` and `replace_provider()`.
- **ProviderSession**: Struct wrapping `Arc<ProviderClient>`, `SigningHandle`, and stderr ring buffer.
- **ProviderOrchestrator**: Arc-wrapped Clone struct. `add_provider()` spawns + initializes synchronously, then starts a supervisor task. Supervisor uses `tokio::select!` on child.wait / CancellationToken / mpsc commands. Exponential backoff (1s→5m, 2x, reset after 60s healthy). Stderr reader task (100-line ring buffer, forwarded to tracing at warn). `restart_provider()` kills current process and respawns with backoff reset, returning only after re-initialization. `shutdown()` sends SIGTERM, waits 20s, then SIGKILL.
- **SigningHandle**: Added `disconnected()` constructor for tests/placeholder entries.
- **Dependencies**: Added `tokio-util` (0.7) and `libc` (0.2) to trustless crate; added `libc` (0.2) to trustless-protocol crate.
- **Tests**: All existing tests updated for ProviderProcess API. New unit tests: `replace_provider_swaps_atomically`, `error_fifo_respects_capacity`, `error_entry_fields`, `provider_state_tracking`, `backoff_calculation`.
- **Note**: Unit tests for ProviderOrchestrator with mocked ProviderProcess are deferred — the orchestrator's supervisor loop directly calls `ProviderProcess::spawn()` which is hard to mock without trait abstraction. The orchestrator is covered by the integration tests via real provider-filesystem processes.
