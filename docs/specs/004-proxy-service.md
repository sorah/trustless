# 004-proxy-service

## Summary

Implement a reverse proxy service and filesystem-based route state management. The proxy forwards HTTP requests to backend services based on hostname-to-backend mappings stored in the state directory. CLI commands manipulate routes, and the proxy re-reads the route file on each request (with debouncing).

## Explanation

### Proxy Service

A reverse proxy implemented as a `tower::Service`. Runs as a plain HTTP service during this mission (TLS termination deferred). The proxy resolves the target backend from the incoming request's `Host` header, then forwards the request using `reqwest`.

### Route Management CLI

```
trustless route add <host> <backend>
trustless route add --force <host> <backend>
trustless route remove <host>
```

- `<host>` is a full hostname (e.g. `api.lo.dev.invalid`)
- `<backend>` is a socket address (e.g. `127.0.0.1:3000`)
- `route add` errors if the host already exists unless `--force` is passed to overwrite.
- `route remove` errors if the host does not exist.
- `route add` validates the hostname: rejects `trustless` (reserved), checks for basic DNS name validity (no spaces, valid characters).

### Code Layout

Proxy service and route state logic live in `trustless/src/` (library code). An example binary in `trustless/examples/proxy.rs` starts a plain HTTP listener using the service. The real `trustless proxy start` CLI subcommand is deferred to a later spec.

## Drawbacks

- Adding `reqwest` as a dependency increases compile time and binary size. Acceptable for a dev tool.
- Per-request mtime checks add a `stat()` syscall per request. Negligible overhead for a dev proxy.

## Considered Alternatives

### WebSocket/Upgrade approach

Three approaches were considered for HTTP upgrade (WebSocket) support:

1. **hyper upgrade API** (chosen) — Uses `hyper::upgrade::on()` to extract upgraded IO from both client and backend, then `tokio::io::copy_bidirectional`. Protocol-agnostic and integrates cleanly with axum.
2. **Raw TCP splice** — Opens a raw TCP connection to backend, forwards request bytes verbatim. More manual work and bypasses HTTP parsing.
3. **axum WebSocket extractor** — Type-safe but WebSocket-specific; requires frame-level decoding/re-encoding between client and backend, adding overhead.

### Route reload strategy

- **Re-read on each request with mtime debounce** (chosen) — Simple, no file watcher dependency. Acceptable for a dev proxy.
- **File watcher with debounce** — More complex, requires `notify` crate. Overkill for this use case.
- **Periodic reload** — Introduces arbitrary latency between route changes and proxy behavior.

## Prior Art

- **Portless** ([vercel-labs/portless](https://github.com/vercel-labs/portless)) — State directory design follows Portless patterns:
  - Source available at `/home/sorah/git/github.com/vercel-labs/portless/`.
  - Routes stored as a JSON file (`routes.json`) in the state directory, containing hostname-to-port mappings with owning PIDs.
  - Stale routes cleaned up by checking whether registered PIDs are still alive.
  - Proxy reads routing information from the filesystem on-the-fly.
  - Route registration via CLI commands (`portless alias <name> <port>`).
- **Mairu** — Agent process lifecycle and state directory patterns (see `/home/sorah/git/github.com/sorah/mairu/`).

## Security Considerations

- The `trustless` hostname is reserved and never forwarded, preventing route injection that could intercept future control API traffic.
- `route add` validates hostnames to reject obviously invalid entries (reserved names, non-DNS characters).
- Backend connection error messages include the backend address in the 502 response body. This is acceptable for a development tool but should be reconsidered if the proxy is ever exposed publicly.
- File locking (`flock`) on route state prevents corruption but is advisory only — a malicious process could bypass it. Acceptable for a local dev tool.

## Mission Scope

### Out of scope

- __TLS termination.__ The proxy runs as a plain HTTP service during this mission. The example binary lives in `trustless/examples/proxy.rs`.
- __Proxy control API.__ All route state is managed via filesystem (`routes.json`). No HTTP API for route management.
- __Process lifecycle.__ No `trustless proxy start` subcommand or auto-start. Deferred to a later spec.
- __`trustless exec` integration.__ PID tracking and stale route cleanup deferred.

### Expected Outcomes

- A working reverse proxy that forwards HTTP requests based on filesystem-managed route table.
- CLI commands to manage routes (`trustless route add`, `trustless route remove`).
- WebSocket/upgrade support via hyper upgrade API.
- An example binary demonstrating the proxy on plain HTTP.

## Implementation Plan

### Dependencies

- Add `axum` for the HTTP server framework.
- Use `reqwest` for upstream-facing HTTP client. A single shared `reqwest::Client` instance is created at startup and shared across requests via axum `State`, benefiting from connection pooling and keep-alive.

### Route State File

Location: `{state_dir}/routes.json`

```json
{
  "routes": {
    "api.lo.dev.invalid": "127.0.0.1:3000",
    "web.lo.dev.invalid": "127.0.0.1:3001"
  }
}
```

Minimal hostname→backend (socket address) map. No PID tracking — stale route cleanup is deferred to the `trustless exec` spec.

The proxy caches the parsed route table in memory with the file's mtime. On each request, it checks the mtime and re-reads only when changed (debounce).

CLI commands (`route add`, `route remove`) use advisory file locking (`flock`) around read-modify-write operations to prevent corruption from concurrent invocations.

### Proxy Behavior

- Reserve `trustless` hostname for future proxy control API. Requests to this host return **503 Service Unavailable** with body "proxy control API not yet implemented" (placeholder until the control API spec).
- When no route matches the request's hostname: return **502 Bad Gateway** with a text body (following Portless behavior).
- Forward proxy headers on each request:
  - `X-Forwarded-For`: client IP address
  - `X-Forwarded-Proto`: `http` or `https` (based on the incoming connection)
  - `X-Forwarded-Host`: original `Host` header value
  - `Forwarded`: RFC 7239 standard header (in addition to X-Forwarded-* headers)
- Support HTTP connection upgrade (including WebSocket): detect `Connection: Upgrade` requests, forward the upgrade to the backend using hyper's upgrade API (`hyper::upgrade::on()`), then splice the two sides with `tokio::io::copy_bidirectional`. This approach is protocol-agnostic (works for WebSocket, SSE, etc.) and integrates cleanly with axum's hyper foundation.
- Preserve the original `Host` header when forwarding to backends (do not rewrite to the backend address).
- Strip the port from the `Host` header before matching against the route table (e.g. `api.lo.dev.invalid:8080` matches route `api.lo.dev.invalid`).
- When the backend connection fails (e.g. connection refused): return **502 Bad Gateway** with error detail in the body (e.g. "failed to connect to backend 127.0.0.1:3000: connection refused").
- When the request has no `Host` header (e.g. HTTP/1.0): return **502 Bad Gateway** (treated as no matching route).
- Log each forwarded request at `info` level: method, host, path, backend address, response status, and duration. Use `tracing` structured logging consistent with the rest of the codebase.

### Module Structure

- `trustless/src/route.rs` — `RouteTable` struct with route state file I/O and mtime-based caching.
- `trustless/src/proxy.rs` — Reverse proxy handler (axum handler functions). Exports a `proxy_router(state) -> axum::Router` builder so later specs can mount it as a fallback route.
- `trustless/src/cmd/route.rs` — CLI subcommands for `trustless route add` / `trustless route remove`.
- `trustless/examples/proxy.rs` — Example binary that starts a plain HTTP listener using the proxy service. Listens on a separate plain HTTP port (default `8080`, configurable via CLI argument), distinct from the TLS port (1443) used in later specs.

### `RouteTable` API

`RouteTable` is a clonable struct (via `Arc`) suitable for use as axum `State`. It manages the route state file with mtime-based caching.

```rust
pub struct RouteTable { /* Arc<Mutex<Inner>> holding state_dir, cached routes, cached mtime */ }

impl RouteTable {
    pub fn new(state_dir: PathBuf) -> Self;

    /// Resolve a hostname to a backend address. Re-reads the file if mtime changed.
    pub fn resolve(&self, host: &str) -> Result<Option<SocketAddr>, Error>;

    /// Add a route. Uses flock for concurrent safety. Errors if host exists (unless force=true).
    pub fn add_route(&self, host: &str, backend: SocketAddr, force: bool) -> Result<(), Error>;

    /// Remove a route. Uses flock. Errors if host does not exist.
    pub fn remove_route(&self, host: &str) -> Result<(), Error>;
}
```

### Test Plan

**Unit tests** in `trustless/src/route.rs` (`#[cfg(test)] mod tests`):

- Route file round-trip: add routes, verify file content, reload and verify resolved addresses
- Duplicate host detection: `add_route` without force errors on existing host
- Force overwrite: `add_route` with force replaces existing entry
- Remove nonexistent host errors
- Host port stripping: `resolve("api.lo.dev.invalid:8080")` matches route `api.lo.dev.invalid`
- Reserved host rejection: `add_route("trustless", ...)` errors
- Mtime caching: verify that modifying the file externally causes re-read on next `resolve()`
- File locking: concurrent add/remove operations don't corrupt the file
- Missing routes file: `resolve()` returns `None` when `routes.json` doesn't exist

**Unit tests** in `trustless/src/proxy.rs` (`#[cfg(test)] mod tests`):

- Forwarding headers: verify `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and `Forwarded` headers are set correctly
- Host header preserved on forwarded request

**Integration tests** in `trustless/tests/proxy.rs`:

- End-to-end forwarding: start the proxy and a mock backend, add a route, verify requests are forwarded and responses returned
- No-route returns 502
- Missing Host header returns 502
- Backend connection refused returns 502 with error detail
- WebSocket upgrade: verify bidirectional data flow through the proxy

## Parallel Implementation Notes

This spec is implemented in parallel with 005 (Provider Registry) and 006 (Proxy Lifecycle). A prep commit (see `tmp/before-004-005-006.md`) establishes shared foundations. Key boundaries:

- **This spec does NOT touch**: `signer.rs`, `provider.rs`, `config.rs`, `trustless-protocol/`, `examples/tls_server.rs`
- **axum** and **reqwest** are already in `Cargo.toml` from the prep commit.
- The proxy service is implemented as a standalone `tower::Service` / axum handler. It does NOT own a TLS listener — that is 006's responsibility. The example binary (`examples/proxy.rs`) runs a plain HTTP listener for testing.
- No interaction with the provider/signer layer. Route resolution is purely filesystem-based (`routes.json`).

### Files owned by this spec

| File | Action |
|------|--------|
| `trustless/src/route.rs` | NEW |
| `trustless/src/proxy.rs` | NEW |
| `trustless/src/cmd/route.rs` | NEW |
| `trustless/src/cmd/mod.rs` | add `pub mod route;` |
| `trustless/src/lib.rs` | add `pub mod route; pub mod proxy;` |
| `trustless/src/main.rs` | add `Route` subcommand |
| `trustless/examples/proxy.rs` | NEW |
| `trustless/tests/proxy.rs` | NEW |

## Current Status

Interview complete. Ready for implementation.

### Checklist

- [ ] **Dependencies** (`trustless/Cargo.toml`):
  - [ ] Add `axum`
  - [ ] Add `reqwest`
- [ ] **Route module** (`trustless/src/route.rs`):
  - [ ] `RouteTable` struct with `Arc<Mutex<Inner>>`, mtime caching
  - [ ] `resolve()`, `add_route()`, `remove_route()` methods
  - [ ] File locking (`flock`) for write operations
  - [ ] Reserved hostname validation (`trustless` rejected)
  - [ ] Basic DNS name validation
  - [ ] Host port stripping in `resolve()`
  - [ ] Unit tests (round-trip, duplicate detection, force, remove nonexistent, port stripping, reserved host, mtime caching, file locking, missing file)
- [ ] **Proxy module** (`trustless/src/proxy.rs`):
  - [ ] axum handler for HTTP request forwarding via shared `reqwest::Client`
  - [ ] `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `Forwarded` headers
  - [ ] Host header preserved on forwarded requests
  - [ ] HTTP upgrade support via `hyper::upgrade::on()` + `tokio::io::copy_bidirectional`
  - [ ] Reserved `trustless` host → 503
  - [ ] No-route / missing Host → 502
  - [ ] Backend connection failure → 502 with error detail
  - [ ] Info-level access logging (method, host, path, backend, status, duration)
  - [ ] Unit tests (forwarding headers, host preservation)
- [ ] **CLI** (`trustless/src/cmd/route.rs`):
  - [ ] `trustless route add <host> <backend>` with `--force` flag
  - [ ] `trustless route remove <host>`
  - [ ] Register subcommands in `main.rs`
- [ ] **Example** (`trustless/examples/proxy.rs`):
  - [ ] Plain HTTP listener on port 8080 (configurable via CLI arg)
  - [ ] Wires up `RouteTable` + `reqwest::Client` + axum router
- [ ] **Integration tests** (`trustless/tests/proxy.rs`):
  - [ ] End-to-end forwarding with mock backend
  - [ ] No-route → 502
  - [ ] Missing Host → 502
  - [ ] Backend refused → 502
  - [ ] WebSocket upgrade bidirectional flow
- [ ] `cargo clippy --workspace` passes

### Updates

Implementors MUST keep this section updated as they work.
