# Module Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-stub` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))
- **003: Remote Signer** — `trustless::signer` ([spec](003-remote-signer.md))

### 004 Proxy Service (dispatched, parallel with 005/006)

- Implement a generic reverse proxy as axum handler functions
- State management for name-to-backend mappings and CLI tools to manipulate them (e.g. add/remove mappings)
- run as a plain HTTP service during this mission
- Exports `proxy_router(state) -> Router` for later integration with 006

### TLS server with remote signer

- HTTPS listener using `tokio`, `hyper`, `rustls`
- Enable HTTP/2
- Default to TLS 1.3 only. Enable TLS 1.2 via `Config::tls12` field.
- Accept TLS connections, terminate TLS using the remote signer
- Listen on a configurable port (default `[::1]:1443` with IPV6_V6ONLY=false)

### 005 Complete Provider registry and orchestration (dispatched, parallel with 004/006)

- Support adding provider, restarting provider
- Collect errors from provider and expose as a function
- ProviderRegistry already in provider.rs from prep commit

### 006 Proxy process lifecycle & CLI-Proxy IPC (dispatched, parallel with 004/005)

- `trustless proxy start` — start foreground proxy process
- Auto-start proxy from `trustless exec` (connect-or-start pattern, ref: mairu `connect_or_start()`)
- State directory: save proxy cert, socket/port info
- Uses axum for control API, bare ProviderRegistry (no orchestrator)

### Proxy control API

- Self-signed ephemeral cert for CLI-to-proxy HTTPS API (as described in `docs/internal.md`)
- `trustless proxy stop` — stop proxy process
- Proxy reload (restart provider, re-initialize certs)
- `trustless proxy status` — show proxy status, active mappings, provider error status

### `trustless exec`

- Assign a subdomain + suffix from a specified profile. Optinally `--domain` to specify by a suffix.
- Pick a backend port. Use ephemeral port (0) to let the OS to assign a port, then release it and use as a `$PORT`
- Register the name-to-backend mapping with the running proxy
- Exec the user command with `PORT` and `HOST` env vars
- Teardown mapping on exit. Use sidecar pattern to monitor the child process and ensure cleanup happens even if the child process is killed.
  - Follow `mairu exec` pattern

### Fill the gap with Portless

- Fancy but minimal html pages for humans
  - Error pages
  - Index of hosted pages

### Utilities

- `trustless list` to list current routes

### Release Engineering

- GitHub Actions for releasing binaries and crates to crates.io
- Mimic Mairu's workflows
