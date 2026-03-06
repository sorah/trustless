# Module Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-stub` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))
- **003: Remote Signer** — `trustless::signer` ([spec](003-remote-signer.md))
- **004: Proxy Service** — `trustless::proxy`, `trustless::route`, `trustless route` ([spec](004-proxy-service.md))
- **005: Provider Registry & Orchestration** — `trustless::provider` ([spec](005-provider-registry.md))
- **006: Proxy Lifecycle & Control API** — `trustless::control`, `trustless proxy start/stop` ([spec](006-proxy-lifecycle.md))
- **TLS server** — HTTPS listener, HTTP/2, TLS 1.2/1.3 configuration (`f701a51`)

### Wiring up 004,005,006

- `src/cmd/proxy.rs` to do:
    - Start the provider registry (005)
    - Run the proxy service (004) and the control API (006)
    - Accept TLS connections, terminate TLS using the remote signer from the provider registry

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
