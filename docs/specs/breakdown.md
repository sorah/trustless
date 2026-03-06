# Module Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-stub` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))

## Remaining Modules

### 003: Remote Signer (rustls integration)

- Implement `rustls::sign::SigningKey` + `rustls::sign::Signer` that delegates signing to the key provider via `ProviderClient::sign()`
- Bridge async-to-sync: `Signer::sign()` is sync but provider is async — need a blocking bridge (e.g. `tokio::runtime::Handle::block_on` or a dedicated signing thread with a channel)
- Implement `rustls::server::ResolvesServerCert` that holds all certificates from `initialize()` and resolves by SNI

### TLS server with remote signer

- HTTPS listener using `tokio`, `hyper`, `rustls`
- Accept TLS connections, terminate TLS using the remote signer from 003
- Reverse-proxy HTTP requests to the backend (localhost:PORT)
- Listen on a configurable port (default `:1443`)

### Proxy Service

- Implement reverse proxy as a `tower::Service`
- State management for name-to-backend mappings and CLI tools to manipulate them (e.g. add/remove mappings)
- run as a plain HTTP service during this mission

### Complete Provider registy and orchestration

- Support adding provider, restarting provider
- Collect errors from provider and expose as a function

### Proxy process lifecycle & CLI-Proxy IPC

- `trustless proxy start` — start foreground proxy process
- Auto-start proxy from `trustless exec` (connect-or-start pattern, ref: mairu `connect_or_start()`)
- State directory: save proxy cert, socket/port info

### Proxy control API

- Self-signed ephemeral cert for CLI-to-proxy HTTPS API (as described in `docs/internal.md`)
- `trustless proxy stop` — stop proxy process
- Proxy reload (restart provider, re-initialize certs)
- `trustless proxy status` — show proxy status, active mappings, provider error status

### `trustless exec`

- Assign a subdomain from available domains
- Pick a random backend port
- Register the name-to-backend mapping with the running proxy
- Spawn the user command with `PORT` and `HOST` env vars
- Teardown mapping on exit

## Implementation Order

```
002  Config & State Dirs          (foundation for everything)
003  Remote Signer                (core TLS integration — the hard part)
004  TLS Proxy Server             (needs 003)
005  Proxy Lifecycle & IPC        (needs 004)
006  `trustless exec`             (needs 005)
```

003 is the most technically interesting — bridging rustls's sync `Signer::sign()` to the async provider protocol.
