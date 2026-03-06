# Module Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-stub` ([spec](001-protocol.md))

## Remaining Modules

### 002: Config & State Directories

- XDG directory discovery (`$XDG_RUNTIME_DIR/trustless`, `~/.local/state/trustless`)
- Profile support (default profile, `--profile=NAME`)
- `trustless setup` — save provider command line to config
- Config file format (TOML or JSON in state dir)

### 003: Remote Signer (rustls integration)

- Implement `rustls::sign::SigningKey` + `rustls::sign::Signer` that delegates signing to the key provider via `ProviderClient::sign()`
- Bridge async-to-sync: `Signer::sign()` is sync but provider is async — need a blocking bridge (e.g. `tokio::runtime::Handle::block_on` or a dedicated signing thread with a channel)
- Implement `rustls::server::ResolvesServerCert` that holds all certificates from `initialize()` and resolves by SNI

### 004: TLS Proxy Server

- HTTPS listener using `tokio`, `hyper`, `rustls`
- Accept TLS connections, terminate TLS using the remote signer from 003
- Reverse-proxy HTTP requests to the backend (localhost:PORT)
- Listen on a configurable port (default `:1443`)

### 005: Proxy Lifecycle & CLI-Proxy IPC

- `trustless proxy start` — foreground proxy
- Auto-start proxy from `trustless exec` (connect-or-start pattern, ref: mairu `connect_or_start()`)
- Self-signed ephemeral cert for CLI-to-proxy HTTPS API (as described in `docs/internal.md`)
- State directory: save proxy cert, socket/port info
- Proxy reload (restart provider, re-initialize certs)

### 006: `trustless exec`

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
