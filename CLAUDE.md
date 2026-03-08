# Trustless

HTTPS on registrable domains for local development, without touching system trust stores. Inspired by [Portless](https://github.com/vercel-labs/portless).

A local TLS-terminating proxy that delegates signing to an external key provider (e.g. AWS Lambda + S3), so developers get HTTPS on real wildcard domains (`*.dev.example.com`) without distributing private keys or installing local CAs.

## Architecture

- **Key provider protocol**: providers are child processes communicating via length-delimited JSON over stdin/stdout. They hold certificates and sign TLS handshakes on request, but never export private keys.
- **Proxy**: `tokio` + `rustls` + `axum`. TLS termination via `LazyConfigAcceptor` (per-connection SNI resolution), HTTP forwarding via `reqwest`, WebSocket upgrade via raw hyper.
- **Remote signing bridge**: async provider calls bridged into rustls's sync `Signer::sign()` via `mpsc` + `oneshot` channels with `block_in_place`.
- **Provider lifecycle**: `ProviderProcess` → `Supervisor` (crash recovery, exponential backoff) → `ProviderOrchestrator` (multi-provider management).
- **`trustless exec`/`run`**: fork+sidecar pattern (from [mairu](https://github.com/sorah/mairu)). Sidecar registers route, parent execs user command with `PORT`/`HOST` env vars.

See `docs/internal.md` for full details.

## Project Status

Core features are complete and at Portless feature parity. Remaining work (`docs/specs/breakdown.md`):
- HTML error pages (502, 508, 404-with-route-index, dark mode)
- Colored CLI output
- `trustless get <name>` (print URL for a service)
- Plain HTTP `*.localhost` support
- Misc quality (cleanup tests, status ordering, secrecy on Message structs)

## Workspace Crates

- **`trustless`** — CLI (`clap`) and proxy server. `src/cmd/` for CLI commands, `src/proxy.rs` for HTTP forwarding, `src/provider/` for provider lifecycle, `src/signer.rs` for remote signing bridge, `src/control/` for control API, `src/route.rs` for route table.
- **`trustless-protocol`** — Protocol types, codec (length-delimited JSON), handler trait, client, and `provider_helpers` for building providers easily.
- **`trustless-provider-filesystem`** — Reference provider backed by static cert files on disk. Use `/home/sorah/tmp/lo` for example certificate directory.
- **`trustless-provider-lambda`** — Provider CLI that delegates to an AWS Lambda function.
- **`trustless-backend-lambda`** — The Lambda function itself (the server-side backend for `trustless-provider-lambda`).

## Rust Coding Guidelines

- Always refer to `/sorah-guides:rust` skill.
- Unit tests in the same file (`#[cfg(test)] mod tests { ... }`), integration tests in `tests/`.
- `thiserror` for library error types, `anyhow` only in CLI context (`src/main.rs`, `src/cmd/*`, `src/examples/*`).
- Prior art for process management and coding style: `/home/sorah/git/github.com/sorah/mairu`

## Referencing library code

Refer to `~/.cargo/registry/src/` to look up dependency internals and docs.
