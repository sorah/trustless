# Task Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-filesystem` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))
- **003: Remote Signer** — `trustless::signer` ([spec](003-remote-signer.md))
- **004: Proxy Service** — `trustless::proxy`, `trustless::route`, `trustless route` ([spec](004-proxy-service.md))
- **005: Provider Registry & Orchestration** — `trustless::provider` ([spec](005-provider-registry.md))
- **006: Proxy Lifecycle & Control API** — `trustless::control`, `trustless proxy start/stop` ([spec](006-proxy-lifecycle.md))
- **TLS server** — HTTPS listener, HTTP/2, TLS 1.2/1.3 configuration (`f701a51`)
- **Proxy control API** — `GET /ping`, `POST /stop`, `POST /reload`, `GET /status`
- **`trustless exec`** — explicit subdomain, fork+sidecar, IPC, route guard
- **`trustless run`** — auto-infer subdomain (`.trustless.json`, `package.json`, git root, cwd)
- **Git worktree detection** — CLI + filesystem fallback, branch prefix, default branch skip
- **Framework injection** — Vite, React Router, Astro, Angular, React Native, Expo
- **`TRUSTLESS=0`/`TRUSTLESS=skip`** — bypass proxy entirely
- **`TRUSTLESS_URL` env var** — set on exec/run
- **AWS Lambda provider** — `trustless-backend-lambda`
- **GitHub Actions** — releasing binaries and crates to crates.io

### Portless Feature Parity

Our respected prior art, Portless, is checked out at `/home/sorah/git/github.com/vercel-labs/portless` and can be used as a reference for filling the gap in features and quality.

#### Feature comparison (Portless → Trustless)

At parity:
- Proxy routing (exact + wildcard subdomain) — done (SNI + Host header routing)
- Port auto-assignment (ephemeral) — done
- HTTP proxy with `X-Forwarded-*` headers — done (`X-Forwarded-For/Proto/Host`, `Forwarded`, `Via`)
- WebSocket upgrade support — done
- Loop detection (`X-Portless-Hops`, max 5) — done (`X-Trustless-Hops`, max 5)
- Hop-by-hop header stripping (RFC 7230) — done
- HTTP/2 + TLS — done (TLS 1.3 default, optional TLS 1.2)
- Framework flag injection — done (same frameworks: Vite, React Router, Astro, Angular, React Native, Expo)
- `PORTLESS=0`/`PORTLESS=skip` bypass — done (`TRUSTLESS=0`/`TRUSTLESS=skip`)
- `PORTLESS_URL` env var — done (`TRUSTLESS_URL`)
- Auto-start proxy on run/exec — done (daemon auto-start)
- Git worktree branch prefix — done
- Project name auto-detection — done (`.trustless.json`, `package.json`, git root, cwd)
- `portless run` (auto-infer name) — done (`trustless run`)
- `portless <name> <cmd>` (explicit name) — done (`trustless exec <name> <cmd>`)
- Provider orchestration + crash recovery — done (exponential backoff, SIGTERM/SIGKILL)
- File-based route storage with locking — done
- Control API — done
- `portless proxy start/stop` — done (`trustless proxy start/stop/reload`)
- Graceful shutdown with drain — done (30s timeout)

Partial or not yet implemented:
- `portless list` (show active routes) — partial (`trustless status` shows routes)
- `portless get <name>` (print URL for service) — done (`trustless get <name>`)
- `portless alias <name> <port>` (static route) — partial (`trustless route add/remove` exists)
- Styled HTML error pages (404, 502, 508) — **not implemented** (plain text only)
- 404 page showing active routes as index — **not implemented**
- Dark mode CSS for error pages — **not implemented**
- Colored / formatted CLI output — **not implemented** (no color crate)

N/A by design (Trustless uses remote signing with real domains instead of local CA + `.localhost`):
- Named `.localhost` URLs — uses registrable domains (`*.dev.example.com`) instead
- `portless trust` (add CA to system trust store)
- `portless hosts sync/clean` (`/etc/hosts` management)
- Local CA + per-hostname cert generation (SNI callback)

#### Remaining work

##### README

- README that sounds fancy

### Release Engineering

- Mimic Mairu's workflows

## Misc quality

- cleanup meaningless tests
- status must show routes first, providers later
- hardening: limit blob, log blob
- secrecy on Message structs
- plain http `*.localhost` support
