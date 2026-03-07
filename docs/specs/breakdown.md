# Task Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-stub` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))
- **003: Remote Signer** — `trustless::signer` ([spec](003-remote-signer.md))
- **004: Proxy Service** — `trustless::proxy`, `trustless::route`, `trustless route` ([spec](004-proxy-service.md))
- **005: Provider Registry & Orchestration** — `trustless::provider` ([spec](005-provider-registry.md))
- **006: Proxy Lifecycle & Control API** — `trustless::control`, `trustless proxy start/stop` ([spec](006-proxy-lifecycle.md))
- **TLS server** — HTTPS listener, HTTP/2, TLS 1.2/1.3 configuration (`f701a51`)
- **Proxy control API**
- **`trustless exec`**
- **AWS Lambda provider**

### Fill the gap with Portless

- Error response should end with `\n`
- Fancy but minimal html pages for humans
  - Error pages
  - Index of hosted pages
- Find other feature parity
  - `trustless run` to auto-determine subdomain name
- README that sounds fancy

### Release Engineering

- GitHub Actions for releasing binaries and crates to crates.io
- Mimic Mairu's workflows

## Misc quality

- cleanup meaningless tests
- status must show routes first, providers later
