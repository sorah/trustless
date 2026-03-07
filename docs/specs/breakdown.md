# Task Breakdown

## Done

- **001: Protocol & Stub Provider** — `trustless-protocol`, `trustless-provider-filesystem` ([spec](001-protocol.md))
- **002: Config & State Directories** — `trustless::config`, `trustless setup` ([spec](002-config.md))
- **003: Remote Signer** — `trustless::signer` ([spec](003-remote-signer.md))
- **004: Proxy Service** — `trustless::proxy`, `trustless::route`, `trustless route` ([spec](004-proxy-service.md))
- **005: Provider Registry & Orchestration** — `trustless::provider` ([spec](005-provider-registry.md))
- **006: Proxy Lifecycle & Control API** — `trustless::control`, `trustless proxy start/stop` ([spec](006-proxy-lifecycle.md))
- **TLS server** — HTTPS listener, HTTP/2, TLS 1.2/1.3 configuration (`f701a51`)
- **Proxy control API**
- **`trustless exec`**
- **AWS Lambda provider**
- **GitHub Actions for releasing binaries and crates to crates.io**
- `trustless run`

### Fill the gap with Portless

Our respected prior art, Portless, is checked out at `/home/sorah/git/github.com/vercel-labs/portless` and can be used as a reference for filling the gap in features and quality.

#### Error responses & pages

- Error response body should end with `\n`
- Fancy but minimal HTML pages for humans (detect `Accept: text/html`)
  - Error pages (502 Bad Gateway, 508 Loop Detected) with troubleshooting hints
  - 404 / unknown-host page showing active routes as an index
  - Dark mode, minimal styling (no external assets)

#### CLI UX

- `trustless run` — auto-determine subdomain name, like `trustless exec` but without explicit name
  - Git worktree branch prefix (compose as `<branch>.<project>`):
    - Only when `git worktree list --porcelain` shows >1 worktree; fallback: detect `.git` file with `gitdir:` pointing to `/worktrees/` (rejects `/modules/` submodules)
    - Skip prefixing for default branches (`main`, `master`) and detached HEAD
    - For slashed branch names, use only the last segment (`feature/auth` → `auth`)
    - Sanitise the branch segment with the same rules as project name
- Colored / formatted CLI output (errors in red, URLs highlighted, etc.)
- `trustless status` — show routes first, providers second (see Misc quality)

#### Exec / run behaviour

- [x] `TRUSTLESS=0` / `TRUSTLESS=skip` — bypass proxy entirely, exec command directly without setting `PORT`/`HOST` or registering routes (useful for CI)
- [x] Framework injection
- Set a `TRUSTLESS_URL` env var with the full public URL (e.g. `https://api.dev.example.com:1443`)

#### README

- README that sounds fancy

### Release Engineering

- Mimic Mairu's workflows

## Misc quality

- cleanup meaningless tests
- status must show routes first, providers later
- hardening: limit blob
- secrecy on Message structs
- [x] rename provider-lambda-function to backend-lambda
- rename provider-filesystem to provider-filesystem
- worktree detection
  - `{{name}}--{{label}}`
- `trustless get`
- plain http `*.localhost` support

