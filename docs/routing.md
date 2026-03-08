# Routing and Running Apps

Trustless gives each local dev server a stable HTTPS URL on a registrable domain. When you start an app with `trustless run` or `trustless exec`, a sidecar process allocates a local port, registers a route with the proxy, and exec's your command with `PORT` and `HOST` environment variables set.

## `trustless run` vs `trustless exec`

| | `trustless run` | `trustless exec` |
|---|---|---|
| **Usage** | `trustless run <command...>` | `trustless exec <subdomain> <command...>` |
| **Subdomain** | Inferred from project context | Explicit positional argument |
| **Use case** | Day-to-day development | When you need a specific subdomain, or run multiple services from the same directory |

Both commands share the same underlying machinery: fork a sidecar, connect to (or auto-start) the proxy, register a route, and exec the command. The only difference is how the subdomain is determined.

## Subdomain inference (`trustless run`)

`trustless run` walks through the following sources in order and uses the first match:

### 1. `.trustless.json` (highest priority)

Searched in the current directory, then each parent directory up to the filesystem boundary (does not cross mount points).

Two forms are supported:

**Label** -- combined with the provider's wildcard domain:

```json
{"name": "my-app"}
```

Result: `my-app.dev.example.com` (assuming the provider serves `*.dev.example.com`).

**Full domain** -- used as-is, bypassing domain resolution entirely:

```json
{"domain": "my-app.dev.example.com"}
```

Result: `my-app.dev.example.com`. The hostname is validated but no wildcard matching is performed. This is useful when the provider has multiple wildcard domains and you want to pin a specific one, or when you want a hostname that doesn't follow the `<label>.<wildcard>` pattern.

When both `domain` and `name` are present, `domain` takes precedence.

### 2. `package.json` `name` field

Searched the same way (current directory, then parents). The `name` value is used as a label. If the name is scoped (`@scope/my-app`), the scope prefix is stripped, yielding `my-app`.

### 3. Git repository root directory name

Determined via `git rev-parse --show-toplevel`, falling back to walking parent directories for a `.git` directory. The basename of the root is used as a label.

### 4. Current directory name

The basename of the working directory is used as a last resort.

### Label sanitization

All labels from sources 2–4 (and `name` in `.trustless.json`) are sanitized to valid DNS labels:

- Lowercased
- Non-alphanumeric characters (underscores, spaces, dots, etc.) replaced with hyphens
- Consecutive hyphens collapsed
- Leading and trailing hyphens trimmed

If sanitization produces an empty string, that source is skipped and the next one is tried.

Labels from `.trustless.json` `name` are used verbatim (not sanitized) -- you are expected to provide a valid DNS label.

### Worktree-aware hostname composition

When the current directory is inside a git worktree (a multi-worktree setup on a non-default branch), `trustless run` incorporates the branch name into the hostname to distinguish worktree checkouts from each other.

**Detection**: Trustless checks for multiple worktrees via `git worktree list`, falling back to parsing the `.git` file and gitdir's HEAD when the git CLI is unavailable. Default branches (`main`, `master`) and detached HEAD are skipped — no worktree prefix is added.

**Branch → prefix conversion**: Only the last segment after `/` is used (`feature/auth` → `auth`), then sanitized to a valid DNS label.

**Hostname forms** (in order of preference):

1. **Dot-separated** `{branch}.{project}.{suffix}` — used when a matching nested wildcard certificate exists. For example, with `*.myapp.dev.example.com`, branch `auth` and project `myapp` produces `auth.myapp.dev.example.com`.

2. **Single-label fallback** `{project}--{branch}.{suffix}` — used when only a flat wildcard like `*.dev.example.com` is available. The same example produces `myapp--auth.dev.example.com`.

This feature only applies to `trustless run` (where the subdomain is inferred). `trustless exec` always uses the explicitly provided subdomain.

## Domain resolution

Once a subdomain label is determined (by either `run` or `exec`), it needs to be combined with a wildcard domain from the provider's certificate. This is where `--profile` and `--domain` come in.

### Provider selection (`--profile`)

If the proxy has a single provider, it is used automatically. With multiple providers, the first provider is used by default; use `--profile` to choose a different one:

```bash
trustless run --profile=prod-certs rails server
trustless exec --profile=prod-certs api rails server
```

The profile can also be set via the `TRUSTLESS_PROFILE` environment variable.

### Domain selection (`--domain`)

If the selected provider's certificate covers a single wildcard domain (e.g. `*.dev.example.com`), it is used automatically. When a certificate covers multiple wildcard domains, you must pick one:

```bash
trustless run --domain=staging.example.com rails server
trustless exec --domain=staging.example.com api rails server
```

### Resolution rules

1. **One provider, one wildcard** -- everything is automatic: `trustless run rails server` → `<label>.dev.example.com`
2. **Multiple providers** -- `--profile` required (or `TRUSTLESS_PROFILE`)
3. **Multiple wildcard domains on the selected provider** -- when the subdomain contains multiple labels (e.g. `branch.myapp` from worktree detection), the best-matching wildcard is auto-selected by label overlap. A suffix whose leading labels match trailing labels of the subdomain is preferred. When no unambiguous match exists, `--domain` is required.
4. **No wildcard domains** -- error (non-wildcard certificates can't generate subdomain hostnames)

These rules apply identically to both `run` and `exec`.

## Port allocation

By default, an ephemeral port is allocated by binding to `127.0.0.1:0` and reading back the assigned port. The port is released before exec'ing the command, so the app can bind to it.

Use `--port` to override:

```bash
trustless run --port=3000 rails server
trustless exec --port=3000 api rails server
```

## Environment variables

The exec'd command receives:

| Variable | Value | Example |
|---|---|---|
| `PORT` | Local port the app should listen on | `4123` |
| `HOST` | Hostname registered with the proxy | `my-app.dev.example.com` |
| `TRUSTLESS_HOST` | Same as `HOST` | `my-app.dev.example.com` |
| `TRUSTLESS_PORT` | Proxy listen port | `1443` |

The app should listen on `127.0.0.1:$PORT`. The browser URL is `https://$HOST:$TRUSTLESS_PORT`.

## Route lifecycle

Routes are stored in `$STATE_DIR/routes.json` and protected by advisory file locks. When the exec'd command exits, the sidecar process removes the route automatically. If the sidecar is killed (e.g. `kill -9`), stale routes may remain until the next `trustless run` or `exec` for the same hostname overwrites them (routes are registered with `force` when created by exec/run).

You can also manage routes manually:

```bash
trustless route add my-app.dev.example.com 127.0.0.1:3000
trustless route remove my-app.dev.example.com
```

## Static routes

`trustless route add` registers a route without starting a command. This is useful for services that manage their own lifecycle (e.g. Docker containers, background daemons):

```bash
trustless route add my-db.dev.example.com 127.0.0.1:5432
```

Static routes persist until explicitly removed with `trustless route remove` or until the proxy restarts (routes.json is ephemeral state).
