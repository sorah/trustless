# Plaintext usage (`http://*.localhost:1355`)

Not every local app needs HTTPS on a registrable domain. Trustless always runs a
**plaintext HTTP listener on port 1355** and routes `*.localhost` hostnames to your apps,
with **zero trust**: no certificates, no key provider, and no changes to your system or
browser trust store.

This is the mode [Portless](https://github.com/vercel-labs/portless) originally provided.
Portless has since moved to HTTPS on port 443, which requires installing and trusting a
local CA. Trustless keeps the plaintext path as a first-class, trust-free option — and
`*.localhost` origins are still treated as
[secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
by modern browsers, so service workers, `crypto.subtle`, and similar APIs keep working.

## The `.localhost` companion route

Every `trustless run` / `trustless exec` registers a `<name>.localhost` route **in addition
to** the HTTPS domain, pointing at the same backend:

```
trustless run rails server
# -> https://my-app.dev.example.com:1443   (when a key provider is configured)
#    http://my-app.localhost:1355           (always)
```

So the plaintext URL is always reachable — even before you configure a key provider, or
while a provider is unavailable.

For a git worktree, the localhost host mirrors the HTTPS form:
`http://<worktree>.<label>.localhost:1355`.

## Fallback when HTTPS isn't available

If no wildcard domain is available (no provider configured, the provider is restarting, or
it has no usable certificate), `trustless run` / `exec` **does not fail**. It continues with
the plaintext URL, surfacing the provider diagnostic as a note:

```
$ trustless exec hello sleep 1000
trustless: error: no wildcard domains in provider 'lo' certificates (provider is restarting)
trustless: note: provider 'lo' is restarting (...)
trustless: note: run `trustless status` for details
trustless: http://hello.localhost:1355 -> localhost:43117
```

When **no provider is configured at all**, the diagnostic is suppressed and only the
plaintext URL is shown:

```
$ trustless exec hello sleep 1000
trustless: http://hello.localhost:1355 -> localhost:43117
```

## URL selection and environment variables

`trustless run` / `exec` display and export a **single** primary URL (to avoid confusion).
The chosen URL also drives the `HOST`, `TRUSTLESS_HOST`, `TRUSTLESS_PORT`, and `TRUSTLESS_URL`
environment variables:

- By default, HTTPS is primary when a domain is available; otherwise the plaintext URL is used.
- The `*.localhost` route is registered either way (so both URLs work), but only the primary
  is printed and exported.

### `run` / `exec` flags

| Flag | Env | Effect |
|------|-----|--------|
| `--prefer-cleartext-url` | `TRUSTLESS_PREFER_CLEARTEXT_URL` | Make the `http://…localhost:1355` URL the primary one (displayed and exported) even when HTTPS is available. |
| `--no-localhost` | `TRUSTLESS_NO_LOCALHOST` | Don't register the `<name>.localhost` companion route. |
| `--require-https-url` | `TRUSTLESS_REQUIRE_HTTPS_URL` | Fail instead of falling back to the plaintext URL when no HTTPS domain is available (the pre-1355 behavior). |

The three flags are **mutually exclusive**. `--require-https-url` also **implies `--no-localhost`**, since a plaintext-only companion would contradict "HTTPS or fail". If resolution naturally produces a `*.localhost` name (a provider has a matching `*.localhost` certificate) or you configure one explicitly, that name is registered as the HTTPS route itself — the companion auto-add simply deduplicates against it, so the name is still served regardless of `--require-https-url`.

Boolean environment variables accept truthy values (`1`, `true`, `yes`, `on`).

## The cleartext listener

The proxy binds the plaintext listener on `127.0.0.1:1355` by default. If the port can't be
bound (for example another process such as Portless is holding it), the proxy logs a warning
and continues HTTPS-only.

| `trustless proxy start` flag | Env | `config.json` key | Effect |
|------|-----|------|--------|
| `--no-cleartext` | `TRUSTLESS_NO_CLEARTEXT` | `"no_cleartext": true` | Disable the plaintext listener entirely. |
| `--cleartext-port <PORT>` | `TRUSTLESS_CLEARTEXT_PORT` | `"cleartext_port": <PORT>` | Override the plaintext port (default `1355`). |

The plaintext listener serves proxy traffic only; the control API (the `trustless.*` host) is
reachable over the HTTPS listener only.

`X-Forwarded-Proto` and `Forwarded` reflect the scheme of the incoming connection — `http`
for the cleartext listener, `https` for the TLS listener.

See [Routing and Running Apps](routing.md) for the rest of the routing model (domain
resolution, port allocation, route lifecycle).
