# 002-config

## Summary

Configuration and state directory management for trustless. Provides XDG-compliant directory discovery, a global config file, and named profiles that store provider command lines. The `trustless setup` CLI command persists a profile so that later modules (proxy, exec) can locate the configured key provider.

## Explanation

### Profiles

A profile stores the command line used to launch a key provider. Profiles live at `{config_dir}/profiles.d/{name}.json`:

```json
{
  "command": ["cargo", "run", "-p", "trustless-provider-filesystem", "--", "--cert-dir", "/path/to/certs"]
}
```

Create or overwrite a profile with `trustless setup`:

```
trustless setup -- provider-command --flag value
trustless setup --profile myprofile -- provider-command --flag value
```

The default profile name is `default`.

### Global config

Optional global settings live at `{config_dir}/config.json`:

```json
{
  "port": 1443
}
```

- `port` (u16, default `1443`): proxy listen port (used by future modules).

When the file is absent, defaults apply.

### State directory

Reserved for future runtime state (e.g. `{state_dir}/proxy.json` for running proxy pid, port, and self-signed certificate).

### Directory resolution

Config directory (in priority order):

1. `$TRUSTLESS_CONFIG_DIR`
2. `$XDG_CONFIG_HOME/trustless`
3. `~/.config/trustless`

State directory (in priority order):

1. `$TRUSTLESS_STATE_DIR`
2. `$XDG_RUNTIME_DIR/trustless`
3. `~/.local/state/trustless/run`

## Prior Art

- Portless uses filesystem-based state management; its background proxy reads routing information on-the-fly from the filesystem. We take a similar approach.
- Mairu's `config.rs` provides a reference for XDG directory discovery in Rust.

## Implementation Plan

- `trustless::Error` — crate-level error type using `thiserror` (`Io`, `Json` variants). Internal library code uses this; `anyhow` is reserved for the CLI (`cmd`) layer.
- `trustless::config::config_dir()` / `state_dir()` — directory discovery functions.
- `trustless::config::Config` — global config struct. Holds the resolved `config_dir` path internally. Provides `load()`, `load_profile(name)`, and `save_profile(name, profile)` so that profile I/O is routed through the config and decoupled from the global `config_dir()` function.
- `trustless::config::Profile` — pure data struct (`command: Vec<String>`), no I/O methods.
- `trustless::cmd::setup` — CLI subcommand that loads `Config`, constructs a `Profile`, and saves it.

See docs/specs/breakdown.md for future modules.

## Current Status

Implemented.
