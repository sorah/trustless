See docs/internals.md for internal details

## We're at early development stage

- Mimic `portless` behaviour but keep things minimal

## Rust coding guideline

- Always refer to `/sorah-guides:rust` skill.
- Always write unit tests in the same file `#[cfg(test)] mod tests { ... }` style, and integration tests in `tests/` directory.

### Errors

- Use of `anyhow` is discouraged outside of command-line interface context, especially `src/main.rs`, `src/examples/*`, `src/bin/*`, and `src/cmd/*` files.
- Choose `thiserror` for defining error types in library code, and use `anyhow` for error handling in CLI code.

### Prior Art for launching proxy and Sorah's rust coding style

`/home/sorah/git/github.com/sorah/mairu` has a certain example how we can run an agent process automatically and in background, plus looking up state and configuration directory.

## Crates

- `trustless` for CLI and proxy server
- `trustless-protocol` for protocol utilities
- `trustless-provider-filesystem` for testing and example key provider implementation. Refer to given static certificate directory for looking up keys
  - Use `/home/sorah/tmp/lo` for example certificate registry directory.

## Referencing library code

Refer to ~/.cargo/registry/src/ if you want to look up actual dependencies internal and documents


