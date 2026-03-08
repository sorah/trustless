# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/sorah/trustless/compare/trustless/v0.1.0...trustless/v0.2.0) - 2026-03-08

### Other

- capture stderr snapshot on errors
- record sign errors in provider error ring buffer
- rename ControlApiNotImplemented to ReservedHostname
- add Server: trustless response header
- HTML status page on trustless.* hostnames
- silently pick first wildcard domain instead of erroring
- add `trustless get <name>`
- introduce named route entries
- show only last error, --all-errors for full history
- restart all providers to bypass backoff
- silently pick first provider when --profile omitted
- add `s` and `l` aliases for status and list
- styled HTML error pages
- styled output with owo-colors
- improve provider-down UX in status and exec
- setsid to detach from tty
- `trustless list` subcommand
- worktree-aware hostname composition
- auto-select wildcard domain by label overlap
- rename trustless-provider-stub → trustless-provider-filesystem
- extract domain.rs, rename wildcard_domain → domain_suffix
- introduce framework detection and flag injection
- support TRUSTLESS=0/skip to bypass proxy in exec and run
- introduce `trustless run` subcommand

## [0.1.0](https://github.com/sorah/trustless/releases/tag/trustless/v0.1.0) - 2026-03-07

### Fixed

- fix X-Forwarded-Proto to report https
- fix test tmpdir lifetime to avoid shared directory pollution

### Other

- workspace deps
- sync provider set with config
- proxy start: tolerate provider startup failures
- extract host from URI authority for HTTP/2
- add tracing to proxy runtime gaps
- validate provider responds to initialize before saving profile
- signer test: auto-build trustless-provider-filesystem
- remove top-level `use` for structs and enums
- use aws-lc-rs instead of ring for rustls
- reduce dependency footprint
- credit mairu as origin of ppid and exec patterns
- introduce `trustless exec` subcommand
- add test-provider subcommand for validating key providers
- add status/reload endpoints with typed API response structs
- replace SigningThread with tokio task
- use LazyConfigAcceptor for TLS
- align launch pattern with mairu's agent
- use hyper_util GracefulShutdown
- wire it up
- enable HTTP/2 and restrict TLS versions
- Merge branch 'worktree-004-proxy-service'
- extract ProxyError, simplify route utilities
- introduce HTTP proxy with route management
- prep for parallel 004/005/006: extract ProviderRegistry to provider module
- introduce remote signer with security hardening
- introduce config & state directories, setup command
- introduce key provider protocol and stub provider
