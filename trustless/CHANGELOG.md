# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
