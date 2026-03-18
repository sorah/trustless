# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1](https://github.com/sorah/trustless/compare/trustless-protocol/v0.2.0...trustless-protocol/v0.2.1) - 2026-03-18

### Other

- [workspace.package] metadata

## [0.2.0](https://github.com/sorah/trustless/compare/trustless-protocol/v0.1.0...trustless-protocol/v0.2.0) - 2026-03-08

### Fixed

- fix clippy warnings in provider_helpers

### Other

- use valid TLS 1.3 blobs in downstream crate tests
- validate sign blob is TLS 1.3 server CertificateVerify
- introduce SecretBox<Base64Bytes> for sign blob and signature
- promote to thiserror error enum with messages
- rename trustless-provider-stub → trustless-provider-filesystem
- extract CertificateSource + CachingBackend into trustless-protocol

## [0.1.0](https://github.com/sorah/trustless/releases/tag/trustless-protocol/v0.1.0) - 2026-03-07

### Other

- workspace deps
- add construction helpers
- replace custom Serialize/Deserialize with derived impls
- add lambda provider
- introduce symmetric Request<P>/Response<R> with typetag dispatch
- rewrite docs & add trustless-protocol doc comments
- remove top-level `use` for structs and enums
- ban serde_json::Value, use typed structs in tests
- reduce dependency footprint
- introduce provider orchestrator with process supervision
- introduce remote signer with security hardening
- introduce key provider protocol and stub provider
