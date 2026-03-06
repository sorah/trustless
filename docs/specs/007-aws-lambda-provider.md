# 007-aws-lambda-provider

## Summary

Create a provider that uses AWS Lambda as the backend, and a function implementation that loads key material from S3. Also prepare a Terraform module to deploy the function onto AWS infrastructure.

## Motivation

To use remotely available keys stored in Amazon S3 via a Lambda function, enabling key providers to run without a persistent process on the client side.

## Explanation

### Protocols

The Lambda provider command (`trustless-provider-lambda`) communicates with the Trustless proxy over the standard stdin/stdout key provider protocol (length-delimited codec + JSON). Internally, it translates protocol messages into AWS Lambda invocations.

The Lambda function itself receives and returns bare JSON — no length-delimited framing. The event payload uses the same JSON structure as `trustless_protocol::message::Request<P>` and the response uses `trustless_protocol::message::Response<R>`. The provider command handles the translation between the two wire formats.

### AWS Lambda Provider Command

```
trustless setup -- trustless-provider-lambda --function-name <lambda-function-name>
```

Invokes a specified function name. 

The `--function-name` parameter accepts both Lambda function names and ARNs (including cross-account ARNs), as the AWS SDK's Invoke API supports both.

AWS SDK configuration (region, credentials) is loaded from the environment or default AWS config files, following the standard AWS SDK behavior. No additional flags are provided for region or credential configuration — users can use `env` command or other wrappers to set `AWS_REGION`, `AWS_DEFAULT_REGION`, etc.

### AWS Lambda Function

Takes the following environment variables:

- `TRUSTLESS_AWS_METHOD` (required): Specify what service the function should use to retrieve key material. Supported values are `"s3"` for fetching from S3. Unsupported values cause the function to fail during Lambda init (before handling requests).
- `TRUSTLESS_S3_URLS` (required): S3 URL prefixes to fetch key materials. Comma separated. Each prefix represents exactly one certificate (one `current` file per prefix). `s3://bucket/prefix/,s3://bucket2/prefix2/,...`
- `TRUSTLESS_KEY_PASSPHRASE_SSM_ARN` (optional): Parameter store ARN of passphrase for encrypted private keys, if applicable.

#### S3 object structure

S3 URLs are parsed by splitting on `://` and `/`. If a prefix does not end with `/`, one is appended automatically.

For each prefix (`{prefix}`):

1. Fetch `{prefix}current` to get the current certificate ID (e.g. `my-cert-id`), trimmed of whitespace. This value is used directly as the certificate ID in the protocol (no prefix or index added). **Note:** Certificate IDs must be unique across all S3 prefixes. If two prefixes produce the same ID, behavior is undefined
2. Fetch `{prefix}{cert-id}/fullchain.pem` to get the certificate chain in PEM format
   - Fall back to `{prefix}{cert-id}/cert.pem` if `fullchain.pem` is not found (S3 NoSuchKey)
3. Fetch `{prefix}{cert-id}/key.pem` to get the private key in PEM format
   - If `TRUSTLESS_KEY_PASSPHRASE_SSM_ARN` is set and the key is PKCS#8 encrypted (`-----BEGIN ENCRYPTED PRIVATE KEY-----`), decrypt it using the passphrase from SSM Parameter Store

The function only requires `s3:GetObject` permission on the relevant objects.

#### Caching

The Lambda function caches certificate and key material in memory (global/static state), persisting across warm invocations. The cache is lost on cold starts. The provider command itself does not cache — it is a thin relay that forwards every request to Lambda.

During `initialize`, the function fetches all certificates and keys from S3 and populates the cache. On subsequent `initialize` calls with a warm cache, the function only checks `current` objects for changes. If the current certificate ID has changed, it fetches the new certificate and key, updates the cache, and returns the updated certificate info. If unchanged, it returns the cached certificate info without additional S3 calls.

During `sign`, if the requested certificate is not in cache (e.g., after a cold start with a sign-before-initialize race), the function loads the specific key on demand and caches it.

Non-current certificates may be evicted from the cache.

The SSM passphrase (if configured) is also cached in memory on first use, protected using the `secrecy` crate. It persists for the Lambda execution environment's lifetime.

#### Signing

The Lambda function loads private keys from PEM into memory and signs locally using `rustls::crypto::aws_lc_rs`, the same approach as `trustless-provider-stub`. KMS-based signing is out of scope.

### Terraform module

Provide a Terraform module to deploy the Lambda function.

```hcl
module "trustless-function" {
    source = "github.com/sorah/trustless//trustless-provider-lambda-function/terraform"

    function_name = "my-trustless-provider"
    source_url    = "https://github.com/sorah/trustless/releases/download/v0.1.0/trustless-provider-lambda-function-x86_64.zip"
    source_sha512 = "..." # optional SHA-512 checksum

    iam_role_arn = aws_iam_role.trustless.arn

    method = "s3"
    s3 = {
      urls = ["s3://my-bucket/my-prefix/", "s3://my-bucket2/my-prefix2/"]
    }

    # architecture = "x86_64"  # default; set to "arm64" for Graviton
    # key_passphrase_ssm_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/my-passphrase"
}
```

Variables:

- `function_name` (required): Lambda function name
- `source_url` (required): URL to download the Lambda function zip package (downloaded via the `http` Terraform data source)
- `source_sha512` (optional): SHA-512 checksum of the zip file. When provided, validated using the `http` data source's postcondition
- `iam_role_arn` (required): IAM role ARN for the Lambda function. The role must have permissions for `s3:GetObject` on the relevant S3 objects, `ssm:GetParameter` on the passphrase parameter (if applicable), and Lambda basic execution (CloudWatch Logs)
- `method` (required): Key material source method (`"s3"`)
- `s3` (required when method is `"s3"`): Object with `urls` list of S3 URL prefixes
- `key_passphrase_ssm_arn` (optional): SSM Parameter Store ARN for the private key passphrase
- `architecture` (optional, default `"x86_64"`): Lambda function architecture. Set to `"arm64"` for Graviton
- `memory_size` (optional, default `256`): Lambda function memory in MB
- `timeout` (optional, default `30`): Lambda function timeout in seconds
- `environment_variables` (optional, default `{}`): Additional environment variables to set on the Lambda function. Merged with the module-managed variables (`TRUSTLESS_AWS_METHOD`, `TRUSTLESS_S3_URLS`, `TRUSTLESS_KEY_PASSPHRASE_SSM_ARN`). User-supplied values take precedence over module-managed ones on collision

The module uses the `provided.al2023` Lambda runtime. The downloaded zip is stored locally at a deterministic path derived from `sha256(source_url + source_sha512)`.

Outputs:

- `function_arn`

## Drawbacks

## Considered Alternatives

- **Caching in provider command vs Lambda function.** Caching could live in the provider command (local process) or in the Lambda function (warm invocation memory). We chose Lambda-side caching because it reduces S3 API calls across all provider command instances and aligns with the standard Lambda warm-start pattern. The provider command remains a stateless relay.

- **Terraform module creating IAM role vs requiring it.** The module could generate scoped-down IAM policies from the S3 URLs, but this adds complexity (parsing S3 URLs in HCL, handling edge cases). Requiring the user to supply `iam_role_arn` keeps the module focused on Lambda deployment and gives users full control over IAM.

- **Shared code in trustless-protocol vs duplication.** The Lambda function and provider-stub share cert loading, SAN extraction, and signing logic. We chose to extract these into `trustless-protocol` behind a feature flag rather than duplicate, since the logic is non-trivial and keeping it in sync across crates would be error-prone.

- **Cert ID from S3: bare ID vs prefixed.** Certificate IDs could include the S3 URL to guarantee uniqueness, but this would leak infrastructure details into the protocol. Using the bare `current` file content keeps IDs clean and user-controlled, with a documented requirement that IDs be unique across prefixes.

## Prior Art

- @docs/writing-key-provider.md

## Security and Privacy Considerations

- __Authorization.__ It is user's responsibility to ensure that the Lambda function is properly secured and only authorized entities can invoke it. The provider command does not implement any additional authentication or authorization mechanisms beyond what AWS Lambda provides.

## Mission Scope

### Out of scope

- __Releasing prebuilt .zip files.__ We'll prepare release engineering workflow to build the Lambda function binary, package it into a zip file, and publish it as a release asset on GitHub. But not during this mission.

### Expected Outcomes

Deliverables:

- `Cargo.toml` (workspace root): add `trustless-provider-lambda` to `members`; add `trustless-provider-lambda-function` to `exclude` (or use a separate workspace config)
- `trustless-protocol/Cargo.toml`: add `provider-helpers` feature flag with dependencies (`rustls-pki-types`, `x509-parser`, `aws-lc-rs` via rustls)
- `trustless-protocol/src/provider_helpers.rs` (or similar): shared cert loading, SAN extraction, scheme detection, and signing helpers with `thiserror`-based error type
- `trustless-provider-stub/Cargo.toml`: update to use `trustless-protocol/provider-helpers` feature
- `trustless-provider-stub/src/main.rs`: refactor to use shared helpers from `trustless-protocol`
- `trustless-provider-lambda/Cargo.toml`: new crate with `clap`, `tokio`, `aws-sdk-lambda`, `trustless-protocol`
- `trustless-provider-lambda/src/main.rs`: provider command implementation
- `trustless-provider-lambda-function/Cargo.toml`: new crate with `lambda_runtime`, `aws-sdk-s3`, `aws-sdk-ssm`, `trustless-protocol` (with `provider-helpers`), `pkcs8`, `secrecy`, `tracing`, `rustls`
- `trustless-provider-lambda-function/src/main.rs`: Lambda function implementation with S3 backend, in-memory cache, and signing
- `trustless-provider-lambda-function/terraform/main.tf`: Terraform module for Lambda deployment
- `trustless-provider-lambda-function/terraform/variables.tf`: module input variables
- `trustless-provider-lambda-function/terraform/outputs.tf`: module outputs

## Implementation Plan

### Crate Structure

- `//trustless-provider-lambda` — provider command binary crate. Implements the stdin/stdout key provider protocol, translating each request into a synchronous (`RequestResponse`) Lambda invocation via `aws-sdk-lambda`. Added to the workspace `members`.
- `//trustless-provider-lambda-function` — AWS Lambda function binary crate. Handles `initialize` and `sign` requests using S3-backed key material. Initialized with `cargo lambda new`. **Excluded from workspace default members** (requires `cargo-lambda` to build). Built separately via `cargo lambda build`.
- `//trustless-provider-lambda-function/terraform` — Terraform module to deploy the Lambda function. Uses `http` data source to download the zip, writes to a local file via `local_file` resource, and references it with `aws_lambda_function.filename`.

### Shared Code in trustless-protocol

Extract cert loading and signing helpers from `trustless-provider-stub` into `trustless-protocol` so both `trustless-provider-stub` and the Lambda function can reuse them:
- PEM parsing (fullchain + key)
- DNS SAN extraction from leaf certificate
- Supported scheme detection via `rustls::sign::SigningKey::choose_scheme`
- Signing operation (lookup cert by ID, verify scheme, sign blob)

These helpers define their own `thiserror`-based error type (e.g., `ProviderHelperError`) with `From`/`Into` conversions to `ErrorPayload` for use in `Handler` implementations.

The shared code is gated behind a `provider-helpers` feature flag in `trustless-protocol` to avoid pulling in `rustls-pki-types`, `x509-parser`, and other heavy dependencies for consumers that only need the protocol types.

### Provider Command (`trustless-provider-lambda`)

- Implements `trustless_protocol::handler::Handler` trait
- On `initialize`: serializes `Request<InitializeParams>` to JSON, invokes Lambda with `RequestResponse`, deserializes `Response<InitializeResult>` from the response payload
- On `sign`: serializes `Request<SignParams>` to JSON, invokes Lambda, deserializes `Response<SignResult>`
- Lambda invocation errors (function errors, timeouts, SDK errors) are translated into protocol `ErrorPayload` responses — the provider command does not crash on Lambda failures
- Uses `clap` for CLI with `--function-name` argument
- AWS SDK configuration loaded from environment/default config files

### Lambda Function

- Use `cargo-lambda` for build tooling
- Use `aws-sdk-s3`, `aws-sdk-ssm`, and the Rust Runtime for AWS Lambda (`lambda_runtime` crate)
- Use `pkcs8` crate for PKCS#8 encrypted private key decryption
- Use `secrecy` crate for passphrase protection in memory
- Use `rustls` (aws-lc-rs backend) for signing, same as `trustless-provider-stub`
- Use `tracing` and `tracing-subscriber` for structured logging to CloudWatch (via stdout)
  - `info`: initialize/sign requests, cache state transitions
  - `debug`: cache hits, S3 fetch details
  - `error`: S3/SSM failures, signing errors

### Default Certificate

The first URL in `TRUSTLESS_S3_URLS` determines the default certificate in the `initialize` response.

### Unit Testing

- Use the `aws-smithy-mocks` crate for mocking S3 and SSM operations.
- Test coverage should include:
  - Cold start `initialize`: fetches all certs from S3, returns correct `InitializeResult`
  - Warm `initialize`: detects unchanged `current`, skips re-fetching certs
  - Warm `initialize` with changed `current`: fetches new cert, evicts old
  - `sign`: signs with cached key, returns correct signature
  - `sign` with missing cert: returns error code 1
  - `sign` with unsupported scheme: returns error code 2
  - Encrypted key decryption with SSM passphrase
  - S3 URL parsing and normalization (trailing slash)
  - `fullchain.pem` fallback to `cert.pem`

## Current Status

Interview complete.

### Implementation Checklist

- [ ] Extract shared provider helpers into `trustless-protocol` behind `provider-helpers` feature flag
- [ ] Refactor `trustless-provider-stub` to use shared helpers
- [ ] Create `trustless-provider-lambda` crate (provider command)
- [ ] Create `trustless-provider-lambda-function` crate (Lambda function)
- [ ] Implement S3 backend with caching, PKCS#8 decryption, signing
- [ ] Implement Lambda function handler (initialize + sign)
- [ ] Implement provider command (stdin/stdout protocol ↔ Lambda invocations)
- [ ] Unit tests for Lambda function (aws-smithy-mocks)
- [ ] Unit tests for provider command
- [ ] Unit tests for shared helpers
- [ ] Create Terraform module (`main.tf`, `variables.tf`, `outputs.tf`)
- [ ] Update workspace `Cargo.toml`

### Updates

Implementors MUST keep this section updated as they work.
