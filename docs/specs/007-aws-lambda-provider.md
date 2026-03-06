# 007-aws-lambda-provider

## Summary
<!-- 1-2 paragraph explanation -->

Create a provider that uses AWS Lambda as the backend, and a function implementation loads key from S3. Also prepare a Terraform module to deploy the function onto actual AWS infrastructures.

## Motivation
<!-- This section should explain the motivation for the proposed change. Why is it needed? What problem does it solve? What usecases? This is the most important section. this can be lengthy. -->

To use remotely available key stored in Amazon S3.

## Explanation
<!-- How we can use the proposed change when implemented? Irrustlate pseudo-code if this is an API change; include internal APIs such as models and concerns. -->
<!-- OTOH, this section should be a quick reference for consumers of the change, make it sound like a API document and get-started guide. Changes invisible to consumers, such as internal data models, must be explained in the 'Implementation Plan' section instead. -->

### Protocols

Lambda function event payload is identical to `trustless_provider::message::Request` (JSON) and its response is `trustless_provider::message::Response` types (JSON).

### AWS Lambda Provider Command

```
trustless setup -- trustless-provider-lambda --function-name <lambda-function-name>
```

Invokes a specified function name. 

AWS SDK configuration (region, credentials) is loaded from the environment or default AWS config files, following the standard AWS SDK behavior. User can use `env` command or anything else that provides the credentials using provider command line.

### AWS Lambda Function

Takes the following environment variables:

- `TRUSTLESS_AWS_METHOD` (required): Specify what service the function should use to retrieve key material. Supported values are `"s3"` for fetching from S3.
- `TRUSTLESS_S3_URLS` (required): S3 url prefixes to fetch the key materials. Comma separated. `s3://bucket/prefix/,s3://bucket2/prefix2/,...`
- `TRUSTLESS_KEY_PASSPHRASE_SSM_ARN` (optional): Parameter store ARN of passphrase for encrypted private keys, if applicable.

#### S3 object structure

_Assume `{prefix}` ends with a slash (`/`)_

1. Lookup `{prefix}current` to get the current certificate ID (e.g. `my-cert-id`)
2. Lookup `{prefix}{cert-id}/fullchain.pem` to get the certificate chain in PEM format
   - fallback to `{prefix}{cert-id}/cert.pem` if `fullchain.pem` is not found
3. Lookup `{prefix}{cert-id}/key.pem` to get the private key in PEM format
   - Decrypt the key using the passphrase from SSM if `TRUSTLESS_KEY_PASSPHRASE_SSM_ARN` is set and the key is encrypted

During the operation, the function should only use `s3:GetObject` call.

#### Caching

To reduce latency, the provider command implements caching. During `initialize`, the provider fetches and caches all certificates and keys from the source to reduce API calls during TLS handshakes. `sign` calls may load specific keys on demand if not already cached, then store them in the cache.

During `initialize` called with hot cache, the provider function should  only check `current` objects for changes. If the current certificate ID has changed, it should fetch the new certificate and key, update the cache, and return the new certificate info in the response. If the current certificate ID is unchanged, it can skip fetching the certificates and keys and return the existing cached certificate info.

Non-current certificates can be evicted.

### Terraform module

Provide a Terraform module to deploy the Lambda function.

```
module "trustless-function" {
    source = "github.com/sorah/trustless//trustless-provider-lambda-function/terraform"

    function_name = "my-trustless-provider"
    source_url = "https://github.com/sorah/trustless/releases/download/v0.1.0/trustless-provider-lambda-function.zip"
    source_sha512 = "..." # sha512 checksum of the zip file

    method = "s3"
    s3 = {
      urls = ["s3://my-bucket/my-prefix/", "s3://my-bucket2/my-prefix2/"]
    }

    key_passphrase_ssm_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/my-passphrase"

    # iam_role_arn = "..." # optional, if set, skip role creation
}
```

Outputs:

- `function_arn`

## Drawbacks
<!-- Why should we not do this? -->

## Considered Alternatives
<!-- Why is this design the best in the space of possible designs? What other designs have been considered and what is the rationale for not choosing them? What is the impact of not doing this? -->
<!-- if any. Authors can omit this section if we don't have alternative consideration, when completing the spec. Otherwise design decisions must be logged in this section. -->

## Prior Art
<!-- if any. we can refer to external projects if needed.-->

- @docs/writing-key-provider.md

## Security and Privacy Considerations
<!-- if any. -->

- __Authorization.__ It is user's responsibility to ensure that the Lambda function is properly secured and only authorized entities can invoke it. The provider command does not implement any additional authentication or authorization mechanisms beyond what AWS Lambda provides.

## Mission Scope

### Out of scope

- __Releasing prebuilt .zip files.__ We'll prepare release engineering workflow to build the Lambda function binary, package it into a zip file, and publish it as a release asset on GitHub. But not during this mission.

### Expected Outcomes

## Implementation Plan
<!-- Detailed explanation of actual data models, code changes that is not visible to consumers of the change. Consumer-facing guides should go into 'Explanation' section instead. -->

- `//trustless-provider-lambda` crate for the provider command implementation
- `//trustless-provider-lambda-function` for the AWS Lambda function implementation
  -  initialize with `cargo lambda new` and add to workspace
- `//trustless-provider-lambda-function/terraform` directory for the Terraform module to deploy the function

### Lambda Function

- Use `cargo-lambda` subcommand
- Use `aws-sdk-s3`, `aws-sdk-ssm` crates and _Rust Runtime for AWS Lambda_ crates.
    - https://github.com/aws/aws-lambda-rust-runtime/raw/refs/heads/main/README.md

### Unit testing

- Add adequate unit tests with mocked AWS SDK operations.

## Current Status
