# AWS Lambda Provider

The AWS Lambda provider lets you use TLS keys stored in Amazon S3 via a Lambda function, without running a persistent key server process. It consists of two components:

- **`trustless-provider-lambda`** -- a provider command that relays the key provider protocol to Lambda invocations
- **`trustless-backend-lambda`** -- the Lambda function that loads key material from S3 and performs signing

## Deploying the Lambda Function

### Prerequisites

- An S3 bucket containing your certificate and key material (see [S3 Object Structure](#s3-object-structure))
- An IAM role for the Lambda function with:
  - `s3:GetObject` on the relevant S3 objects
  - Lambda basic execution permissions (CloudWatch Logs)
  - `ssm:GetParameter` on the passphrase parameter, if using encrypted keys

### Terraform

Use the provided Terraform module:

```hcl
module "trustless_provider" {
  source = "github.com/sorah/trustless//trustless-backend-lambda/terraform"

  function_name = "my-trustless-provider"
  source_url    = "https://github.com/sorah/trustless/releases/download/trustless-provider-lambda%2Fv0.1.0/trustless-backend-lambda.arm64.zip"
  architecture  = "arm64"

  ### optional; SHA-512 of the base64-encoded zip content
  # source_sha512 = "..."
  # # curl -L "${source_url}" |base64 -w 0 |sha512sum

  iam_role_arn = aws_iam_role.trustless.arn

  method = "s3"
  s3 = {
    urls = ["s3://my-bucket/certs/"]
  }

  # memory_size  = 256        # MB, default
  # timeout      = 30         # seconds, default
  # key_passphrase_ssm_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/my-passphrase"
}
```

The module outputs `function_arn`.

#### Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `function_name` | yes | | Lambda function name |
| `source_url` | yes | | URL to download the function zip package |
| `source_sha512` | no | `null` | SHA-512 checksum of the zip (base64-encoded representation) |
| `iam_role_arn` | yes | | IAM role ARN for the function |
| `method` | yes | | Key material source method (`"s3"`) |
| `s3` | when method is `"s3"` | `null` | Object with `urls` list of S3 URL prefixes |
| `key_passphrase_ssm_arn` | no | `null` | SSM Parameter Store ARN for the key passphrase |
| `architecture` | no | `"x86_64"` | `"x86_64"` or `"arm64"` |
| `memory_size` | no | `256` | Memory in MB |
| `timeout` | no | `30` | Timeout in seconds |
| `environment_variables` | no | `{}` | Additional environment variables (merged with module-managed ones; user values take precedence) |

#### Choosing a zip package

Find a prebuilt zip package for the Lambda function from the releases page. It is attached to `trustless-provider-lambda` crate releases:

- https://github.com/sorah/trustless/releases?q=trustless-provider-lambda&expanded=true

#### IAM Role

The module requires an existing IAM role ARN. Here is an example role definition:

```hcl
resource "aws_iam_role" "trustless" {
  name                 = "trustless"
  description          = "Trustless key provider"
  assume_role_policy   = data.aws_iam_policy_document.trustless_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "trustless_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy" "lambda_basic_execution" {
  name = "AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "trustless_lambda" {
  role       = aws_iam_role.trustless.name
  policy_arn = data.aws_iam_policy.lambda_basic_execution.arn
}

resource "aws_iam_role_policy" "trustless" {
  role   = aws_iam_role.trustless.name
  policy = data.aws_iam_policy_document.trustless.json
}

data "aws_iam_policy_document" "trustless" {
  # Include this statement if using encrypted keys with SSM passphrase
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.passphrase.arn]
  }

  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/certs/*",
    ]
  }
}
```

### S3 Object Structure

Organize your certificate files under an S3 prefix. The layout is compatible with [acmesmith](https://github.com/sorah/acmesmith) S3 storage output. For each prefix (e.g. `s3://my-bucket/certs/`):

```
s3://my-bucket/certs/current           # text file containing the current cert ID, e.g. "my-cert-2026-03"
s3://my-bucket/certs/my-cert-2026-03/fullchain.pem   # certificate chain (leaf first)
s3://my-bucket/certs/my-cert-2026-03/key.pem         # private key
```

- `current` -- contains the certificate ID (whitespace-trimmed). This ID is used directly in the protocol, so it must be unique across all S3 prefixes.
- `fullchain.pem` -- PEM certificate chain. Falls back to `cert.pem` if `fullchain.pem` is not found.
- `key.pem` -- PEM private key. Supports PKCS#8 encrypted keys (`BEGIN ENCRYPTED PRIVATE KEY`) and legacy OpenSSL PEM encryption (`Proc-Type: 4,ENCRYPTED`) when a passphrase is configured via `key_passphrase_ssm_arn`.

To rotate certificates, upload the new cert/key files under a new ID directory and update the `current` file. The Lambda function detects changes on the next `initialize` call.

## Setting Up the Provider Command

### Register with Trustless

```
trustless setup -- trustless-provider-lambda --function-name my-trustless-provider
```

The `--function-name` parameter accepts Lambda function names or ARNs (including cross-account ARNs).

### AWS Credentials

The provider command uses standard AWS SDK credential resolution (environment variables, `~/.aws/config`, instance profiles, etc.). Configure `AWS_REGION` or `AWS_DEFAULT_REGION` as needed. You can wrap the command with `env` if you need to set credentials per-profile:

```
trustless setup -- env AWS_PROFILE=my-profile trustless-provider-lambda --function-name my-trustless-provider
```

### Verify

Test that the provider works:

```
trustless test-provider -- trustless-provider-lambda --function-name my-trustless-provider
```

## Authorization

**You are responsible for controlling who can invoke the Lambda function.** Anyone with `lambda:InvokeFunction` permission on the provider function can sign TLS handshakes for its domains -- effectively impersonating them.

Grant `lambda:InvokeFunction` only to developers who need local HTTPS, and revoke it when they no longer need access. This is the primary access control mechanism: revoking IAM permission immediately cuts off signing ability without needing to rotate keys or certificates.

```hcl
# Example: policy to grant developers access to the provider function
data "aws_iam_policy_document" "trustless_developer" {
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [module.trustless_provider.function_arn]
  }
}
```

## How It Works

The provider command is a stateless relay: it translates each key provider protocol message into a synchronous Lambda invocation and returns the response. All caching happens inside the Lambda function, which keeps certificate and key material in memory across warm invocations.

- On cold start, the function fetches all certificates and keys from S3.
- On warm `initialize`, it only checks `current` files for changes and re-fetches if needed.
- Signing is performed locally in the Lambda function using `rustls::crypto::aws_lc_rs`.
