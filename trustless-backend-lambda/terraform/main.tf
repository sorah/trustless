locals {
  source_hash = sha256("${var.source_url}${var.source_sha512}")

  module_env_vars = merge(
    {
      TRUSTLESS_AWS_METHOD = var.method
    },
    var.method == "s3" && var.s3 != null ? {
      TRUSTLESS_S3_URLS = join(",", var.s3.urls)
    } : {},
    var.key_passphrase_ssm_arn != null ? {
      TRUSTLESS_KEY_PASSPHRASE_SSM_ARN = var.key_passphrase_ssm_arn
    } : {},
  )
}

data "http" "source" {
  url = var.source_url

  lifecycle {
    postcondition {
      condition     = var.source_sha512 == null || sha512(self.response_body_base64) == var.source_sha512
      error_message = "SHA-512 checksum mismatch for source zip"
    }
  }
}

resource "local_file" "source" {
  filename       = "${path.module}/.terraform/source-${local.source_hash}.zip"
  content_base64 = sensitive(data.http.source.response_body_base64)
}

resource "aws_lambda_function" "this" {
  function_name    = var.function_name
  filename         = local_file.source.filename
  source_code_hash = local_file.source.content_sha256

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = [var.architecture]
  role          = var.iam_role_arn
  memory_size   = var.memory_size
  timeout       = var.timeout

  environment {
    variables = merge(local.module_env_vars, var.environment_variables)
  }
}
