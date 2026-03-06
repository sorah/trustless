variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "source_url" {
  type        = string
  description = "URL to download the Lambda function zip package"
}

variable "source_sha512" {
  type        = string
  description = "SHA-512 checksum of the zip file. When provided, validated via postcondition"
  default     = null
}

variable "iam_role_arn" {
  type        = string
  description = "IAM role ARN for the Lambda function"
}

variable "method" {
  type        = string
  description = "Key material source method (e.g. 's3')"
}

variable "s3" {
  type = object({
    urls = list(string)
  })
  description = "S3 configuration: list of S3 URL prefixes for key material"
  default     = null
}

variable "key_passphrase_ssm_arn" {
  type        = string
  description = "SSM Parameter Store ARN for the private key passphrase"
  default     = null
}

variable "architecture" {
  type        = string
  description = "Lambda function architecture"
  default     = "x86_64"
}

variable "memory_size" {
  type        = number
  description = "Lambda function memory in MB"
  default     = 256
}

variable "timeout" {
  type        = number
  description = "Lambda function timeout in seconds"
  default     = 30
}

variable "environment_variables" {
  type        = map(string)
  description = "Additional environment variables. Merged with module-managed variables; user values take precedence on collision"
  default     = {}
}
