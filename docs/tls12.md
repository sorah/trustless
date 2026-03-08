# TLS 1.2 Support

Trustless supports TLS 1.2 but it is **disabled by default**. TLS 1.3 is strongly preferred.

## Enabling TLS 1.2

Enable on the proxy with the `--tls12` flag or the `tls12` config option:

```bash
trustless proxy start --tls12
```

```json
{"tls12": true}
```

## Blob Check Interaction

When TLS 1.2 is enabled, you must also disable the provider blob check by setting `TRUSTLESS_DISABLE_BLOB_CHECK_TLS=1` on the provider process. The blob check only accepts TLS 1.3 CertificateVerify messages and will reject TLS 1.2 ServerKeyExchange blobs.

For providers launched via Trustless config, set the environment variable in the provider command's environment. For `trustless-backend-lambda`, set it on the Lambda function's environment.

### Why the blob check rejects TLS 1.2

TLS 1.3 CertificateVerify has a well-defined structure (64-byte `0x20` padding + context string + hash) that can be validated cheaply. TLS 1.2 ServerKeyExchange blobs (`client_random` + `server_random` + ECDH params) have no fixed prefix and cannot be reliably distinguished from arbitrary data without parsing the variable-length ECDH parameters.

Rather than accept all blobs when TLS 1.2 might be in use, the check conservatively rejects anything that doesn't match TLS 1.3. Operators who enable TLS 1.2 explicitly opt out of this check.

## Why TLS 1.3 Only by Default

- TLS 1.3 has a simpler, more secure handshake
- The blob check provides defense-in-depth validation that the provider only signs legitimate TLS handshake data
- All modern browsers and HTTP clients support TLS 1.3
- For local development (Trustless's primary use case), there is rarely a need for TLS 1.2 compatibility
