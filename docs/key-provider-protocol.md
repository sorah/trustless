# Trustless Key Provider Protocol

Trustless connects to a specified key provider by running a command line specified by user, and communicates via stdin/stdout in [length delimited codec](https://docs.rs/tokio-util/latest/tokio_util/codec/length_delimited/index.html) with JSON payload. Key provider commands are spawned by the Trustless proxy, and maintained as long as the proxy is running for performance reason. Providers may be restarted if a user sends reload command to a proxy.

## Payload

JSON-RPC ish.

```
{
    "id": 123,
    "method": "...",
    "params": { ... }
}
```

### Returning error

```
{
    "id": 123,
    "error": {
        "code": 1,
        "message": "Error message"
    }
}
```

## Methods

### `initialize`

Returns all certificates available in a key provider

__Request:__

```json
{
    "method": "initialize",
    "params": {
    }
}
```

__Response:__

```json
{
    "result": {
        "default": "cert1",
        "certificates": [
            {
                "id": "cert1",
                "domains": ["*.lo.myteam.invalid"],
                "pem": "PEM string(s)",
                "schemes": ["RSA_PSS_SHA256", "RSA_PSS_SHA384", "RSA_PKCS1_SHA256"]
            },
            ...
        ]
    }
}
```

`.certificates.schemes` lists the signature schemes the provider supports for this certificate's key. Scheme names follow rustls `SignatureScheme` variant names (e.g., `RSA_PSS_SHA256`, `ECDSA_NISTP256_SHA256`, `ED25519`). The field is strongly recommended — certificates without valid schemes are skipped with a warning during registration. When absent, it defaults to an empty list.

`.certificates.id` is encouraged to be dynamic, rotated after certificate/key renewal. It is used in `sign` method, so providers can reject operation on expired keys and inform user to reload the proxy to retrieve updated certificates.

### `sign`

Sign the given blob with the key corresponding to the specified certificate. The `scheme` field specifies the signature scheme to use (e.g., `RSA_PSS_SHA256`, `ECDSA_NISTP256_SHA256`). The provider must use exactly the requested scheme for signing.

__Request:__

```json
{
    "method": "sign",
    "params": {
        "certificate_id": "cert1",
        "scheme": "RSA_PSS_SHA256",
        "blob": "base64 string"
    }
}
```

__Response:__

```json
{
    "result": {
        "signature": "base64 string"
    }
}
```

## Provider Lifecycle

- The provider process is spawned when the proxy starts or when a reload is triggered.
- `initialize` is called once per spawn. The proxy caches all certificates from this response.
- `sign` is called many times during the provider's lifetime. Requests are serialized on the wire (one at a time per provider process).
- If the provider process crashes, the proxy automatically restarts it with exponential backoff (1s initial, 2x multiplier, up to 300s max). Backoff resets after 60s of continuous healthy operation.
- `trustless proxy reload` triggers a manual restart of all providers, bypassing backoff.

## Error Codes

Error responses use `code` (a positive integer) and a human-readable `message`. Conventional codes:

| Code | Meaning |
|------|---------|
| 1 | Certificate not found |
| 2 | Unsupported signature scheme |
| 3 | Signing failed |

These codes are not strictly standardized. Providers may use any positive integer with a descriptive message.

## Supported Signature Schemes

The following scheme names are recognized by the proxy:

- `RSA_PKCS1_SHA256`, `RSA_PKCS1_SHA384`, `RSA_PKCS1_SHA512`
- `RSA_PSS_SHA256`, `RSA_PSS_SHA384`, `RSA_PSS_SHA512`
- `ECDSA_NISTP256_SHA256`, `ECDSA_NISTP384_SHA384`, `ECDSA_NISTP521_SHA512`
- `ED25519`, `ED448`

All schemes declared for a single certificate must share the same algorithm family (e.g., all RSA or all ECDSA). Certificates with mixed algorithm families are rejected during registration.
