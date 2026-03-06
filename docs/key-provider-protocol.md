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

Returns all certificates avaialble in a key provider

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
                "pem": "PEM string(s)"
            },
            ...
        ]
    }
}
```

`.certificates.id` is encouraged to be dynamic, rotated after certificate/key renewal. It is used in `sign` method, so providers can reject operation on expired keys and inform user to reload the proxy to retrieve updated certificates.

### `sign`

Sign the given blob with the key corresponding to the specified certificate.

__Request:__

```json
{
    "method": "sign",
    "params": {
        "certificate_id": "cert1",
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
