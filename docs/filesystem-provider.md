# Filesystem Provider

The filesystem provider (`trustless-provider-filesystem`) loads TLS certificates and private keys from a local directory. It's the simplest way to get started with Trustless -- no cloud services or remote infrastructure required.

## When to Use

Use this provider when:

- You're a solo developer or small team and already have a wildcard certificate (e.g. from Let's Encrypt / acmesmith)
- You want to try Trustless without deploying anything to the cloud
- You have a shared filesystem (NFS, synced folder) where certificates are distributed

For team use with access control and instant revocation, consider the [AWS Lambda Provider](lambda-provider.md) instead.

## Directory Structure

Organize your certificate files under a root directory. The layout is compatible with [acmesmith](https://github.com/sorah/acmesmith) storage output:

```
/path/to/certs/
  certs/
    example.com/
      current              # text file containing the current version, e.g. "2026-03"
      2026-03/
        fullchain.pem      # certificate chain (leaf first)
        key.pem            # private key (PEM)
```

- **`current`** -- contains the version string (whitespace-trimmed) pointing to the active subdirectory.
- **`fullchain.pem`** -- PEM certificate chain. Falls back to `cert.pem` if `fullchain.pem` is not found.
- **`key.pem`** -- PEM private key. Supports PKCS#8 encrypted keys (`BEGIN ENCRYPTED PRIVATE KEY`) and legacy OpenSSL PEM encryption (`Proc-Type: 4,ENCRYPTED`) when a passphrase is set.

Multiple domains are supported -- add additional directories under `certs/`:

```
certs/
  dev.example.com/
    current
    2026-03/...
  staging.example.com/
    current
    2026-01/...
```

## Quick Start

### 1. Install

Download a binary from [GitHub Releases](https://github.com/sorah/trustless/releases), or build from source:

```bash
cargo install trustless-provider-filesystem
```

### 2. Prepare certificates

Place your wildcard certificate and key in the directory structure shown above. For example, if you manage certificates with acmesmith, its S3 or filesystem storage already uses this layout.

### 3. Register with Trustless

```bash
trustless setup -- trustless-provider-filesystem --cert-dir /path/to/certs
```

### 4. Verify

```bash
trustless test-provider
```

### 5. Run your app

```bash
trustless run rails server
# -> https://my-app.dev.example.com:1443
```

## Encrypted Keys

If your private keys are encrypted, set the passphrase via environment variable. Wrap the provider command with `env`:

```bash
trustless setup -- env TRUSTLESS_KEY_PASSPHRASE=secret trustless-provider-filesystem --cert-dir /path/to/certs
```

## Certificate Rotation

To rotate certificates, add a new version directory and update the `current` file:

```bash
# Upload new cert
mkdir -p /path/to/certs/certs/example.com/2026-06
cp fullchain.pem key.pem /path/to/certs/certs/example.com/2026-06/

# Switch to new version
echo 2026-06 > /path/to/certs/certs/example.com/current

# Reload the proxy to pick up the change
trustless proxy reload
```

## Security Considerations

The filesystem provider reads private keys directly from disk. Anyone with read access to the key files can extract them. For team environments where you want to avoid distributing raw key material, use a remote provider like the [AWS Lambda Provider](lambda-provider.md) which performs signing server-side without exporting keys.
