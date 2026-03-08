# trustless-provider-failure

A failure-injecting proxy provider for testing. Wraps another provider process and returns errors when specified trigger files exist on disk, allowing you to test proxy behavior under provider failure without modifying real providers.

## Usage

```
trustless-provider-failure \
  [--sign-error-file <PATH>] \
  [--initialize-error-file <PATH>] \
  -- <PROVIDER_COMMAND>...
```

### Example

```bash
trustless setup --profile=dut -- trustless-provider-failure \
  --sign-error-file /tmp/sign-to-fail \
  --initialize-error-file /tmp/initialize-to-fail \
  -- trustless-provider-filesystem --cert-dir /path/to/certs
```

Then toggle failures at runtime:

```bash
# Trigger sign failures
touch /tmp/sign-to-fail

# Stop sign failures
rm /tmp/sign-to-fail

# Trigger initialize failures
touch /tmp/initialize-to-fail
```

## Options

- `--sign-error-file <PATH>` — When this file exists, all `sign` requests return `ErrorCode::SigningFailed`.
- `--initialize-error-file <PATH>` — When this file exists, all `initialize` requests return `ErrorCode::Internal`.

Both flags are optional. When omitted, the corresponding request type is always forwarded to the wrapped provider.
