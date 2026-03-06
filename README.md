# trustless

Portless, and trustless, by sharing private keys for registrable domains. Useful when your app relies on same-site behavior and secure context.

## Security Notice

> [!CAUTION]
> This software allows to use a private key with limited usage, but it is still sharing a private key. Use at your own risk.


## Prior Art: Portless

This software is heavily inspired by [vercel-labs/portless](https://github.com/vercel-labs/portless).

However, Portless does only support `.localhost` domains, not registrable domains. In certain cases, we need to develop applications served on secure context + registrable domains. For secure context requirement, use of `localhost` domain is sufficient. However, when we need to test applications that require same-site behavior, we need to use registrable domains, because all `*.localhost` names are considered a independent single site, thus not allowed to test same-site behavior, because `localhost` is not a registrable domain.

But, to support registrable domains plus secure context requires use of HTTPS with trusted certificates. However, I'd like to get rid of intervention against system trust store. This software allows sharing a publicly trusted certificate and keys in limited way. So this software is named _trustless._

## Usage

```
# Explicit name
trustless exec api rails server
# -> https://api.developers.invalid:1443
```

### Proxy

```
trustless proxy start
```

> Proxy auto-starts when you run `trustless exec` command. Use `proxy start` if you want to explicitly start foreground.

## How it works

- `trustless exec` starts a specified command with `PORT` and `HOST` environment variables where randomly assigned port, and configures the trustless proxy to forward requests to that port on an assigned domain name. This design follows Portless, so you may want to check out their explanation.
- Before the first-time use, Trustless has to be setup using `trustless setup` command by giving your key provider command line. Key providers are responsible to return certificate data with available domains, and to sign blob used for TLS server authentication. You need to deploy it in your development infrastructure to actually share keys among your team.

## Setup

### Deploy your key provider

See [AWS Lambda Provider](docs/lambda-provider.md) for deploying a key provider backed by AWS Lambda and S3. For writing a custom provider, see [Writing a Key Provider](docs/writing-key-provider.md).

### Profiles

You can use multiple profiles if you have multiple shared key providers. Default to `default` profile.

```
trustless setup --profile=another -- ...
trustless run --profile=another rails server
```

### DNS setup

- We recommend to configure your key provider to host certificate and key for dedicated registrable domain, isolated from other environment entirely: e.g. `*.lo.mycompany-dev.com`. And configure its DNS records to point `127.0.0.1` and `::1`. Trustless does not support overriding DNS records in any manner; i.e. `/etc/hosts` or local DNS resolver.
  - As you're sharing private keys partially, you don't want to configure the domain with existing records such as staging servers, or production servers. Doing so results into a huge security risk, users allowed to use a such key server can impersonate the existing domain.

## State directory

- `$XDG_RUNTIME_PATH/trustless` or `~/.local/state/trustless`
