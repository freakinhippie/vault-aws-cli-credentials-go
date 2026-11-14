# Vault AWS CLI/SDK Credentials Helper

The Vault AWS CLI/SDK Credential Helper (`vaultcreds`) implements the AWS CLI/SDK external credentials helper interface as outlined here: https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-sourcing-external.html

`vaultcreds` retrieves short-lived AWS credentials from Vault / OpenBao and writes them to stdout in credential-process JSON format.

## Installation

From source:

```bash
go install github.com/freakinhippie/vault-aws-cli-credentials-go/cmd/vaultcreds@latest
```

From Homebrew:

```bash
brew tap freakinhippie/homebrew-tap
brew install vaultcreds
```

From Chocolatey:

```powershell
choco install vaultcreds
```

Chocolatey packages are published by a dedicated Windows GitHub Actions workflow after each GitHub release is published.

From release artifacts: download the package for your OS/architecture and place `vaultcreds` on your `PATH`.

## Configuration

Configuration precedence is:

1. CLI flags
2. Environment variables
3. Config file (`--config` or `VAULTCREDS_CONFIG`)
4. Defaults

| Flag                   | Environment                     | Description                                       |
| :--------------------- | :------------------------------ | :------------------------------------------------ |
| `-c`, `--config`       | `VAULTCREDS_CONFIG`             | Configuration file path                           |
| `-V`, `--vault-addr`   | `VAULT_ADDR`                    | Vault server URL                                  |
| `-C`, `--vault-cacert` | `VAULT_CACERT`                  | Vault CA certificate file                         |
| `--vault-capath`       | `VAULT_CAPATH`                  | Vault CA certificates directory                   |
| `-m`, `--mount`        | `VAULTCREDS_MOUNT`              | AWS secrets backend mount (default `aws`)         |
| `-r`, `--role`         | `VAULTCREDS_ROLE`               | Vault role                                        |
| `-t`, `--ttl`          | `VAULTCREDS_TTL`                | Requested credential TTL (default `1h`)           |
| `-T`, `--type`         | `VAULTCREDS_CREDENTIAL_TYPE`    | Credential type: `sts` or `creds` (default `sts`) |
| `--cache`              | `VAULTCREDS_CACHE_CREDENTIALS`  | Enable secure credential caching                  |
| `--cache-keyctl-scope` | `VAULTCREDS_CACHE_KEYCTL_SCOPE` | Linux kernel keyring scope (default `session`)    |
| `--validate-config`    | N/A                             | Validate config and exit                          |
| `--version`            | N/A                             | Show version and exit                             |

Additional Vault variables honored:

- `VAULT_TOKEN`
- `VAULT_TOKEN_HELPER`
- `VAULT_NAMESPACE`
- `VAULT_SKIP_VERIFY`
- `VAULT_CLIENT_TIMEOUT` (seconds or Go duration such as `90s`; default 60s)
- `VAULT_CONFIG_PATH` (overrides the `~/.vault` CLI config used to discover `token_helper`)
- `VAULT_DISABLE_REDIRECTS` (default `false`)

HTTP redirects mirror the Vault client: one redirect for status 301, 302, or 307,
including a change of host, with authentication and namespace headers preserved.
HTTPS-to-HTTP downgrades and further redirects are refused. Set
`VAULT_DISABLE_REDIRECTS=true` to refuse all redirects.

TTL accepts integer seconds, Go durations such as `1h30m`, and day/week extensions
such as `1d12h` or `1w`. Extensions are converted to Go durations before sending
them to Vault. Zero (`0` or `0s`) retains Vault's default-TTL behavior; an empty
TTL omits the query parameter. Negative and overflowing durations are rejected.

Configuration files use top-level `key = value` entries. Unknown and duplicate
keys are errors; UTF-8 BOMs and inline comments preceded by whitespace are
supported. Help, version, and cache maintenance work independently of credential
configuration files and Vault environment settings.

Token resolution matches Vault CLI behavior order:

1. `VAULT_TOKEN`
2. Token helper (`VAULT_TOKEN_HELPER`, `~/.vault` or `VAULT_CONFIG_PATH` `token_helper`)
3. `~/.vault-token` (only when no token helper is configured; this mirrors the
   vault CLI, where the file *is* the default internal helper, so a broken
   external helper is reported as an error instead of being masked by a stale
   token file)

## Credential Caching

Caching is disabled by default.

When enabled (`--cache` or `VAULTCREDS_CACHE_CREDENTIALS=true`), `vaultcreds` uses secure OS storage when available:

- Linux: Secret Service, then kernel keyctl, then an initialized `pass` store
- macOS: Keychain
- Windows: Credential Manager (WinCred)

If caching is requested but a secure backend is unavailable or errors, `vaultcreds` prints a warning and continues in non-caching mode. `vaultcreds` does not write plaintext credentials to disk.

## Cache Management Commands

Use these commands to inspect or clean existing cache entries:

```bash
vaultcreds --cache-list
vaultcreds --cache-purge "<cache-key>[,<cache-key>...]"
vaultcreds --cache-purge-expired
vaultcreds --cache-purge-all
vaultcreds --cache-keyring-recovery-help
```

Notes:

- Cache maintenance commands are mutually exclusive (run one at a time).
- `--cache-keyring-recovery-help` prints OS-specific instructions for recovering/resetting the underlying keyring.
- `vaultcreds` cannot directly reset OS keyring passwords; this must be done with OS keyring tooling.

## Caching Setup Summary

For full OS-specific setup and headless/server guidance, see [`README_CACHING.md`](README_CACHING.md).

- Linux: prefers a user D-Bus session and Secret Service provider; headless sessions can use kernel keyctl or an initialized `pass` store.
- macOS: uses Keychain in the invoking user context.
- Windows: uses Credential Manager (WinCred) in the user logon context.
- If secure backend access is unavailable, `vaultcreds` falls back to non-caching mode and logs a warning.

## AWS CLI example

`credential_process` should use the full path to `vaultcreds`; do not rely on `PATH` lookup.

```ini
[profile vault-dev]
credential_process = /usr/local/bin/vaultcreds --vault-addr=https://vault.example.com:8200 --role=dev-role
region = us-east-1
```

## Status

Implemented:

- Config loading and validation
- Vault token resolution (env, helper, token file)
- Vault AWS credential retrieval (`sts` and `creds`)
- Credential-process JSON output
- Optional secure caching (Linux/macOS/Windows)
- Command-path tests for cache hit/miss, token errors, Vault errors, and successful output
- Integration/E2E test harness for `vault -dev` (build tag `integration`)

Planned:

- Additional release automation polish

## Testing

Run unit tests:

```bash
go test ./...
```

Run integration/E2E tests (requires local `vault` binary):

```bash
go test -tags=integration ./internal/e2e -v
```

## Make Targets

```bash
make help
make build
make test
make test-integration
make fmt
make vet
make tidy
```

## Releasing

See [`RELEASING.md`](RELEASING.md) for one-time setup (GitHub secrets, Homebrew tap, Chocolatey account/API key) and the tag-based release workflow.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
