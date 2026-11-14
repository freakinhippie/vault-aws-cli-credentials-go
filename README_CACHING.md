# Credential Caching Guide

This document explains how to enable and operate `vaultcreds` credential caching across supported operating systems.

## Overview

- Caching is **disabled by default**.
- Enable caching with either:
  - `--cache`
  - `VAULTCREDS_CACHE_CREDENTIALS=true`
  - `cache=true` or `cache_credentials=true` in a config file
- Cache entries are stored in OS secure storage and keyed by Vault context (`vault_addr`, namespace, mount, role, credential type, TTL).
- Entry names are human-readable and include Vault context across all supported cache backends (Linux Secret Service, macOS Keychain, Windows Credential Manager), so entries are identifiable at a glance.
- `vaultcreds` never writes plaintext AWS credentials to disk.
- If secure storage is unavailable, `vaultcreds` logs a warning and continues without caching.

## Quick Enablement

CLI:

```bash
/path/to/vaultcreds --cache --vault-addr=https://vault.example.com --role=dev-role
```

Environment:

```bash
export VAULTCREDS_CACHE_CREDENTIALS=true
```

Config file:

```ini
cache_credentials = true
```

## Linux (Secret Service)

`vaultcreds` prefers the Secret Service backend (for example, GNOME Keyring / compatible libsecret providers). When no Secret Service daemon is available, it automatically falls back to other secure OS-backed keyring implementations in order: the kernel `keyctl` keyring, then `pass(1)`. Plaintext file storage is never used.

Requirements (Secret Service):

- A running user D-Bus session (`DBUS_SESSION_BUS_ADDRESS` is set).
- A Secret Service provider running in that session.
- An unlocked keyring/collection for writes and reads.

Desktop sessions typically satisfy this automatically after login.

### Headless or server Linux

In non-GUI environments, Secret Service often fails due to missing session D-Bus or locked keyrings. `vaultcreds` then tries the secure `keyctl` and `pass(1)` backends automatically before giving up.

Practical guidance:

- Run `vaultcreds` as a real user session (not system-wide root service) when possible.
- Ensure the process has a valid user D-Bus session.
- Ensure the keyring collection can be unlocked non-interactively for your service account.
- On SSH/headless hosts, ensure the kernel keyring API is permitted, or use an initialized `pass` store with an unlocked GPG key. The `keyctl` command-line executable is not required.

If no secure backend is available, `vaultcreds` disables caching with a warning on stderr and still fetches credentials directly from Vault.

### Kernel keyring scope

The default scope is `session`, shared by credential helper processes that inherit
the same Linux session keyring. Separate login/SSH sessions may have separate caches.
For cross-session sharing under the same user, `user` and `usersession` are also
supported. Process/thread scopes are rejected because separate credential helper
invocations could not reuse their entries.

Configure the scope using any of:

```bash
vaultcreds --cache --cache-keyctl-scope=session --role=dev-role
export VAULTCREDS_CACHE_KEYCTL_SCOPE=user
```

```ini
cache_keyctl_scope = "session"
```

Precedence is flag > environment > config file > `session`. Maintenance commands
ignore credential config files so a broken file cannot block recovery; use the same
scope flag or environment variable when listing or purging a non-default scope:

```bash
vaultcreds --cache-list --cache-keyctl-scope=user
```

### Backend isolation and timeouts

`pass` entries live under the dedicated `vaultcreds/` prefix. Cache maintenance
operates within this prefix, and traversal paths are rejected. GPG is run with
batch mode and pinentry disabled; an unavailable unlocked key causes a cache
warning and a live Vault fetch.

Keyring operations run in a disposable helper process with a five-second limit per
operation. The credential path also has an overall deadline of the Vault client
timeout plus ten seconds (70 seconds by default). Credentials pass between these
processes over anonymous pipes and are never written to plaintext files.

Credentials without a future expiration are fetched normally and are not cached.
Legacy entries without expiration and malformed entries can be removed with
`--cache-purge-expired`. Cache keys now use a length-prefixed hash and preserve
case-sensitive URL paths. Older keys will miss after upgrading; remove leftover
entries using the cache maintenance commands. Unprefixed entries from the pending
`pass` implementation are deliberately outside the new maintenance namespace.

## macOS (Keychain)

`vaultcreds` uses macOS Keychain.

Requirements:

- The invoking user has an active keychain.
- The process runs in that user context.
- Build with `CGO_ENABLED=1` and the macOS SDK/Xcode command-line tools. The
  Byteness Keychain backend calls Apple's Security and CoreFoundation frameworks
  through CGO. Current dependencies cannot compile a macOS binary with
  `CGO_ENABLED=0`, even when caching will be disabled at runtime.
- The keyring library also imports a CGO-based Touch ID implementation, although
  `vaultcreds` does not enable biometric authentication. Ordinary Keychain access
  already requires CGO independently of Touch ID.

Vault HTTP/TLS requests, token-helper execution, and credential JSON formatting do
not require CGO. Linux and Windows builds use `CGO_ENABLED=0`. Retaining macOS
Keychain caching requires a macOS build environment, or a properly configured
cross C compiler and macOS SDK on Linux; setting `GOOS=darwin` alone is insufficient.
Replacing the Keychain backend with a CGO-free implementation would be a separate
change requiring validation of storage, permissions, and cache compatibility.

### Headless / CI / launchd considerations

- Run `vaultcreds` in the target user context, not as a different user.
- Ensure the login keychain is available/unlocked for non-interactive jobs.
- If keychain access prompts appear, pre-authorize the binary and rerun.

If Keychain access is unavailable, `vaultcreds` logs a cache warning and continues without caching.

## Windows (Credential Manager / WinCred)

`vaultcreds` uses Windows Credential Manager (WinCred backend).

Requirements:

- The process runs as a user account with a loaded profile.
- Credential Manager is available in that logon context.

### Server and service accounts

- Prefer running under a normal user account for predictable credential store behavior.
- For scheduled tasks/services, ensure the account profile is loaded and has access to Credential Manager.

If WinCred is unavailable in that context, `vaultcreds` falls back to non-caching mode.

## Validating Caching

1. Enable caching.
2. Run `vaultcreds` once and verify success.
3. Run the same command again.
4. Confirm no cache warnings were printed.

`vaultcreds` cache warnings include:

- `cache warning: disabling credential caching (...)`
- `cache warning: disabling credential caching after read failure (...)`
- `cache warning: credentials not cached (...)`

If you see these, credential retrieval still works, but every call fetches directly from Vault.

## Managing Existing Entries

List entries:

```bash
vaultcreds --cache-list
```

Purge specific entries (comma-separated keys):

```bash
vaultcreds --cache-purge "vault.example.com:8200/aws/sts/role/1h.abcd1234"
```

Purge expired entries:

```bash
vaultcreds --cache-purge-expired
```

Purge all entries:

```bash
vaultcreds --cache-purge-all
```

Keyring password recovery/reset guidance:

```bash
vaultcreds --cache-keyring-recovery-help
```

`vaultcreds` cannot reset OS keyring passwords directly; use native keyring tooling and then reinitialize by purging old vaultcreds entries.

## Operational Notes

- Cached credentials honor expiration. Near-expiry entries (within one minute) are treated as misses.
- Different Vault addr/namespace/mount/role/type/TTL combinations generate different cache keys.
- Cache key format is path-like for readability: `{vault_fqdn[:port]}/[{namespace}/]{mount}/{type}/{role}/{ttl}.{hex}`.
- Caching is optional and safe to enable incrementally per profile or environment.
