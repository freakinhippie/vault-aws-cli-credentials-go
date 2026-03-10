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

`vaultcreds` uses the Secret Service backend (for example, GNOME Keyring / compatible libsecret providers).

Requirements:

- A running user D-Bus session (`DBUS_SESSION_BUS_ADDRESS` is set).
- A Secret Service provider running in that session.
- An unlocked keyring/collection for writes and reads.

Desktop sessions typically satisfy this automatically after login.

### Headless or server Linux

In non-GUI environments, Secret Service often fails due to missing session D-Bus or locked keyrings.

Practical guidance:

- Run `vaultcreds` as a real user session (not system-wide root service) when possible.
- Ensure the process has a valid user D-Bus session.
- Ensure the keyring collection can be unlocked non-interactively for your service account.

If these are not available, `vaultcreds` will fall back to non-caching mode with warnings on stderr.

## macOS (Keychain)

`vaultcreds` uses macOS Keychain.

Requirements:

- The invoking user has an active keychain.
- The process runs in that user context.
- The binary must be built on macOS with `CGO_ENABLED=1`; macOS Keychain support is not available in `CGO_ENABLED=0` builds.

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
