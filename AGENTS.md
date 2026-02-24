# Basics

Packaging uses `goreleaser` and builds packages for Linux, MacOS, and Windows for both x86 & ARM based systems.

## Vault Integration

Integration with Hashicorp Vault should model the `vault` CLI tool, by reading `VAULT_ADDR`, `VAULT_CACERT`, `VAULT_TOKEN`, etc. Also, it must also use the Vault Token Helper interface in the same way for retrieving tokens.

## Credential Caching

By default, credentials should only be returned to the calling process and **_never_** be written to disk in plaintext. However, if the user has requested credential caching, they should be stored securely depending on the available features of the OS (such as secret keyring, etc), which should be detected automatically and require no user interaction.

## Testing (Unit, Integration, & End-to-End)

All code paths should be supported by tests, thoroughly covering real-world usage scenarios. Whenever possible, tests should mock APIs and/or harness `vault -dev` mode with some pseudo AWS STS service backing it.