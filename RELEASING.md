# Releasing

This repository uses GitHub Actions + GoReleaser for automated releases.

## Release Trigger

Releases run when a tag matching `v*` is pushed, for example:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The CI workflow runs tests/build checks and then runs:

```bash
goreleaser release --clean --skip=chocolatey
```

Chocolatey is published by a dedicated workflow on GitHub Release publication.

## One-Time Setup

### 1) GitHub repository secrets

Set these in:
`freakinhippie/vault-aws-cli-credentials-go` -> `Settings` -> `Secrets and variables` -> `Actions`.

- `HOMEBREW_TAP_SSH_KEY`
  - SSH private key (PEM/OpenSSH format) for a key allowed to push to `freakinhippie/homebrew-tap`.
  - Used by GoReleaser Homebrew cask publishing.

- `CHOCOLATEY_API_KEY`
  - Chocolatey API key from your Chocolatey account.
  - Used by `.github/workflows/chocolatey-publish.yml`.

### 2) Create Homebrew tap repository

Create:

- `https://github.com/freakinhippie/homebrew-tap`

Requirements:

- Repo exists before the first release.
- The public key pair for `HOMEBREW_TAP_SSH_KEY` has write access to this repo.

### 3) Chocolatey publisher setup

Create and verify a Chocolatey account and API key, and ensure package name ownership for `vaultcreds`.

Chocolatey publication is automated by the `Chocolatey Publish` workflow:

- Trigger: GitHub Release `published` event.
- Runner: `windows-latest`.
- Source artifact: `vaultcreds_<tag>_windows_x86_64.zip` from the GitHub release.
- Integrity source: `checksums.txt` from the same GitHub release.
- Manual retry option: workflow dispatch with a `tag` input.

### 4) Add/host Chocolatey icon asset

`.goreleaser.yaml` references:

`https://raw.githubusercontent.com/freakinhippie/vault-aws-cli-credentials-go/main/.github/assets/vaultcreds-icon.png`

Ensure this file exists and is reachable for Chocolatey metadata.

## Recommended Release Steps

1. Ensure `main` is green.
2. Create and push a semver tag (`vX.Y.Z`).
3. Wait for CI `release` job completion.
4. Verify GitHub release artifacts and Homebrew tap update.
5. Verify Chocolatey package publish workflow completion.

## Notes

- The workflow intentionally publishes from a macOS runner to support darwin builds with `CGO_ENABLED=1`.
- Chocolatey publication runs as a separate Windows workflow after release publication.
