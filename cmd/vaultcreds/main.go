package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/awscred"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/cache"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/config"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/vault"
)

var version = "dev"

type tokenResolver interface {
	Resolve(opts vault.TokenOptions) (string, error)
}

type vaultClient interface {
	GetAWSCredentials(ctx context.Context, mount, role, credentialType, ttl string) (vault.AWSCredentials, error)
}

type credentialCache interface {
	Load(key string) (cache.CachedCredentials, bool, error)
	Save(key string, creds cache.CachedCredentials) error
	ListEntries() ([]cache.Entry, error)
	PurgeKeys(keys []string) (int, error)
	PurgeExpired() (int, error)
	PurgeAll() (int, error)
}

type runDeps struct {
	newTokenResolver func() tokenResolver
	newVaultClient   func(cfg vault.ClientConfig) (vaultClient, error)
	newCacheStore    func() (credentialCache, error)
}

func defaultRunDeps() runDeps {
	return runDeps{
		newTokenResolver: func() tokenResolver {
			return vault.NewTokenResolver()
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return vault.NewClient(cfg)
		},
		newCacheStore: func() (credentialCache, error) {
			return cache.NewDefaultStore()
		},
	}
}

func main() {
	exitCode := run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr)
	os.Exit(exitCode)
}

func run(args []string, environ []string, stdout, stderr io.Writer) int {
	return runWithDeps(args, environ, stdout, stderr, defaultRunDeps())
}

func runWithDeps(args []string, environ []string, stdout, stderr io.Writer, deps runDeps) int {
	cfg, err := config.Load(args, environ)
	if err != nil {
		if errors.Is(err, config.ErrHelpRequested) {
			_, _ = fmt.Fprintln(stdout, config.HelpText(resolvedBinaryPath()))
			return 0
		}

		_, _ = fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 2
	}

	if cfg.ValidateOnly {
		_, _ = fmt.Fprintln(stdout, "configuration is valid")
		return 0
	}
	if cfg.IsCacheMaintenanceMode() {
		return runCacheMaintenance(cfg, stdout, stderr, deps)
	}

	cacheKey := cache.BuildKey(cfg.VaultAddr, cfg.VaultNamespace, cfg.Mount, cfg.Role, cfg.CredentialType, cfg.TTL)
	var credentialCache credentialCache
	if cfg.CacheCredentials {
		credentialCache, err = deps.newCacheStore()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache warning: disabling credential caching (%v)\n", err)
			credentialCache = nil
		}
		if credentialCache != nil {
			cached, ok, err := credentialCache.Load(cacheKey)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "cache warning: disabling credential caching after read failure (%v)\n", err)
				credentialCache = nil
			}
			if ok {
				return writeOutput(stdout, stderr, awscred.ProcessOutput{
					AccessKeyID:     cached.AccessKeyID,
					SecretAccessKey: cached.SecretAccessKey,
					SessionToken:    cached.SessionToken,
					Expiration:      cached.Expiration,
				})
			}
		}
	}

	tokenResolver := deps.newTokenResolver()
	token, err := tokenResolver.Resolve(vault.TokenOptions{
		Token:       cfg.VaultToken,
		TokenHelper: cfg.VaultTokenHelper,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault token error: %v\n", err)
		return 2
	}

	client, err := deps.newVaultClient(vault.ClientConfig{
		Addr:       cfg.VaultAddr,
		Token:      token,
		Namespace:  cfg.VaultNamespace,
		CACertPath: cfg.VaultCACert,
		CAPath:     cfg.VaultCAPath,
		SkipVerify: cfg.VaultSkipVerify,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault client error: %v\n", err)
		return 2
	}

	creds, err := client.GetAWSCredentials(context.Background(), cfg.Mount, cfg.Role, cfg.CredentialType, cfg.TTL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault request error: %v\n", err)
		return 1
	}

	if credentialCache != nil {
		if err := credentialCache.Save(cacheKey, cache.CachedCredentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Expiration:      creds.Expiration,
		}); err != nil {
			_, _ = fmt.Fprintf(stderr, "cache warning: credentials not cached (%v)\n", err)
		}
	}

	return writeOutput(stdout, stderr, awscred.ProcessOutput{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration,
	})
}

func runCacheMaintenance(cfg config.Config, stdout, stderr io.Writer, deps runDeps) int {
	if cfg.CacheKeyringRecoveryHelp {
		_, _ = fmt.Fprintln(stdout, keyringRecoveryHelp())
		return 0
	}

	store, err := deps.newCacheStore()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
		return 2
	}

	switch {
	case cfg.CacheList:
		entries, err := store.ListEntries()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
			return 2
		}
		if len(entries) == 0 {
			_, _ = fmt.Fprintln(stdout, "no cache entries found")
			return 0
		}
		for _, entry := range entries {
			status := "valid"
			exp := "n/a"
			if entry.Expiration != nil {
				exp = entry.Expiration.UTC().Format(timeLayout)
				if entry.Expired {
					status = "expired"
				}
			}
			_, _ = fmt.Fprintf(stdout, "%s\taccess_key=%s\texpires=%s\tstatus=%s\n", entry.Key, entry.AccessKey, exp, status)
		}
		return 0
	case len(cfg.CachePurgeKeys) > 0:
		n, err := store.PurgeKeys(cfg.CachePurgeKeys)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "purged %d cache entr(ies)\n", n)
		return 0
	case cfg.CachePurgeExpired:
		n, err := store.PurgeExpired()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "purged %d expired cache entr(ies)\n", n)
		return 0
	case cfg.CachePurgeAll:
		n, err := store.PurgeAll()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "purged %d cache entr(ies)\n", n)
		return 0
	default:
		_, _ = fmt.Fprintln(stderr, "cache maintenance error: no operation selected")
		return 2
	}
}

const timeLayout = "2006-01-02T15:04:05Z07:00"

func keyringRecoveryHelp() string {
	switch runtime.GOOS {
	case "linux":
		return strings.TrimSpace(`
Keyring password recovery/reset is managed by your desktop keyring service, not by vaultcreds.

Linux guidance:
- GNOME Keyring: use Seahorse to change/reset the keyring password.
- If the keyring is unrecoverable, create a new login/default keyring in Seahorse.
- After recovery, run: vaultcreds --cache-purge-all
`)
	case "darwin":
		return strings.TrimSpace(`
Keychain password recovery/reset is managed by macOS Keychain Access, not by vaultcreds.

macOS guidance:
- Open Keychain Access and use "Change Password for Keychain 'login'" or reset the default keychain.
- After recovery, run: vaultcreds --cache-purge-all
`)
	case "windows":
		return strings.TrimSpace(`
Credential Manager password/reset is managed by Windows account/profile recovery, not by vaultcreds.

Windows guidance:
- Use Control Panel > Credential Manager to inspect/remove credentials.
- If profile credentials are corrupted, recover/reset the Windows user profile credentials.
- After recovery, run: vaultcreds --cache-purge-all
`)
	default:
		return "Keyring password recovery/reset must be done with OS-specific keyring tooling; vaultcreds cannot reset keyring passwords directly."
	}
}

func writeOutput(stdout, stderr io.Writer, payload awscred.ProcessOutput) int {
	out, err := payload.JSON()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "output encoding error: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintln(stdout, string(out))
	return 0
}

func resolvedBinaryPath() string {
	exe, err := os.Executable()
	if err == nil && exe != "" {
		if abs, err := filepath.Abs(exe); err == nil {
			return abs
		}
		return exe
	}

	arg0 := strings.TrimSpace(os.Args[0])
	if arg0 == "" {
		return "vaultcreds"
	}
	if strings.Contains(arg0, string(filepath.Separator)) {
		if abs, err := filepath.Abs(arg0); err == nil {
			return abs
		}
		return arg0
	}
	if p, err := exec.LookPath(arg0); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	return arg0
}
