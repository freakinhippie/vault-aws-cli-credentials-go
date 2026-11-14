package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/awscred"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/cache"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/config"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/vault"
)

var version = "dev"

// credentialProcessSlack extends the Vault request timeout so the token
// helper subprocess and the Vault request share one overall deadline without
// the AWS CLI waiting indefinitely on a hung helper.
const credentialProcessSlack = 10 * time.Second

type tokenResolver interface {
	Resolve(ctx context.Context, opts vault.TokenOptions) (string, error)
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
	newCacheStore    func(context.Context, string) (credentialCache, error)
}

func defaultRunDeps() runDeps {
	return runDeps{
		newTokenResolver: func() tokenResolver {
			return vault.NewTokenResolver()
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return vault.NewClient(cfg)
		},
		newCacheStore: func(ctx context.Context, scope string) (credentialCache, error) {
			return cache.NewProcessStore(ctx, scope)
		},
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == cache.WorkerArgument {
		os.Exit(cache.RunWorker(os.Stdin, os.Stdout))
	}
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

	if cfg.ShowVersion {
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	}
	if cfg.ValidateOnly {
		_, _ = fmt.Fprintln(stdout, "configuration is valid")
		return 0
	}
	// Bound the whole credential path (token helper + Vault request) with one
	// deadline and honor SIGINT/SIGTERM so a hung token helper can never wedge
	// the AWS CLI indefinitely.
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	timeout := cfg.ClientTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rootCtx, timeout+credentialProcessSlack)
	defer cancel()

	if cfg.IsCacheMaintenanceMode() {
		return runCacheMaintenance(ctx, cfg, stdout, stderr, deps)
	}

	cacheKey := cache.BuildKey(cfg.VaultAddr, cfg.VaultNamespace, cfg.Mount, cfg.Role, cfg.CredentialType, cfg.TTL)
	var credentialCache credentialCache
	if cfg.CacheCredentials {
		credentialCache, err = deps.newCacheStore(ctx, cfg.CacheKeyctlScope)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache warning: disabling credential caching (%v)\n", err)
			credentialCache = nil
		}
		if credentialCache != nil {
			cached, ok, err := credentialCache.Load(cacheKey)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "cache warning: disabling credential caching after read failure (%v)\n", err)
				credentialCache = nil
			} else if ok {
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
	token, err := tokenResolver.Resolve(ctx, vault.TokenOptions{
		Token:       cfg.VaultToken,
		TokenHelper: cfg.VaultTokenHelper,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault token error: %v\n", err)
		return 2
	}

	client, err := deps.newVaultClient(vault.ClientConfig{
		Addr:             cfg.VaultAddr,
		Token:            token,
		Namespace:        cfg.VaultNamespace,
		CACertPath:       cfg.VaultCACert,
		CAPath:           cfg.VaultCAPath,
		SkipVerify:       cfg.VaultSkipVerify,
		ClientTimeout:    cfg.ClientTimeout,
		DisableRedirects: cfg.VaultDisableRedirects,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault client error: %v\n", err)
		return 2
	}

	creds, err := client.GetAWSCredentials(ctx, cfg.Mount, cfg.Role, cfg.CredentialType, cfg.TTL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "vault request error: %v\n", err)
		return 1
	}

	if credentialCache != nil && creds.Expiration != nil {
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

func runCacheMaintenance(ctx context.Context, cfg config.Config, stdout, stderr io.Writer, deps runDeps) int {
	if cfg.CacheKeyringRecoveryHelp {
		_, _ = fmt.Fprintln(stdout, keyringRecoveryHelp())
		return 0
	}

	store, err := deps.newCacheStore(ctx, cfg.CacheKeyctlScope)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
		return 2
	}

	switch {
	case cfg.CacheList:
		entries, err := store.ListEntries()
		if err != nil {
			if len(entries) == 0 {
				_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
				return 2
			}
			_, _ = fmt.Fprintf(stderr, "cache warning: some entries could not be read (%v)\n", err)
		}
		if len(entries) == 0 {
			_, _ = fmt.Fprintln(stdout, "no cache entries found")
			return 0
		}
		for _, entry := range entries {
			status := "valid"
			switch {
			case entry.Corrupt:
				status = "corrupt"
			case entry.Expired:
				status = "expired"
			}
			exp := "n/a"
			if entry.Expiration != nil {
				exp = entry.Expiration.UTC().Format(timeLayout)
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
		if err != nil && n == 0 {
			_, _ = fmt.Fprintf(stderr, "cache maintenance error: %v\n", err)
			return 2
		} else if err != nil {
			_, _ = fmt.Fprintf(stderr, "cache warning: purged %d entries but some could not be read (%v)\n", n, err)
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

// writeOutput emits the AWS credential_process protocol payload, enforcing
// the contract boundary: never print an empty or malformed credential document
// with exit code 0.
func writeOutput(stdout, stderr io.Writer, payload awscred.ProcessOutput) int {
	if payload.AccessKeyID == "" || payload.SecretAccessKey == "" {
		_, _ = fmt.Fprintln(stderr, "output error: refusing to emit credentials without an access key or secret key")
		return 1
	}
	if payload.Expiration != nil {
		if strings.TrimSpace(*payload.Expiration) == "" {
			_, _ = fmt.Fprintln(stderr, "output error: refusing to emit credentials with an empty expiration")
			return 1
		}
		if _, err := time.Parse(time.RFC3339, *payload.Expiration); err != nil {
			_, _ = fmt.Fprintf(stderr, "output error: invalid expiration %q (want RFC3339)\n", *payload.Expiration)
			return 1
		}
	}

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
