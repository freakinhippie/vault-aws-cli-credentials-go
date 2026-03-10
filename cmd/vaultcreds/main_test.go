package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/cache"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/vault"
)

type fakeTokenResolver struct {
	token string
	err   error
}

func (f fakeTokenResolver) Resolve(_ vault.TokenOptions) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

type fakeVaultClient struct {
	creds vault.AWSCredentials
	err   error
}

func (f fakeVaultClient) GetAWSCredentials(_ context.Context, _, _, _, _ string) (vault.AWSCredentials, error) {
	if f.err != nil {
		return vault.AWSCredentials{}, f.err
	}
	return f.creds, nil
}

type fakeCacheStore struct {
	loaded          cache.CachedCredentials
	loadedHit       bool
	loadErr         error
	saved           cache.CachedCredentials
	savedKey        string
	saveErr         error
	loadedKey       string
	loadInvoked     bool
	saveInvoked     bool
	listedEntries   []cache.Entry
	listErr         error
	purgedKeys      []string
	purgeKeysErr    error
	purgeExpiredN   int
	purgeExpiredErr error
	purgeAllN       int
	purgeAllErr     error
}

func (f *fakeCacheStore) Load(key string) (cache.CachedCredentials, bool, error) {
	f.loadInvoked = true
	f.loadedKey = key
	if f.loadErr != nil {
		return cache.CachedCredentials{}, false, f.loadErr
	}
	return f.loaded, f.loadedHit, nil
}

func (f *fakeCacheStore) Save(key string, creds cache.CachedCredentials) error {
	f.saveInvoked = true
	f.savedKey = key
	f.saved = creds
	return f.saveErr
}

func (f *fakeCacheStore) ListEntries() ([]cache.Entry, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listedEntries, nil
}

func (f *fakeCacheStore) PurgeKeys(keys []string) (int, error) {
	if f.purgeKeysErr != nil {
		return 0, f.purgeKeysErr
	}
	f.purgedKeys = append(f.purgedKeys, keys...)
	return len(keys), nil
}

func (f *fakeCacheStore) PurgeExpired() (int, error) {
	if f.purgeExpiredErr != nil {
		return 0, f.purgeExpiredErr
	}
	return f.purgeExpiredN, nil
}

func (f *fakeCacheStore) PurgeAll() (int, error) {
	if f.purgeAllErr != nil {
		return 0, f.purgeAllErr
	}
	return f.purgeAllN, nil
}

func baseEnv() []string {
	return []string{
		"VAULT_ADDR=https://vault.example",
		"VAULTCREDS_ROLE=dev-role",
	}
}

func TestRunValidateConfig(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exit := runWithDeps([]string{"--validate-config"}, baseEnv(), &stdout, &stderr, defaultRunDeps())
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d", exit)
	}
	if !strings.Contains(stdout.String(), "configuration is valid") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stdout strings.Builder
	var stderr strings.Builder

	exit := runWithDeps([]string{"--help"}, nil, &stdout, &stderr, defaultRunDeps())
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d", exit)
	}
	if !strings.Contains(stdout.String(), "Usage:") || !strings.Contains(stdout.String(), "--vault-addr") {
		t.Fatalf("unexpected help output: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "credential_process = ") || !strings.Contains(stdout.String(), "--vault-addr=https://vault.example.com --role=dev-role") {
		t.Fatalf("missing credential_process sts example: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--mount=aws-team --role=app-role --type=creds") {
		t.Fatalf("missing credential_process creds example: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), " --config=/etc/vaultcreds/config.toml") {
		t.Fatalf("unexpected help output: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunCacheHitSkipsVault(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{
		loadedHit: true,
		loaded: cache.CachedCredentials{
			AccessKeyID:     "AKIA_CACHE",
			SecretAccessKey: "SECRET_CACHE",
			SessionToken:    "SESSION_CACHE",
		},
	}
	vaultCalled := false

	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			vaultCalled = true
			return fakeVaultClient{}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return cacheStore, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	env := append(baseEnv(), "VAULTCREDS_CACHE_CREDENTIALS=true")
	exit := runWithDeps(nil, env, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if vaultCalled {
		t.Fatal("vault should not be called on cache hit")
	}
	if !cacheStore.loadInvoked {
		t.Fatal("expected cache load")
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out["AccessKeyId"] != "AKIA_CACHE" {
		t.Fatalf("unexpected output: %#v", out)
	}
}

func TestRunTokenError(t *testing.T) {
	t.Parallel()

	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{err: errors.New("no token")}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return fakeVaultClient{}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return &fakeCacheStore{}, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps(nil, baseEnv(), &stdout, &stderr, deps)
	if exit != 2 {
		t.Fatalf("expected exit 2, got %d", exit)
	}
	if !strings.Contains(stderr.String(), "vault token error") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunVaultError(t *testing.T) {
	t.Parallel()

	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return fakeVaultClient{err: errors.New("permission denied")}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return &fakeCacheStore{}, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps(nil, baseEnv(), &stdout, &stderr, deps)
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	if !strings.Contains(stderr.String(), "vault request error") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunSuccessWritesCacheAndOutput(t *testing.T) {
	t.Parallel()

	exp := "2026-02-24T20:00:00Z"
	cacheStore := &fakeCacheStore{}

	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return fakeVaultClient{creds: vault.AWSCredentials{
				AccessKeyID:     "AKIA",
				SecretAccessKey: "SECRET",
				SessionToken:    "SESSION",
				Expiration:      &exp,
			}}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return cacheStore, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	env := append(baseEnv(), "VAULTCREDS_CACHE_CREDENTIALS=true")
	exit := runWithDeps(nil, env, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}

	if !cacheStore.saveInvoked {
		t.Fatal("expected cache save")
	}
	if cacheStore.saved.AccessKeyID != "AKIA" || cacheStore.saved.SecretAccessKey != "SECRET" {
		t.Fatalf("unexpected saved creds: %#v", cacheStore.saved)
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out["AccessKeyId"] != "AKIA" || out["SecretAccessKey"] != "SECRET" {
		t.Fatalf("unexpected output: %#v", out)
	}
}

func TestRunCacheSetupErrorFallsBackToNoCache(t *testing.T) {
	t.Parallel()

	vaultCalled := false
	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			vaultCalled = true
			return fakeVaultClient{creds: vault.AWSCredentials{
				AccessKeyID:     "AKIA",
				SecretAccessKey: "SECRET",
			}}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return nil, errors.New("no secure backend")
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	env := append(baseEnv(), "VAULTCREDS_CACHE_CREDENTIALS=true")
	exit := runWithDeps(nil, env, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !vaultCalled {
		t.Fatal("expected vault to be called")
	}
	if !strings.Contains(stderr.String(), "cache warning: disabling credential caching") {
		t.Fatalf("expected cache warning, got %q", stderr.String())
	}
}

func TestRunCacheReadErrorFallsBackToNoCache(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{loadErr: errors.New("boom")}
	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return fakeVaultClient{creds: vault.AWSCredentials{
				AccessKeyID:     "AKIA",
				SecretAccessKey: "SECRET",
			}}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return cacheStore, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	env := append(baseEnv(), "VAULTCREDS_CACHE_CREDENTIALS=true")
	exit := runWithDeps(nil, env, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !cacheStore.loadInvoked {
		t.Fatal("expected cache load")
	}
	if !strings.Contains(stderr.String(), "cache warning: disabling credential caching after read failure") {
		t.Fatalf("expected cache warning, got %q", stderr.String())
	}
}

func TestRunCacheWriteErrorWarnsButSucceeds(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{saveErr: errors.New("write failed")}
	deps := runDeps{
		newTokenResolver: func() tokenResolver {
			return fakeTokenResolver{token: "token"}
		},
		newVaultClient: func(cfg vault.ClientConfig) (vaultClient, error) {
			return fakeVaultClient{creds: vault.AWSCredentials{
				AccessKeyID:     "AKIA",
				SecretAccessKey: "SECRET",
			}}, nil
		},
		newCacheStore: func() (credentialCache, error) {
			return cacheStore, nil
		},
	}

	var stdout strings.Builder
	var stderr strings.Builder
	env := append(baseEnv(), "VAULTCREDS_CACHE_CREDENTIALS=true")
	exit := runWithDeps(nil, env, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !cacheStore.saveInvoked {
		t.Fatal("expected cache save")
	}
	if !strings.Contains(stderr.String(), "cache warning: credentials not cached") {
		t.Fatalf("expected cache warning, got %q", stderr.String())
	}
}

func TestRunCacheList(t *testing.T) {
	t.Parallel()

	exp := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	cacheStore := &fakeCacheStore{
		listedEntries: []cache.Entry{
			{Key: "vault.example/aws/sts/dev/1h.abcd1234", AccessKey: "AKIA1"},
			{Key: "vault.example/aws/sts/prod/1h.ef567890", AccessKey: "AKIA2", Expiration: &exp, Expired: true},
		},
	}
	deps := runDeps{
		newTokenResolver: func() tokenResolver { return fakeTokenResolver{} },
		newVaultClient:   func(cfg vault.ClientConfig) (vaultClient, error) { return fakeVaultClient{}, nil },
		newCacheStore:    func() (credentialCache, error) { return cacheStore, nil },
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps([]string{"--cache-list"}, nil, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "vault.example/aws/sts/dev/1h.abcd1234") {
		t.Fatalf("expected listed key in stdout, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "status=expired") {
		t.Fatalf("expected expired status in stdout, got %q", stdout.String())
	}
}

func TestRunCachePurgeKeys(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{}
	deps := runDeps{
		newTokenResolver: func() tokenResolver { return fakeTokenResolver{} },
		newVaultClient:   func(cfg vault.ClientConfig) (vaultClient, error) { return fakeVaultClient{}, nil },
		newCacheStore:    func() (credentialCache, error) { return cacheStore, nil },
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps([]string{"--cache-purge=a,b"}, nil, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if len(cacheStore.purgedKeys) != 2 {
		t.Fatalf("expected two purged keys, got %#v", cacheStore.purgedKeys)
	}
}

func TestRunCachePurgeExpired(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{purgeExpiredN: 3}
	deps := runDeps{
		newTokenResolver: func() tokenResolver { return fakeTokenResolver{} },
		newVaultClient:   func(cfg vault.ClientConfig) (vaultClient, error) { return fakeVaultClient{}, nil },
		newCacheStore:    func() (credentialCache, error) { return cacheStore, nil },
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps([]string{"--cache-purge-expired"}, nil, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "purged 3 expired cache entr(ies)") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestRunCachePurgeAll(t *testing.T) {
	t.Parallel()

	cacheStore := &fakeCacheStore{purgeAllN: 4}
	deps := runDeps{
		newTokenResolver: func() tokenResolver { return fakeTokenResolver{} },
		newVaultClient:   func(cfg vault.ClientConfig) (vaultClient, error) { return fakeVaultClient{}, nil },
		newCacheStore:    func() (credentialCache, error) { return cacheStore, nil },
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps([]string{"--cache-purge-all"}, nil, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "purged 4 cache entr(ies)") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestRunCacheKeyringRecoveryHelp(t *testing.T) {
	t.Parallel()

	deps := runDeps{
		newTokenResolver: func() tokenResolver { return fakeTokenResolver{} },
		newVaultClient:   func(cfg vault.ClientConfig) (vaultClient, error) { return fakeVaultClient{}, nil },
		newCacheStore:    func() (credentialCache, error) { return &fakeCacheStore{}, nil },
	}

	var stdout strings.Builder
	var stderr strings.Builder
	exit := runWithDeps([]string{"--cache-keyring-recovery-help"}, nil, &stdout, &stderr, deps)
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", exit, stderr.String())
	}
	if !strings.Contains(strings.ToLower(stdout.String()), "reset") && !strings.Contains(strings.ToLower(stdout.String()), "recovery") {
		t.Fatalf("unexpected help output: %q", stdout.String())
	}
}
