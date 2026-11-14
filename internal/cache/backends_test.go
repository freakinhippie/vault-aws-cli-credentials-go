package cache

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/byteness/keyring"
)

// A successful build must retain the native secure storage backend. In
// particular, compiling a macOS binary without Keychain support would silently
// disable caching even though the credential fetch path still worked.
func TestNativeSecureBackendRegistered(t *testing.T) {
	t.Parallel()
	var required keyring.BackendType
	switch runtime.GOOS {
	case "darwin":
		required = keyring.KeychainBackend
	case "windows":
		required = keyring.WinCredBackend
	case "linux":
		required = keyring.KeyCtlBackend
	default:
		t.Skip("no supported native backend on this platform")
	}
	if !slices.Contains(keyring.AvailableBackends(), required) {
		t.Fatalf("native %s backend %q is missing from this build", runtime.GOOS, required)
	}
}

func TestDefaultKeyringConfigForOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		goos        string
		available   []keyring.BackendType
		wantName    string
		wantAllowed []keyring.BackendType
		wantErr     string
	}{
		{
			name:        "linux secret service",
			goos:        "linux",
			available:   []keyring.BackendType{keyring.SecretServiceBackend},
			wantName:    "secret-service",
			wantAllowed: []keyring.BackendType{keyring.SecretServiceBackend},
		},
		{
			name:        "linux headless falls back to keyctl",
			goos:        "linux",
			available:   []keyring.BackendType{keyring.KeyCtlBackend, keyring.PassBackend},
			wantName:    "keyctl",
			wantAllowed: []keyring.BackendType{keyring.KeyCtlBackend, keyring.PassBackend},
		},
		{
			name:        "linux only pass",
			goos:        "linux",
			available:   []keyring.BackendType{keyring.PassBackend},
			wantName:    "pass",
			wantAllowed: []keyring.BackendType{keyring.PassBackend},
		},
		{
			name:        "linux never allows file backend",
			goos:        "linux",
			available:   []keyring.BackendType{keyring.FileBackend, keyring.SecretServiceBackend, keyring.KWalletBackend},
			wantName:    "secret-service",
			wantAllowed: []keyring.BackendType{keyring.SecretServiceBackend},
		},
		{
			name:      "linux without secure backend fails",
			goos:      "linux",
			available: []keyring.BackendType{keyring.FileBackend},
			wantErr:   "no secure linux keyring backend",
		},
		{
			name:        "darwin keychain",
			goos:        "darwin",
			available:   []keyring.BackendType{keyring.KeychainBackend},
			wantName:    "keychain",
			wantAllowed: []keyring.BackendType{keyring.KeychainBackend},
		},
		{
			name:        "windows wincred",
			goos:        "windows",
			available:   []keyring.BackendType{keyring.WinCredBackend},
			wantName:    "wincred",
			wantAllowed: []keyring.BackendType{keyring.WinCredBackend},
		},
		{
			name:      "darwin missing keychain backend",
			goos:      "darwin",
			available: nil,
			wantErr:   "rebuild on macOS with cgo enabled",
		},
		{
			name:      "unknown os",
			goos:      "plan9",
			available: []keyring.BackendType{keyring.FileBackend},
			wantErr:   ErrNoSecureBackend.Error(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, name, err := defaultKeyringConfigForOS(tt.goos, tt.available)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrNoSecureBackend) {
					t.Fatalf("expected ErrNoSecureBackend, got %v", err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != tt.wantName {
				t.Fatalf("expected backend name %q, got %q", tt.wantName, name)
			}
			if cfg.KeyCtlScope != "session" || cfg.PassPrefix != serviceName {
				t.Fatalf("unsafe backend config: scope=%q prefix=%q", cfg.KeyCtlScope, cfg.PassPrefix)
			}
			if cfg.ServiceName != serviceName {
				t.Fatalf("expected service name %q, got %q", serviceName, cfg.ServiceName)
			}
			if len(cfg.AllowedBackends) != len(tt.wantAllowed) {
				t.Fatalf("expected allowed backends %#v, got %#v", tt.wantAllowed, cfg.AllowedBackends)
			}
			for i := range tt.wantAllowed {
				if cfg.AllowedBackends[i] != tt.wantAllowed[i] {
					t.Fatalf("expected allowed backends %#v, got %#v", tt.wantAllowed, cfg.AllowedBackends)
				}
			}
			for _, b := range cfg.AllowedBackends {
				if b == keyring.FileBackend {
					t.Fatal("file backend must never be allowed")
				}
			}
		})
	}
}

// TestNewDefaultStoreFailsClosed locks in the core security contract: when
// the OS keyring cannot be opened, vaultcreds must return ErrNoSecureBackend
// (so the caller disables caching) rather than falling back to any insecure
// store.
func TestNewDefaultStoreFailsClosed(t *testing.T) {
	origOpen := openKeyring
	origAvailable := availableBackends
	t.Cleanup(func() {
		openKeyring = origOpen
		availableBackends = origAvailable
	})

	availableBackends = func() []keyring.BackendType {
		return []keyring.BackendType{
			keyring.SecretServiceBackend,
			keyring.KeychainBackend,
			keyring.WinCredBackend,
			keyring.KeyCtlBackend,
			keyring.PassBackend,
		}
	}
	openKeyring = func(keyring.Config) (keyring.Keyring, error) {
		return nil, errors.New("keyring unavailable")
	}

	_, err := NewDefaultStore()
	if !errors.Is(err, ErrNoSecureBackend) {
		t.Fatalf("expected ErrNoSecureBackend, got %v", err)
	}
	if !strings.Contains(err.Error(), "keyring unavailable") {
		t.Fatalf("expected underlying cause in error, got %v", err)
	}
}

type fakeRing struct {
	items    map[string]string
	getErr   error
	removeOK bool
}

func (f *fakeRing) Get(key string) (keyring.Item, error) {
	if f.getErr != nil {
		return keyring.Item{}, f.getErr
	}
	v, ok := f.items[key]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return keyring.Item{Key: key, Data: []byte(v)}, nil
}

func (f *fakeRing) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}

func (f *fakeRing) Set(item keyring.Item) error {
	if f.items == nil {
		f.items = map[string]string{}
	}
	f.items[item.Key] = string(item.Data)
	return nil
}

func (f *fakeRing) Remove(key string) error {
	if _, ok := f.items[key]; !ok {
		if f.removeOK {
			return nil
		}
		return keyring.ErrKeyNotFound
	}
	delete(f.items, key)
	return nil
}

func (f *fakeRing) Keys() ([]string, error) {
	keys := make([]string, 0, len(f.items))
	for k := range f.items {
		keys = append(keys, k)
	}
	return keys, nil
}

func TestKeyringBackendGetNotFoundIsMiss(t *testing.T) {
	t.Parallel()

	backend := &keyringBackend{name: "fake", ring: &fakeRing{}}
	got, err := backend.Get("missing")
	if err != nil {
		t.Fatalf("missing key must be a miss, not an error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty value on miss, got %q", got)
	}
}

func TestKeyringBackendGetRealErrorIsError(t *testing.T) {
	t.Parallel()

	backend := &keyringBackend{name: "fake", ring: &fakeRing{getErr: errors.New("keychain locked")}}
	_, err := backend.Get("k")
	if err == nil {
		t.Fatal("expected backend error, not a silent miss")
	}
	if !strings.Contains(err.Error(), "keychain locked") {
		t.Fatalf("expected underlying cause, got %v", err)
	}
}

func TestKeyringBackendRemoveReportsExistence(t *testing.T) {
	t.Parallel()

	ring := &fakeRing{items: map[string]string{"k": "v"}}
	backend := &keyringBackend{name: "fake", ring: ring}

	removed, err := backend.Remove("k")
	if err != nil || !removed {
		t.Fatalf("expected removal of existing key, got removed=%v err=%v", removed, err)
	}

	removed, err = backend.Remove("k")
	if err != nil || removed {
		t.Fatalf("expected not-found to report removed=false, got removed=%v err=%v", removed, err)
	}
}

func TestKeyringRemovalCountsWithIdempotentBackend(t *testing.T) {
	t.Parallel()
	ring := &fakeRing{items: map[string]string{"k": "v"}, removeOK: true}
	store := NewStore(&keyringBackend{name: "fake-secret-service", ring: ring})
	n, err := store.PurgeKeys([]string{"missing", "k", "k"})
	if err != nil || n != 1 {
		t.Fatalf("removed=%d err=%v", n, err)
	}
}

func TestBackendKeyRejectsTraversal(t *testing.T) {
	t.Parallel()
	backend := &keyringBackend{name: "pass", ring: &fakeRing{}}
	for _, key := range []string{"../other", "safe/../../other", "/absolute", "safe//key", `safe\..\other`, "-option", "safe/./key", ""} {
		if err := backend.Set(key, "secret"); err == nil {
			t.Fatalf("accepted write key %q", key)
		}
		if _, err := backend.Get(key); err == nil {
			t.Fatalf("accepted read key %q", key)
		}
		if _, err := backend.Remove(key); err == nil {
			t.Fatalf("accepted removal key %q", key)
		}
	}
}

func TestPassMaintenanceIsIsolated(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pass fallback")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	t.Setenv("VAULTCREDS_TEST_PASS_LOG", logPath)
	script := filepath.Join(dir, "pass")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\n' \"$*\" >> \"$VAULTCREDS_TEST_PASS_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, serviceName)
	if err := os.Mkdir(prefix, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "bank.gpg"), filepath.Join(prefix, "cache-key.gpg")} {
		if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _, err := defaultKeyringConfigForOS("linux", []keyring.BackendType{keyring.PassBackend})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PassDir, cfg.PassCmd = dir, script
	ring, err := keyring.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewStore(&keyringBackend{name: "pass", ring: ring}).PurgeAll()
	if err != nil || n != 1 {
		t.Fatalf("removed=%d err=%v", n, err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(calls) != "rm -f vaultcreds/cache-key\n" {
		t.Fatalf("unexpected pass commands: %s", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "bank.gpg")); err != nil {
		t.Fatal("unrelated secret touched")
	}
}

func TestConfiguredScopeReachesKeyring(t *testing.T) {
	originalOpen, originalAvailable := openKeyring, availableBackends
	t.Cleanup(func() { openKeyring, availableBackends = originalOpen, originalAvailable })
	availableBackends = func() []keyring.BackendType {
		return []keyring.BackendType{keyring.KeyCtlBackend, keyring.KeychainBackend, keyring.WinCredBackend}
	}
	for _, scope := range []string{"session", "user", "usersession"} {
		openKeyring = func(cfg keyring.Config) (keyring.Keyring, error) {
			if cfg.KeyCtlScope != scope {
				t.Fatalf("scope=%q want=%q", cfg.KeyCtlScope, scope)
			}
			return &fakeRing{}, nil
		}
		if _, err := newStoreWithScope(scope); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := newStoreWithScope("process"); err == nil {
		t.Fatal("accepted process scope")
	}
}
