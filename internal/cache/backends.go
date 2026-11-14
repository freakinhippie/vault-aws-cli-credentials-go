package cache

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/byteness/keyring"
)

const (
	serviceName = "vaultcreds"
)

var openKeyring = keyring.Open
var availableBackends = keyring.AvailableBackends

// preferredSecureBackends lists, per OS, the keyring backends that store
// secrets in OS-protected storage. Insecure backends (file) are never
// allowed; the keyring library picks the first listed backend that actually
// opens, so headless Linux sessions can still fall through to the secure
// kernel keyctl or pass(1) backends when no Secret Service daemon runs.
var preferredSecureBackends = map[string][]keyring.BackendType{
	"linux":   {keyring.SecretServiceBackend, keyring.KeyCtlBackend, keyring.PassBackend},
	"darwin":  {keyring.KeychainBackend},
	"windows": {keyring.WinCredBackend},
}

type keyringBackend struct {
	name string
	ring keyring.Keyring
}

func NewDefaultStore() (*Store, error) {
	return newStoreWithScope("session")
}

func newStoreWithScope(scope string) (*Store, error) {
	cfg, _, err := defaultKeyringConfig()
	if err != nil {
		return nil, err
	}

	switch scope {
	case "session", "user", "usersession":
		cfg.KeyCtlScope = scope
	default:
		return nil, fmt.Errorf("invalid keyctl scope %q", scope)
	}
	var failures []error
	for _, backend := range cfg.AllowedBackends {
		selected := cfg
		selected.AllowedBackends = []keyring.BackendType{backend}
		ring, err := openKeyring(selected)
		if err == nil {
			return NewStore(&keyringBackend{name: string(backend), ring: ring}), nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", backend, err))
	}
	return nil, fmt.Errorf("%w: %w", ErrNoSecureBackend, errors.Join(failures...))
}

func (b *keyringBackend) Get(key string) (string, error) {
	if err := validateBackendKey(key); err != nil {
		return "", err
	}
	item, err := b.ring.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("cache backend %s get failed: %w", b.name, err)
	}
	return string(item.Data), nil
}

func (b *keyringBackend) Set(key, value string) error {
	if err := validateBackendKey(key); err != nil {
		return err
	}
	err := b.ring.Set(keyring.Item{
		Key:   key,
		Label: fmt.Sprintf("vaultcreds cached aws credentials: %s", key),
		Data:  []byte(value),
	})
	if err != nil {
		return fmt.Errorf("cache backend %s set failed: %w", b.name, err)
	}
	return nil
}

func (b *keyringBackend) Keys() ([]string, error) {
	keys, err := b.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("cache backend %s list failed: %w", b.name, err)
	}
	return keys, nil
}

func (b *keyringBackend) Remove(key string) (bool, error) {
	if err := validateBackendKey(key); err != nil {
		return false, err
	}
	// Some backends report success for absent items. Enumerate metadata rather
	// than decrypting a secret to distinguish absence consistently.
	keys, err := b.Keys()
	if err != nil {
		return false, err
	}
	if !slices.Contains(keys, key) {
		return false, nil
	}
	if err := b.ring.Remove(key); err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("cache backend %s remove failed: %w", b.name, err)
	}
	return true, nil
}

func defaultKeyringConfig() (keyring.Config, string, error) {
	return defaultKeyringConfigForOS(runtime.GOOS, availableBackends())
}

func defaultKeyringConfigForOS(goos string, available []keyring.BackendType) (keyring.Config, string, error) {
	preferred, supported := preferredSecureBackends[goos]
	if !supported {
		return keyring.Config{}, "", ErrNoSecureBackend
	}

	var allowed []keyring.BackendType
	for _, backend := range preferred {
		if hasBackend(available, backend) {
			allowed = append(allowed, backend)
		}
	}
	if len(allowed) == 0 {
		return keyring.Config{}, "", fmt.Errorf("%w: no secure %s keyring backend is available (tried: %s)%s",
			ErrNoSecureBackend, goos, joinBackends(preferred), osSpecificHint(goos))
	}

	return keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: allowed,
		KeyCtlScope:     "session",
		PassPrefix:      serviceName,
	}, string(allowed[0]), nil
}

func osSpecificHint(goos string) string {
	switch goos {
	case "darwin":
		return "; rebuild on macOS with cgo enabled"
	case "linux":
		return "; start a Secret Service daemon or ensure keyctl/pass(1) is usable"
	default:
		return ""
	}
}

func joinBackends(backends []keyring.BackendType) string {
	names := make([]string, 0, len(backends))
	for _, backend := range backends {
		names = append(names, string(backend))
	}
	return strings.Join(names, ", ")
}

func hasBackend(backends []keyring.BackendType, want keyring.BackendType) bool {
	for _, backend := range backends {
		if backend == want {
			return true
		}
	}
	return false
}

// Keys become paths inside the pass prefix. Never allow traversal or option
// injection, including Windows-style separators on Unix.
func validateBackendKey(key string) error {
	if key == "" || strings.ContainsAny(key, "\\\x00\r\n") || strings.HasPrefix(key, "-") {
		return errors.New("invalid credential cache key")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("invalid credential cache key path")
		}
	}
	return nil
}
