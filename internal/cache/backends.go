package cache

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/byteness/keyring"
)

const (
	serviceName = "vaultcreds"
)

var openKeyring = keyring.Open
var availableBackends = keyring.AvailableBackends

type keyringBackend struct {
	name string
	ring keyring.Keyring
}

func NewDefaultStore() (*Store, error) {
	cfg, backendName, err := defaultKeyringConfig()
	if err != nil {
		return nil, err
	}

	ring, err := openKeyring(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSecureBackend, err)
	}
	return NewStore(&keyringBackend{name: backendName, ring: ring}), nil
}

func (b *keyringBackend) Name() string { return b.name }

func (b *keyringBackend) Get(key string) (string, error) {
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

func (b *keyringBackend) Remove(key string) error {
	if err := b.ring.Remove(key); err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil
		}
		return fmt.Errorf("cache backend %s remove failed: %w", b.name, err)
	}
	return nil
}

func defaultKeyringConfig() (keyring.Config, string, error) {
	return defaultKeyringConfigForOS(runtime.GOOS, availableBackends())
}

func defaultKeyringConfigForOS(goos string, available []keyring.BackendType) (keyring.Config, string, error) {
	switch goos {
	case "linux":
		if !hasBackend(available, keyring.SecretServiceBackend) {
			return keyring.Config{}, "", fmt.Errorf("%w: linux secret-service backend is not compiled into this binary", ErrNoSecureBackend)
		}
		return keyring.Config{
			ServiceName:     serviceName,
			AllowedBackends: []keyring.BackendType{keyring.SecretServiceBackend},
		}, "secret-service", nil
	case "darwin":
		if !hasBackend(available, keyring.KeychainBackend) {
			return keyring.Config{}, "", fmt.Errorf("%w: macOS keychain backend is not compiled into this binary; rebuild on macOS with cgo enabled", ErrNoSecureBackend)
		}
		return keyring.Config{
			ServiceName:     serviceName,
			AllowedBackends: []keyring.BackendType{keyring.KeychainBackend},
		}, "keychain", nil
	case "windows":
		if !hasBackend(available, keyring.WinCredBackend) {
			return keyring.Config{}, "", fmt.Errorf("%w: windows credential manager backend is not compiled into this binary", ErrNoSecureBackend)
		}
		return keyring.Config{
			ServiceName:     serviceName,
			AllowedBackends: []keyring.BackendType{keyring.WinCredBackend},
		}, "wincred", nil
	default:
		return keyring.Config{}, "", ErrNoSecureBackend
	}
}

func hasBackend(backends []keyring.BackendType, want keyring.BackendType) bool {
	for _, backend := range backends {
		if backend == want {
			return true
		}
	}
	return false
}
