package cache

import (
	"errors"
	"strings"
	"testing"

	"github.com/byteness/keyring"
)

func TestDefaultKeyringConfigForOS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		goos      string
		available []keyring.BackendType
		wantName  string
		wantErr   string
	}{
		{
			name:      "linux secret service",
			goos:      "linux",
			available: []keyring.BackendType{keyring.SecretServiceBackend},
			wantName:  "secret-service",
		},
		{
			name:      "darwin keychain",
			goos:      "darwin",
			available: []keyring.BackendType{keyring.KeychainBackend},
			wantName:  "keychain",
		},
		{
			name:      "windows wincred",
			goos:      "windows",
			available: []keyring.BackendType{keyring.WinCredBackend},
			wantName:  "wincred",
		},
		{
			name:      "darwin missing keychain backend",
			goos:      "darwin",
			available: nil,
			wantErr:   "rebuild on macOS with cgo enabled",
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
			if cfg.ServiceName != serviceName {
				t.Fatalf("expected service name %q, got %q", serviceName, cfg.ServiceName)
			}
			if len(cfg.AllowedBackends) != 1 || cfg.AllowedBackends[0] != tt.available[0] {
				t.Fatalf("unexpected allowed backends: %#v", cfg.AllowedBackends)
			}
		})
	}
}
