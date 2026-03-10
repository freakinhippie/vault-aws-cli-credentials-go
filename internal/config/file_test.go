package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "vaultcreds.toml")
	content := `
# comment
vault_addr = "https://vault.example"
vault_cacert = '/tmp/ca.pem'
vault-capath = "/etc/ssl/certs" # inline comment
mount = "aws-custom"
role = "app-role"
ttl = "1h"
credential_type = "creds"
cache_credentials = true
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := parseConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if cfg.VaultAddr != "https://vault.example" {
		t.Fatalf("vault addr mismatch: %q", cfg.VaultAddr)
	}
	if cfg.VaultCACert != "/tmp/ca.pem" {
		t.Fatalf("vault cacert mismatch: %q", cfg.VaultCACert)
	}
	if cfg.VaultCAPath != "/etc/ssl/certs" {
		t.Fatalf("vault capath mismatch: %q", cfg.VaultCAPath)
	}
	if cfg.Mount != "aws-custom" {
		t.Fatalf("mount mismatch: %q", cfg.Mount)
	}
	if cfg.Role != "app-role" {
		t.Fatalf("role mismatch: %q", cfg.Role)
	}
	if cfg.TTL != "1h" {
		t.Fatalf("ttl mismatch: %q", cfg.TTL)
	}
	if cfg.CredentialType != "creds" {
		t.Fatalf("credential type mismatch: %q", cfg.CredentialType)
	}
	if cfg.CacheCredentials == nil || !*cfg.CacheCredentials {
		t.Fatal("cache credentials mismatch")
	}
}
