package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrecedence(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "vaultcreds.toml")
	content := "vault_addr = \"https://file.example\"\nrole = \"file-role\"\nmount = \"file-mount\"\ncredential_type = \"creds\"\ncache_credentials = true\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	env := []string{
		"VAULTCREDS_CONFIG=" + cfgPath,
		"VAULT_ADDR=https://env.example",
		"VAULTCREDS_ROLE=env-role",
		"VAULTCREDS_MOUNT=env-mount",
		"VAULTCREDS_CREDENTIAL_TYPE=sts",
	}

	args := []string{
		"--vault-addr", "https://flag.example",
		"--role", "flag-role",
		"--mount", "flag-mount",
		"--type", "creds",
		"--cache=true",
	}

	cfg, err := Load(args, env)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.VaultAddr != "https://flag.example" {
		t.Fatalf("vault addr mismatch: %q", cfg.VaultAddr)
	}
	if cfg.Role != "flag-role" {
		t.Fatalf("role mismatch: %q", cfg.Role)
	}
	if cfg.Mount != "flag-mount" {
		t.Fatalf("mount mismatch: %q", cfg.Mount)
	}
	if cfg.CredentialType != "creds" {
		t.Fatalf("credential type mismatch: %q", cfg.CredentialType)
	}
	if !cfg.CacheCredentials {
		t.Fatal("expected cache credentials to be true")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(nil, []string{"VAULT_ADDR=https://vault.example", "VAULTCREDS_ROLE=my-role"})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Mount != "aws" {
		t.Fatalf("mount mismatch: %q", cfg.Mount)
	}
	if cfg.CredentialType != "sts" {
		t.Fatalf("credential type mismatch: %q", cfg.CredentialType)
	}
	if cfg.TTL != "1h" {
		t.Fatalf("ttl mismatch: %q", cfg.TTL)
	}
}

func TestLoadHelp(t *testing.T) {
	t.Parallel()

	_, err := Load([]string{"--help"}, nil)
	if !errors.Is(err, ErrHelpRequested) {
		t.Fatalf("expected help error, got %v", err)
	}
}

func TestLoadValidation(t *testing.T) {
	t.Parallel()

	_, err := Load(nil, []string{"VAULTCREDS_ROLE=my-role"})
	if err == nil {
		t.Fatal("expected error for missing vault address")
	}

	_, err = Load(nil, []string{"VAULT_ADDR=https://vault.example"})
	if err == nil {
		t.Fatal("expected error for missing role")
	}

	_, err = Load(nil, []string{
		"VAULT_ADDR=https://vault.example",
		"VAULTCREDS_ROLE=my-role",
		"VAULTCREDS_CREDENTIAL_TYPE=invalid",
	})
	if err == nil {
		t.Fatal("expected invalid credential type error")
	}
}

func TestLoadValidateConfigFlag(t *testing.T) {
	t.Parallel()

	cfg, err := Load([]string{"--validate-config"}, []string{"VAULT_ADDR=https://vault.example", "VAULTCREDS_ROLE=my-role"})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.ValidateOnly {
		t.Fatal("expected validate-only mode")
	}
}

func TestLoadCacheMaintenanceDoesNotRequireVaultSettings(t *testing.T) {
	t.Parallel()

	cfg, err := Load([]string{"--cache-list"}, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.CacheList {
		t.Fatal("expected cache-list mode")
	}
}

func TestLoadCacheMaintenanceMutuallyExclusive(t *testing.T) {
	t.Parallel()

	_, err := Load([]string{"--cache-list", "--cache-purge-all"}, nil)
	if err == nil {
		t.Fatal("expected mutually exclusive operation error")
	}
}

func TestLoadCachePurgeCSV(t *testing.T) {
	t.Parallel()

	cfg, err := Load([]string{"--cache-purge", "k1, k2,,k3"}, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.CachePurgeKeys) != 3 {
		t.Fatalf("expected 3 keys, got %#v", cfg.CachePurgeKeys)
	}
}
