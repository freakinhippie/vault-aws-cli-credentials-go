package config

import (
	"os"
	"path/filepath"
	"strings"
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

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vaultcreds.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestParseConfigFileUnknownKeyFails(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "vault_addr = \"https://v\"\nvaultaddress = \"typo\"\n")
	_, err := parseConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "unknown config key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
	if !strings.Contains(err.Error(), ":2") {
		t.Fatalf("expected line number in error, got %v", err)
	}
}

func TestParseConfigFileDuplicateKeyFails(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "role = \"a\"\nrole = \"b\"\n")
	_, err := parseConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestParseConfigFileSectionHeaderFailsWithGuidance(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "[vault]\nvault_addr = \"https://v\"\n")
	_, err := parseConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "section header") {
		t.Fatalf("expected section header error, got %v", err)
	}
}

func TestParseConfigFileMissingEqualsFails(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "just-a-key\n")
	_, err := parseConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "key = value") {
		t.Fatalf("expected key = value error, got %v", err)
	}
}

func TestParseConfigFileStripsUTF8BOM(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "\ufeffvault_addr = \"https://bom.example\"\nrole = \"r\"\n")
	cfg, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("parse with BOM: %v", err)
	}
	if cfg.VaultAddr != "https://bom.example" {
		t.Fatalf("BOM broke first key: %q", cfg.VaultAddr)
	}
}

func TestParseConfigFileHashInsideUnquotedValue(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "vault_token = hvs.CAESsecret#123\nvault_addr = https://x#frag\n")
	cfg, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.VaultToken != "hvs.CAESsecret#123" {
		t.Fatalf("token truncated at #: %q", cfg.VaultToken)
	}
	if cfg.VaultAddr != "https://x#frag" {
		t.Fatalf("addr truncated at #: %q", cfg.VaultAddr)
	}
}

func TestParseConfigFileQuotedKey(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "\"ttl\" = \"90s\"\n")
	cfg, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("parse quoted key: %v", err)
	}
	if cfg.TTL != "90s" {
		t.Fatalf("quoted key mismatch: %q", cfg.TTL)
	}
}

func TestParseConfigFileInvalidBooleanFails(t *testing.T) {
	t.Parallel()

	path := writeTempConfig(t, "cache_credentials = yes-please\n")
	_, err := parseConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "invalid boolean") {
		t.Fatalf("expected invalid boolean error, got %v", err)
	}
}
