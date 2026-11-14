package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestLoadConfigFileFlagFormsAllLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vaultcreds.toml")
	content := "vault_addr = \"https://file.example\"\nrole = \"file-role\"\nmount = \"file-mount\"\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	formats := [][]string{
		{"-c", cfgPath},
		{"-c=" + cfgPath},
		{"--config", cfgPath},
		{"--config=" + cfgPath},
		{"-config", cfgPath},
		{"-config=" + cfgPath},
	}

	// All spellings the Go flag package accepts must load the file and
	// produce identical settings.
	for _, args := range formats {
		args := args
		t.Run("values/"+strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			cfg, err := Load(append([]string{"--validate-config"}, args...), nil)
			if err != nil {
				t.Fatalf("load with %v: %v", args, err)
			}
			if cfg.VaultAddr != "https://file.example" || cfg.Role != "file-role" || cfg.Mount != "file-mount" {
				t.Fatalf("config file not applied for %v: %+v", args, cfg)
			}
			if cfg.ConfigPath != cfgPath {
				t.Fatalf("config path mismatch: %q", cfg.ConfigPath)
			}
		})
	}
}

func TestLoadConfigFlagOverridesEnvPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.toml")
	pathB := filepath.Join(dir, "b.toml")
	if err := os.WriteFile(pathA, []byte("vault_addr = \"https://a.example\"\nrole = \"role-a\"\n"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(pathB, []byte("vault_addr = \"https://b.example\"\nrole = \"role-b\"\n"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}

	// env path + flag path: the flag file must win, not the env file.
	cfg, err := Load([]string{"--validate-config", "-config=" + pathB}, []string{"VAULTCREDS_CONFIG=" + pathA})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.VaultAddr != "https://b.example" || cfg.Role != "role-b" || cfg.ConfigPath != pathB {
		t.Fatalf("flag config path did not win: %+v", cfg)
	}

	// duplicate flags: the last one wins for both values and reported path.
	cfg, err = Load([]string{"--validate-config", "-c", pathA, "-c", pathB}, nil)
	if err != nil {
		t.Fatalf("load dup: %v", err)
	}
	if cfg.VaultAddr != "https://b.example" || cfg.Role != "role-b" || cfg.ConfigPath != pathB {
		t.Fatalf("duplicate -c did not use last value: %+v", cfg)
	}
}

func TestLoadEmptyConfigFlagIsError(t *testing.T) {
	t.Parallel()

	_, err := Load([]string{"--config", "", "--validate-config"}, []string{"VAULTCREDS_CONFIG=/tmp/whatever.toml"})
	if err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("expected non-empty config error, got %v", err)
	}
}

func TestLoadMissingConfigFileIsFatal(t *testing.T) {
	t.Parallel()

	_, err := Load([]string{"--config=/nope/missing.toml", "--validate-config"}, nil)
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func writeBrokenConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broken.toml")
	if err := os.WriteFile(path, []byte("this is not valid\n"), 0o600); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	return path
}

func TestLoadModeFlagsTolerateBrokenConfigFile(t *testing.T) {
	t.Parallel()

	broken := writeBrokenConfig(t)

	cfg, err := Load([]string{"--version"}, []string{"VAULTCREDS_CONFIG=" + broken})
	if err != nil || !cfg.ShowVersion {
		t.Fatalf("--version must ignore broken config: %v", err)
	}

	cfg, err = Load([]string{"--cache-list"}, []string{"VAULTCREDS_CONFIG=" + broken})
	if err != nil || !cfg.CacheList {
		t.Fatalf("--cache-list must ignore broken config: %v", err)
	}

	cfg, err = Load([]string{"--cache-purge-all"}, []string{"VAULTCREDS_CONFIG=" + broken})
	if err != nil || !cfg.CachePurgeAll {
		t.Fatalf("--cache-purge-all must ignore broken config: %v", err)
	}

	if _, err := Load([]string{"--validate-config"}, []string{"VAULTCREDS_CONFIG=" + broken}); err == nil {
		t.Fatal("--validate-config must report broken config errors")
	}
}

func TestLoadTTLValidation(t *testing.T) {
	t.Parallel()

	valid := []string{"0", "0s", "+1h", "3600", "60", "1s", "90s", "1h", "1.5h", "0.5h", "30m", "1h30m", "7d", "1w", "1d12h"}
	invalid := []string{"NaN", "Inf", "inf", "-Inf", "-1", "1e300", "1x", "abc", "1h30", "d", "1..5h", "-5m", "9223372036854775807", "999999999999999999d"}

	for _, v := range valid {
		if err := validateTTL(v); err != nil {
			t.Fatalf("ttl %q should be valid: %v", v, err)
		}
	}
	for _, v := range invalid {
		if err := validateTTL(v); err == nil {
			t.Fatalf("ttl %q should be invalid", v)
		}
	}
}

func TestLoadTTLThroughLoad(t *testing.T) {
	t.Parallel()

	env := []string{"VAULT_ADDR=https://vault.example", "VAULTCREDS_ROLE=r"}

	cfg, err := Load([]string{"--validate-config", "--ttl=1h30m"}, env)
	if err != nil {
		t.Fatalf("compound ttl should load: %v", err)
	}
	if cfg.TTL != "1h30m" {
		t.Fatalf("ttl mismatch: %q", cfg.TTL)
	}

	if _, err := Load([]string{"--validate-config", "--ttl=NaN"}, env); err == nil {
		t.Fatal("NaN ttl should fail validation")
	}
	if _, err := Load([]string{"--validate-config", "--ttl=-1"}, env); err == nil {
		t.Fatal("negative ttl should fail validation")
	}
}

func TestLoadInvalidBooleanEnvFails(t *testing.T) {
	t.Parallel()

	_, err := Load(nil, []string{
		"VAULT_ADDR=https://vault.example",
		"VAULTCREDS_ROLE=r",
		"VAULT_SKIP_VERIFY=yes",
	})
	if err == nil || !strings.Contains(err.Error(), "VAULT_SKIP_VERIFY") {
		t.Fatalf("expected VAULT_SKIP_VERIFY boolean error, got %v", err)
	}

	_, err = Load(nil, []string{
		"VAULT_ADDR=https://vault.example",
		"VAULTCREDS_ROLE=r",
		"VAULTCREDS_CACHE_CREDENTIALS=enabled",
	})
	if err == nil || !strings.Contains(err.Error(), "VAULTCREDS_CACHE_CREDENTIALS") {
		t.Fatalf("expected VAULTCREDS_CACHE_CREDENTIALS boolean error, got %v", err)
	}
}

func TestLoadClientTimeout(t *testing.T) {
	t.Parallel()

	cfg, err := Load(nil, []string{"VAULT_ADDR=https://v", "VAULTCREDS_ROLE=r", "VAULT_CLIENT_TIMEOUT=90"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ClientTimeout != 90*time.Second {
		t.Fatalf("timeout mismatch: %v", cfg.ClientTimeout)
	}

	cfg, err = Load(nil, []string{"VAULT_ADDR=https://v", "VAULTCREDS_ROLE=r", "VAULT_CLIENT_TIMEOUT=2m"})
	if err != nil {
		t.Fatalf("load duration: %v", err)
	}
	if cfg.ClientTimeout != 2*time.Minute {
		t.Fatalf("timeout mismatch: %v", cfg.ClientTimeout)
	}

	if _, err := Load(nil, []string{"VAULT_ADDR=https://v", "VAULTCREDS_ROLE=r", "VAULT_CLIENT_TIMEOUT=-5"}); err == nil {
		t.Fatal("negative timeout should fail")
	}
	if _, err := Load(nil, []string{"VAULT_ADDR=https://v", "VAULTCREDS_ROLE=r", "VAULT_CLIENT_TIMEOUT=banana"}); err == nil {
		t.Fatal("garbage timeout should fail")
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
	if cfg.ClientTimeout != 60*time.Second {
		t.Fatalf("default timeout mismatch: %v", cfg.ClientTimeout)
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

	_, err = Load([]string{"--cache-list", "--cache-purge", "k"}, nil)
	if err == nil {
		t.Fatal("expected mutually exclusive operation error for list+purge")
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

func TestLoadCachePurgeEmptyIsError(t *testing.T) {
	t.Parallel()

	if _, err := Load([]string{"--cache-purge", ""}, nil); err == nil {
		t.Fatal("expected error for empty --cache-purge")
	}
	if _, err := Load([]string{"--cache-purge", ","}, nil); err == nil {
		t.Fatal("expected error for no-op --cache-purge")
	}
}

func TestLoadVersionDoesNotRequireVaultSettings(t *testing.T) {
	t.Parallel()

	cfg, err := Load([]string{"--version"}, nil)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.ShowVersion {
		t.Fatal("expected version mode")
	}
}

func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	homeEnv := "HOME"
	if runtime.GOOS == "windows" {
		homeEnv = "USERPROFILE"
	}
	t.Setenv(homeEnv, home)

	got, err := expandHome("~/ca.pem")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if got != filepath.Join(home, "ca.pem") {
		t.Fatalf("expand mismatch: %q", got)
	}

	plain, err := expandHome("/etc/ca.pem")
	if err != nil || plain != "/etc/ca.pem" {
		t.Fatalf("plain path changed: %q %v", plain, err)
	}
}

func TestLoadCacertTildeExpansion(t *testing.T) {
	home := t.TempDir()
	homeEnv := "HOME"
	if runtime.GOOS == "windows" {
		homeEnv = "USERPROFILE"
	}
	t.Setenv(homeEnv, home)

	cfg, err := Load(nil, []string{
		"VAULT_ADDR=https://vault.example",
		"VAULTCREDS_ROLE=r",
		"VAULT_CACERT=~/ca.pem",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.VaultCACert != filepath.Join(home, "ca.pem") {
		t.Fatalf("cacert not expanded: %q", cfg.VaultCACert)
	}
}

func TestCacheKeyctlScopePrecedence(t *testing.T) {
	t.Parallel()
	path := writeTempConfig(t, "vault_addr = https://vault.example\nrole = r\ncache_keyctl_scope = user\n")
	for _, tc := range []struct {
		args, env []string
		want      string
	}{
		{args: []string{"--role=r", "--vault-addr=https://v"}, want: "session"},
		{args: []string{"--config", path}, want: "user"},
		{args: []string{"--config", path}, env: []string{"VAULTCREDS_CACHE_KEYCTL_SCOPE=usersession"}, want: "usersession"},
		{args: []string{"--config", path, "--cache-keyctl-scope=session"}, env: []string{"VAULTCREDS_CACHE_KEYCTL_SCOPE=user"}, want: "session"},
	} {
		cfg, err := Load(tc.args, tc.env)
		if err != nil || cfg.CacheKeyctlScope != tc.want {
			t.Fatalf("scope=%q want=%q err=%v", cfg.CacheKeyctlScope, tc.want, err)
		}
	}
	for _, scope := range []string{"", "process", "thread", "group", "unknown"} {
		if _, err := Load([]string{"--cache-list", "--cache-keyctl-scope=" + scope}, nil); err == nil {
			t.Fatalf("accepted scope %q", scope)
		}
	}
}

func TestRecoveryIgnoresCredentialEnvironment(t *testing.T) {
	t.Parallel()
	env := []string{"VAULT_SKIP_VERIFY=yes", "VAULT_CLIENT_TIMEOUT=invalid", "VAULT_DISABLE_REDIRECTS=invalid", "VAULTCREDS_CACHE_CREDENTIALS=invalid", "VAULTCREDS_CONFIG=/missing"}
	for _, args := range [][]string{{"--version"}, {"--cache-list"}, {"--cache-purge-all"}, {"--cache-keyring-recovery-help"}} {
		if _, err := Load(args, env); err != nil {
			t.Fatalf("%v blocked: %v", args, err)
		}
	}
}

func TestDurationWireValuesAndOverflow(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{"1w": "168h0m0s", "1d12h": "36h0m0s", "7d": "168h0m0s", "1h30m": "1h30m", "0": "0", "0s": "0s", "1ms": "1ms"} {
		cfg, err := Load([]string{"--role=r", "--vault-addr=https://v", "--ttl=" + input}, nil)
		if err != nil || cfg.TTL != want {
			t.Fatalf("%q normalized=%q want=%q err=%v", input, cfg.TTL, want, err)
		}
	}
	for _, input := range []string{"18446744074", "9223372036854775807", "2562047h47m16s"} {
		if _, err := parseClientTimeout(input); err == nil {
			t.Fatalf("accepted overflow timeout %q", input)
		}
	}
}

func TestLoadVaultDisableRedirects(t *testing.T) {
	t.Parallel()
	cfg, err := Load([]string{"--role=r", "--vault-addr=https://v"}, []string{"VAULT_DISABLE_REDIRECTS=true"})
	if err != nil || !cfg.VaultDisableRedirects {
		t.Fatalf("redirect config ignored: %v", err)
	}
}
