package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var ErrHelpRequested = errors.New("help requested")

const (
	defaultMount          = "aws"
	defaultCredentialType = "sts"
	defaultTTL            = "1h"
)

func HelpText(binaryPath string) string {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "vaultcreds"
	}

	text := strings.TrimSpace(`
Usage:
  vaultcreds [flags]

Description:
  Retrieve short-lived AWS credentials from Vault/OpenBao and emit
  AWS credential_process JSON to stdout.

Flags:
  -c, --config string        Configuration file path (env: VAULTCREDS_CONFIG)
  -V, --vault-addr string    Vault server URL (env: VAULT_ADDR) [required]
  -C, --vault-cacert string  Vault CA certificate file (env: VAULT_CACERT)
      --vault-capath string  Vault CA certificates directory (env: VAULT_CAPATH)
  -m, --mount string         Vault AWS secrets backend mount (env: VAULTCREDS_MOUNT, default: aws)
  -r, --role string          Vault role (env: VAULTCREDS_ROLE) [required]
  -t, --ttl string           Requested credential TTL (env: VAULTCREDS_TTL, default: 1h)
  -T, --type string          Credential type: sts or creds (env: VAULTCREDS_CREDENTIAL_TYPE, default: sts)
      --cache                Enable secure credential caching (env: VAULTCREDS_CACHE_CREDENTIALS)
      --cache-list           List cache entries
      --cache-purge string   Purge comma-separated cache key(s)
      --cache-purge-expired  Purge expired cache entries
      --cache-purge-all      Purge all cache entries
      --cache-keyring-recovery-help  Show OS-specific keyring reset/recovery guidance
      --validate-config      Validate configuration and exit
  -h, --help                 Show help

Additional Vault env vars:
  VAULT_TOKEN, VAULT_TOKEN_HELPER, VAULT_NAMESPACE, VAULT_SKIP_VERIFY

Examples (AWS shared config):
  credential_process = {{ .BinaryPath }} --vault-addr=https://vault.example.com --role=dev-role
  credential_process = {{ .BinaryPath }} --vault-addr=https://vault.example.com --mount=aws-team --role=app-role --type=creds
  credential_process = {{ .BinaryPath }} --config=/etc/vaultcreds/config.toml
`)
	text = strings.ReplaceAll(text, "{{ .BinaryPath }}", binaryPath)
	return text
}

type Config struct {
	ConfigPath               string
	VaultAddr                string
	VaultCACert              string
	VaultCAPath              string
	VaultNamespace           string
	VaultToken               string
	VaultTokenHelper         string
	VaultSkipVerify          bool
	Mount                    string
	Role                     string
	TTL                      string
	CredentialType           string
	CacheCredentials         bool
	CacheList                bool
	CachePurgeKeys           []string
	CachePurgeExpired        bool
	CachePurgeAll            bool
	CacheKeyringRecoveryHelp bool
	ValidateOnly             bool
}

type fileConfig struct {
	VaultAddr        string
	VaultCACert      string
	VaultCAPath      string
	VaultNamespace   string
	VaultToken       string
	VaultTokenHelper string
	VaultSkipVerify  *bool
	Mount            string
	Role             string
	TTL              string
	CredentialType   string
	CacheCredentials *bool
}

func Load(args []string, environ []string) (Config, error) {
	env := envMap(environ)
	cfg := Config{
		ConfigPath:     env["VAULTCREDS_CONFIG"],
		Mount:          defaultMount,
		CredentialType: defaultCredentialType,
		TTL:            defaultTTL,
	}

	if path, ok := findConfigPathArg(args); ok {
		cfg.ConfigPath = path
	}

	if cfg.ConfigPath != "" {
		fc, err := parseConfigFile(cfg.ConfigPath)
		if err != nil {
			return Config{}, err
		}
		applyFileConfig(&cfg, fc)
	}

	applyEnvConfig(&cfg, env)

	var (
		flagConfigPath               string
		flagVaultAddr                string
		flagVaultCACert              string
		flagVaultCAPath              string
		flagMount                    string
		flagRole                     string
		flagTTL                      string
		flagType                     string
		flagCache                    bool
		flagCacheList                bool
		flagCachePurge               string
		flagCachePurgeExpired        bool
		flagCachePurgeAll            bool
		flagCacheKeyringRecoveryHelp bool
		flagValidateConfig           bool
	)

	fs := flag.NewFlagSet("vaultcreds", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flagConfigPath, "c", "", "Configuration file path")
	fs.StringVar(&flagConfigPath, "config", "", "Configuration file path")
	fs.StringVar(&flagVaultAddr, "V", "", "Vault server URL")
	fs.StringVar(&flagVaultAddr, "vault-addr", "", "Vault server URL")
	fs.StringVar(&flagVaultCACert, "C", "", "Vault CA certificate file")
	fs.StringVar(&flagVaultCACert, "vault-cacert", "", "Vault CA certificate file")
	fs.StringVar(&flagVaultCAPath, "vault-capath", "", "Vault CA certificate directory")
	fs.StringVar(&flagMount, "m", "", "Vault aws secrets engine mount")
	fs.StringVar(&flagMount, "mount", "", "Vault aws secrets engine mount")
	fs.StringVar(&flagRole, "r", "", "Vault role")
	fs.StringVar(&flagRole, "role", "", "Vault role")
	fs.StringVar(&flagTTL, "t", "", "Credential TTL")
	fs.StringVar(&flagTTL, "ttl", "", "Credential TTL")
	fs.StringVar(&flagType, "T", "", "Credential type (sts or creds)")
	fs.StringVar(&flagType, "type", "", "Credential type (sts or creds)")
	fs.BoolVar(&flagCache, "cache", false, "Cache credentials in secure storage")
	fs.BoolVar(&flagCacheList, "cache-list", false, "List cache entries")
	fs.StringVar(&flagCachePurge, "cache-purge", "", "Purge comma-separated cache key(s)")
	fs.BoolVar(&flagCachePurgeExpired, "cache-purge-expired", false, "Purge expired cache entries")
	fs.BoolVar(&flagCachePurgeAll, "cache-purge-all", false, "Purge all cache entries")
	fs.BoolVar(&flagCacheKeyringRecoveryHelp, "cache-keyring-recovery-help", false, "Show OS-specific keyring reset/recovery guidance")
	fs.BoolVar(&flagValidateConfig, "validate-config", false, "Validate configuration and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, ErrHelpRequested
		}
		return Config{}, err
	}

	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		seen[f.Name] = true
	})

	if seen["c"] || seen["config"] {
		cfg.ConfigPath = flagConfigPath
	}
	if seen["V"] || seen["vault-addr"] {
		cfg.VaultAddr = flagVaultAddr
	}
	if seen["C"] || seen["vault-cacert"] {
		cfg.VaultCACert = flagVaultCACert
	}
	if seen["vault-capath"] {
		cfg.VaultCAPath = flagVaultCAPath
	}
	if seen["m"] || seen["mount"] {
		cfg.Mount = flagMount
	}
	if seen["r"] || seen["role"] {
		cfg.Role = flagRole
	}
	if seen["t"] || seen["ttl"] {
		cfg.TTL = flagTTL
	}
	if seen["T"] || seen["type"] {
		cfg.CredentialType = flagType
	}
	if seen["cache"] {
		cfg.CacheCredentials = flagCache
	}
	if seen["cache-list"] {
		cfg.CacheList = flagCacheList
	}
	if seen["cache-purge"] {
		cfg.CachePurgeKeys = splitCSV(flagCachePurge)
	}
	if seen["cache-purge-expired"] {
		cfg.CachePurgeExpired = flagCachePurgeExpired
	}
	if seen["cache-purge-all"] {
		cfg.CachePurgeAll = flagCachePurgeAll
	}
	if seen["cache-keyring-recovery-help"] {
		cfg.CacheKeyringRecoveryHelp = flagCacheKeyringRecoveryHelp
	}
	if seen["validate-config"] {
		cfg.ValidateOnly = flagValidateConfig
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.IsCacheMaintenanceMode() {
		return validateCacheMaintenance(cfg)
	}
	if cfg.VaultAddr == "" {
		return errors.New("vault address is required (set --vault-addr or VAULT_ADDR)")
	}
	if cfg.Role == "" {
		return errors.New("vault role is required (set --role or VAULTCREDS_ROLE)")
	}
	switch cfg.CredentialType {
	case "sts", "creds":
	default:
		return fmt.Errorf("invalid credential type %q, expected sts or creds", cfg.CredentialType)
	}
	if cfg.Mount == "" {
		return errors.New("mount cannot be empty")
	}
	if cfg.TTL != "" {
		if _, err := strconv.ParseInt(cfg.TTL, 10, 64); err == nil {
			return nil
		}
		if _, err := strconv.ParseFloat(cfg.TTL, 64); err == nil {
			return nil
		}
		if !isDurationLike(cfg.TTL) {
			return fmt.Errorf("invalid ttl %q", cfg.TTL)
		}
	}
	return nil
}

func validateCacheMaintenance(cfg Config) error {
	ops := 0
	if cfg.CacheList {
		ops++
	}
	if len(cfg.CachePurgeKeys) > 0 {
		ops++
	}
	if cfg.CachePurgeExpired {
		ops++
	}
	if cfg.CachePurgeAll {
		ops++
	}
	if cfg.CacheKeyringRecoveryHelp {
		ops++
	}
	if ops == 0 {
		return errors.New("cache maintenance mode requires an operation")
	}
	if ops > 1 {
		return errors.New("cache maintenance operations are mutually exclusive")
	}
	return nil
}

func (cfg Config) IsCacheMaintenanceMode() bool {
	return cfg.CacheList || len(cfg.CachePurgeKeys) > 0 || cfg.CachePurgeExpired || cfg.CachePurgeAll || cfg.CacheKeyringRecoveryHelp
}

func isDurationLike(v string) bool {
	if len(v) < 2 {
		return false
	}
	unit := v[len(v)-1]
	if strings.IndexByte("smhd", unit) == -1 {
		return false
	}
	_, err := strconv.Atoi(v[:len(v)-1])
	return err == nil
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func applyFileConfig(cfg *Config, fc fileConfig) {
	if fc.VaultAddr != "" {
		cfg.VaultAddr = fc.VaultAddr
	}
	if fc.VaultCACert != "" {
		cfg.VaultCACert = fc.VaultCACert
	}
	if fc.VaultCAPath != "" {
		cfg.VaultCAPath = fc.VaultCAPath
	}
	if fc.VaultNamespace != "" {
		cfg.VaultNamespace = fc.VaultNamespace
	}
	if fc.VaultToken != "" {
		cfg.VaultToken = fc.VaultToken
	}
	if fc.VaultTokenHelper != "" {
		cfg.VaultTokenHelper = fc.VaultTokenHelper
	}
	if fc.VaultSkipVerify != nil {
		cfg.VaultSkipVerify = *fc.VaultSkipVerify
	}
	if fc.Mount != "" {
		cfg.Mount = fc.Mount
	}
	if fc.Role != "" {
		cfg.Role = fc.Role
	}
	if fc.TTL != "" {
		cfg.TTL = fc.TTL
	}
	if fc.CredentialType != "" {
		cfg.CredentialType = fc.CredentialType
	}
	if fc.CacheCredentials != nil {
		cfg.CacheCredentials = *fc.CacheCredentials
	}
}

func applyEnvConfig(cfg *Config, env map[string]string) {
	if v := env["VAULTCREDS_CONFIG"]; v != "" {
		cfg.ConfigPath = v
	}
	if v := env["VAULT_ADDR"]; v != "" {
		cfg.VaultAddr = v
	}
	if v := env["VAULT_CACERT"]; v != "" {
		cfg.VaultCACert = v
	}
	if v := env["VAULT_CAPATH"]; v != "" {
		cfg.VaultCAPath = v
	}
	if v := env["VAULT_NAMESPACE"]; v != "" {
		cfg.VaultNamespace = v
	}
	if v := env["VAULT_TOKEN"]; v != "" {
		cfg.VaultToken = v
	}
	if v := env["VAULT_TOKEN_HELPER"]; v != "" {
		cfg.VaultTokenHelper = v
	}
	if v := env["VAULT_SKIP_VERIFY"]; v != "" {
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			cfg.VaultSkipVerify = parsed
		}
	}
	if v := env["VAULTCREDS_MOUNT"]; v != "" {
		cfg.Mount = v
	}
	if v := env["VAULTCREDS_ROLE"]; v != "" {
		cfg.Role = v
	}
	if v := env["VAULTCREDS_TTL"]; v != "" {
		cfg.TTL = v
	}
	if v := env["VAULTCREDS_CREDENTIAL_TYPE"]; v != "" {
		cfg.CredentialType = v
	}
	if v := env["VAULTCREDS_CACHE_CREDENTIALS"]; v != "" {
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			cfg.CacheCredentials = parsed
		}
	}
}

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		m[parts[0]] = parts[1]
	}
	return m
}

func findConfigPathArg(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-c" || arg == "--config":
			if i+1 < len(args) {
				return args[i+1], true
			}
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config="), true
		}
	}
	return "", false
}
