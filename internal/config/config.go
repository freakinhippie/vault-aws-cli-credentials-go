package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrHelpRequested = errors.New("help requested")

const (
	defaultMount          = "aws"
	defaultCredentialType = "sts"
	defaultTTL            = "1h"
	defaultClientTimeout  = 60 * time.Second
)

// ttlUnitPattern accepts Vault-style durations composed of one or more
// numeric+unit segments, e.g. "90s", "1h", "1.5h", "1h30m", "1d12h", "1w".
var ttlUnitPattern = regexp.MustCompile(`\d+(?:\.\d+)?[smhdw]`)

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
      --cache-keyctl-scope string    Linux kernel keyring scope (env: VAULTCREDS_CACHE_KEYCTL_SCOPE, default: session)
      --validate-config      Validate configuration and exit
      --version              Show version and exit
  -h, --help                 Show help

Additional Vault env vars:
  VAULT_TOKEN, VAULT_TOKEN_HELPER, VAULT_NAMESPACE, VAULT_SKIP_VERIFY,
  VAULT_DISABLE_REDIRECTS, VAULT_CLIENT_TIMEOUT (seconds or Go duration, default 60s)

Examples (AWS shared config):
  credential_process = {{ .BinaryPath }} --vault-addr=https://vault.example.com:8200 --role=dev-role
  credential_process = {{ .BinaryPath }} --vault-addr=https://vault.example.com:8200 --mount=aws-team --role=app-role --type=creds
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
	VaultDisableRedirects    bool
	CacheKeyctlScope         string
	Mount                    string
	Role                     string
	TTL                      string
	CredentialType           string
	ClientTimeout            time.Duration
	CacheCredentials         bool
	CacheList                bool
	CachePurgeKeys           []string
	CachePurgeExpired        bool
	CachePurgeAll            bool
	CacheKeyringRecoveryHelp bool
	ValidateOnly             bool
	ShowVersion              bool
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
	CacheKeyctlScope string
}

// Load resolves configuration with a strict precedence of CLI flag >
// environment variable > config file > built-in default. Flags are parsed
// first so every spelling the Go flag package accepts (-c v, -c=v, --config v,
// --config=v, -config=v, ...) resolves the same config file that is then
// actually loaded.
func Load(args []string, environ []string) (Config, error) {
	env := envMap(environ)

	var (
		flagCacheKeyctlScope         string
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
		flagVersion                  bool
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
	fs.StringVar(&flagCacheKeyctlScope, "cache-keyctl-scope", "", "Linux kernel keyring scope")
	fs.BoolVar(&flagCacheList, "cache-list", false, "List cache entries")
	fs.StringVar(&flagCachePurge, "cache-purge", "", "Purge comma-separated cache key(s)")
	fs.BoolVar(&flagCachePurgeExpired, "cache-purge-expired", false, "Purge expired cache entries")
	fs.BoolVar(&flagCachePurgeAll, "cache-purge-all", false, "Purge all cache entries")
	fs.BoolVar(&flagCacheKeyringRecoveryHelp, "cache-keyring-recovery-help", false, "Show OS-specific keyring reset/recovery guidance")
	fs.BoolVar(&flagValidateConfig, "validate-config", false, "Validate configuration and exit")
	fs.BoolVar(&flagVersion, "version", false, "Show version and exit")

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

	flagConfigSeen := seen["c"] || seen["config"]
	if flagConfigSeen && strings.TrimSpace(flagConfigPath) == "" {
		return Config{}, errors.New("--config requires a non-empty file path")
	}
	if seen["cache-purge"] && len(splitCSV(flagCachePurge)) == 0 {
		return Config{}, errors.New("--cache-purge requires at least one cache key")
	}

	cacheMaintenanceRequested := flagCacheList || flagCachePurgeExpired || flagCachePurgeAll ||
		flagCacheKeyringRecoveryHelp || seen["cache-purge"]

	cfg := Config{
		Mount:                    defaultMount,
		CredentialType:           defaultCredentialType,
		TTL:                      defaultTTL,
		ClientTimeout:            defaultClientTimeout,
		CacheKeyringRecoveryHelp: flagCacheKeyringRecoveryHelp,
		CacheKeyctlScope:         "session",
		CacheList:                flagCacheList,
		CachePurgeKeys:           splitCSV(flagCachePurge),
		CachePurgeExpired:        flagCachePurgeExpired,
		CachePurgeAll:            flagCachePurgeAll,
		ValidateOnly:             flagValidateConfig,
		ShowVersion:              flagVersion,
	}

	// Version and recovery help have no dependency on credential settings.
	if cfg.ShowVersion || cfg.CacheKeyringRecoveryHelp {
		return cfg, validate(cfg)
	}
	// Cache maintenance ignores the credential config file and Vault environment.
	// The scope still selects the kernel keyring that maintenance should operate on.
	if cacheMaintenanceRequested {
		cfg.CacheKeyctlScope = firstSeen(flagCacheKeyctlScope, seen, "cache-keyctl-scope", "", env, "VAULTCREDS_CACHE_KEYCTL_SCOPE", "", "session")
		if err := validateKeyctlScope(cfg.CacheKeyctlScope); err != nil {
			return Config{}, err
		}
		return cfg, validate(cfg)
	}

	// Resolve the effective config path (flag > env) before loading the file.
	if flagConfigSeen {
		cfg.ConfigPath = flagConfigPath
	} else if env["VAULTCREDS_CONFIG"] != "" {
		cfg.ConfigPath = env["VAULTCREDS_CONFIG"]
	}

	var fc fileConfig
	if cfg.ConfigPath != "" {
		expanded, err := expandHome(cfg.ConfigPath)
		if err != nil {
			return Config{}, err
		}
		cfg.ConfigPath = expanded
		fc, err = parseConfigFile(cfg.ConfigPath)
		if err != nil {
			return Config{}, err
		}
	}

	// Merge scalar settings with flag > env > file > default precedence.
	cfg.CacheKeyctlScope = firstSeen(flagCacheKeyctlScope, seen, "cache-keyctl-scope", "", env, "VAULTCREDS_CACHE_KEYCTL_SCOPE", fc.CacheKeyctlScope, "session")
	cfg.VaultAddr = firstSeen(flagVaultAddr, seen, "V", "vault-addr", env, "VAULT_ADDR", fc.VaultAddr, "")
	cfg.Role = firstSeen(flagRole, seen, "r", "role", env, "VAULTCREDS_ROLE", fc.Role, "")
	cfg.Mount = firstSeen(flagMount, seen, "m", "mount", env, "VAULTCREDS_MOUNT", fc.Mount, defaultMount)
	cfg.TTL = firstSeen(flagTTL, seen, "t", "ttl", env, "VAULTCREDS_TTL", fc.TTL, defaultTTL)
	cfg.CredentialType = firstSeen(flagType, seen, "T", "type", env, "VAULTCREDS_CREDENTIAL_TYPE", fc.CredentialType, defaultCredentialType)
	cfg.VaultNamespace = envOrFile(env, "VAULT_NAMESPACE", fc.VaultNamespace)
	cfg.VaultToken = envOrFile(env, "VAULT_TOKEN", fc.VaultToken)
	cfg.VaultTokenHelper = envOrFile(env, "VAULT_TOKEN_HELPER", fc.VaultTokenHelper)
	if v := firstSeen(flagVaultCACert, seen, "C", "vault-cacert", env, "VAULT_CACERT", fc.VaultCACert, ""); v != "" {
		expanded, err := expandHome(v)
		if err != nil {
			return Config{}, err
		}
		cfg.VaultCACert = expanded
	}
	if v := firstSeen(flagVaultCAPath, seen, "vault-capath", "vault-capath", env, "VAULT_CAPATH", fc.VaultCAPath, ""); v != "" {
		expanded, err := expandHome(v)
		if err != nil {
			return Config{}, err
		}
		cfg.VaultCAPath = expanded
	}

	envBool := func(envKey string, fileVal *bool) (bool, error) {
		if v := env[envKey]; v != "" {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return false, fmt.Errorf("invalid boolean in %s: %q", envKey, v)
			}
			return parsed, nil
		}
		if fileVal != nil {
			return *fileVal, nil
		}
		return false, nil
	}

	var err error
	if cfg.VaultSkipVerify, err = envBool("VAULT_SKIP_VERIFY", fc.VaultSkipVerify); err != nil {
		return Config{}, err
	}
	if cfg.VaultDisableRedirects, err = envBool("VAULT_DISABLE_REDIRECTS", nil); err != nil {
		return Config{}, err
	}
	switch {
	case seen["cache"]:
		cfg.CacheCredentials = flagCache
	default:
		if cfg.CacheCredentials, err = envBool("VAULTCREDS_CACHE_CREDENTIALS", fc.CacheCredentials); err != nil {
			return Config{}, err
		}
	}

	if v := env["VAULT_CLIENT_TIMEOUT"]; v != "" {
		timeout, err := parseClientTimeout(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid VAULT_CLIENT_TIMEOUT: %w", err)
		}
		cfg.ClientTimeout = timeout
	}

	cfg.CacheList = flagCacheList
	if seen["cache-purge"] {
		cfg.CachePurgeKeys = splitCSV(flagCachePurge)
	}
	cfg.CachePurgeExpired = flagCachePurgeExpired
	cfg.CachePurgeAll = flagCachePurgeAll
	cfg.ValidateOnly = flagValidateConfig
	cfg.ShowVersion = flagVersion

	cfg.TTL, err = normalizeTTL(cfg.TTL)
	if err != nil {
		return Config{}, err
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// firstSeen returns the flag value when either of its names was provided,
// otherwise the environment value, otherwise the config-file value,
// otherwise the given default.
func firstSeen(flagVal string, seen map[string]bool, primaryName, aliasName string, env map[string]string, envKey, fileVal, def string) string {
	if seen[primaryName] || (aliasName != "" && seen[aliasName]) {
		return flagVal
	}
	if v := env[envKey]; v != "" {
		return v
	}
	if fileVal != "" {
		return fileVal
	}
	return def
}

// envOrFile resolves settings that have no CLI flag: env > file.
func envOrFile(env map[string]string, envKey, fileVal string) string {
	if v := env[envKey]; v != "" {
		return v
	}
	return fileVal
}

func validate(cfg Config) error {
	if cfg.ShowVersion {
		return nil
	}
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
	if err := validateTTL(cfg.TTL); err != nil {
		return err
	}
	if err := validateKeyctlScope(cfg.CacheKeyctlScope); err != nil {
		return err
	}
	if cfg.ClientTimeout < 0 {
		return errors.New("client timeout must be positive")
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

// normalizeTTL preserves Vault durations and converts the d/w extensions into
// Go durations before transmission. Zero retains Vault's default-TTL semantics.
func normalizeTTL(v string) (string, error) {
	if v == "" {
		return v, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 || n > math.MaxInt64/int64(time.Second) {
			return "", fmt.Errorf("invalid ttl %q: duration out of range", v)
		}
		return v, nil
	}
	if !strings.ContainsAny(v, "dw") {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return "", fmt.Errorf("invalid ttl %q: expected a non-negative duration", v)
		}
		return v, nil
	}
	segments := ttlUnitPattern.FindAllString(v, -1)
	if strings.Join(segments, "") != v {
		return "", fmt.Errorf("invalid ttl %q", v)
	}
	total := new(big.Rat)
	for _, segment := range segments {
		n, ok := new(big.Rat).SetString(segment[:len(segment)-1])
		if !ok {
			return "", fmt.Errorf("invalid ttl %q", v)
		}
		units := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}
		total.Add(total, n.Mul(n, new(big.Rat).SetInt64(int64(units[segment[len(segment)-1]]))))
	}
	if total.Cmp(new(big.Rat).SetInt64(math.MaxInt64)) > 0 {
		return "", fmt.Errorf("invalid ttl %q: duration out of range", v)
	}
	nanos := new(big.Int).Quo(total.Num(), total.Denom())
	return time.Duration(nanos.Int64()).String(), nil
}

func validateTTL(v string) error {
	_, err := normalizeTTL(v)
	return err
}

func validateKeyctlScope(scope string) error {
	switch scope {
	case "session", "user", "usersession":
		return nil
	default:
		return fmt.Errorf("invalid cache keyctl scope %q: expected session, user, or usersession", scope)
	}
}

// parseClientTimeout accepts Vault-style plain seconds or a Go duration.
func parseClientTimeout(v string) (time.Duration, error) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 || n > (math.MaxInt64-int64(10*time.Second))/int64(time.Second) {
			return 0, fmt.Errorf("must be positive, got %q", v)
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("must be seconds or a Go duration, got %q", v)
	}
	if d <= 0 || d > time.Duration(math.MaxInt64)-10*time.Second {
		return 0, fmt.Errorf("must be positive, got %q", v)
	}
	return d, nil
}

// expandHome expands a leading ~ to the current user's home directory.
func expandHome(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if v != "~" && !strings.HasPrefix(v, "~/") && !strings.HasPrefix(v, `~\`) {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expand ~ in %q: %w", v, err)
	}
	rest := strings.TrimLeft(strings.TrimPrefix(v, "~"), `/\`)
	if rest == "" {
		return home, nil
	}
	return filepath.Join(home, filepathLike(rest)), nil
}

// filepathLike normalizes separators in the remainder of a ~-path so Windows
// style paths keep working.
func filepathLike(v string) string {
	return strings.ReplaceAll(v, "/", string(os.PathSeparator))
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

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, pair := range environ {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		m[parts[0]] = parts[1]
	}
	return m
}
