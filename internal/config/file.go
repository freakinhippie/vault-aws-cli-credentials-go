package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/kv"
)

const bom = "\ufeff"

func parseConfigFile(path string) (fileConfig, error) {
	// #nosec G304 -- The config file path is explicitly selected by the user via flag or environment variable.
	f, err := os.Open(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	var cfg fileConfig
	seenKeys := map[string]int{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	first := true
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, bom)
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			return fileConfig{}, fmt.Errorf("config parse error at %s:%d: unsupported section header %q, use top-level \"key = value\" entries", path, lineNo, line)
		}

		key, value, ok := kv.SplitKeyValue(line)
		if !ok {
			return fileConfig{}, fmt.Errorf("config parse error at %s:%d: expected \"key = value\"", path, lineNo)
		}
		if prev, dup := seenKeys[key]; dup {
			return fileConfig{}, fmt.Errorf("config parse error at %s:%d: duplicate key %q (first defined on line %d)", path, lineNo, key, prev)
		}
		seenKeys[key] = lineNo

		switch key {
		case "vault_addr":
			cfg.VaultAddr = value
		case "vault_cacert":
			cfg.VaultCACert = value
		case "vault_capath":
			cfg.VaultCAPath = value
		case "vault_namespace":
			cfg.VaultNamespace = value
		case "vault_token":
			cfg.VaultToken = value
		case "vault_token_helper":
			cfg.VaultTokenHelper = value
		case "vault_skip_verify":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fileConfig{}, fmt.Errorf("invalid boolean for %q at %s:%d", key, path, lineNo)
			}
			cfg.VaultSkipVerify = &parsed
		case "mount":
			cfg.Mount = value
		case "role":
			cfg.Role = value
		case "ttl":
			cfg.TTL = value
		case "credential_type", "type":
			cfg.CredentialType = value
		case "cache_keyctl_scope":
			cfg.CacheKeyctlScope = value
		case "cache", "cache_credentials":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fileConfig{}, fmt.Errorf("invalid boolean for %q at %s:%d", key, path, lineNo)
			}
			cfg.CacheCredentials = &parsed
		default:
			return fileConfig{}, fmt.Errorf("unknown config key %q at %s:%d", key, path, lineNo)
		}
	}

	if err := scanner.Err(); err != nil {
		return fileConfig{}, fmt.Errorf("read config file: %w", err)
	}
	return cfg, nil
}
