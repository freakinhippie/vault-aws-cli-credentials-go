package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseConfigFile(path string) (fileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	var cfg fileConfig
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keyPart, valuePart, ok := strings.Cut(line, "=")
		if !ok {
			return fileConfig{}, fmt.Errorf("config parse error at %s:%d", path, lineNo)
		}

		key := normalizeKey(keyPart)
		value := strings.TrimSpace(valuePart)
		value = trimInlineComment(value)
		value = stripQuotes(value)

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
				return fileConfig{}, fmt.Errorf("invalid boolean at %s:%d", path, lineNo)
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
		case "cache", "cache_credentials":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fileConfig{}, fmt.Errorf("invalid boolean at %s:%d", path, lineNo)
			}
			cfg.CacheCredentials = &parsed
		}
	}

	if err := scanner.Err(); err != nil {
		return fileConfig{}, fmt.Errorf("read config file: %w", err)
	}
	return cfg, nil
}

func normalizeKey(v string) string {
	n := strings.TrimSpace(strings.ToLower(v))
	n = strings.ReplaceAll(n, "-", "_")
	return n
}

func trimInlineComment(v string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(v[:i])
			}
		}
	}
	return strings.TrimSpace(v)
}

func stripQuotes(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
