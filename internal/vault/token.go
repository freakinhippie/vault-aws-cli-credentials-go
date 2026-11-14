package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/kv"
	"github.com/freakinhippie/vault-aws-cli-credentials-go/internal/subprocess"
)

var ErrNoTokenAvailable = errors.New("no vault token available")

type TokenResolver struct {
	HomeDir     string
	ReadFile    func(path string) ([]byte, error)
	ExecCommand func(ctx context.Context, name string, args ...string) (string, error)
	LookPath    func(file string) (string, error)
	LookupEnv   func(key string) (string, bool)
}

type TokenOptions struct {
	Token       string
	TokenHelper string
}

func NewTokenResolver() *TokenResolver {
	return &TokenResolver{
		LookPath: exec.LookPath,
	}
}

// Resolve finds a Vault token: explicit token first, then the configured or
// discovered token helper, then ~/.vault-token (only when no helper is
// configured, matching the vault CLI where the file itself is the default
// internal helper). Helper failures are surfaced, never silently masked by a
// possibly-stale token file.
func (r *TokenResolver) Resolve(ctx context.Context, opts TokenOptions) (string, error) {
	if opts.Token != "" {
		return opts.Token, nil
	}

	helper := strings.TrimSpace(opts.TokenHelper)
	if helper == "" {
		discovered, err := r.discoverTokenHelper()
		if err != nil {
			return "", err
		}
		helper = discovered
	}

	if helper != "" {
		token, err := r.tokenFromHelper(ctx, helper)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}
		return "", fmt.Errorf("%w: token helper %q returned no token", ErrNoTokenAvailable, helper)
	}

	token, err := r.tokenFromFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoTokenAvailable
		}
		return "", fmt.Errorf("read ~/.vault-token: %w", err)
	}
	if token == "" {
		return "", ErrNoTokenAvailable
	}
	return token, nil
}

// discoverTokenHelper finds token_helper from the Vault CLI config, honoring
// VAULT_CONFIG_PATH just like the vault CLI, falling back to ~/.vault.
func (r *TokenResolver) discoverTokenHelper() (string, error) {
	path := ""
	if r.lookupEnv("VAULT_CONFIG_PATH") != "" {
		path = r.lookupEnv("VAULT_CONFIG_PATH")
	} else {
		home, err := r.homeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, ".vault")
	}

	b, err := r.readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read vault cli config %s: %w", path, err)
	}

	return parseTokenHelper(string(b))
}

// parseTokenHelper extracts token_helper from an HCL-style or JSON Vault CLI
// config document.
func parseTokenHelper(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			return "", fmt.Errorf("parse vault cli config: %w", err)
		}
		raw, exists := doc["token_helper"]
		if !exists {
			return "", nil
		}
		value, ok := raw.(string)
		if !ok {
			return "", errors.New("vault cli config token_helper must be a string")
		}
		return strings.TrimSpace(value), nil
	}

	for _, raw := range strings.Split(trimmed, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := kv.SplitKeyValue(line)
		if !ok {
			keyPart, _, _ := strings.Cut(line, "=")
			if strings.TrimSpace(keyPart) == "token_helper" {
				return "", errors.New("malformed token_helper in vault cli config")
			}
			continue
		}
		if key != "token_helper" {
			continue
		}
		if value != "" {
			return value, nil
		}
	}
	return "", nil
}

func (r *TokenResolver) tokenFromHelper(ctx context.Context, helper string) (string, error) {
	parts, err := splitCommand(helper)
	if err != nil {
		return "", err
	}
	if len(parts) == 0 {
		return "", errors.New("token helper command is empty")
	}

	executable := parts[0]
	if executable == "~" || strings.HasPrefix(executable, "~/") || strings.HasPrefix(executable, `~\`) {
		home, err := r.homeDir()
		if err != nil {
			return "", err
		}
		executable = filepath.Join(home, strings.TrimLeft(strings.TrimPrefix(executable, "~"), `/\`))
	}
	name, err := r.resolveExecutable(executable)
	if err != nil {
		return "", err
	}

	args := append(parts[1:], "get")
	out, err := r.execCommand(ctx, name, args...)
	if err != nil {
		return "", fmt.Errorf("token helper get failed: %w", err)
	}
	return strings.TrimSpace(out), nil
}

func (r *TokenResolver) tokenFromFile() (string, error) {
	home, err := r.homeDir()
	if err != nil {
		return "", err
	}
	b, err := r.readFile(filepath.Join(home, ".vault-token"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (r *TokenResolver) homeDir() (string, error) {
	if r.HomeDir != "" {
		return r.HomeDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return home, nil
}

// readFile reads home-relative files with ordinary semantics so symlinked
// ~/.vault / ~/.vault-token files (a common secrets-injection pattern) work
// the same way they do with the vault CLI.
func (r *TokenResolver) readFile(path string) ([]byte, error) {
	if r.ReadFile != nil {
		return r.ReadFile(path)
	}
	// #nosec G304 -- Home-relative Vault CLI config/token files selected per vault CLI conventions.
	return os.ReadFile(path)
}

func (r *TokenResolver) resolveExecutable(name string) (string, error) {
	if name == "" {
		return "", errors.New("token helper command is empty")
	}
	if hasPathSeparator(name) {
		return name, nil
	}

	resolved, err := r.lookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve token helper %q: %w", name, err)
	}
	return resolved, nil
}

func (r *TokenResolver) execCommand(ctx context.Context, name string, args ...string) (string, error) {
	if r.ExecCommand != nil {
		return r.ExecCommand(ctx, name, args...)
	}

	cmd := subprocess.Command(ctx, name, args...)
	out, err := subprocess.Run(ctx, cmd, 64<<10, 300)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *TokenResolver) lookPath(file string) (string, error) {
	if r.LookPath == nil {
		return exec.LookPath(file)
	}
	return r.LookPath(file)
}

func (r *TokenResolver) lookupEnv(key string) string {
	if r.LookupEnv != nil {
		v, _ := r.LookupEnv(key)
		return v
	}
	return os.Getenv(key)
}

func hasPathSeparator(v string) bool {
	return strings.ContainsAny(v, `/\`)
}

func splitCommand(input string) ([]string, error) {
	var (
		parts []string
		curr  strings.Builder
		quote rune
	)

	for _, r := range input {
		switch {
		case quote == 0 && (r == '\'' || r == '"'):
			quote = r
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == ' ' || r == '\t'):
			if curr.Len() > 0 {
				parts = append(parts, curr.String())
				curr.Reset()
			}
		default:
			curr.WriteRune(r)
		}
	}

	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in command %q", input)
	}
	if curr.Len() > 0 {
		parts = append(parts, curr.String())
	}
	return parts, nil
}
