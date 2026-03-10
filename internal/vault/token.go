package vault

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrNoTokenAvailable = errors.New("no vault token available")

type TokenResolver struct {
	HomeDir     string
	ReadFile    func(path string) ([]byte, error)
	ExecCommand func(name string, args ...string) (string, error)
}

type TokenOptions struct {
	Token       string
	TokenHelper string
}

func NewTokenResolver() *TokenResolver {
	return &TokenResolver{
		ReadFile: os.ReadFile,
		ExecCommand: func(name string, args ...string) (string, error) {
			cmd := exec.Command(name, args...)
			out, err := cmd.Output()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(out)), nil
		},
	}
}

func (r *TokenResolver) Resolve(opts TokenOptions) (string, error) {
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
		token, err := r.tokenFromHelper(helper)
		if err == nil && token != "" {
			return token, nil
		}
	}

	token, err := r.tokenFromFile()
	if err == nil && token != "" {
		return token, nil
	}
	return "", ErrNoTokenAvailable
}

func (r *TokenResolver) discoverTokenHelper() (string, error) {
	home, err := r.homeDir()
	if err != nil {
		return "", err
	}
	b, err := r.readFile(filepath.Join(home, ".vault"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read ~/.vault: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "token_helper") {
			continue
		}
		_, valuePart, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v := strings.TrimSpace(valuePart)
		v = stripQuotes(v)
		if v != "" {
			return v, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan ~/.vault: %w", err)
	}
	return "", nil
}

func (r *TokenResolver) tokenFromHelper(helper string) (string, error) {
	parts, err := splitCommand(helper)
	if err != nil {
		return "", err
	}
	if len(parts) == 0 {
		return "", errors.New("token helper command is empty")
	}

	args := append(parts[1:], "get")
	out, err := r.execCommand(parts[0], args...)
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

func (r *TokenResolver) readFile(path string) ([]byte, error) {
	if r.ReadFile == nil {
		return os.ReadFile(path)
	}
	return r.ReadFile(path)
}

func (r *TokenResolver) execCommand(name string, args ...string) (string, error) {
	if r.ExecCommand == nil {
		cmd := exec.Command(name, args...)
		out, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	return r.ExecCommand(name, args...)
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

func stripQuotes(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
