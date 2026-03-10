package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTokenUsesExplicitToken(t *testing.T) {
	t.Parallel()

	r := NewTokenResolver()
	token, err := r.Resolve(TokenOptions{Token: "from-env"})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "from-env" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenUsesHelper(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{
		ExecCommand: func(name string, args ...string) (string, error) {
			if name != "helper" {
				t.Fatalf("unexpected helper binary: %s", name)
			}
			if len(args) != 2 || args[0] != "--foo" || args[1] != "get" {
				t.Fatalf("unexpected helper args: %#v", args)
			}
			return "token-from-helper\n", nil
		},
		ReadFile: func(path string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		HomeDir: t.TempDir(),
	}

	token, err := r.Resolve(TokenOptions{TokenHelper: "helper --foo"})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "token-from-helper" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenFallsBackToFile(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	r := &TokenResolver{
		HomeDir: home,
		ExecCommand: func(name string, args ...string) (string, error) {
			return "", errors.New("helper failure")
		},
	}

	token, err := r.Resolve(TokenOptions{TokenHelper: "helper"})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "file-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenDiscoversHelperFromVaultConfig(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{
		HomeDir: t.TempDir(),
		ExecCommand: func(name string, args ...string) (string, error) {
			if name != "my-helper" {
				t.Fatalf("unexpected helper: %s", name)
			}
			if len(args) != 2 || args[0] != "--bar" || args[1] != "get" {
				t.Fatalf("unexpected args: %#v", args)
			}
			return "hcl-token", nil
		},
	}

	vaultConfig := "token_helper = \"my-helper --bar\"\n"
	if err := os.WriteFile(filepath.Join(r.HomeDir, ".vault"), []byte(vaultConfig), 0o600); err != nil {
		t.Fatalf("write vault config: %v", err)
	}

	token, err := r.Resolve(TokenOptions{})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "hcl-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenNoSources(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{HomeDir: t.TempDir()}
	_, err := r.Resolve(TokenOptions{})
	if !errors.Is(err, ErrNoTokenAvailable) {
		t.Fatalf("expected ErrNoTokenAvailable, got %v", err)
	}
}
