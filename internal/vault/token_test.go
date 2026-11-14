package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestResolveTokenUsesExplicitToken(t *testing.T) {
	t.Parallel()

	r := NewTokenResolver()
	token, err := r.Resolve(context.Background(), TokenOptions{Token: "from-env"})
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
		LookPath: func(file string) (string, error) {
			if file != "helper" {
				t.Fatalf("unexpected helper lookup: %s", file)
			}
			return "/usr/local/bin/helper", nil
		},
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "/usr/local/bin/helper" {
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

	token, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: "helper --foo"})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "token-from-helper" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenHelperFailureSurfaces(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	// Even with a stale ~/.vault-token present, a failing configured helper
	// must hard-fail like the vault CLI instead of masking with the file.
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("stale-file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	r := &TokenResolver{
		HomeDir: home,
		LookPath: func(file string) (string, error) {
			return "/usr/local/bin/helper", nil
		},
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			return "", errors.New("helper failure: keyring locked")
		},
	}

	_, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: "helper"})
	if err == nil {
		t.Fatal("expected helper failure to surface")
	}
	if errors.Is(err, ErrNoTokenAvailable) {
		t.Fatalf("error must not collapse to ErrNoTokenAvailable: %v", err)
	}
	if !strings.Contains(err.Error(), "keyring locked") {
		t.Fatalf("expected helper cause in error, got: %v", err)
	}
}

func TestResolveTokenHelperEmptyOutputIsError(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{
		HomeDir:  t.TempDir(),
		LookPath: func(file string) (string, error) { return "/usr/local/bin/helper", nil },
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			return "", nil
		},
	}

	_, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: "helper"})
	if !errors.Is(err, ErrNoTokenAvailable) {
		t.Fatalf("expected ErrNoTokenAvailable, got %v", err)
	}
}

func TestResolveTokenUsesFileWhenNoHelper(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	r := &TokenResolver{HomeDir: home}
	token, err := r.Resolve(context.Background(), TokenOptions{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if token != "file-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenSymlinkedTokenFile(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	realDir := t.TempDir()
	realToken := filepath.Join(realDir, "vault-token")
	if err := os.WriteFile(realToken, []byte("symlink-token\n"), 0o600); err != nil {
		t.Fatalf("write real token: %v", err)
	}
	if err := os.Symlink(realToken, filepath.Join(home, ".vault-token")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	r := &TokenResolver{HomeDir: home}
	token, err := r.Resolve(context.Background(), TokenOptions{})
	if err != nil {
		t.Fatalf("symlinked ~/.vault-token must resolve like the vault CLI: %v", err)
	}
	if token != "symlink-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenSymlinkedVaultConfig(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	realDir := t.TempDir()
	realCfg := filepath.Join(realDir, ".vault")
	if err := os.WriteFile(realCfg, []byte("token_helper = \"cfg-helper\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Symlink(realCfg, filepath.Join(home, ".vault")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	r := &TokenResolver{
		HomeDir: home,
		LookPath: func(file string) (string, error) {
			if file != "cfg-helper" {
				t.Fatalf("unexpected helper: %s", file)
			}
			return "/usr/bin/cfg-helper", nil
		},
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			return "cfg-helper-token", nil
		},
	}

	token, err := r.Resolve(context.Background(), TokenOptions{})
	if err != nil {
		t.Fatalf("symlinked ~/.vault must be readable: %v", err)
	}
	if token != "cfg-helper-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenMissingHelperIsError(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	r := &TokenResolver{
		HomeDir: home,
		LookPath: func(file string) (string, error) {
			return "", errors.New("not found")
		},
	}

	_, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: "missing-helper"})
	if err == nil || !strings.Contains(err.Error(), "missing-helper") {
		t.Fatalf("expected helper resolution error, got %v", err)
	}
}

func TestResolveTokenMalformedHelperIsError(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	r := &TokenResolver{HomeDir: home}
	_, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: `"unterminated`})
	if err == nil || !strings.Contains(err.Error(), "unterminated quote") {
		t.Fatalf("expected malformed helper error, got %v", err)
	}
}

func TestResolveTokenUsesQuotedHelperPath(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "helpers/vault helper" {
				t.Fatalf("unexpected helper path: %q", name)
			}
			if len(args) != 2 || args[0] != "--flag" || args[1] != "get" {
				t.Fatalf("unexpected helper args: %#v", args)
			}
			return "quoted-token", nil
		},
	}

	token, err := r.Resolve(context.Background(), TokenOptions{TokenHelper: `"helpers/vault helper" --flag`})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "quoted-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenDiscoversHelperFromVaultConfig(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{
		HomeDir: t.TempDir(),
		LookPath: func(file string) (string, error) {
			if file != "my-helper" {
				t.Fatalf("unexpected helper lookup: %s", file)
			}
			return "/usr/local/bin/my-helper", nil
		},
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			if name != "/usr/local/bin/my-helper" {
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

	token, err := r.Resolve(context.Background(), TokenOptions{})
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "hcl-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestResolveTokenHonorsVaultConfigPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vault-cli.hcl")
	if err := os.WriteFile(cfgPath, []byte("token_helper = \"env-helper\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &TokenResolver{
		HomeDir: t.TempDir(),
		LookupEnv: func(key string) (string, bool) {
			if key == "VAULT_CONFIG_PATH" {
				return cfgPath, true
			}
			return "", false
		},
		LookPath: func(file string) (string, error) {
			if file != "env-helper" {
				t.Fatalf("unexpected helper: %s", file)
			}
			return "/usr/bin/env-helper", nil
		},
		ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			return "vp-token", nil
		},
	}

	token, err := r.Resolve(context.Background(), TokenOptions{})
	if err != nil {
		t.Fatalf("VAULT_CONFIG_PATH must be honored: %v", err)
	}
	if token != "vp-token" {
		t.Fatalf("token mismatch: %q", token)
	}
}

func TestParseTokenHelper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"plain", "token_helper = \"helper --x\"\n", "helper --x"},
		{"inline comment", "token_helper = \"helper\" # note\n", "helper"},
		{"prefix overmatch ignored", "token_helperfoo = \"bad\"\n", ""},
		{"unquoted", "token_helper = helper\n", "helper"},
		{"json", "{\"token_helper\": \"json-helper\"}", "json-helper"},
		{"no helper", "# nothing\nfoo = \"bar\"\n", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTokenHelper(tt.content)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestTokenFromHelperRejectsMalformedCommand(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{}
	_, err := r.tokenFromHelper(context.Background(), `"unterminated`)
	if err == nil || !strings.Contains(err.Error(), "unterminated quote") {
		t.Fatalf("expected malformed helper error, got %v", err)
	}
}

func TestResolveTokenNoSources(t *testing.T) {
	t.Parallel()

	r := &TokenResolver{HomeDir: t.TempDir()}
	_, err := r.Resolve(context.Background(), TokenOptions{})
	if !errors.Is(err, ErrNoTokenAvailable) {
		t.Fatalf("expected ErrNoTokenAvailable, got %v", err)
	}
}

// TestTokenHelperProcess doubles as a portable executable token helper.
func TestTokenHelperProcess(t *testing.T) {
	mode := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			break
		}
	}
	if mode == "" {
		return
	}
	switch mode {
	case "stderr":
		fmt.Fprintln(os.Stderr, "agent not unlocked")
		os.Exit(1)
	case "sleep":
		time.Sleep(2 * time.Second)
		os.Exit(0)
	case "descendant":
		cmd := exec.Command(os.Args[0], "-test.run=^TestTokenHelperProcess$", "--", "sleep")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "flood":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 100000))
		os.Exit(0)
	}
	os.Exit(2)
}

func helperCommand(t *testing.T, mode string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return `"` + executable + `" -test.run=^TestTokenHelperProcess$ -- ` + mode
}

func TestTokenHelperStderrIncludedInError(t *testing.T) {
	t.Parallel()
	_, err := NewTokenResolver().Resolve(t.Context(), TokenOptions{TokenHelper: helperCommand(t, "stderr")})
	if err == nil || !strings.Contains(err.Error(), "agent not unlocked") {
		t.Fatalf("expected helper stderr, got %v", err)
	}
}

func TestTokenHelperHonorsContextDeadline(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"sleep", "descendant"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := NewTokenResolver().Resolve(ctx, TokenOptions{TokenHelper: helperCommand(t, mode)})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 1800*time.Millisecond {
				t.Fatalf("helper exceeded cancellation bound: %v", elapsed)
			}
		})
	}
}

func TestTokenHelperOutputBounded(t *testing.T) {
	t.Parallel()
	_, err := NewTokenResolver().Resolve(t.Context(), TokenOptions{TokenHelper: helperCommand(t, "flood")})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error: %v", err)
	}
}

func TestTokenHelperExpandsHomeAfterParsing(t *testing.T) {
	t.Parallel()
	home := filepath.Join(t.TempDir(), "home with spaces")
	for _, helper := range []string{`~/bin/helper --flag`, `"~/bin/helper" --flag`} {
		r := &TokenResolver{HomeDir: home, ExecCommand: func(_ context.Context, name string, args ...string) (string, error) {
			if name != filepath.Join(home, "bin", "helper") {
				t.Fatalf("helper path=%q", name)
			}
			if strings.Join(args, " ") != "--flag get" {
				t.Fatalf("args=%v", args)
			}
			return "token", nil
		}}
		if _, err := r.Resolve(t.Context(), TokenOptions{TokenHelper: helper}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMalformedDiscoveredHelperNeverFallsBack(t *testing.T) {
	t.Parallel()
	for _, content := range []string{`token_helper = "unfinished`, `{"token_helper":123}`} {
		r := &TokenResolver{HomeDir: t.TempDir(), ReadFile: func(path string) ([]byte, error) {
			if filepath.Base(path) == ".vault-token" {
				t.Fatal("unexpected fallback to token file")
			}
			return []byte(content), nil
		}, LookupEnv: func(string) (string, bool) { return "", false }}
		if _, err := r.Resolve(t.Context(), TokenOptions{}); err == nil {
			t.Fatal("accepted malformed helper config")
		}
	}
}
