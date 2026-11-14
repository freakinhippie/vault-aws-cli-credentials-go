package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClientGetAWSCredentialsSTS(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:      "https://vault.example",
		token:     "test-token",
		namespace: "team/ns",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
					t.Fatalf("vault token header mismatch: %q", got)
				}
				if got := r.Header.Get("X-Vault-Request"); got != "true" {
					t.Fatalf("missing X-Vault-Request header: %q", got)
				}
				if got := r.Header.Get("X-Vault-Namespace"); got != "team/ns" {
					t.Fatalf("vault namespace header mismatch: %q", got)
				}
				if got := r.URL.Path; got != "/v1/aws/sts/app-role" {
					t.Fatalf("path mismatch: %q", got)
				}
				if got := r.URL.Query().Get("ttl"); got != "1h" {
					t.Fatalf("ttl mismatch: %q", got)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"lease_duration":3600,"data":{"access_key":"AKIA","secret_key":"SECRET","security_token":"SESSION"}}`)),
					Header:     make(http.Header),
				}, nil
			}),
			Timeout: 5 * time.Second,
		},
		now: func() time.Time {
			return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		},
	}

	creds, err := c.GetAWSCredentials(context.Background(), "aws", "app-role", "sts", "1h")
	if err != nil {
		t.Fatalf("get creds: %v", err)
	}

	if creds.AccessKeyID != "AKIA" {
		t.Fatalf("access key mismatch: %q", creds.AccessKeyID)
	}
	if creds.SecretAccessKey != "SECRET" {
		t.Fatalf("secret key mismatch: %q", creds.SecretAccessKey)
	}
	if creds.SessionToken != "SESSION" {
		t.Fatalf("session token mismatch: %q", creds.SessionToken)
	}
	// Expiration applies the 30s clock-skew margin for a 1h lease.
	if creds.Expiration == nil || *creds.Expiration != "2026-01-01T12:59:30Z" {
		t.Fatalf("expiration mismatch: %#v", creds.Expiration)
	}
}

func TestClientNestedMountPathNotEscaped(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:  "https://vault.example",
		token: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.URL.Path; got != "/v1/aws-team/us-east1/sts/app-role" {
					t.Fatalf("nested mount path was escaped or mangled: %q", got)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"lease_duration":60,"data":{"access_key":"AKIA","secret_key":"S","security_token":"T"}}`)),
					Header:     make(http.Header),
				}, nil
			}),
		},
		now: time.Now,
	}

	if _, err := c.GetAWSCredentials(context.Background(), "aws-team/us-east1", "app-role", "sts", ""); err != nil {
		t.Fatalf("get creds: %v", err)
	}
}

func TestClientVaultRedirectPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                     string
		status                   int
		location                 string
		disabled, secondRedirect bool
		wantRequests             int
		wantErr                  bool
	}{
		{name: "301", status: 301, location: "https://active.example/v1/aws/sts/role", wantRequests: 2},
		{name: "302", status: 302, location: "https://active.example/v1/aws/sts/role", wantRequests: 2},
		{name: "307", status: 307, location: "https://active.example/v1/aws/sts/role", wantRequests: 2},
		{name: "relative", status: 307, location: "/v1/aws/sts/role", wantRequests: 2},
		{name: "disabled", status: 307, location: "https://active.example/", disabled: true, wantRequests: 1, wantErr: true},
		{name: "downgrade", status: 307, location: "http://active.example/", wantRequests: 1, wantErr: true},
		{name: "chain", status: 307, location: "https://active.example/", secondRedirect: true, wantRequests: 2, wantErr: true},
		{name: "303", status: 303, location: "https://active.example/", wantRequests: 1, wantErr: true},
		{name: "308", status: 308, location: "https://active.example/", wantRequests: 1, wantErr: true},
		{name: "missing location", status: 307, wantRequests: 1, wantErr: true},
		{name: "invalid location", status: 307, location: "http://%invalid", wantRequests: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(ClientConfig{Addr: "https://standby.example", Token: "test-token", Namespace: "team", DisableRedirects: tc.disabled})
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			var deadline time.Time
			c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Host != r.URL.Host {
					t.Fatalf("Host header %q does not match redirect destination %q", r.Host, r.URL.Host)
				}
				current, ok := r.Context().Deadline()
				if !ok {
					t.Fatal("request is missing a deadline")
				}
				if requests == 1 {
					deadline = current
				} else if !current.Equal(deadline) {
					t.Fatal("redirect reset the request timeout")
				}
				if r.Header.Get("X-Vault-Token") != "test-token" || r.Header.Get("X-Vault-Namespace") != "team" || r.Header.Get("X-Vault-Request") != "true" {
					t.Fatal("headers lost on redirect")
				}
				if requests == 1 || tc.secondRedirect {
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{tc.location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"lease_duration":3600,"data":{"access_key":"AKIA","secret_key":"SECRET","security_token":"SESSION"}}`)), Request: r}, nil
			})
			_, err = c.GetAWSCredentials(t.Context(), "aws", "role", "sts", "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			if requests != tc.wantRequests {
				t.Fatalf("requests=%d want=%d", requests, tc.wantRequests)
			}
		})
	}
}

func TestClientNonJSONErrorBodyIncludesStatus(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:  "https://vault.example",
		token: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Body:       io.NopCloser(strings.NewReader("<html>502 Bad Gateway</html>")),
					Header:     make(http.Header),
				}, nil
			}),
		},
		now: time.Now,
	}

	_, err := c.GetAWSCredentials(context.Background(), "aws", "role", "sts", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected status 502 in error, got: %v", err)
	}
	if strings.Contains(err.Error(), "<html>") {
		t.Fatalf("response body must stay private: %v", err)
	}
}

func TestClientIAMCredentialsThroughSTSAlias(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:  "https://vault.example",
		token: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"lease_duration":3600,"data":{"access_key":"AKIA","secret_key":"SECRET","security_token":""}}`)),
					Header:     make(http.Header),
				}, nil
			}),
		},
		now: time.Now,
	}

	_, err := c.GetAWSCredentials(context.Background(), "aws", "role", "sts", "")
	if err != nil {
		t.Fatalf("IAM credentials are valid through the sts alias: %v", err)
	}
}

func TestClientGetAWSCredentialsError(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:  "https://vault.example",
		token: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"errors":["permission denied"]}`)),
					Header:     make(http.Header),
				}, nil
			}),
			Timeout: 5 * time.Second,
		},
		now: time.Now,
	}

	_, err := c.GetAWSCredentials(context.Background(), "aws", "app-role", "sts", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied in error, got: %v", err)
	}
}

func TestClientConstructorValidation(t *testing.T) {
	t.Parallel()

	_, err := NewClient(ClientConfig{})
	if err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("expected address validation error, got %v", err)
	}

	_, err = NewClient(ClientConfig{Addr: "https://vault.example"})
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected token validation error, got %v", err)
	}
}

func TestClientRedirectPolicyConfigured(t *testing.T) {
	t.Parallel()

	client, err := NewClient(ClientConfig{Addr: "https://vault.example", Token: "t"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("client must disable automatic redirects to protect the vault token")
	}
	if client.httpClient.Timeout < 30*time.Second {
		t.Fatalf("expected a bounded request timeout, got %v", client.httpClient.Timeout)
	}
}

func TestClientGetAWSCredentialsMissingKeys(t *testing.T) {
	t.Parallel()

	c := &Client{
		addr:  "https://vault.example",
		token: "test-token",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"lease_duration":3600,"data":{}}`)),
					Header:     make(http.Header),
				}, nil
			}),
		},
		now: time.Now,
	}

	_, err := c.GetAWSCredentials(context.Background(), "aws", "app-role", "sts", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !strings.Contains(got, "missing access_key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTLSConfigSkipVerifyDefaultsOff(t *testing.T) {
	t.Parallel()

	cfg, err := newTLSConfig("", "", false)
	if err != nil {
		t.Fatalf("new TLS config: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to default to false")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected minimum TLS version: %v", cfg.MinVersion)
	}
}

func TestNewTLSConfigSkipVerifyOptIn(t *testing.T) {
	t.Parallel()

	cfg, err := newTLSConfig("", "", true)
	if err != nil {
		t.Fatalf("new TLS config: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify when explicitly enabled")
	}
}

func TestNewTLSConfigLoadsCertificatesFromCAPath(t *testing.T) {
	t.Parallel()

	certDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideCA := filepath.Join(outsideDir, "ca-outside.pem")
	subject1 := writeTestCertificateTo(t, outsideCA)

	subject2 := writeTestCertificateTo(t, filepath.Join(certDir, "ca.pem"))

	// A symlinked CA file (common with c_rehash style layouts) must load.
	if err := os.Symlink(outsideCA, filepath.Join(certDir, "linked-ca.pem")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	// Certificates in subdirectories must be found recursively.
	subDir := filepath.Join(certDir, "nested")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	subject3 := writeTestCertificateTo(t, filepath.Join(subDir, "nested-ca.pem"))

	if err := os.WriteFile(filepath.Join(certDir, "ignored.txt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	cfg, err := newTLSConfig("", certDir, false)
	if err != nil {
		t.Fatalf("new TLS config: %v", err)
	}
	subjects := cfg.RootCAs.Subjects()
	if !subjectsContain(subjects, subject1) {
		t.Fatal("expected symlinked certificate from VAULT_CAPATH to be added to the root pool")
	}
	if !subjectsContain(subjects, subject2) {
		t.Fatal("expected certificate from VAULT_CAPATH to be added to the root pool")
	}
	if !subjectsContain(subjects, subject3) {
		t.Fatal("expected certificate from VAULT_CAPATH subdirectory to be added to the root pool")
	}
}

func TestNewTLSConfigCAPointingToRealFileLoads(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	real := filepath.Join(dir, "real-ca.pem")
	writeTestCertificateTo(t, real)
	link := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(real, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	cfg, err := newTLSConfig(link, "", false)
	if err != nil {
		t.Fatalf("new TLS config with symlinked VAULT_CACERT: %v", err)
	}
	certPath := cfg.RootCAs.Subjects()
	if len(certPath) == 0 {
		t.Fatal("expected symlinked VAULT_CACERT to load")
	}
}

func TestNewTLSConfigDanglingCAFileFails(t *testing.T) {
	t.Parallel()

	certDir := t.TempDir()
	if err := os.Symlink(filepath.Join(certDir, "missing-target.pem"), filepath.Join(certDir, "dangling.pem")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	_, err := newTLSConfig("", certDir, false)
	if err == nil {
		t.Fatal("expected error for unreadable CA file in VAULT_CAPATH")
	}
}

func writeTestCertificateTo(t *testing.T, path string) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "vaultcreds-test-ca-" + filepath.Base(path),
			Organization: []string{"vaultcreds"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert.RawSubject
}

func subjectsContain(subjects [][]byte, want []byte) bool {
	for _, subject := range subjects {
		if string(subject) == string(want) {
			return true
		}
	}
	return false
}

func TestClientResponseErrorsNeverContainSecrets(t *testing.T) {
	t.Parallel()
	for _, status := range []int{200, 502} {
		for _, body := range []string{
			`{"data":{"access_key":"AKIA_TEST","secret_key":"PRIVATE_SECRET","security_token":"PRIVATE_TOKEN"},"lease_duration":"invalid"}`,
			`{"data":{"secret_key":"PRIVATE_SECRET","security_token":"PRIVATE_TOKEN"}`,
			"PRIVATE_SECRET PRIVATE_TOKEN",
		} {
			c := &Client{addr: "https://vault.example", now: time.Now, httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			_, err := c.GetAWSCredentials(t.Context(), "aws", "r", "sts", "")
			if err == nil {
				t.Fatal("expected malformed response error")
			}
			if strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatalf("secret in error: %v", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("missing status: %v", err)
			}
		}
	}
}

func TestClientEscapesReservedPathCharacters(t *testing.T) {
	t.Parallel()
	c := &Client{addr: "https://vault.example", now: time.Now, httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.EscapedPath() != "/v1/aws/team%23blue/sts/role%3Fname" || r.URL.Fragment != "" || r.URL.Query().Get("ttl") != "1h" {
			t.Fatalf("invalid URL: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{"access_key":"AKIA","secret_key":"S"}}`)), Header: make(http.Header)}, nil
	})}}
	if _, err := c.GetAWSCredentials(t.Context(), "aws/team#blue", "role?name", "sts", "1h"); err != nil {
		t.Fatal(err)
	}
}
