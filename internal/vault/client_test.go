package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
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
	if creds.Expiration == nil || *creds.Expiration != "2026-01-01T13:00:00Z" {
		t.Fatalf("expiration mismatch: %#v", creds.Expiration)
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
	rawSubject := writeTestCertificate(t, filepath.Join(certDir, "ca.pem"))

	if err := os.WriteFile(filepath.Join(certDir, "ignored.txt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	cfg, err := newTLSConfig("", certDir, false)
	if err != nil {
		t.Fatalf("new TLS config: %v", err)
	}
	if !subjectsContain(cfg.RootCAs.Subjects(), rawSubject) {
		t.Fatal("expected certificate from VAULT_CAPATH to be added to the root pool")
	}
}

func writeTestCertificate(t *testing.T, path string) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "vaultcreds-test-ca",
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
