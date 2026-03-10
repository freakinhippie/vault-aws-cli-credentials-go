package vault

import (
	"context"
	"io"
	"net/http"
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
