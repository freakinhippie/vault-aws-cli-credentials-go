package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultRequestTimeout = 60 * time.Second
	maxResponseBytes      = 1 << 20
	// expirationSkewMargin trims a small amount off reported expirations so a
	// client clock running slightly behind the Vault server does not serve
	// credentials past their real expiry.
	expirationSkewMargin = 30 * time.Second
)

type ClientConfig struct {
	Addr             string
	Token            string
	Namespace        string
	CACertPath       string
	CAPath           string
	SkipVerify       bool
	ClientTimeout    time.Duration
	DisableRedirects bool
}

type Client struct {
	addr             string
	token            string
	namespace        string
	httpClient       *http.Client
	now              func() time.Time
	disableRedirects bool
}

type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      *string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, errors.New("vault address cannot be empty")
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("vault token cannot be empty")
	}

	tlsConfig, err := newTLSConfig(cfg.CACertPath, cfg.CAPath, cfg.SkipVerify)
	if err != nil {
		return nil, err
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = tlsConfig

	timeout := cfg.ClientTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	return &Client{
		addr:             strings.TrimRight(cfg.Addr, "/"),
		token:            cfg.Token,
		namespace:        cfg.Namespace,
		disableRedirects: cfg.DisableRedirects,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Redirects are handled explicitly below, matching Vault's single-hop
			// policy while keeping net/http's automatic redirect handling disabled.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}, nil
}

func (c *Client) GetAWSCredentials(ctx context.Context, mount, role, credentialType, ttl string) (AWSCredentials, error) {
	// Vault's timeout covers the logical request, including its redirect hop.
	if c.httpClient.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.httpClient.Timeout)
		defer cancel()
	}
	// Preserve nested mounts while escaping reserved URL characters.
	segments := strings.Split(mount, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	u := fmt.Sprintf("%s/v1/%s/%s/%s", c.addr, strings.Join(segments, "/"), url.PathEscape(credentialType), url.PathEscape(role))
	if ttl != "" {
		query := url.Values{}
		query.Set("ttl", ttl)
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("X-Vault-Request", "true")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	// Vault follows one 301/302/307 redirect, preserving authentication and
	// namespace headers, and refuses an HTTPS protocol downgrade. The HTTP
	// client itself must not follow additional redirects.
	started := c.now().UTC()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("request vault aws credentials: %w", err)
	}
	if !c.disableRedirects && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307) {
		target, locationErr := resp.Location()
		resp.Body.Close()
		if locationErr != nil {
			return AWSCredentials{}, errors.New("vault redirect has an invalid or missing Location")
		}
		if req.URL.Scheme == "https" && target.Scheme != "https" {
			return AWSCredentials{}, errors.New("vault redirect would cause protocol downgrade")
		}
		redirected := req.Clone(ctx)
		redirected.URL = target
		redirected.Host = target.Host
		resp, err = c.httpClient.Do(redirected)
		if err != nil {
			return AWSCredentials{}, fmt.Errorf("follow vault redirect: %w", err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return AWSCredentials{}, fmt.Errorf("vault returned redirect status %d (redirect following disabled or single-hop limit reached)", resp.StatusCode)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if readErr != nil {
		return AWSCredentials{}, fmt.Errorf("read vault response (status %d): %w", resp.StatusCode, readErr)
	}
	if len(body) > maxResponseBytes {
		return AWSCredentials{}, fmt.Errorf("vault response exceeds size limit (status %d)", resp.StatusCode)
	}

	var payload struct {
		LeaseDuration int64 `json:"lease_duration"`
		Data          struct {
			AccessKey     string `json:"access_key"`
			SecretKey     string `json:"secret_key"`
			SecurityToken string `json:"security_token"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	decodeErr := json.Unmarshal(body, &payload)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if decodeErr == nil && len(payload.Errors) > 0 {
			return AWSCredentials{}, fmt.Errorf("vault request failed: status %d: %s", resp.StatusCode, strings.Join(payload.Errors, "; "))
		}
		return AWSCredentials{}, fmt.Errorf("vault request failed: status %d", resp.StatusCode)
	}

	if decodeErr != nil {
		return AWSCredentials{}, fmt.Errorf("decode vault response: status %d: %w", resp.StatusCode, decodeErr)
	}

	if payload.Data.AccessKey == "" || payload.Data.SecretKey == "" {
		return AWSCredentials{}, errors.New("vault response missing access_key or secret_key")
	}
	// Modern Vault roles can return IAM-user credentials through either
	// endpoint; the endpoint alone does not imply a session token is required.

	creds := AWSCredentials{
		AccessKeyID:     payload.Data.AccessKey,
		SecretAccessKey: payload.Data.SecretKey,
		SessionToken:    payload.Data.SecurityToken,
	}
	if payload.LeaseDuration > 0 {
		if payload.LeaseDuration > math.MaxInt64/int64(time.Second) {
			return AWSCredentials{}, errors.New("vault lease duration is out of range")
		}
		lease := time.Duration(payload.LeaseDuration) * time.Second
		margin := expirationSkewMargin
		if lease/10 < margin {
			margin = lease / 10
		}
		expiresAt := started.Add(lease - margin).Format(time.RFC3339)
		creds.Expiration = &expiresAt
	}
	return creds, nil
}

func newTLSConfig(caCertPath, caPath string, skipVerify bool) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if caCertPath != "" {
		// #nosec G304 -- VAULT_CACERT is an explicit user-selected file path that this CLI is expected to read as provided.
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_CACERT: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("failed to append certificate from VAULT_CACERT")
		}
	}

	if caPath != "" {
		if err := appendCertsFromDir(pool, caPath); err != nil {
			return nil, err
		}
	}

	return &tls.Config{
		RootCAs: pool,
		// #nosec G402 -- VAULT_SKIP_VERIFY intentionally mirrors the Vault CLI and is disabled unless the user opts in.
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}, nil
}

// appendCertsFromDir loads CA PEM files from dir recursively, following
// symlinks (matching go-rootcerts/vault CLI behavior). Unreadable files are a
// hard error so a broken CA setup cannot fail silently; files that read but
// contain no certificates are ignored.
func appendCertsFromDir(pool *x509.CertPool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read VAULT_CAPATH: %w", err)
	}
	for _, entry := range entries {
		full := filepath.Join(dir, entry.Name())
		info, err := os.Stat(full)
		if err != nil {
			return fmt.Errorf("read VAULT_CAPATH entry %s: %w", full, err)
		}
		if info.IsDir() {
			if err := appendCertsFromDir(pool, full); err != nil {
				return err
			}
			continue
		}
		// #nosec G304 -- VAULT_CAPATH contents are explicitly user-selected certificate files.
		pem, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read VAULT_CAPATH file %s: %w", full, err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	return nil
}
