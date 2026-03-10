package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ClientConfig struct {
	Addr       string
	Token      string
	Namespace  string
	CACertPath string
	CAPath     string
	SkipVerify bool
}

type Client struct {
	addr       string
	token      string
	namespace  string
	httpClient *http.Client
	now        func() time.Time
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &Client{
		addr:      strings.TrimRight(cfg.Addr, "/"),
		token:     cfg.Token,
		namespace: cfg.Namespace,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		now: time.Now,
	}, nil
}

func (c *Client) GetAWSCredentials(ctx context.Context, mount, role, credentialType, ttl string) (AWSCredentials, error) {
	path := fmt.Sprintf("/v1/%s/%s/%s", url.PathEscape(mount), credentialType, url.PathEscape(role))
	u := c.addr + path
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
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return AWSCredentials{}, fmt.Errorf("request vault aws credentials: %w", err)
	}
	defer resp.Body.Close()

	var payload struct {
		LeaseDuration int64 `json:"lease_duration"`
		Data          struct {
			AccessKey     string `json:"access_key"`
			SecretKey     string `json:"secret_key"`
			SecurityToken string `json:"security_token"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return AWSCredentials{}, fmt.Errorf("decode vault response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(payload.Errors) > 0 {
			return AWSCredentials{}, fmt.Errorf("vault request failed: %s", strings.Join(payload.Errors, "; "))
		}
		return AWSCredentials{}, fmt.Errorf("vault request failed: status %d", resp.StatusCode)
	}

	if payload.Data.AccessKey == "" || payload.Data.SecretKey == "" {
		return AWSCredentials{}, errors.New("vault response missing access_key or secret_key")
	}

	creds := AWSCredentials{
		AccessKeyID:     payload.Data.AccessKey,
		SecretAccessKey: payload.Data.SecretKey,
		SessionToken:    payload.Data.SecurityToken,
	}
	if payload.LeaseDuration > 0 {
		expiresAt := c.now().UTC().Add(time.Duration(payload.LeaseDuration) * time.Second).Format(time.RFC3339)
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
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_CACERT: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("failed to append certificate from VAULT_CACERT")
		}
	}

	if caPath != "" {
		entries, err := os.ReadDir(caPath)
		if err != nil {
			return nil, fmt.Errorf("read VAULT_CAPATH: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			pem, err := os.ReadFile(filepath.Join(caPath, entry.Name()))
			if err != nil {
				continue
			}
			pool.AppendCertsFromPEM(pem)
		}
	}

	return &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}, nil
}
