package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

var ErrNoSecureBackend = errors.New("no secure credential cache backend available")

type CachedCredentials struct {
	AccessKeyID     string  `json:"access_key_id"`
	SecretAccessKey string  `json:"secret_access_key"`
	SessionToken    string  `json:"session_token,omitempty"`
	Expiration      *string `json:"expiration,omitempty"`
}

type Backend interface {
	Name() string
	Get(key string) (string, error)
	Set(key, value string) error
	Keys() ([]string, error)
	Remove(key string) error
}

type Store struct {
	backend Backend
	now     func() time.Time
}

type Entry struct {
	Key        string
	AccessKey  string
	Expiration *time.Time
	Expired    bool
}

func NewStore(backend Backend) *Store {
	return &Store{backend: backend, now: time.Now}
}

func (s *Store) Load(key string) (CachedCredentials, bool, error) {
	raw, err := s.backend.Get(key)
	if err != nil {
		return CachedCredentials{}, false, err
	}
	if raw == "" {
		return CachedCredentials{}, false, nil
	}

	var creds CachedCredentials
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return CachedCredentials{}, false, fmt.Errorf("decode cached credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return CachedCredentials{}, false, nil
	}
	if creds.Expiration != nil {
		expiresAt, err := time.Parse(time.RFC3339, *creds.Expiration)
		if err != nil {
			return CachedCredentials{}, false, nil
		}
		if s.now().UTC().Add(1 * time.Minute).After(expiresAt) {
			return CachedCredentials{}, false, nil
		}
	}
	return creds, true, nil
}

func (s *Store) Save(key string, creds CachedCredentials) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("cache credentials missing access key or secret key")
	}
	b, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("encode cached credentials: %w", err)
	}
	return s.backend.Set(key, string(b))
}

func (s *Store) ListEntries() ([]Entry, error) {
	keys, err := s.backend.Keys()
	if err != nil {
		return nil, fmt.Errorf("list cache keys: %w", err)
	}
	sort.Strings(keys)

	entries := make([]Entry, 0, len(keys))
	for _, key := range keys {
		raw, err := s.backend.Get(key)
		if err != nil {
			return nil, fmt.Errorf("read cache key %q: %w", key, err)
		}
		if raw == "" {
			continue
		}

		entry := Entry{Key: key}
		var creds CachedCredentials
		if err := json.Unmarshal([]byte(raw), &creds); err == nil {
			entry.AccessKey = creds.AccessKeyID
			if creds.Expiration != nil {
				if exp, err := time.Parse(time.RFC3339, *creds.Expiration); err == nil {
					entry.Expiration = &exp
					entry.Expired = s.now().UTC().Add(1 * time.Minute).After(exp)
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *Store) Delete(key string) error {
	return s.backend.Remove(key)
}

func (s *Store) PurgeKeys(keys []string) (int, error) {
	removed := 0
	for _, key := range keys {
		k := strings.TrimSpace(key)
		if k == "" {
			continue
		}
		if err := s.backend.Remove(k); err != nil {
			return removed, fmt.Errorf("purge cache key %q: %w", k, err)
		}
		removed++
	}
	return removed, nil
}

func (s *Store) PurgeExpired() (int, error) {
	entries, err := s.ListEntries()
	if err != nil {
		return 0, err
	}
	expired := make([]string, 0)
	for _, entry := range entries {
		if entry.Expired {
			expired = append(expired, entry.Key)
		}
	}
	return s.PurgeKeys(expired)
}

func (s *Store) PurgeAll() (int, error) {
	keys, err := s.backend.Keys()
	if err != nil {
		return 0, fmt.Errorf("list cache keys: %w", err)
	}
	return s.PurgeKeys(keys)
}

func BuildKey(vaultAddr, namespace, mount, role, credentialType, ttl string) string {
	source := fmt.Sprintf("%s|%s|%s|%s|%s|%s", vaultAddr, namespace, mount, role, credentialType, ttl)
	sum := sha256.Sum256([]byte(source))
	parts := []string{sanitizeHostPart(vaultHost(vaultAddr))}
	if ns := normalizeNamespace(namespace); ns != "" {
		for _, seg := range strings.Split(ns, "/") {
			parts = append(parts, sanitizePathPart(seg))
		}
	}
	parts = append(parts,
		sanitizePathPart(mount),
		sanitizePathPart(credentialType),
		sanitizePathPart(role),
		sanitizePathPart(ttl),
	)
	return fmt.Sprintf("%s.%s", strings.Join(parts, "/"), hex.EncodeToString(sum[:4]))
}

func vaultHost(addr string) string {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err == nil && u.Host != "" {
		return u.Host
	}
	return addr
}

func normalizeNamespace(ns string) string {
	ns = strings.Trim(strings.TrimSpace(ns), "/")
	if ns == "" || ns == "root" {
		return ""
	}
	return ns
}

func sanitizeHostPart(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown-vault"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == ':' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown-vault"
	}
	return out
}

func sanitizePathPart(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "default"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	return out
}
