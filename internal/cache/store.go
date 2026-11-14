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

// expiryRefreshBuffer keeps serving a cached entry only while it remains
// comfortably valid.
const expiryRefreshBuffer = 1 * time.Minute

type CachedCredentials struct {
	AccessKeyID     string  `json:"access_key_id"`
	SecretAccessKey string  `json:"secret_access_key"`
	SessionToken    string  `json:"session_token,omitempty"`
	Expiration      *string `json:"expiration,omitempty"`
}

type Backend interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Keys() ([]string, error)
	// Remove deletes the key and reports whether an entry actually existed.
	Remove(key string) (bool, error)
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
	// Corrupt marks an entry whose payload could not be decoded; such entries
	// are unusable and eligible for purging.
	Corrupt bool
}

func NewStore(backend Backend) *Store {
	return &Store{backend: backend, now: time.Now}
}

// Load returns a usable cached entry. Entries without a valid future
// expiration are always treated as a miss: short-lived cloud credentials must
// never be served indefinitely from the cache (for example Vault responses
// that omitted a lease).
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
	if creds.Expiration == nil {
		return CachedCredentials{}, false, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, *creds.Expiration)
	if err != nil {
		return CachedCredentials{}, false, nil
	}
	if s.now().UTC().Add(expiryRefreshBuffer).After(expiresAt) {
		return CachedCredentials{}, false, nil
	}
	return creds, true, nil
}

// Save stores credentials, requiring a valid future expiration so a missing
// lease can never turn into an entry that outlives the credentials it holds.
func (s *Store) Save(key string, creds CachedCredentials) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("cache credentials missing access key or secret key")
	}
	if creds.Expiration == nil {
		return errors.New("refusing to cache credentials without an expiration")
	}
	expiresAt, err := time.Parse(time.RFC3339, *creds.Expiration)
	if err != nil {
		return fmt.Errorf("invalid cache expiration: %w", err)
	}
	if !expiresAt.After(s.now().UTC()) {
		return errors.New("refusing to cache credentials that are already expired")
	}
	// #nosec G117 -- Credentials are serialized only for storage in the secure OS keyring backend, not plaintext disk.
	b, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("encode cached credentials: %w", err)
	}
	return s.backend.Set(key, string(b))
}

// ListEntries lists all cache entries. Per-key read failures are collected
// and returned alongside the entries that could be read, so one unreadable
// item does not make cache maintenance impossible.
func (s *Store) ListEntries() ([]Entry, error) {
	keys, err := s.backend.Keys()
	if err != nil {
		return nil, fmt.Errorf("list cache keys: %w", err)
	}
	sort.Strings(keys)

	var readErrs []error
	entries := make([]Entry, 0, len(keys))
	for _, key := range keys {
		raw, err := s.backend.Get(key)
		if err != nil {
			readErrs = append(readErrs, fmt.Errorf("read cache key %q: %w", key, err))
			continue
		}
		if raw == "" {
			continue
		}

		entry := Entry{Key: key}
		var creds CachedCredentials
		if err := json.Unmarshal([]byte(raw), &creds); err != nil {
			entry.Corrupt = true
			entry.Expired = true
			entries = append(entries, entry)
			continue
		}
		entry.AccessKey = creds.AccessKeyID
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			entry.Corrupt, entry.Expired = true, true
			entries = append(entries, entry)
			continue
		}
		if creds.Expiration != nil {
			if exp, err := time.Parse(time.RFC3339, *creds.Expiration); err == nil {
				entry.Expiration = &exp
				entry.Expired = s.now().UTC().Add(expiryRefreshBuffer).After(exp)
				entries = append(entries, entry)
				continue
			}
		}
		// No usable expiration (missing or unparseable): legacy or malformed
		// entries are treated as stale so they can be purged.
		entry.Expired = true
		entries = append(entries, entry)
	}
	return entries, errors.Join(readErrs...)
}

func (s *Store) PurgeKeys(keys []string) (int, error) {
	removed := 0
	for _, key := range keys {
		k := strings.TrimSpace(key)
		if k == "" {
			continue
		}
		didRemove, err := s.backend.Remove(k)
		if err != nil {
			return removed, fmt.Errorf("purge cache key %q: %w", k, err)
		}
		if didRemove {
			removed++
		}
	}
	return removed, nil
}

// PurgeExpired removes entries that are expired, stale (no usable
// expiration), or corrupt.
func (s *Store) PurgeExpired() (int, error) {
	entries, listErr := s.ListEntries()
	if listErr != nil && len(entries) == 0 {
		return 0, listErr
	}

	purgeable := make([]string, 0)
	for _, entry := range entries {
		if entry.Expired || entry.Corrupt {
			purgeable = append(purgeable, entry.Key)
		}
	}
	removed, err := s.PurgeKeys(purgeable)
	if err != nil {
		return removed, err
	}
	return removed, listErr
}

func (s *Store) PurgeAll() (int, error) {
	keys, err := s.backend.Keys()
	if err != nil {
		return 0, fmt.Errorf("list cache keys: %w", err)
	}
	return s.PurgeKeys(keys)
}

// BuildKey derives a stable, human-readable cache key. The hashed source is
// length-prefixed (so field boundaries cannot collide) and built from
// normalized values (trailing slashes and the explicit "root" namespace do
// not create duplicate entries for the same context).
func BuildKey(vaultAddr, namespace, mount, role, credentialType, ttl string) string {
	fields := []string{
		normalizeAddr(vaultAddr),
		normalizeNamespace(namespace),
		strings.TrimSpace(mount),
		strings.TrimSpace(role),
		strings.TrimSpace(credentialType),
		strings.TrimSpace(ttl),
	}
	var hashed strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&hashed, "%d:%s;", len(field), field)
	}
	sum := sha256.Sum256([]byte(hashed.String()))

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
	return fmt.Sprintf("%s.%s", strings.Join(parts, "/"), hex.EncodeToString(sum[:8]))
}

func normalizeAddr(addr string) string {
	addr = strings.TrimRight(strings.TrimSpace(addr), "/")
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return addr
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
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
