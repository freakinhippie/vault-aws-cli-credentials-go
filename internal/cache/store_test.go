package cache

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type memoryBackend struct {
	values    map[string]string
	errGet    error
	errSet    error
	errKeys   error
	errRemove error
	failGetOn map[string]bool
}

func (m *memoryBackend) Get(key string) (string, error) {
	if m.errGet != nil {
		return "", m.errGet
	}
	if m.failGetOn != nil && m.failGetOn[key] {
		return "", errors.New("get failed for " + key)
	}
	if m.values == nil {
		return "", nil
	}
	return m.values[key], nil
}

func (m *memoryBackend) Set(key, value string) error {
	if m.errSet != nil {
		return m.errSet
	}
	if m.values == nil {
		m.values = map[string]string{}
	}
	m.values[key] = value
	return nil
}

func (m *memoryBackend) Keys() ([]string, error) {
	if m.errKeys != nil {
		return nil, m.errKeys
	}
	keys := make([]string, 0, len(m.values))
	for k := range m.values {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *memoryBackend) Remove(key string) (bool, error) {
	if m.errRemove != nil {
		return false, m.errRemove
	}
	if m.values == nil {
		return false, nil
	}
	if _, ok := m.values[key]; !ok {
		return false, nil
	}
	delete(m.values, key)
	return true, nil
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	backend := &memoryBackend{}
	store := NewStore(backend)
	store.now = func() time.Time {
		return time.Date(2026, 2, 24, 10, 0, 0, 0, time.UTC)
	}
	exp := "2026-02-24T11:00:00Z"
	key := BuildKey("https://vault", "ns", "aws", "role", "sts", "1h")

	err := store.Save(key, CachedCredentials{
		AccessKeyID:     "AKIA",
		SecretAccessKey: "SECRET",
		SessionToken:    "SESSION",
		Expiration:      &exp,
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	creds, ok, err := store.Load(key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok {
		t.Fatal("expected cache hit")
	}
	if creds.AccessKeyID != "AKIA" || creds.SecretAccessKey != "SECRET" || creds.SessionToken != "SESSION" {
		t.Fatalf("unexpected credentials: %#v", creds)
	}
}

func TestStoreLoadSkipsExpired(t *testing.T) {
	t.Parallel()

	backend := &memoryBackend{values: map[string]string{}}
	store := NewStore(backend)
	store.now = func() time.Time {
		return time.Date(2026, 2, 24, 10, 59, 30, 0, time.UTC)
	}
	backend.values["k"] = `{"access_key_id":"AKIA","secret_access_key":"SECRET","expiration":"2026-02-24T11:00:00Z"}`

	_, ok, err := store.Load("k")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok {
		t.Fatal("expected expired cache miss")
	}
}

func TestStoreNeverServesEntriesWithoutExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 24, 10, 0, 0, 0, time.UTC)
	backend := &memoryBackend{values: map[string]string{
		"legacy": `{"access_key_id":"AKIA","secret_access_key":"SECRET"}`,
	}}
	store := NewStore(backend)
	store.now = func() time.Time { return now.AddDate(4, 0, 0) }

	_, ok, err := store.Load("legacy")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok {
		t.Fatal("expiration-less entries must never be served, even years later")
	}
}

func TestStoreSaveRejectsMissingOrPastExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 24, 10, 0, 0, 0, time.UTC)
	store := NewStore(&memoryBackend{})
	store.now = func() time.Time { return now }

	if err := store.Save("k", CachedCredentials{AccessKeyID: "AKIA", SecretAccessKey: "SECRET"}); err == nil {
		t.Fatal("expected save rejection without expiration")
	}

	past := "2020-01-01T00:00:00Z"
	if err := store.Save("k", CachedCredentials{AccessKeyID: "AKIA", SecretAccessKey: "SECRET", Expiration: &past}); err == nil {
		t.Fatal("expected save rejection for past expiration")
	}

	bad := "not-a-timestamp"
	if err := store.Save("k", CachedCredentials{AccessKeyID: "AKIA", SecretAccessKey: "SECRET", Expiration: &bad}); err == nil {
		t.Fatal("expected save rejection for unparseable expiration")
	}
}

func TestStoreBackendErrors(t *testing.T) {
	t.Parallel()

	exp := "2099-01-01T00:00:00Z"

	store := NewStore(&memoryBackend{errGet: errors.New("boom")})
	_, _, err := store.Load("k")
	if err == nil {
		t.Fatal("expected backend get error")
	}

	store = NewStore(&memoryBackend{errSet: errors.New("boom")})
	err = store.Save("k", CachedCredentials{AccessKeyID: "AKIA", SecretAccessKey: "SECRET", Expiration: &exp})
	if err == nil {
		t.Fatal("expected backend set error")
	}
}

func TestBuildKeyReadableContext(t *testing.T) {
	t.Parallel()

	key := BuildKey("https://vault.example.com:8200", "team/prod", "aws-team", "app-role", "sts", "1h")
	if !strings.HasPrefix(key, "vault.example.com:8200/team/prod/aws-team/sts/app-role/1h.") {
		t.Fatalf("unexpected key format: %q", key)
	}
}

func TestBuildKeyOmitsRootNamespace(t *testing.T) {
	t.Parallel()

	key := BuildKey("https://vault.example.com:8200", "", "aws", "role", "sts", "1h")
	if !strings.HasPrefix(key, "vault.example.com:8200/aws/sts/role/1h.") {
		t.Fatalf("expected root namespace omitted, got %q", key)
	}
	key = BuildKey("https://vault.example.com:8200", "root", "aws", "role", "sts", "1h")
	if !strings.HasPrefix(key, "vault.example.com:8200/aws/sts/role/1h.") {
		t.Fatalf("expected explicit root namespace omitted, got %q", key)
	}
}

func TestBuildKeyDeterministicAndDistinct(t *testing.T) {
	t.Parallel()

	a := BuildKey("https://vault.example", "ns", "aws", "role", "sts", "1h")
	b := BuildKey("https://vault.example", "ns", "aws", "role", "sts", "1h")
	c := BuildKey("https://vault.example", "ns", "aws", "other-role", "sts", "1h")
	if a != b {
		t.Fatalf("expected deterministic keys: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("expected distinct keys for different context: %q == %q", a, c)
	}
}

func TestBuildKeyNormalizesEquivalentContexts(t *testing.T) {
	t.Parallel()

	withSlash := BuildKey("https://vault.example.com/", "", "aws", "role", "sts", "1h")
	withoutSlash := BuildKey("https://vault.example.com", "", "aws", "role", "sts", "1h")
	if withSlash != withoutSlash {
		t.Fatalf("trailing slash created duplicate cache context: %q != %q", withSlash, withoutSlash)
	}

	explicitRoot := BuildKey("https://vault.example.com", "root", "aws", "role", "sts", "1h")
	implicit := BuildKey("https://vault.example.com", "", "aws", "role", "sts", "1h")
	if explicitRoot != implicit {
		t.Fatalf("explicit root namespace created duplicate cache context: %q != %q", explicitRoot, implicit)
	}
}

func TestBuildKeyNoDelimiterCollision(t *testing.T) {
	t.Parallel()

	a := BuildKey("https://vault.example", "ns", "aws", "a|", "x", "1h")
	b := BuildKey("https://vault.example", "ns", "aws", "a", "|x", "1h")
	if a == b {
		t.Fatalf("delimiter collision: %q == %q", a, b)
	}
}

func TestStoreListAndPurge(t *testing.T) {
	t.Parallel()

	expired := "2020-01-01T00:00:00Z"
	valid := "2099-01-01T00:00:00Z"
	backend := &memoryBackend{
		values: map[string]string{
			"k1": `{"access_key_id":"AKIA1","secret_access_key":"SECRET1","expiration":"` + expired + `"}`,
			"k2": `{"access_key_id":"AKIA2","secret_access_key":"SECRET2","expiration":"` + valid + `"}`,
		},
	}
	store := NewStore(backend)

	entries, err := store.ListEntries()
	if err != nil {
		t.Fatalf("list entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	n, err := store.PurgeExpired()
	if err != nil {
		t.Fatalf("purge expired: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired entry purged, got %d", n)
	}
	if _, ok := backend.values["k1"]; ok {
		t.Fatal("expected k1 removed")
	}
	if _, ok := backend.values["k2"]; !ok {
		t.Fatal("expected k2 to remain")
	}

	n, err = store.PurgeAll()
	if err != nil {
		t.Fatalf("purge all: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 remaining entry purged, got %d", n)
	}
	if len(backend.values) != 0 {
		t.Fatalf("expected empty backend, got %#v", backend.values)
	}
}

func TestStorePurgeExpiredRemovesLegacyAndCorruptEntries(t *testing.T) {
	t.Parallel()

	backend := &memoryBackend{
		values: map[string]string{
			"legacy":  `{"access_key_id":"AKIA1","secret_access_key":"SECRET1"}`,
			"corrupt": `{{{not json`,
			"valid":   `{"access_key_id":"AKIA3","secret_access_key":"SECRET3","expiration":"2099-01-01T00:00:00Z"}`,
		},
	}
	store := NewStore(backend)

	entries, err := store.ListEntries()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	statuses := map[string]Entry{}
	for _, e := range entries {
		statuses[e.Key] = e
	}
	if !statuses["legacy"].Expired {
		t.Fatal("legacy expiration-less entry must be listed as stale/expired")
	}
	if !statuses["corrupt"].Corrupt {
		t.Fatal("corrupt entry must be flagged corrupt")
	}
	if statuses["valid"].Expired || statuses["valid"].Corrupt {
		t.Fatal("valid entry misclassified")
	}

	n, err := store.PurgeExpired()
	if err != nil {
		t.Fatalf("purge expired: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected legacy+corrupt purged, got %d", n)
	}
	if _, ok := backend.values["valid"]; !ok {
		t.Fatal("valid entry must remain")
	}
}

func TestStoreListEntriesToleratesPerKeyErrors(t *testing.T) {
	t.Parallel()

	backend := &memoryBackend{
		values: map[string]string{
			"good": `{"access_key_id":"AKIA","secret_access_key":"SECRET","expiration":"2099-01-01T00:00:00Z"}`,
			"bad":  `{"access_key_id":"X","secret_access_key":"Y"}`,
		},
		failGetOn: map[string]bool{"bad": true},
	}
	store := NewStore(backend)

	entries, err := store.ListEntries()
	if err == nil {
		t.Fatal("expected partial read error to be reported")
	}
	if len(entries) != 1 || entries[0].Key != "good" {
		t.Fatalf("expected readable entries to still be returned, got %#v", entries)
	}
}

func TestStorePurgeKeysCountsOnlyExistingEntries(t *testing.T) {
	t.Parallel()

	backend := &memoryBackend{values: map[string]string{"exists": "x"}}
	store := NewStore(backend)

	n, err := store.PurgeKeys([]string{"exists", "typo-key"})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected only the existing key counted, got %d", n)
	}
}

func TestBuildKeyPreservesCaseSensitiveBasePaths(t *testing.T) {
	t.Parallel()
	a := BuildKey("https://vault/Tenant", "", "aws", "r", "sts", "1h")
	b := BuildKey("https://vault/tenant", "", "aws", "r", "sts", "1h")
	if a == b {
		t.Fatal("case-sensitive URL paths share a cache key")
	}
	c := BuildKey("https://VAULT/Tenant/", "", "aws", "r", "sts", "1h")
	if a != c {
		t.Fatal("equivalent hosts and trailing slashes must share a key")
	}
}

func TestPurgeMalformedCredentialsWithFutureExpiration(t *testing.T) {
	t.Parallel()
	backend := &memoryBackend{values: map[string]string{"bad": `{"access_key_id":"AKIA","expiration":"2099-01-01T00:00:00Z"}`}}
	store := NewStore(backend)
	entries, err := store.ListEntries()
	if err != nil || len(entries) != 1 || !entries[0].Corrupt {
		t.Fatalf("malformed entry not corrupt: %v %v", entries, err)
	}
	n, err := store.PurgeExpired()
	if err != nil || n != 1 {
		t.Fatalf("purge=%d err=%v", n, err)
	}
}
