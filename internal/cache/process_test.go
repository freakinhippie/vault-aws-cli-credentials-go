package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const testWorkerCredentials = `{"access_key_id":"AKIA_TEST","secret_access_key":"TEST_SECRET","expiration":"2099-01-01T00:00:00Z"}`

func TestCacheWorkerProcess(t *testing.T) {
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
	if mode == "hang" {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	if mode == "invalid" {
		os.Stdout.WriteString("invalid response")
		os.Exit(0)
	}
	if mode == "fail" {
		os.Exit(1)
	}
	if mode == "worker" {
		os.Exit(runWorker(os.Stdin, os.Stdout, func(scope string) (*Store, error) {
			if scope != "session" {
				return nil, errors.New("scope not forwarded")
			}
			return NewStore(&memoryBackend{values: map[string]string{"test": testWorkerCredentials}}), nil
		}))
	}
	os.Exit(2)
}

func testProcessStore(t *testing.T, mode string) *ProcessStore {
	t.Helper()
	s, err := NewProcessStore(t.Context(), "session")
	if err != nil {
		t.Fatal(err)
	}
	s.args = []string{"-test.run=^TestCacheWorkerProcess$", "--", mode}
	return s
}

func TestProcessStoreProtocol(t *testing.T) {
	t.Parallel()
	s := testProcessStore(t, "worker")
	credentials, found, err := s.Load("test")
	if err != nil || !found || credentials.SecretAccessKey != "TEST_SECRET" {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if _, found, err := s.Load("absent"); err != nil || found {
		t.Fatalf("miss: found=%v err=%v", found, err)
	}
	if err := s.Save("saved", credentials); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("saved", CachedCredentials{}); err == nil {
		t.Fatal("accepted invalid credentials")
	}
	entries, err := s.ListEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: count=%d err=%v", len(entries), err)
	}
	if n, err := s.PurgeKeys([]string{"test", "absent"}); err != nil || n != 1 {
		t.Fatalf("purge: count=%d err=%v", n, err)
	}
	if n, err := s.PurgeExpired(); err != nil || n != 0 {
		t.Fatalf("purge expired: count=%d err=%v", n, err)
	}
	if n, err := s.PurgeAll(); err != nil || n != 1 {
		t.Fatalf("purge all: count=%d err=%v", n, err)
	}
}

func TestProcessStoreDeadlineAndInvalidResponse(t *testing.T) {
	t.Parallel()
	s := testProcessStore(t, "hang")
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	s.ctx = ctx
	start := time.Now()
	if _, _, err := s.Load("test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(start) > 1800*time.Millisecond {
		t.Fatal("cache worker exceeded cancellation bound")
	}
	for _, mode := range []string{"invalid", "fail"} {
		if _, _, err := testProcessStore(t, mode).Load("test"); err == nil {
			t.Fatalf("accepted %s worker", mode)
		}
	}
}

func TestWorkerRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	open := func(string) (*Store, error) { return NewStore(&memoryBackend{}), nil }
	var output bytes.Buffer
	if code := runWorker(strings.NewReader("invalid"), &output, open); code != 2 {
		t.Fatalf("malformed request exit=%d", code)
	}
	for _, op := range []string{"unknown", "load"} {
		output.Reset()
		input, _ := json.Marshal(workerRequest{Scope: "session", Operation: op})
		selectedOpen := open
		if op == "load" {
			selectedOpen = func(string) (*Store, error) { return nil, ErrNoSecureBackend }
		}
		if code := runWorker(bytes.NewReader(input), &output, selectedOpen); code != 0 {
			t.Fatalf("response exit=%d", code)
		}
		var r workerResponse
		if err := json.Unmarshal(output.Bytes(), &r); err != nil || r.Error == "" {
			t.Fatalf("missing error response: %v", err)
		}
	}
}

func TestPassEnvironmentDisablesPrompts(t *testing.T) {
	t.Parallel()
	env := nonInteractiveEnv([]string{"PATH=/bin", "PASSWORD_STORE_GPG_OPTS=--existing"})
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/bin", "PASSWORD_STORE_GPG_OPTS=--existing --batch --no-tty --pinentry-mode error", "PASSWORD_STORE_ENABLE_EXTENSIONS=false"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q", want)
		}
	}
}
