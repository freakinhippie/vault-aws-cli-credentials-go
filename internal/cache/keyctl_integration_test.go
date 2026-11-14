//go:build integration && linux

package cache

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/byteness/keyring"
)

func TestKeyctlWorker(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "keyctl-worker" {
		return
	}
	availableBackends = func() []keyring.BackendType { return []keyring.BackendType{keyring.KeyCtlBackend} }
	os.Exit(RunWorker(os.Stdin, os.Stdout))
}

func TestKeyctlSessionSharedAcrossProcesses(t *testing.T) {
	s, err := NewProcessStore(t.Context(), "session")
	if err != nil {
		t.Fatal(err)
	}
	s.args = []string{"-test.run=^TestKeyctlWorker$", "--", "keyctl-worker"}
	key := fmt.Sprintf("test-keyctl-%d-%d", os.Getpid(), time.Now().UnixNano())
	if _, _, err := s.Load(key); err != nil {
		if os.Getenv("VAULTCREDS_KEYCTL_REQUIRE") == "1" {
			t.Fatal(err)
		}
		t.Skipf("kernel keyring unavailable: %v", err)
	}
	expiration := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := s.Save(key, CachedCredentials{AccessKeyID: "AKIA_TEST", SecretAccessKey: "TEST_SECRET", Expiration: &expiration}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.ctx = ctx
		if _, err := s.PurgeKeys([]string{key}); err != nil {
			t.Error(err)
		}
	})
	credentials, found, err := s.Load(key)
	if err != nil || !found || credentials.SecretAccessKey != "TEST_SECRET" {
		t.Fatalf("cross-process cache load: found=%v err=%v", found, err)
	}
}
