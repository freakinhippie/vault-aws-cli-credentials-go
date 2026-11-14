package awscred

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProcessOutputJSONDefaultsVersion(t *testing.T) {
	t.Parallel()

	b, err := ProcessOutput{
		AccessKeyID:     "akid",
		SecretAccessKey: "secret",
	}.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}

	out := string(b)
	if !strings.Contains(out, `"Version":1`) {
		t.Fatalf("expected default version in output: %s", out)
	}
	if strings.Contains(out, "Expiration") {
		t.Fatalf("expected expiration to be omitted: %s", out)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if version, ok := fields["Version"].(float64); !ok || version != 1 {
		t.Fatalf("Version must serialize as integer 1: %s", out)
	}
	wantKeys := map[string]bool{"Version": true, "AccessKeyId": true, "SecretAccessKey": true}
	if len(fields) != len(wantKeys) {
		t.Fatalf("unexpected field set: %#v", fields)
	}
	for key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing %s in output: %s", key, out)
		}
	}
}

func TestProcessOutputJSONFullContract(t *testing.T) {
	t.Parallel()

	exp := "2026-02-24T20:00:00Z"
	b, err := ProcessOutput{
		Version:         1,
		AccessKeyID:     "akid",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Expiration:      &exp,
	}.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}

	var got ProcessOutput
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := ProcessOutput{
		Version:         1,
		AccessKeyID:     "akid",
		SecretAccessKey: "secret",
		SessionToken:    "session",
		Expiration:      &exp,
	}
	if got.Version != want.Version || got.AccessKeyID != want.AccessKeyID ||
		got.SecretAccessKey != want.SecretAccessKey || got.SessionToken != want.SessionToken ||
		got.Expiration == nil || *got.Expiration != *want.Expiration {
		t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v\njson: %s", got, want, string(b))
	}
}
