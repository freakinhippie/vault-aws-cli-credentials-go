package awscred

import (
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
}
