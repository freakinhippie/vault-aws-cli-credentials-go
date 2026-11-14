package subprocess

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLimitedBufferHandlesCopyAndFurtherWrites(t *testing.T) {
	t.Parallel()
	b := &limitedBuffer{limit: 4}
	if n, err := io.Copy(b, strings.NewReader("12345678")); n != 8 || err != nil {
		t.Fatalf("copy=%d err=%v", n, err)
	}
	if n, err := b.Write([]byte("more")); n != 4 || err != nil {
		t.Fatalf("write=%d err=%v", n, err)
	}
	if !b.truncated || !bytes.Equal(b.Bytes(), []byte("1234")) {
		t.Fatalf("retained %q truncated=%v", b.String(), b.truncated)
	}
}

func TestRunWithCancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd := Command(ctx, os.Args[0], "-test.run=^$")
	if _, err := Run(ctx, cmd, 1024, 1024); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}
