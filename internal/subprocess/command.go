// Package subprocess runs helpers with cancellation and bounded output.
package subprocess

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Command bounds pipe cleanup even when descendants retain inherited handles.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 -- Callers select the executable explicitly; no shell is used.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	configureCancellation(cmd)
	return cmd
}

// Run captures output without allowing a helper to exhaust memory. Stderr is
// retained only up to stderrLimit and is included in errors, never stdout.
func Run(ctx context.Context, cmd *exec.Cmd, stdoutLimit, stderrLimit int) ([]byte, error) {
	stdout := &limitedBuffer{limit: stdoutLimit}
	stderr := &limitedBuffer{limit: stderrLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	if stdout.truncated {
		return nil, fmt.Errorf("helper output exceeds %d bytes", stdoutLimit)
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedBuffer) String() string { return b.buffer.String() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.limit - b.buffer.Len(); n > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}
