package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

type Command struct {
	Path                     string
	Args                     []string
	Stdin                    []byte
	Directory                string
	Timeout                  time.Duration
	StdoutLimit, StderrLimit int64
}
type CommandResult struct {
	Status       CapabilityStatus `json:"status"`
	ExitCode     int              `json:"exit_code"`
	Signal       string           `json:"signal,omitempty"`
	Stdout       []byte           `json:"-"`
	Stderr       []byte           `json:"-"`
	StdoutDigest string           `json:"stdout_digest"`
	StderrDigest string           `json:"stderr_digest"`
	StartedAt    time.Time        `json:"started_at"`
	EndedAt      time.Time        `json:"ended_at"`
	Error        string           `json:"error,omitempty"`
}

func Run(ctx context.Context, allowed map[string]struct{}, c Command) CommandResult {
	r := CommandResult{Status: Failed, StartedAt: time.Now().UTC()}
	defer func() { r.EndedAt = time.Now().UTC() }()
	if _, ok := allowed[c.Path]; !ok || !filepath.IsAbs(c.Path) {
		r.Error = "executable is not allowed"
		return r
	}
	if c.Timeout <= 0 {
		r.Error = "timeout must be positive"
		return r
	}
	runCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, c.Path, c.Args...)
	cmd.Dir = c.Directory
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stdin = bytes.NewReader(c.Stdin)
	var out, errb limitedBuffer
	out.n = c.StdoutLimit
	errb.n = c.StderrLimit
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	r.Stdout, r.Stderr = out.b, errb.b
	r.StdoutDigest = digest(out.b)
	r.StderrDigest = digest(errb.b)
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		r.Error = "adapter timed out"
		return r
	}
	if out.hit || errb.hit {
		r.Error = "adapter output limit exceeded"
		return r
	}
	if err == nil {
		r.Status = Observed
		return r
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		r.ExitCode = exit.ExitCode()
		r.Error = fmt.Sprintf("adapter exited %d", r.ExitCode)
		return r
	}
	r.Error = fmt.Sprintf("run adapter: %v", err)
	return r
}

type limitedBuffer struct {
	b   []byte
	n   int64
	hit bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(len(b.b)+len(p)) > b.n {
		remain := b.n - int64(len(b.b))
		if remain > 0 {
			b.b = append(b.b, p[:remain]...)
		}
		b.hit = true
		return len(p), nil
	}
	b.b = append(b.b, p...)
	return len(p), nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
