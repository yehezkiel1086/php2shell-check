package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultCommandTimeout is the hard safety limit for running any host binary.
const DefaultCommandTimeout = 10 * time.Second

// ErrNonAbsolutePath is returned when Runner is given a non-absolute binary path.
var ErrNonAbsolutePath = errors.New("binary path must be absolute")

// Runner abstracts host process execution for testability and strict safety enforcement.
type Runner interface {
	Run(ctx context.Context, binPath string, args ...string) (stdout, stderr []byte, err error)
}

// ExecRunner executes host binaries directly via exec.CommandContext with an absolute
// path, no shell interpolation, and a fixed timeout.
type ExecRunner struct {
	Timeout time.Duration
}

// NewExecRunner returns an ExecRunner configured with the 10-second safety timeout.
func NewExecRunner() *ExecRunner {
	return &ExecRunner{Timeout: DefaultCommandTimeout}
}

// Run executes binPath with args under a timeout context.
func (r *ExecRunner) Run(ctx context.Context, binPath string, args ...string) ([]byte, []byte, error) {
	if !isAbsoluteBinaryPath(binPath) {
		return nil, nil, fmt.Errorf("refusing to execute %q: %w", binPath, ErrNonAbsolutePath)
	}

	timeout := r.Timeout
	if timeout <= 0 || timeout > DefaultCommandTimeout {
		timeout = DefaultCommandTimeout
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Safety rule: execute binary directly with absolute path and no shell.
	cmd := exec.CommandContext(tctx, binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("exec %s: %w", binPath, err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func isAbsoluteBinaryPath(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return true
	}
	return filepath.IsAbs(p)
}
