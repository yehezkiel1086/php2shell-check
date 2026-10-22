package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/cli"
)

func TestHelpListsGlobalFlagsForEveryCommand(t *testing.T) {
	t.Parallel()

	expectedGlobalFlags := []string{
		"--format",
		"--output",
		"--fail-on",
		"--offline",
		"--quiet",
		"--no-color",
		"--advisory-file",
	}

	commands := [][]string{
		{"--help"},
		{"scan", "--help"},
		{"scan", "local", "--help"},
		{"scan", "image", "--help"},
		{"scan", "sbom", "--help"},
		{"scan", "path", "--help"},
		{"scan", "remote", "--help"},
		{"advisories", "--help"},
		{"advisories", "list", "--help"},
		{"version", "--help"},
	}

	for _, args := range commands {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, args, &stdout, &stderr)
			if code != cli.ExitCodeClean {
				t.Fatalf("Run(%v) exit code = %d, want %d (stderr: %s)", args, code, cli.ExitCodeClean, stderr.String())
			}

			out := stdout.String()
			for _, flag := range expectedGlobalFlags {
				if !strings.Contains(out, flag) {
					t.Errorf("help output for %v missing global flag %q\noutput:\n%s", args, flag, out)
				}
			}
		})
	}
}

func TestStubCommandsReturnNotImplemented(t *testing.T) {
	t.Parallel()

	stubs := [][]string{
		{"scan", "local"},
		{"scan", "image", "php:8.3-fpm"},
		{"scan", "sbom", "bom.json"},
		{"scan", "path", "/var/www"},
		{"scan", "remote", "--authorized", "https://example.com"},
		{"advisories", "list"},
	}

	for _, args := range stubs {
		name := strings.Join(args, "_")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, args, &stdout, &stderr)
			if code != cli.ExitCodeError {
				t.Fatalf("Run(%v) exit code = %d, want %d", args, code, cli.ExitCodeError)
			}
			if !strings.Contains(stderr.String(), cli.ErrNotImplemented.Error()) {
				t.Fatalf("Run(%v) stderr = %q, want substring %q", args, stderr.String(), cli.ErrNotImplemented.Error())
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	info := cli.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc1234",
		Date:    "2026-10-22T00:00:00Z",
	}

	code := cli.Run(context.Background(), info, []string{"version"}, &stdout, &stderr)
	if code != cli.ExitCodeClean {
		t.Fatalf("version exit code = %d, want %d (stderr: %s)", code, cli.ExitCodeClean, stderr.String())
	}

	want := "php2shell-check 1.2.3 (commit: abc1234, date: 2026-10-22T00:00:00Z)\n"
	if stdout.String() != want {
		t.Fatalf("version stdout = %q, want %q", stdout.String(), want)
	}
}

func TestInvalidGlobalFlagsReturnExitCodeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "invalid format",
			args: []string{"--format", "html", "version"},
		},
		{
			name: "invalid fail-on",
			args: []string{"--fail-on", "always", "version"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := cli.Run(context.Background(), cli.BuildInfo{}, tc.args, &stdout, &stderr)
			if code != cli.ExitCodeError {
				t.Fatalf("Run(%v) exit code = %d, want %d", tc.args, code, cli.ExitCodeError)
			}
		})
	}
}
