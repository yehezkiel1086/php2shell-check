package cli_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestScanSBOMPathAndRemoteCommands(t *testing.T) {
	t.Parallel()

	t.Run("scan_sbom_cyclonedx", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		fixture := filepath.Join("..", "..", "testdata", "sbom", "cyclonedx.json")
		code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, []string{"scan", "sbom", fixture, "--no-color"}, &stdout, &stderr)
		if code != cli.ExitCodeLikelyOrUnknown {
			t.Fatalf("scan sbom exit code = %d, want %d (stderr: %s)", code, cli.ExitCodeLikelyOrUnknown, stderr.String())
		}
		if !strings.Contains(stdout.String(), "LIKELY_VULNERABLE") {
			t.Errorf("scan sbom output missing LIKELY_VULNERABLE:\n%s", stdout.String())
		}
	})

	t.Run("scan_path_fixtures", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		fixtureDir := filepath.Join("..", "..", "testdata", "path")
		code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, []string{"scan", "path", fixtureDir, "--no-color"}, &stdout, &stderr)
		if code != cli.ExitCodeVulnerable {
			t.Fatalf("scan path exit code = %d, want %d (stderr: %s)", code, cli.ExitCodeVulnerable, stderr.String())
		}
		if !strings.Contains(stdout.String(), "UNKNOWN") || !strings.Contains(stdout.String(), "VULNERABLE") {
			t.Errorf("scan path output missing expected verdicts:\n%s", stdout.String())
		}
	})

	t.Run("scan_remote_requires_authorized", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, []string{"scan", "remote", "https://example.com"}, &stdout, &stderr)
		if code != cli.ExitCodeError {
			t.Fatalf("scan remote without --authorized exit code = %d, want %d", code, cli.ExitCodeError)
		}
		if !strings.Contains(stderr.String(), "--authorized") {
			t.Errorf("stderr = %q, want --authorized error", stderr.String())
		}
	})

	t.Run("scan_remote_with_authorized_capped_at_likely_vulnerable", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "Apache/2.4.58")
			w.Header().Set("X-Powered-By", "PHP/8.3.10")
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		var stdout, stderr bytes.Buffer
		code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, []string{"scan", "remote", "--authorized", srv.URL, "--no-color"}, &stdout, &stderr)
		if code != cli.ExitCodeLikelyOrUnknown {
			t.Fatalf("scan remote exit code = %d, want %d (stderr: %s)", code, cli.ExitCodeLikelyOrUnknown, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "LIKELY_VULNERABLE") {
			t.Errorf("scan remote output missing LIKELY_VULNERABLE:\n%s", out)
		}
		if !strings.Contains(out, "banner, may be hidden or spoofed") {
			t.Errorf("scan remote output missing banner caveat label:\n%s", out)
		}
		if !strings.Contains(out, "expose_php = Off") {
			t.Errorf("scan remote output missing expose_php=Off suggestion:\n%s", out)
		}
	})
}

func TestAdvisoriesListCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), cli.BuildInfo{Version: "0.1.0"}, []string{"advisories", "list"}, &stdout, &stderr)
	if code != cli.ExitCodeClean {
		t.Fatalf("advisories list exit code = %d, want %d (stderr: %s)", code, cli.ExitCodeClean, stderr.String())
	}

	out := stdout.String()
	wantSubstrings := []string{
		"CVE-2026-109618",
		"CVE-2026-109619",
		"5.4.0 .. 8.5.11",
		"8.5.12",
		"8.4.27",
		"8.3.36",
		"8.2.35",
		"session.upload_progress.enabled",
		"fatal_error_backtraces",
	}
	for _, sub := range wantSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("advisories list output missing %q\noutput:\n%s", sub, out)
		}
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
