// Package main runs the coverage gate and end-to-end CLI verification suite across all scan modes.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const minCoveragePercent = 80.0

var coverageRe = regexp.MustCompile(`coverage:\s+([0-9.]+)%\s+of\s+statements`)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("All coverage gates and E2E mode checks passed.")
}

func execute() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return run(ctx)
}

func run(ctx context.Context) error {
	// 1. Verify >= 80% coverage gate on phpver, match, and remediate.
	gatedPkgs := []string{
		"./internal/phpver",
		"./internal/match",
		"./internal/remediate",
	}
	for _, pkg := range gatedPkgs {
		cov, err := checkCoverage(ctx, pkg)
		if err != nil {
			return err
		}
		fmt.Printf("[coverage] %s: %.1f%% (gate >= %.1f%%)\n", pkg, cov, minCoveragePercent)
	}

	// 2. Build binary into a temporary directory.
	tmpDir, err := os.MkdirTemp("", "php2shell-e2e-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	binName := "php2shell-check"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tmpDir, binName)

	buildCmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binPath, "./cmd/php2shell-check")
	if out, buildErr := buildCmd.CombinedOutput(); buildErr != nil {
		return fmt.Errorf("build binary: %w\n%s", buildErr, string(out))
	}

	// 3. Create a tiny docker-save image tarball fixture with PHP 8.3.10.
	imageTarPath := filepath.Join(tmpDir, "fixture-image.tar")
	if err := writeFixtureImageTarball(imageTarPath); err != nil {
		return fmt.Errorf("create fixture image tarball: %w", err)
	}

	// 4. Start local passive HTTP test server for remote mode.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58")
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 5. Run every CLI mode against fixtures and verify exit codes.
	cases := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{
			name:     "version",
			args:     []string{"version"},
			wantCode: 0,
		},
		{
			name:     "advisories list",
			args:     []string{"advisories", "list"},
			wantCode: 0,
		},
		{
			name:     "scan local (--fail-on never)",
			args:     []string{"scan", "local", "--fail-on", "never", "--no-color"},
			wantCode: 0,
		},
		{
			name:     "scan image tarball (VULNERABLE -> exit 1)",
			args:     []string{"scan", "image", imageTarPath, "--no-color"},
			wantCode: 1,
		},
		{
			name:     "scan sbom CycloneDX (LIKELY_VULNERABLE -> exit 2)",
			args:     []string{"scan", "sbom", filepath.Join("testdata", "sbom", "cyclonedx.json"), "--no-color"},
			wantCode: 2,
		},
		{
			name:     "scan sbom SPDX (LIKELY_VULNERABLE -> exit 2)",
			args:     []string{"scan", "sbom", filepath.Join("testdata", "sbom", "spdx.json"), "--no-color"},
			wantCode: 2,
		},
		{
			name:     "scan path fixtures (VULNERABLE -> exit 1)",
			args:     []string{"scan", "path", filepath.Join("testdata", "path"), "--no-color"},
			wantCode: 1,
		},
		{
			name:     "scan remote without --authorized (error -> exit 3)",
			args:     []string{"scan", "remote", srv.URL},
			wantCode: 3,
		},
		{
			name:     "scan remote with --authorized (LIKELY_VULNERABLE -> exit 2)",
			args:     []string{"scan", "remote", "--authorized", srv.URL, "--no-color"},
			wantCode: 2,
		},
	}

	for _, tc := range cases {
		gotCode, out, runErr := runBinary(ctx, binPath, tc.args)
		if runErr != nil {
			return fmt.Errorf("case %q execution failed: %w", tc.name, runErr)
		}
		if gotCode != tc.wantCode {
			return fmt.Errorf("case %q: exit code = %d, want %d\noutput:\n%s", tc.name, gotCode, tc.wantCode, out)
		}
		fmt.Printf("[e2e] %-48s exit=%d OK\n", tc.name, gotCode)
	}

	return nil
}

func checkCoverage(ctx context.Context, pkg string) (float64, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-cover", pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("go test -cover %s failed: %w\n%s", pkg, err, string(out))
	}
	m := coverageRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return 0, fmt.Errorf("could not parse coverage output for %s: %s", pkg, string(out))
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid coverage float for %s: %w", pkg, err)
	}
	if pct < minCoveragePercent {
		return pct, fmt.Errorf("package %s coverage %.1f%% is below required %.1f%% gate", pkg, pct, minCoveragePercent)
	}
	return pct, nil
}

func runBinary(ctx context.Context, binPath string, args []string) (int, string, error) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out), nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out), nil
	}
	return -1, string(out), err
}

func writeFixtureImageTarball(destPath string) error {
	var layerBuf bytes.Buffer
	tw := tar.NewWriter(&layerBuf)

	files := map[string]string{
		"usr/local/include/php/main/php_version.h": "#define PHP_VERSION \"8.3.10\"\n",
		"usr/local/sbin/php-fpm":                   "ELF-placeholder\x008.3.10\x00",
	}
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}

	raw := layerBuf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}, tarball.WithMediaType(types.DockerLayer))
	if err != nil {
		return err
	}

	img := mutate.MediaType(empty.Image, types.DockerManifestSchema2)
	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return err
	}
	return tarball.WriteToFile(destPath, nil, img)
}
