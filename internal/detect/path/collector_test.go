package path

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func TestCollectFixtures(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("..", "..", "..", "testdata", "path")
	col := NewCollector(Options{RootPath: fixtureDir})
	installs, err := col.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect(%q) unexpected error: %v", fixtureDir, err)
	}

	// Expected entries across Dockerfile (2), docker-compose.yml (2), composer.json (2), .php-version (1), .tool-versions (1) = 8
	if len(installs) != 8 {
		t.Fatalf("len(installs) = %d, want 8: %+v", len(installs), installs)
	}

	byLoc := make(map[string]inventory.PHPInstall, len(installs))
	for _, inst := range installs {
		if inst.Source != inventory.SourcePath {
			t.Errorf("install %s Source = %q, want %q", inst.ID, inst.Source, inventory.SourcePath)
		}
		if inst.Confidence != inventory.ConfidenceMedium {
			t.Errorf("install %s Confidence = %q, want %q", inst.ID, inst.Confidence, inventory.ConfidenceMedium)
		}
		if len(inst.Evidence) == 0 {
			t.Fatalf("install %s missing Evidence", inst.ID)
		}
		byLoc[inst.BinaryPath] = inst
	}

	wantCases := []struct {
		loc         string
		upstreamVer string
		sapi        inventory.SAPI
	}{
		{loc: "Dockerfile:2", upstreamVer: "php:8.3-fpm", sapi: inventory.SAPIFPM},
		{loc: "Dockerfile:3", upstreamVer: "8.3.10", sapi: inventory.SAPICLI},
		{loc: "docker-compose.yml:3", upstreamVer: "8.3.36", sapi: inventory.SAPIFPM},
		{loc: "docker-compose.yml:5", upstreamVer: "php:8.2-apache", sapi: inventory.SAPIApache2Handler},
		{loc: "composer.json:4", upstreamVer: "^8.2", sapi: inventory.SAPIUnknown},
		{loc: "composer.json:9", upstreamVer: "8.2.30", sapi: inventory.SAPIUnknown},
		{loc: ".php-version:2", upstreamVer: "8.3.12", sapi: inventory.SAPICLI},
		{loc: ".tool-versions:2", upstreamVer: "8.3", sapi: inventory.SAPICLI},
	}

	for _, tc := range wantCases {
		inst, ok := byLoc[tc.loc]
		if !ok {
			t.Errorf("missing install at %q; got keys: %v", tc.loc, keys(byLoc))
			continue
		}
		if inst.UpstreamVersion != tc.upstreamVer {
			t.Errorf("%s UpstreamVersion = %q, want %q", tc.loc, inst.UpstreamVersion, tc.upstreamVer)
		}
		if inst.SAPI != tc.sapi {
			t.Errorf("%s SAPI = %q, want %q", tc.loc, inst.SAPI, tc.sapi)
		}
		if !strings.HasPrefix(inst.Evidence[0], tc.loc+" -> ") {
			t.Errorf("%s Evidence[0] = %q, want prefix %q", tc.loc, inst.Evidence[0], tc.loc+" -> ")
		}
	}
}

func TestCollectExcludeAndSymlinkEscape(t *testing.T) {
	t.Parallel()

	outsideDir := t.TempDir()
	outsideComposer := filepath.Join(outsideDir, "composer.json")
	if err := os.WriteFile(outsideComposer, []byte(`{"require":{"php":"^8.1"}}`), 0o600); err != nil {
		t.Fatalf("write outside composer.json: %v", err)
	}

	rootDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootDir, ".php-version"), []byte("8.3.36\n"), 0o600); err != nil {
		t.Fatalf("write .php-version: %v", err)
	}

	vendorDir := filepath.Join(rootDir, "vendor", "pkg")
	if err := os.MkdirAll(vendorDir, 0o750); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "composer.json"), []byte(`{"require":{"php":"^7.4"}}`), 0o600); err != nil {
		t.Fatalf("write vendor composer.json: %v", err)
	}

	// Best-effort symlink to outside file (on Windows without Developer Mode os.Symlink may fail; ignore if unsupported).
	_ = os.Symlink(outsideComposer, filepath.Join(rootDir, "composer.json"))

	col := NewCollector(Options{
		RootPath: rootDir,
		Exclude:  []string{"vendor"},
	})
	installs, err := col.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if len(installs) != 1 {
		t.Fatalf("len(installs) = %d, want 1 (vendor and outside symlink excluded): %+v", len(installs), installs)
	}
	if !strings.HasPrefix(installs[0].BinaryPath, ".php-version:1") {
		t.Errorf("BinaryPath = %q, want .php-version:1", installs[0].BinaryPath)
	}
}

func keys(m map[string]inventory.PHPInstall) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
