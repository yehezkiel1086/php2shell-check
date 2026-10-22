package sbom_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/sbom"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func TestCollectCycloneDXAndSPDXFixtures(t *testing.T) {
	t.Parallel()

	c := sbom.NewCollector()

	t.Run("CycloneDX JSON fixture", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join("..", "..", "..", "testdata", "sbom", "cyclonedx.json")
		installs, err := c.Collect(context.Background(), path)
		if err != nil {
			t.Fatalf("Collect(cyclonedx.json) unexpected error: %v", err)
		}
		if len(installs) != 2 {
			t.Fatalf("Collect(cyclonedx.json) len = %d, want 2: %+v", len(installs), installs)
		}

		first := installs[0]
		if first.Source != inventory.SourceSBOM || first.Confidence != inventory.ConfidenceMedium {
			t.Errorf("Source=%q Confidence=%q, want sbom medium", first.Source, first.Confidence)
		}
		if first.PackageName != "php8.3-fpm" || first.UpstreamVersion != "8.3.35" || first.SAPI != inventory.SAPIFPM {
			t.Errorf("unexpected first component: %+v", first)
		}
		if first.Distro.ID != "debian" || first.Distro.VersionID != "12" {
			t.Errorf("unexpected first Distro: %+v", first.Distro)
		}

		second := installs[1]
		if second.PackageName != "libapache2-mod-php8.2" || second.UpstreamVersion != "8.2.34" || second.SAPI != inventory.SAPIApache2Handler {
			t.Errorf("unexpected second component: %+v", second)
		}
	})

	t.Run("SPDX JSON fixture", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join("..", "..", "..", "testdata", "sbom", "spdx.json")
		installs, err := c.Collect(context.Background(), path)
		if err != nil {
			t.Fatalf("Collect(spdx.json) unexpected error: %v", err)
		}
		if len(installs) != 2 {
			t.Fatalf("Collect(spdx.json) len = %d, want 2: %+v", len(installs), installs)
		}

		if installs[0].PackageManager != "apk" || installs[0].PackageName != "php83-cli" || installs[0].UpstreamVersion != "8.3.35" {
			t.Errorf("unexpected SPDX apk component: %+v", installs[0])
		}
		if installs[1].PackageManager != "rpm" || installs[1].PackageName != "php-fpm" || installs[1].UpstreamVersion != "8.4.26" {
			t.Errorf("unexpected SPDX rpm component: %+v", installs[1])
		}
	})

	t.Run("Invalid SBOM rejected", func(t *testing.T) {
		t.Parallel()
		_, err := sbom.ParseBytes([]byte(`{"hello": "world"}`), "bad.json")
		if !errors.Is(err, sbom.ErrUnsupportedSBOM) {
			t.Fatalf("ParseBytes() error = %v, want ErrUnsupportedSBOM", err)
		}
	})
}
