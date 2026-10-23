package report_test

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/image"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
	"github.com/yehezkiel1086/php2shell-check/internal/report"
)

type memTarEntry struct {
	name string
	body []byte
}

func makeMemLayer(t *testing.T, entries []memTarEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%s): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close mem tar: %v", err)
	}

	raw := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatalf("LayerFromOpener: %v", err)
	}
	return layer
}

func makeMemImage(t *testing.T, env, entrypoint, cmd []string, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("ConfigFile: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS = "linux"
	cfg.Architecture = "amd64"
	cfg.Config.Env = env
	cfg.Config.Entrypoint = entrypoint
	cfg.Config.Cmd = cmd
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate.ConfigFile: %v", err)
	}
	return img
}

func renderAndAssertAllFormats(t *testing.T, rep report.Report, baseName string) {
	t.Helper()

	formats := []struct {
		format     string
		goldenFile string
	}{
		{format: report.FormatTable, goldenFile: baseName + ".table.golden"},
		{format: report.FormatJSON, goldenFile: baseName + ".json.golden"},
		{format: report.FormatSARIF, goldenFile: baseName + ".sarif.golden"},
		{format: report.FormatMD, goldenFile: baseName + ".md.golden"},
	}

	for _, tc := range formats {
		t.Run(tc.format, func(t *testing.T) {
			var buf bytes.Buffer
			err := report.Render(&buf, rep, report.Options{
				Format:      tc.format,
				NoColor:     true,
				ToolVersion: rep.ToolVersion,
				Mode:        rep.Mode,
			})
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.format, err)
			}
			assertGolden(t, tc.goldenFile, buf.String())
		})
	}
}

func TestFourImageFixturesGoldens(t *testing.T) {
	t.Parallel()

	adv, err := advisory.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	collector := image.NewCollector(image.Options{Offline: true})

	// Fixture 1: Official Apache (cli and apache2handler module)
	t.Run("fixture1_official_apache", func(t *testing.T) {
		t.Parallel()
		layer := makeMemLayer(t, []memTarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "usr/local/include/php/main/php_version.h", body: []byte("#define PHP_VERSION \"8.3.35\"\n")},
			{name: "usr/local/bin/php", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/lib/apache2/modules/libphp.so", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/local/etc/php/conf.d/security.ini", body: []byte("session.upload_progress.enabled = 1\n")},
		})
		img := makeMemImage(t, []string{"PHP_VERSION=8.3.35"}, []string{"docker-php-entrypoint"}, []string{"apache2-foreground"}, layer)

		ref := "php:8.3.35-apache"
		installs, err := collector.InspectImage(context.Background(), img, ref)
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		if len(installs) != 2 {
			t.Fatalf("expected 2 installs (cli and apache2handler), got %d: %+v", len(installs), installs)
		}

		findings := match.EvaluateAll(installs, adv)
		recs := remediate.BuildAll(findings, adv, remediate.Options{})
		rep := report.Build(findings, recs, adv, report.Options{
			ToolVersion: "0.1.0-test",
			Mode:        "image",
			NoColor:     true,
		})

		renderAndAssertAllFormats(t, rep, "fixture1_official_apache")
	})

	// Fixture 2: Official FPM (fpm)
	t.Run("fixture2_official_fpm", func(t *testing.T) {
		t.Parallel()
		layer := makeMemLayer(t, []memTarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "usr/local/include/php/main/php_version.h", body: []byte("#define PHP_VERSION \"8.3.35\"\n")},
			{name: "usr/local/sbin/php-fpm", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/local/etc/php/conf.d/security.ini", body: []byte("session.upload_progress.enabled = 1\n")},
		})
		img := makeMemImage(t, []string{"PHP_VERSION=8.3.35"}, []string{"docker-php-entrypoint"}, []string{"php-fpm"}, layer)

		ref := "php:8.3.35-fpm"
		installs, err := collector.InspectImage(context.Background(), img, ref)
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		if len(installs) != 1 {
			t.Fatalf("expected 1 install (fpm), got %d: %+v", len(installs), installs)
		}

		findings := match.EvaluateAll(installs, adv)
		recs := remediate.BuildAll(findings, adv, remediate.Options{})
		rep := report.Build(findings, recs, adv, report.Options{
			ToolVersion: "0.1.0-test",
			Mode:        "image",
			NoColor:     true,
		})

		renderAndAssertAllFormats(t, rep, "fixture2_official_fpm")
	})

	// Fixture 3: Debian-layout apt (cli and fpm)
	t.Run("fixture3_debian_apt", func(t *testing.T) {
		t.Parallel()
		dpkgStatus := `Package: php8.3-cli
Status: install ok installed
Version: 2:8.3.35-1+deb12u1
Architecture: amd64

Package: php8.3-fpm
Status: install ok installed
Version: 2:8.3.35-1+deb12u1
Architecture: amd64
`
		layer := makeMemLayer(t, []memTarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "var/lib/dpkg/status", body: []byte(dpkgStatus)},
			{name: "usr/bin/php8.3", body: []byte("ELF")},
			{name: "usr/sbin/php-fpm8.3", body: []byte("ELF")},
			{name: "etc/php/8.3/fpm/pool.d/www.conf", body: []byte("[www]\nphp_admin_value[session.upload_progress.enabled] = 0\n")},
			{name: "etc/php/8.3/cli/php.ini", body: []byte("session.upload_progress.enabled = 0\n")},
		})
		img := makeMemImage(t, nil, nil, nil, layer)

		ref := "lab/ubuntu-apt-php8.3:8.3.35"
		installs, err := collector.InspectImage(context.Background(), img, ref)
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}
		if len(installs) != 2 {
			t.Fatalf("expected 2 installs (cli and fpm), got %d: %+v", len(installs), installs)
		}

		findings := match.EvaluateAll(installs, adv)
		recs := remediate.BuildAll(findings, adv, remediate.Options{})
		rep := report.Build(findings, recs, adv, report.Options{
			ToolVersion: "0.1.0-test",
			Mode:        "image",
			NoColor:     true,
		})

		renderAndAssertAllFormats(t, rep, "fixture3_debian_apt")
	})

	// Fixture 4: Floating tag (ResolvedFromTag: true)
	t.Run("fixture4_floating_tag", func(t *testing.T) {
		t.Parallel()
		layer := makeMemLayer(t, []memTarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "usr/local/include/php/main/php_version.h", body: []byte("#define PHP_VERSION \"8.3.35\"\n")},
			{name: "usr/local/bin/php", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/lib/apache2/modules/libphp.so", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/local/etc/php/conf.d/security.ini", body: []byte("session.upload_progress.enabled = 1\n")},
		})
		img := makeMemImage(t, []string{"PHP_VERSION=8.3.35"}, []string{"docker-php-entrypoint"}, []string{"apache2-foreground"}, layer)

		ref := "php:8-apache"
		installs, err := collector.InspectImage(context.Background(), img, ref)
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}

		findings := match.EvaluateAll(installs, adv)
		recs := remediate.BuildAll(findings, adv, remediate.Options{})
		rep := report.Build(findings, recs, adv, report.Options{
			ToolVersion: "0.1.0-test",
			Mode:        "image",
			NoColor:     true,
		})

		if !rep.ResolvedFromTag {
			t.Errorf("rep.ResolvedFromTag must be true for ref %q", ref)
		}

		renderAndAssertAllFormats(t, rep, "fixture4_floating_tag")
	})
}
