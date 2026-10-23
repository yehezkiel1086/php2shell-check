package image_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/image"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
)

type tarEntry struct {
	name     string
	typeflag byte
	body     []byte
	linkname string
}

func makeLayerFromEntries(t *testing.T, entries []tarEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: tf,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("write tar body %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	rawBytes := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(rawBytes)), nil
	})
	if err != nil {
		t.Fatalf("create layer from tar bytes: %v", err)
	}
	return layer
}

func buildTestImage(t *testing.T, env, entrypoint, cmd []string, layers ...v1.Layer) v1.Image {
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
	cfg.Config.Env = env
	cfg.Config.Entrypoint = entrypoint
	cfg.Config.Cmd = cmd
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("mutate.ConfigFile: %v", err)
	}
	return img
}

func writeDockerTarball(t *testing.T, img v1.Image) string {
	t.Helper()
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	tag, err := name.NewTag("example.local/test/php:latest")
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}
	if err := tarball.WriteToFile(tarPath, tag, img); err != nil {
		t.Fatalf("tarball.WriteToFile: %v", err)
	}
	return tarPath
}

func TestSourceBuiltOfficialPHPImageTarball(t *testing.T) {
	t.Parallel()

	layer := makeLayerFromEntries(t, []tarEntry{
		{
			name: "etc/os-release",
			body: []byte("ID=debian\nVERSION_ID=\"12\"\n"),
		},
		{
			name: "usr/local/include/php/main/php_version.h",
			body: []byte("/* PHP version */\n#define PHP_VERSION \"8.4.26\"\n"),
		},
		{
			name: "usr/local/sbin/php-fpm",
			body: []byte("\x7fELF\x00PHP/8.4.26\x00"),
		},
		{
			name: "usr/local/etc/php/conf.d/docker-php-security.ini",
			body: []byte("session.upload_progress.enabled = Off\n"),
		},
	})

	img := buildTestImage(
		t,
		[]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin", "PHP_VERSION=8.4.26"},
		[]string{"docker-php-entrypoint"},
		[]string{"php-fpm"},
		layer,
	)
	tarPath := writeDockerTarball(t, img)

	c := image.NewCollector(image.Options{Offline: true})
	installs, err := c.Collect(context.Background(), tarPath)
	if err != nil {
		t.Fatalf("Collect(%q) unexpected error: %v", tarPath, err)
	}
	if len(installs) != 1 {
		t.Fatalf("Collect() returned %d installs, want 1: %+v", len(installs), installs)
	}

	inst := installs[0]
	if inst.Source != inventory.SourceImage {
		t.Errorf("Source = %q, want image", inst.Source)
	}
	if inst.SAPI != inventory.SAPIFPM {
		t.Errorf("SAPI = %q, want fpm", inst.SAPI)
	}
	if inst.UpstreamVersion != "8.4.26" {
		t.Errorf("UpstreamVersion = %q, want 8.4.26", inst.UpstreamVersion)
	}
	if got := inst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Errorf("IniSettings[session.upload_progress.enabled] = %q, want 0", got)
	}

	evJoined := strings.Join(inst.Evidence, "\n")
	for _, wantEv := range []string{
		"php_version_h: /usr/local/include/php/main/php_version.h => 8.4.26",
		"image_env: PHP_VERSION=8.4.26",
		"binary_bytes: /usr/local/sbin/php-fpm => PHP/8.4.26",
		"image_cmd: docker-php-entrypoint php-fpm",
		"source: /usr/local/etc/php/conf.d/docker-php-security.ini",
	} {
		if !strings.Contains(evJoined, wantEv) {
			t.Errorf("Evidence missing %q\ngot:\n%s", wantEv, evJoined)
		}
	}
}

func TestDpkgManagedImageAndOCILayout(t *testing.T) {
	t.Parallel()

	dpkgStatus := `Package: php8.3-fpm
Status: install ok installed
Version: 2:8.3.35-1+deb12u1
Architecture: amd64

Package: bash
Status: install ok installed
Version: 5.2.15-2
`
	layer := makeLayerFromEntries(t, []tarEntry{
		{
			name: "etc/os-release",
			body: []byte("ID=debian\nVERSION_ID=\"12\"\n"),
		},
		{
			name: "var/lib/dpkg/status",
			body: []byte(dpkgStatus),
		},
		{
			name: "etc/php/8.3/fpm/pool.d/www.conf",
			body: []byte("[www]\nphp_admin_value[session.upload_progress.enabled] = 0\n"),
		},
	})

	img := buildTestImage(t, nil, nil, []string{"php-fpm8.3"}, layer)

	// Test 1: Docker-save tarball
	tarPath := writeDockerTarball(t, img)
	c := image.NewCollector(image.Options{Offline: true})
	installs, err := c.Collect(context.Background(), tarPath)
	if err != nil || len(installs) != 1 {
		t.Fatalf("Collect(tarball) = %+v, err = %v", installs, err)
	}
	inst := installs[0]
	if inst.PackageManager != "deb" || inst.PackageName != "php8.3-fpm" || inst.PackageVersion != "2:8.3.35-1+deb12u1" {
		t.Errorf("package = %s/%s/%s", inst.PackageManager, inst.PackageName, inst.PackageVersion)
	}
	if inst.UpstreamVersion != "8.3.35" || inst.SAPI != inventory.SAPIFPM {
		t.Errorf("UpstreamVersion=%q SAPI=%q, want 8.3.35 fpm", inst.UpstreamVersion, inst.SAPI)
	}
	if got := inst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Errorf("IniSettings[session.upload_progress.enabled] = %q, want 0", got)
	}

	// Test 2: OCI layout directory
	ociDir := filepath.Join(t.TempDir(), "oci-layout-dir")
	p, err := layout.Write(ociDir, empty.Index)
	if err != nil {
		t.Fatalf("layout.Write: %v", err)
	}
	if appendErr := p.AppendImage(img); appendErr != nil {
		t.Fatalf("p.AppendImage: %v", appendErr)
	}

	ociInstalls, err := c.Collect(context.Background(), ociDir)
	if err != nil || len(ociInstalls) != 1 {
		t.Fatalf("Collect(ociDir) = %+v, err = %v", ociInstalls, err)
	}
	if ociInstalls[0].PackageName != "php8.3-fpm" {
		t.Errorf("OCI PackageName = %q, want php8.3-fpm", ociInstalls[0].PackageName)
	}
}

func TestLayerWhiteoutsHonored(t *testing.T) {
	t.Parallel()

	layer1 := makeLayerFromEntries(t, []tarEntry{
		{
			name: "usr/local/include/php/main/php_version.h",
			body: []byte("#define PHP_VERSION \"8.2.30\"\n"),
		},
		{
			name: "usr/local/etc/php/conf.d/01-old.ini",
			body: []byte("session.upload_progress.enabled = 1\n"),
		},
		{
			name: "usr/local/etc/php/conf.d/02-remove-me.ini",
			body: []byte("session.upload_progress.enabled = 1\n"),
		},
	})

	// Layer 2 uses opaque whiteout on conf.d/, replaces php_version.h with 8.3.36, and adds a clean ini.
	layer2 := makeLayerFromEntries(t, []tarEntry{
		{
			name: "usr/local/etc/php/conf.d/.wh..wh..opq",
		},
		{
			name: "usr/local/etc/php/conf.d/10-hardened.ini",
			body: []byte("session.upload_progress.enabled = 0\n"),
		},
		{
			name: "usr/local/include/php/main/.wh.php_version.h",
		},
		{
			name: "usr/local/include/php/main/php_version.h",
			body: []byte("#define PHP_VERSION \"8.3.36\"\n"),
		},
	})

	img := buildTestImage(t, nil, nil, []string{"php-fpm"}, layer1, layer2)
	c := image.NewCollector(image.Options{Offline: true})
	installs, err := c.InspectImage(context.Background(), img, "test:whiteout")
	if err != nil || len(installs) != 1 {
		t.Fatalf("InspectImage() = %+v, err = %v", installs, err)
	}

	inst := installs[0]
	if inst.UpstreamVersion != "8.3.36" {
		t.Errorf("UpstreamVersion after whiteout replacement = %q, want 8.3.36", inst.UpstreamVersion)
	}
	if got := inst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Errorf("session.upload_progress.enabled after opaque whiteout = %q, want 0", got)
	}
	for _, cf := range inst.ConfigFiles {
		if strings.Contains(cf, "01-old.ini") || strings.Contains(cf, "02-remove-me.ini") {
			t.Errorf("whited-out config file %q still present in ConfigFiles", cf)
		}
	}
}

func TestRejectsPathTraversalAndEscapingSymlinks(t *testing.T) {
	t.Parallel()

	t.Run("path traversal entry", func(t *testing.T) {
		t.Parallel()
		badLayer := makeLayerFromEntries(t, []tarEntry{
			{
				name: "../../etc/evil",
				body: []byte("pwn"),
			},
		})
		img := buildTestImage(t, nil, nil, nil, badLayer)
		c := image.NewCollector(image.Options{Offline: true})
		_, err := c.InspectImage(context.Background(), img, "test:traversal")
		if !errors.Is(err, image.ErrPathTraversal) {
			t.Fatalf("InspectImage() error = %v, want ErrPathTraversal", err)
		}
	})

	t.Run("symlink escaping root", func(t *testing.T) {
		t.Parallel()
		badLayer := makeLayerFromEntries(t, []tarEntry{
			{
				name:     "usr/bin/php",
				typeflag: tar.TypeSymlink,
				linkname: "../../../etc/shadow",
			},
		})
		img := buildTestImage(t, nil, nil, nil, badLayer)
		c := image.NewCollector(image.Options{Offline: true})
		_, err := c.InspectImage(context.Background(), img, "test:symlink-escape")
		if !errors.Is(err, image.ErrSymlinkEscape) {
			t.Fatalf("InspectImage() error = %v, want ErrSymlinkEscape", err)
		}
	})
}

func TestOversizeFileAndTotalByteCaps(t *testing.T) {
	t.Parallel()

	layer := makeLayerFromEntries(t, []tarEntry{
		{
			name: "usr/local/bin/php",
			body: bytes.Repeat([]byte("A"), 4096),
		},
	})
	img := buildTestImage(t, nil, nil, nil, layer)

	t.Run("per-file byte cap", func(t *testing.T) {
		t.Parallel()
		c := image.NewCollector(image.Options{
			Offline:       true,
			MaxFileBytes:  1024,
			MaxTotalBytes: 1024 * 1024,
		})
		_, err := c.InspectImage(context.Background(), img, "test:file-cap")
		if !errors.Is(err, image.ErrFileTooLarge) {
			t.Fatalf("InspectImage() error = %v, want ErrFileTooLarge", err)
		}
	})

	t.Run("total byte cap across layers", func(t *testing.T) {
		t.Parallel()
		c := image.NewCollector(image.Options{
			Offline:       true,
			MaxFileBytes:  8192,
			MaxTotalBytes: 2048,
		})
		_, err := c.InspectImage(context.Background(), img, "test:total-cap")
		if !errors.Is(err, image.ErrTotalBytesLimit) {
			t.Fatalf("InspectImage() error = %v, want ErrTotalBytesLimit", err)
		}
	})
}

func TestApkInstalledAndUnsupportedRPMDatabase(t *testing.T) {
	t.Parallel()

	t.Run("Alpine apk installed db", func(t *testing.T) {
		t.Parallel()
		apkDB := "C:Q1...\nP:php83-fpm\nV:8.3.35-r0\nA:x86_64\n\n"
		layer := makeLayerFromEntries(t, []tarEntry{
			{name: "etc/os-release", body: []byte("ID=alpine\nVERSION_ID=3.20.3\n")},
			{name: "lib/apk/db/installed", body: []byte(apkDB)},
		})
		img := buildTestImage(t, nil, nil, []string{"php-fpm83"}, layer)
		c := image.NewCollector(image.Options{Offline: true})
		installs, err := c.InspectImage(context.Background(), img, "alpine:php")
		if err != nil || len(installs) != 1 {
			t.Fatalf("InspectImage(apk) = %+v, err = %v", installs, err)
		}
		if installs[0].PackageManager != "apk" || installs[0].PackageName != "php83-fpm" || installs[0].UpstreamVersion != "8.3.35" {
			t.Errorf("unexpected apk install: %+v", installs[0])
		}
	})

	t.Run("Unsupported RPM db emits UNKNOWN verdict rather than guessing", func(t *testing.T) {
		t.Parallel()
		layer := makeLayerFromEntries(t, []tarEntry{
			{name: "etc/os-release", body: []byte("ID=rocky\nVERSION_ID=\"9.4\"\n")},
			{name: "var/lib/rpm/rpmdb.sqlite", body: []byte("SQLite format 3\x00")},
			{name: "usr/sbin/php-fpm", body: []byte("ELF")},
		})
		img := buildTestImage(t, nil, nil, []string{"php-fpm"}, layer)
		c := image.NewCollector(image.Options{Offline: true})
		installs, err := c.InspectImage(context.Background(), img, "rocky:php")
		if err != nil || len(installs) != 1 {
			t.Fatalf("InspectImage(rpm) = %+v, err = %v", installs, err)
		}

		adv, err := advisory.LoadEmbedded()
		if err != nil {
			t.Fatalf("LoadEmbedded: %v", err)
		}
		finding := match.Evaluate(installs[0], adv)
		if finding.Verdict != match.VerdictUnknown {
			t.Fatalf("expected Verdict UNKNOWN for unsupported RPM DB, got %s", finding.Verdict)
		}
		if !strings.Contains(strings.Join(installs[0].Evidence, "\n"), "rpm_db_unsupported") {
			t.Errorf("expected rpm_db_unsupported in Evidence, got: %v", installs[0].Evidence)
		}
	})
}

func TestApache2HandlerNeverHasCLIBinaryTarget(t *testing.T) {
	t.Parallel()

	t.Run("source built apache with libphp.so and php cli binary", func(t *testing.T) {
		t.Parallel()
		layer := makeLayerFromEntries(t, []tarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "usr/local/include/php/main/php_version.h", body: []byte("#define PHP_VERSION \"8.3.35\"\n")},
			{name: "usr/local/bin/php", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "usr/lib/apache2/modules/libphp.so", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
		})
		img := buildTestImage(t, []string{"PHP_VERSION=8.3.35"}, []string{"docker-php-entrypoint"}, []string{"apache2-foreground"}, layer)
		c := image.NewCollector(image.Options{Offline: true})
		installs, err := c.InspectImage(context.Background(), img, "php:8.3.35-apache")
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}

		var foundApache, foundCLI bool
		for _, inst := range installs {
			if inst.SAPI == inventory.SAPIApache2Handler {
				foundApache = true
				if inst.BinaryPath != "" {
					t.Errorf("apache2handler must have empty BinaryPath, got %q", inst.BinaryPath)
				}
				if strings.Contains(inst.ModulePath, "/bin/php") || strings.HasSuffix(inst.ModulePath, "/php") {
					t.Errorf("apache2handler ModulePath must never be a CLI binary, got %q", inst.ModulePath)
				}
				if inst.ModulePath != "/usr/lib/apache2/modules/libphp.so" {
					t.Errorf("apache2handler ModulePath = %q, want /usr/lib/apache2/modules/libphp.so", inst.ModulePath)
				}
			}
			if inst.SAPI == inventory.SAPICLI {
				foundCLI = true
				if inst.BinaryPath != "/usr/local/bin/php" {
					t.Errorf("cli BinaryPath = %q, want /usr/local/bin/php", inst.BinaryPath)
				}
			}
		}
		if !foundApache || !foundCLI {
			t.Fatalf("expected both apache and cli installs, got apache=%v cli=%v (total %d installs)", foundApache, foundCLI, len(installs))
		}
	})

	t.Run("source built apache with missing .so falling back to config file", func(t *testing.T) {
		t.Parallel()
		layer := makeLayerFromEntries(t, []tarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "usr/local/include/php/main/php_version.h", body: []byte("#define PHP_VERSION \"8.3.35\"\n")},
			{name: "usr/local/bin/php", body: []byte("\x7fELF\x00PHP/8.3.35\x00")},
			{name: "etc/apache2/apache2.conf", body: []byte("ServerRoot /etc/apache2\n")},
		})
		img := buildTestImage(t, []string{"PHP_VERSION=8.3.35"}, []string{"docker-php-entrypoint"}, []string{"apache2-foreground"}, layer)
		c := image.NewCollector(image.Options{Offline: true})
		installs, err := c.InspectImage(context.Background(), img, "php:8.3.35-apache")
		if err != nil {
			t.Fatalf("InspectImage: %v", err)
		}

		for _, inst := range installs {
			if inst.SAPI == inventory.SAPIApache2Handler {
				if inst.BinaryPath != "" {
					t.Errorf("apache2handler must have empty BinaryPath, got %q", inst.BinaryPath)
				}
				if strings.Contains(inst.ModulePath, "/bin/php") || strings.HasSuffix(inst.ModulePath, "/php") {
					t.Errorf("apache2handler ModulePath must never be a CLI binary, got %q", inst.ModulePath)
				}
				if inst.ModulePath != "/etc/apache2/apache2.conf" {
					t.Errorf("expected config fallback as ModulePath, got %q", inst.ModulePath)
				}
				evJoined := strings.Join(inst.Evidence, "\n")
				if !strings.Contains(evJoined, "apache module file not found on disk; discovered via config") {
					t.Errorf("expected fallback config note in Evidence, got:\n%s", evJoined)
				}
			}
		}
	})

	t.Run("dpkg libapache2-mod-php package", func(t *testing.T) {
		t.Parallel()
		dpkgStatus := `Package: libapache2-mod-php8.3
Status: install ok installed
Version: 2:8.3.35-1+deb12u1
Architecture: amd64
`
		layer := makeLayerFromEntries(t, []tarEntry{
			{name: "etc/os-release", body: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			{name: "var/lib/dpkg/status", body: []byte(dpkgStatus)},
			{name: "usr/lib/apache2/modules/libphp8.3.so", body: []byte("ELF")},
		})
		img := buildTestImage(t, nil, nil, nil, layer)
		c := image.NewCollector(image.Options{Offline: true})
		installs, err := c.InspectImage(context.Background(), img, "debian:php-apache")
		if err != nil || len(installs) != 1 {
			t.Fatalf("InspectImage: err=%v, installs=%+v", err, installs)
		}
		inst := installs[0]
		if inst.SAPI != inventory.SAPIApache2Handler {
			t.Fatalf("SAPI = %q, want apache2handler", inst.SAPI)
		}
		if inst.BinaryPath != "" {
			t.Errorf("apache2handler BinaryPath must be empty, got %q", inst.BinaryPath)
		}
		if inst.ModulePath != "/usr/lib/apache2/modules/libphp8.3.so" {
			t.Errorf("ModulePath = %q, want /usr/lib/apache2/modules/libphp8.3.so", inst.ModulePath)
		}
	})
}
