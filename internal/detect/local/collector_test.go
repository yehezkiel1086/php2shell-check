package local_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

type fakeResponse struct {
	stdout []byte
	stderr []byte
	err    error
}

type fakeRunner struct {
	responses map[string]fakeResponse
}

func (f *fakeRunner) Run(_ context.Context, binPath string, args ...string) ([]byte, []byte, error) {
	key := binPath + " " + strings.Join(args, " ")
	if resp, ok := f.responses[key]; ok {
		return resp.stdout, resp.stderr, resp.err
	}
	if resp, ok := f.responses[binPath]; ok {
		return resp.stdout, resp.stderr, resp.err
	}
	return nil, nil, fmt.Errorf("unexpected command: %s", key)
}

type permDenyFS struct {
	base     fs.FS
	denyOpen map[string]bool
	denyStat map[string]bool
}

func (p *permDenyFS) Open(name string) (fs.File, error) {
	if p.denyOpen[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return p.base.Open(name)
}

func (p *permDenyFS) Stat(name string) (fs.FileInfo, error) {
	if p.denyStat[name] {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
	}
	return fs.Stat(p.base, name)
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "testdata", "local", name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return data
}

func TestCollectDebianHostWithCLIFPMModuleAndFrankenPHP(t *testing.T) {
	t.Parallel()

	phpVCLI := readTestdata(t, "php_v_cli.txt")
	phpVFPM := readTestdata(t, "php_v_fpm.txt")
	phpVFranken := readTestdata(t, "php_v_frankenphp.txt")
	phpICLI := readTestdata(t, "php_i_cli.txt")
	osReleaseDeb := readTestdata(t, "os-release-debian12")
	phpIni := readTestdata(t, "php.ini")
	hardeningIni := readTestdata(t, "99-hardening.ini")
	wwwConf := readTestdata(t, "www.conf")

	// Construct fake ELF bytes for libphp8.3.so containing "PHP/8.3.35".
	fakeModuleBytes := bytes.Join([][]byte{
		bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 0x00}, 1024),
		[]byte("\x00ApacheModule\x00PHP/8.3.35\x00"),
	}, nil)

	mapFS := fstest.MapFS{
		"etc/os-release":                              {Data: osReleaseDeb},
		"usr/bin/php8.3":                              {Data: []byte("ELF")},
		"usr/bin/phpize8.3":                           {Data: []byte("#!/bin/sh")}, // helper script, must be ignored
		"usr/sbin/php-fpm8.3":                         {Data: []byte("ELF")},
		"custom/bin/frankenphp":                       {Data: []byte("ELF")},
		"etc/php/8.3/cli/php.ini":                     {Data: phpIni},
		"etc/php/8.3/cli/conf.d/99-hardening.ini":     {Data: hardeningIni},
		"etc/php/8.3/fpm/php.ini":                     {Data: phpIni},
		"etc/php/8.3/fpm/conf.d/99-hardening.ini":     {Data: hardeningIni},
		"etc/php/8.3/fpm/pool.d/www.conf":             {Data: wwwConf},
		"usr/lib/apache2/modules/libphp8.3.so":        {Data: fakeModuleBytes},
		"etc/php/8.3/apache2/php.ini":                 {Data: phpIni},
		"etc/php/8.3/apache2/conf.d/99-hardening.ini": {Data: hardeningIni},
	}

	runner := &fakeRunner{
		responses: map[string]fakeResponse{
			"/usr/bin/php8.3 -v":                                                                      {stdout: phpVCLI},
			"/usr/bin/php8.3 -i":                                                                      {stdout: phpICLI},
			"/usr/sbin/php-fpm8.3 -v":                                                                 {stdout: phpVFPM},
			"/custom/bin/frankenphp -v":                                                               {stdout: phpVFranken},
			"/usr/bin/dpkg-query -S /usr/bin/php8.3":                                                  {stdout: []byte("php8.3-cli: /usr/bin/php8.3\n")},
			"/usr/bin/dpkg-query -W -f=${Package}\t${Version}\n php8.3-cli":                           {stdout: []byte("php8.3-cli\t8.3.35-1+deb12u1\n")},
			"/usr/bin/dpkg-query -S /usr/sbin/php-fpm8.3":                                             {stdout: []byte("php8.3-fpm: /usr/sbin/php-fpm8.3\n")},
			"/usr/bin/dpkg-query -W -f=${Package}\t${Version}\n php8.3-fpm":                           {stdout: []byte("php8.3-fpm\t8.3.35-1+deb12u1\n")},
			"/usr/bin/dpkg-query -S /usr/lib/apache2/modules/libphp8.3.so":                            {stdout: []byte("libapache2-mod-php8.3: /usr/lib/apache2/modules/libphp8.3.so\n")},
			"/usr/bin/dpkg-query -W -f=${Package}\t${Version}\n libapache2-mod-php8.3":                {stdout: []byte("libapache2-mod-php8.3\t8.3.35-1+deb12u1\n")},
		},
	}

	collector := local.NewCollector(local.Config{
		FS:      mapFS,
		Runner:  runner,
		PathEnv: "/custom/bin:/usr/bin",
	})

	installs, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() unexpected error: %v", err)
	}

	if len(installs) != 4 {
		t.Fatalf("Collect() returned %d installs, want 4: %+v", len(installs), installs)
	}

	byTarget := make(map[string]inventory.PHPInstall)
	for _, inst := range installs {
		target := inst.BinaryPath
		if target == "" {
			target = inst.ModulePath
		}
		byTarget[target] = inst
	}

	// 1. Verify CLI install
	cliInst, ok := byTarget["/usr/bin/php8.3"]
	if !ok {
		t.Fatal("missing /usr/bin/php8.3 install")
	}
	if cliInst.SAPI != inventory.SAPICLI || cliInst.UpstreamVersion != "8.3.35" {
		t.Errorf("cli SAPI=%q Version=%q, want cli 8.3.35", cliInst.SAPI, cliInst.UpstreamVersion)
	}
	if cliInst.Distro.ID != "debian" || cliInst.Distro.VersionID != "12" {
		t.Errorf("cli Distro = %+v, want debian 12", cliInst.Distro)
	}
	if cliInst.PackageManager != "deb" || cliInst.PackageName != "php8.3-cli" || cliInst.PackageVersion != "8.3.35-1+deb12u1" {
		t.Errorf("cli package = %s/%s/%s, want deb/php8.3-cli/8.3.35-1+deb12u1",
			cliInst.PackageManager, cliInst.PackageName, cliInst.PackageVersion)
	}
	if got := cliInst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Errorf("cli session.upload_progress.enabled = %q, want 0", got)
	}

	// 2. Verify FPM install (static parsing of php.ini, conf.d/99-hardening.ini, and pool.d/www.conf)
	fpmInst, ok := byTarget["/usr/sbin/php-fpm8.3"]
	if !ok {
		t.Fatal("missing /usr/sbin/php-fpm8.3 install")
	}
	if fpmInst.SAPI != inventory.SAPIFPM || fpmInst.UpstreamVersion != "8.3.35" {
		t.Errorf("fpm SAPI=%q Version=%q, want fpm 8.3.35", fpmInst.SAPI, fpmInst.UpstreamVersion)
	}
	// In www.conf, php_value[session.upload_progress.enabled] = 1 overrides 99-hardening.ini's 0,
	// and php_admin_value[fatal_error_backtraces] = 0 overrides php.ini's On.
	if got := fpmInst.IniSettings["session.upload_progress.enabled"]; got != "1" {
		t.Errorf("fpm session.upload_progress.enabled = %q, want 1 (from pool www.conf)", got)
	}
	if got := fpmInst.IniSettings["fatal_error_backtraces"]; got != "0" {
		t.Errorf("fpm fatal_error_backtraces = %q, want 0 (from pool www.conf php_admin_value)", got)
	}
	evJoined := strings.Join(fpmInst.Evidence, "\n")
	for _, wantEv := range []string{
		"source: /etc/php/8.3/fpm/php.ini",
		"source: /etc/php/8.3/fpm/conf.d/99-hardening.ini",
		"source: /etc/php/8.3/fpm/pool.d/www.conf (php_value)",
		"source: /etc/php/8.3/fpm/pool.d/www.conf (php_admin_value)",
	} {
		if !strings.Contains(evJoined, wantEv) {
			t.Errorf("fpm Evidence missing %q\ngot:\n%s", wantEv, evJoined)
		}
	}

	// 3. Verify FrankenPHP install from PATH
	frankenInst, ok := byTarget["/custom/bin/frankenphp"]
	if !ok {
		t.Fatal("missing /custom/bin/frankenphp install")
	}
	if frankenInst.SAPI != inventory.SAPIFrankenPHP || frankenInst.UpstreamVersion != "8.4.26" {
		t.Errorf("frankenphp SAPI=%q Version=%q, want frankenphp 8.4.26", frankenInst.SAPI, frankenInst.UpstreamVersion)
	}

	// 4. Verify Apache module install (libphp8.3.so byte scan + static Apache ini)
	modInst, ok := byTarget["/usr/lib/apache2/modules/libphp8.3.so"]
	if !ok {
		t.Fatal("missing /usr/lib/apache2/modules/libphp8.3.so install")
	}
	if modInst.SAPI != inventory.SAPIApache2Handler || modInst.UpstreamVersion != "8.3.35" {
		t.Errorf("module SAPI=%q Version=%q, want apache2handler 8.3.35", modInst.SAPI, modInst.UpstreamVersion)
	}
	if got := modInst.IniSettings["session.upload_progress.enabled"]; got != "0" {
		t.Errorf("apache module session.upload_progress.enabled = %q, want 0 (from 99-hardening.ini)", got)
	}
}

func TestPackageOwnershipRPMAndAPK(t *testing.T) {
	t.Parallel()

	t.Run("RPM on Rocky Linux", func(t *testing.T) {
		t.Parallel()
		mapFS := fstest.MapFS{
			"etc/os-release":                  {Data: readTestdata(t, "os-release-rocky9")},
			"opt/remi/php83/root/usr/bin/php": {Data: []byte("ELF")},
		}
		runner := &fakeRunner{
			responses: map[string]fakeResponse{
				"/opt/remi/php83/root/usr/bin/php -v": {stdout: readTestdata(t, "php_v_cli.txt")},
				"/opt/remi/php83/root/usr/bin/php -i": {stdout: []byte("Server API => Command Line Interface\n")},
				"/usr/bin/rpm -qf --queryformat %{NAME}\t%{VERSION}-%{RELEASE}\n /opt/remi/php83/root/usr/bin/php": {
					stdout: []byte("php83-php-cli\t8.3.35-1.el9.remi\n"),
				},
			},
		}
		c := local.NewCollector(local.Config{FS: mapFS, Runner: runner})
		installs, err := c.Collect(context.Background())
		if err != nil || len(installs) != 1 {
			t.Fatalf("Collect() = %+v, err = %v", installs, err)
		}
		inst := installs[0]
		if inst.Distro.ID != "rocky" || inst.Distro.VersionID != "9.4" {
			t.Errorf("Distro = %+v, want rocky 9.4", inst.Distro)
		}
		if inst.PackageManager != "rpm" || inst.PackageName != "php83-php-cli" || inst.PackageVersion != "8.3.35-1.el9.remi" {
			t.Errorf("package = %s/%s/%s", inst.PackageManager, inst.PackageName, inst.PackageVersion)
		}
	})

	t.Run("APK on Alpine Linux", func(t *testing.T) {
		t.Parallel()
		mapFS := fstest.MapFS{
			"etc/os-release": {Data: readTestdata(t, "os-release-alpine320")},
			"usr/bin/php83":  {Data: []byte("ELF")},
		}
		runner := &fakeRunner{
			responses: map[string]fakeResponse{
				"/usr/bin/php83 -v":                        {stdout: readTestdata(t, "php_v_cli.txt")},
				"/usr/bin/php83 -i":                        {stdout: []byte("Server API => Command Line Interface\n")},
				"/sbin/apk info --who-owns /usr/bin/php83": {stdout: []byte("/usr/bin/php83 is owned by php83-cli-8.3.35-r0\n")},
			},
		}
		c := local.NewCollector(local.Config{FS: mapFS, Runner: runner})
		installs, err := c.Collect(context.Background())
		if err != nil || len(installs) != 1 {
			t.Fatalf("Collect() = %+v, err = %v", installs, err)
		}
		inst := installs[0]
		if inst.Distro.ID != "alpine" || inst.Distro.VersionID != "3.20.3" {
			t.Errorf("Distro = %+v, want alpine 3.20.3", inst.Distro)
		}
		if inst.PackageManager != "apk" || inst.PackageName != "php83-cli" || inst.PackageVersion != "8.3.35-r0" {
			t.Errorf("package = %s/%s/%s", inst.PackageManager, inst.PackageName, inst.PackageVersion)
		}
	})
}

func TestPermissionErrorsBecomeEvidenceNotFatalErrors(t *testing.T) {
	t.Parallel()

	baseFS := fstest.MapFS{
		"usr/bin/php8.3":                       {Data: []byte("ELF")},
		"usr/sbin/php-fpm8.3":                  {Data: []byte("ELF")},
		"etc/php/8.3/fpm/php.ini":              {Data: []byte("session.upload_progress.enabled = 0\n")},
		"usr/lib/apache2/modules/libphp8.3.so": {Data: []byte("ELF")},
	}

	pfs := &permDenyFS{
		base: baseFS,
		denyOpen: map[string]bool{
			"etc/php/8.3/fpm/php.ini":              true,
			"usr/lib/apache2/modules/libphp8.3.so": true,
		},
	}

	runner := &fakeRunner{
		responses: map[string]fakeResponse{
			"/usr/bin/php8.3 -v":      {err: fmt.Errorf("exec /usr/bin/php8.3: %w", fs.ErrPermission)},
			"/usr/sbin/php-fpm8.3 -v": {stdout: readTestdata(t, "php_v_fpm.txt")},
		},
	}

	c := local.NewCollector(local.Config{FS: pfs, Runner: runner})
	installs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() returned fatal error on permission denied: %v", err)
	}
	if len(installs) != 3 {
		t.Fatalf("Collect() returned %d installs, want 3", len(installs))
	}

	for _, inst := range installs {
		ev := strings.Join(inst.Evidence, "\n")
		if !strings.Contains(ev, "permission_denied:") {
			t.Errorf("install %+v missing permission_denied evidence", inst)
		}
	}
}

func TestExecRunnerRejectsRelativePath(t *testing.T) {
	t.Parallel()

	r := local.NewExecRunner()
	_, _, err := r.Run(context.Background(), "php", "-v")
	if !errors.Is(err, local.ErrNonAbsolutePath) {
		t.Fatalf("ExecRunner.Run(\"php\") error = %v, want %v", err, local.ErrNonAbsolutePath)
	}
}

func TestScanModuleBytesCapAndChunkBoundary(t *testing.T) {
	t.Parallel()

	// Place "PHP/8.4.27" right across the 64 KiB chunk boundary.
	payload := bytes.Join([][]byte{
		bytes.Repeat([]byte("A"), 64*1024-3),
		[]byte("PHP/8.4.27\x00"),
	}, nil)

	ver, matched, err := local.ScanModuleBytes(bytes.NewReader(payload), 128*1024)
	if err != nil {
		t.Fatalf("ScanModuleBytes across boundary failed: %v", err)
	}
	if ver != "8.4.27" || matched != "PHP/8.4.27" {
		t.Fatalf("ScanModuleBytes = (%q, %q), want (8.4.27, PHP/8.4.27)", ver, matched)
	}

	// Verify maxBytes cap prevents finding version past the limit.
	_, _, err = local.ScanModuleBytes(bytes.NewReader(payload), 1024)
	if !errors.Is(err, local.ErrVersionNotFound) {
		t.Fatalf("ScanModuleBytes past cap error = %v, want ErrVersionNotFound", err)
	}
}
