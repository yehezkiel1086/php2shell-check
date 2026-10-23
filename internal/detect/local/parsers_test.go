package local_test

import (
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
)

func TestParsersPreserveExactScanDir(t *testing.T) {
	t.Parallel()

	exactScanDir := "/opt/php/8.3.35/etc/conf.d"
	exactLine := "Scan for additional .ini files in: " + exactScanDir

	t.Run("ParsePHPIniOutput preserves exact scan dir", func(t *testing.T) {
		t.Parallel()
		raw := strings.Join([]string{
			"Configuration File (php.ini) Path: /opt/php/8.3.35/etc",
			"Loaded Configuration File:         /opt/php/8.3.35/etc/php.ini",
			exactLine,
			"Additional .ini files parsed:      (none)",
		}, "\n") + "\n"

		res := local.ParsePHPIniOutput([]byte(raw))
		if res.ScanIniDir != exactScanDir {
			t.Fatalf("ParsePHPIniOutput ScanIniDir = %q, want %q", res.ScanIniDir, exactScanDir)
		}
		if res.ConfigFilePath != "/opt/php/8.3.35/etc" {
			t.Errorf("ConfigFilePath = %q, want /opt/php/8.3.35/etc", res.ConfigFilePath)
		}
		if res.LoadedConfigFile != "/opt/php/8.3.35/etc/php.ini" {
			t.Errorf("LoadedConfigFile = %q, want /opt/php/8.3.35/etc/php.ini", res.LoadedConfigFile)
		}
	})

	t.Run("ParsePHPInfoOutput preserves exact scan dir", func(t *testing.T) {
		t.Parallel()
		raw := strings.Join([]string{
			"phpinfo()",
			"Configuration File (php.ini) Path => /opt/php/8.3.35/etc",
			"Loaded Configuration File => /opt/php/8.3.35/etc/php.ini",
			"Scan this dir for additional .ini files => " + exactScanDir,
			"Additional .ini files parsed => (none)",
		}, "\n") + "\n"

		res := local.ParsePHPInfoOutput([]byte(raw))
		if res.ScanIniDir != exactScanDir {
			t.Fatalf("ParsePHPInfoOutput ScanIniDir = %q, want %q", res.ScanIniDir, exactScanDir)
		}
	})
}
