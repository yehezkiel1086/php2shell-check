package local_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func FuzzParseIniAndPool(f *testing.F) {
	f.Add("session.upload_progress.enabled = Off\nfatal_error_backtraces = 0\n")
	f.Add("[www]\nphp_admin_value[session.upload_progress.enabled] = 0\nphp_value[fatal_error_backtraces] = Off\n")
	f.Add("; comment\n# hash comment\nkey = \"quoted ; value\"\n")

	f.Fuzz(func(_ *testing.T, input string) {
		inst := inventory.PHPInstall{Source: inventory.SourceLocal, SAPI: inventory.SAPIFPM}
		_ = local.ParseIniReader(strings.NewReader(input), "/etc/php.ini", &inst)
		_ = local.ParseFPMPoolReader(strings.NewReader(input), "/etc/php-fpm.d/www.conf", &inst)
	})
}

func FuzzParsePHPVersionAndInfo(f *testing.F) {
	f.Add([]byte("PHP 8.3.35 (cli) (built: Oct 10 2026)\n"))
	f.Add([]byte("FrankenPHP v1.3.0 PHP 8.4.26 Caddy\n"))
	f.Add([]byte("Server API => Command Line Interface\nsession.upload_progress.enabled => Off => Off\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _, _ = local.ParsePHPVersionOutput(data, "/usr/bin/php")
		_ = local.ParsePHPInfoOutput(data)
		_, _, _ = local.ScanModuleBytes(bytes.NewReader(data), 4096)
	})
}
