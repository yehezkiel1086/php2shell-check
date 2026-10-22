package image_test

import (
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/image"
)

func FuzzParseImagePackageDatabases(f *testing.F) {
	f.Add([]byte("Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.35-1+deb12u1\n\n"))
	f.Add([]byte("P:php83-fpm\nV:8.3.35-r0\n\n"))
	f.Add([]byte("#define PHP_VERSION \"8.4.26\"\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = image.ParseDpkgStatus(data, "/var/lib/dpkg/status")
		_ = image.ParseApkInstalled(data, "/lib/apk/db/installed")
		_, _ = image.ParsePHPVersionHeader(data)
	})
}
