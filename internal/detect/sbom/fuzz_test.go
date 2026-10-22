package sbom_test

import (
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/sbom"
)

func FuzzParseSBOMBytes(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"php8.3-fpm","version":"8.3.35","purl":"pkg:deb/debian/php8.3-fpm@8.3.35-1+deb12u1"}]}`))
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"php83-cli","versionInfo":"8.3.35-r0"}]}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = sbom.ParseBytes(data, "fuzz.json")
	})
}
