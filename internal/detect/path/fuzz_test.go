package path

import "testing"

func FuzzParseManifests(f *testing.F) {
	f.Add([]byte("FROM php:8.3-fpm\nFROM php:8.3.36-cli\n"))
	f.Add([]byte("services:\n  app:\n    image: php:8.2-apache\n"))
	f.Add([]byte(`{"require":{"php":"^8.2"},"config":{"platform":{"php":"8.2.30"}}}`))
	f.Add([]byte("8.3.12\n"))
	f.Add([]byte("php 8.3\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		_ = parseDockerfileBytes(data, "Dockerfile")
		_ = parseComposeBytes(data, "docker-compose.yml")
		_ = parseComposerBytes(data, "composer.json")
		_ = parsePHPVersionFileBytes(data, ".php-version")
		_ = parseToolVersionsBytes(data, ".tool-versions")
	})
}
