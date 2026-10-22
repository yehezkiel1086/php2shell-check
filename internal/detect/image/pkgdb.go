package image

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// PackageRecord represents a PHP package discovered from an image package database.
type PackageRecord struct {
	Manager         string
	Name            string
	Version         string
	UpstreamVersion string
	SAPI            inventory.SAPI
	SourceFile      string
}

// ParseDpkgStatus parses a Debian/Ubuntu /var/lib/dpkg/status file and returns installed PHP packages.
func ParseDpkgStatus(data []byte, sourceFile string) []PackageRecord {
	var out []PackageRecord
	blocks := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n")

	for _, block := range blocks {
		var pkg, status, version string
		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := scanner.Text()
			if k, v, ok := strings.Cut(line, ":"); ok {
				switch strings.TrimSpace(k) {
				case "Package":
					pkg = strings.TrimSpace(v)
				case "Status":
					status = strings.TrimSpace(v)
				case "Version":
					version = strings.TrimSpace(v)
				}
			}
		}

		if pkg == "" || version == "" || !strings.Contains(status, "installed") {
			continue
		}
		sapi, isPHP := classifyPHPPackageName(pkg)
		if !isPHP {
			continue
		}
		upstream := extractUpstreamVersionFromPkgVersion(version)
		if upstream == "" {
			continue
		}

		out = append(out, PackageRecord{
			Manager:         "deb",
			Name:            pkg,
			Version:         version,
			UpstreamVersion: upstream,
			SAPI:            sapi,
			SourceFile:      sourceFile,
		})
	}

	return out
}

// ParseApkInstalled parses an Alpine /lib/apk/db/installed file and returns installed PHP packages.
func ParseApkInstalled(data []byte, sourceFile string) []PackageRecord {
	var out []PackageRecord
	blocks := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n")

	for _, block := range blocks {
		var pkg, version string
		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) < 3 || line[1] != ':' {
				continue
			}
			switch line[0] {
			case 'P':
				pkg = strings.TrimSpace(line[2:])
			case 'V':
				version = strings.TrimSpace(line[2:])
			}
		}

		if pkg == "" || version == "" {
			continue
		}
		sapi, isPHP := classifyPHPPackageName(pkg)
		if !isPHP {
			continue
		}
		upstream := extractUpstreamVersionFromPkgVersion(version)
		if upstream == "" {
			continue
		}

		out = append(out, PackageRecord{
			Manager:         "apk",
			Name:            pkg,
			Version:         version,
			UpstreamVersion: upstream,
			SAPI:            sapi,
			SourceFile:      sourceFile,
		})
	}

	return out
}

func classifyPHPPackageName(pkg string) (inventory.SAPI, bool) {
	lower := strings.ToLower(pkg)

	switch {
	case strings.HasPrefix(lower, "libapache2-mod-php"):
		return inventory.SAPIApache2Handler, true
	case strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, "-fpm"):
		return inventory.SAPIFPM, true
	case strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, "-cli"):
		return inventory.SAPICLI, true
	case strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, "-cgi"):
		return inventory.SAPICGI, true
	case strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, "-apache2"):
		return inventory.SAPIApache2Handler, true
	case lower == "php" || isBareVersionedPHPPkg(lower):
		return inventory.SAPICLI, true
	default:
		return inventory.SAPIUnknown, false
	}
}

func isBareVersionedPHPPkg(lower string) bool {
	if !strings.HasPrefix(lower, "php") {
		return false
	}
	rest := lower[len("php"):]
	if rest == "" {
		return true
	}
	for i := 0; i < len(rest); i++ {
		if (rest[i] < '0' || rest[i] > '9') && rest[i] != '.' {
			return false
		}
	}
	return true
}

func extractUpstreamVersionFromPkgVersion(pkgVer string) string {
	// Strip optional Debian/RPM epoch prefix like "2:8.1.2-1ubuntu2.19".
	cleaned := pkgVer
	if colonIdx := strings.IndexByte(cleaned, ':'); colonIdx > 0 {
		cleaned = cleaned[colonIdx+1:]
	}
	parsed, err := phpver.Parse(cleaned)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d%s", parsed.Major, parsed.Minor, parsed.Patch, parsed.PreRelease)
}

// ParsePHPVersionHeader extracts the PHP_VERSION string from main/php_version.h.
func ParsePHPVersionHeader(data []byte) (string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "#define") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "PHP_VERSION" {
			raw := strings.Trim(fields[2], `"'`)
			if v, err := phpver.Parse(raw); err == nil {
				return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.PreRelease), true
			}
		}
	}
	return "", false
}
