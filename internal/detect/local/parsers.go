package local

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// DefaultMaxModuleBytes caps the number of bytes read from a shared library (32 MiB).
const DefaultMaxModuleBytes int64 = 32 * 1024 * 1024

// ErrVersionNotFound indicates that no valid PHP version could be extracted.
var ErrVersionNotFound = errors.New("PHP version pattern not found")

// TrackedIniKeys lists the security-relevant php.ini directives tracked in inventory.
func isTrackedIniKey(key string) bool {
	switch key {
	case "session.upload_progress.enabled", "fatal_error_backtraces":
		return true
	default:
		return false
	}
}

// NormalizeIniValue normalizes PHP INI boolean strings ("Off", "On", "false", "true", "no", "yes")
// to "0" or "1" while trimming surrounding quotes and whitespace.
func NormalizeIniValue(raw string) string {
	val := strings.TrimSpace(raw)
	val = strings.Trim(val, `"'`)
	val = strings.TrimSpace(val)

	switch strings.ToLower(val) {
	case "off", "false", "no", "none", "0":
		return "0"
	case "on", "true", "yes", "1":
		return "1"
	default:
		return val
	}
}

// ParseOSRelease parses /etc/os-release key=value lines into an inventory.Distro.
func ParseOSRelease(r io.Reader) (inventory.Distro, error) {
	var d inventory.Distro
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := strings.Trim(strings.TrimSpace(v), `"'`)
		switch key {
		case "ID":
			d.ID = strings.ToLower(val)
		case "VERSION_ID":
			d.VersionID = val
		}
	}
	if err := scanner.Err(); err != nil {
		return d, fmt.Errorf("scan os-release: %w", err)
	}
	return d, nil
}

// ParsePHPVersionOutput extracts the upstream PHP version, raw version token,
// and SAPI from the output of `php -v` (or `php-fpm -v` / `frankenphp -v`).
func ParsePHPVersionOutput(out []byte, binPath string) (string, string, inventory.SAPI, error) {
	text := string(out)
	sapi := inferSAPIFromVersionText(text, binPath)

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "PHP" {
				continue
			}
			candidate := strings.Trim(fields[i+1], ",;()")
			v, err := phpver.Parse(candidate)
			if err != nil {
				continue
			}
			upstream := fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.PreRelease)
			return upstream, v.Raw, sapi, nil
		}
	}

	return "", "", sapi, fmt.Errorf("parse php -v output: %w", ErrVersionNotFound)
}

func inferSAPIFromVersionText(text, binPath string) inventory.SAPI {
	lower := strings.ToLower(text)
	base := strings.ToLower(path.Base(strings.ReplaceAll(binPath, `\`, "/")))

	switch {
	case strings.Contains(lower, "frankenphp") || strings.Contains(base, "frankenphp"):
		return inventory.SAPIFrankenPHP
	case strings.Contains(lower, "(fpm-fcgi)") || strings.Contains(base, "fpm"):
		return inventory.SAPIFPM
	case strings.Contains(lower, "(cli)"):
		return inventory.SAPICLI
	case strings.Contains(lower, "(cgi-fcgi)") || strings.Contains(base, "cgi"):
		return inventory.SAPICGI
	case strings.Contains(lower, "(litespeed)") || strings.Contains(base, "lsphp"):
		return inventory.SAPILiteSpeed
	case strings.HasPrefix(base, "php"):
		return inventory.SAPICLI
	default:
		return inventory.SAPIUnknown
	}
}

// PHPInfoResult holds the parsed metadata and INI directives from `php -i`.
type PHPInfoResult struct {
	ServerAPI          string
	LoadedConfigFile   string
	ScanIniDir         string
	AdditionalIniFiles []string
	IniSettings        map[string]string
}

// ParsePHPInfoOutput parses the plain-text output of `php -i`.
func ParsePHPInfoOutput(out []byte) PHPInfoResult {
	res := PHPInfoResult{
		IniSettings: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inAdditionalIni := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inAdditionalIni {
			if line == "" || strings.Contains(line, "=>") {
				inAdditionalIni = false
			} else {
				appendCommaSeparatedFiles(&res.AdditionalIniFiles, line)
				if !strings.HasSuffix(line, ",") {
					inAdditionalIni = false
				}
				continue
			}
		}

		if !strings.Contains(line, "=>") {
			continue
		}

		parts := strings.Split(line, "=>")
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Server API":
			res.ServerAPI = val
		case "Loaded Configuration File":
			if !isNoneValue(val) {
				res.LoadedConfigFile = val
			}
		case "Scan this dir for additional .ini files":
			if !isNoneValue(val) {
				res.ScanIniDir = val
			}
		case "Additional .ini files parsed":
			if !isNoneValue(val) {
				appendCommaSeparatedFiles(&res.AdditionalIniFiles, val)
				if strings.HasSuffix(val, ",") {
					inAdditionalIni = true
				}
			}
		default:
			if isTrackedIniKey(key) {
				res.IniSettings[key] = NormalizeIniValue(val)
			}
		}
	}

	return res
}

func appendCommaSeparatedFiles(dst *[]string, raw string) {
	for _, token := range strings.Split(raw, ",") {
		cleaned := strings.TrimSpace(token)
		if cleaned != "" && !isNoneValue(cleaned) {
			*dst = append(*dst, cleaned)
		}
	}
}

func isNoneValue(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return lower == "" || lower == "(none)" || lower == "none"
}

// ParseIniReader statically parses a php.ini or conf.d/*.ini stream without executing anything,
// recording tracked directives and their file origin on target.
func ParseIniReader(r io.Reader, sourceLabel string, target *inventory.PHPInstall) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := stripIniComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		if !isTrackedIniKey(key) {
			continue
		}
		norm := NormalizeIniValue(v)
		target.SetIniSetting(key, norm, sourceLabel)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse ini %s: %w", sourceLabel, err)
	}
	return nil
}

// ParseFPMPoolReader statically parses PHP-FPM pool configuration files for
// php_value, php_admin_value, php_flag, and php_admin_flag directives.
func ParseFPMPoolReader(r io.Reader, sourceLabel string, target *inventory.PHPInstall) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := stripIniComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		lhs, rhs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		lhs = strings.TrimSpace(lhs)
		directive, key, ok := parseFPMDirectiveKey(lhs)
		if !ok || !isTrackedIniKey(key) {
			continue
		}
		norm := NormalizeIniValue(rhs)
		target.SetIniSetting(key, norm, fmt.Sprintf("%s (%s)", sourceLabel, directive))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse fpm pool %s: %w", sourceLabel, err)
	}
	return nil
}

func parseFPMDirectiveKey(lhs string) (string, string, bool) {
	openIdx := strings.IndexByte(lhs, '[')
	closeIdx := strings.LastIndexByte(lhs, ']')
	if openIdx <= 0 || closeIdx <= openIdx+1 {
		return "", "", false
	}
	directive := strings.TrimSpace(lhs[:openIdx])
	switch directive {
	case "php_value", "php_admin_value", "php_flag", "php_admin_flag":
	default:
		return "", "", false
	}
	key := strings.TrimSpace(lhs[openIdx+1 : closeIdx])
	return directive, key, key != ""
}

func stripIniComment(s string) string {
	inQuotes := false
	var quoteChar byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch == '"' || ch == '\'') && (i == 0 || s[i-1] != '\\') {
			if !inQuotes {
				inQuotes = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuotes = false
			}
			continue
		}
		if !inQuotes && (ch == ';' || ch == '#') {
			return s[:i]
		}
	}
	return s
}

// ScanModuleBytes scans up to maxBytes from r for a "PHP/x.y.z" pattern in pure Go
// without shelling out to external tools.
func ScanModuleBytes(r io.Reader, maxBytes int64) (string, string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxModuleBytes
	}

	limited := io.LimitReader(r, maxBytes)
	const chunkSize = 64 * 1024
	const overlap = 64

	buf := make([]byte, chunkSize+overlap)
	carry := 0

	for {
		n, err := limited.Read(buf[carry : carry+chunkSize])
		total := carry + n
		if total > 0 {
			if upstream, matched, ok := findPHPVersionInSlice(buf[:total]); ok {
				return upstream, matched, nil
			}
			if total > overlap {
				copy(buf[:overlap], buf[total-overlap:total])
				carry = overlap
			} else {
				carry = total
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", fmt.Errorf("read module bytes: %w", err)
		}
	}

	return "", "", ErrVersionNotFound
}

func findPHPVersionInSlice(data []byte) (string, string, bool) {
	prefix := []byte("PHP/")
	search := data
	for {
		idx := bytes.Index(search, prefix)
		if idx < 0 {
			return "", "", false
		}
		after := search[idx+len(prefix):]
		end := 0
		for end < len(after) && end < 64 && isVersionByte(after[end]) {
			end++
		}
		if end > 0 {
			candidate := string(after[:end])
			if v, err := phpver.Parse(candidate); err == nil {
				upstream := fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.PreRelease)
				return upstream, "PHP/" + v.Raw, true
			}
		}
		search = search[idx+len(prefix):]
	}
}

func isVersionByte(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		b == '.' || b == '-' || b == '+' || b == '~'
}
