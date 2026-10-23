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
	case "off", "false", "no", "none", "0", "":
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

// PHPInfoResult holds the parsed metadata and INI directives from `php --ini` or `php -i`.
type PHPInfoResult struct {
	ServerAPI          string
	ConfigFilePath     string
	LoadedConfigFile   string
	LoadedConfigNone   bool
	ScanIniDir         string
	ScanIniDirNone     bool
	AdditionalIniFiles []string
	IniSettings        map[string]string
}

// ParsePHPIniOutput parses the output of `php --ini` without modifying or corrupting file paths.
func ParsePHPIniOutput(out []byte) PHPInfoResult {
	res := PHPInfoResult{
		IniSettings: make(map[string]string),
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	inAdditionalIni := false

	const (
		prefixConfigPath = "Configuration File (php.ini) Path:"
		prefixLoadedFile = "Loaded Configuration File:"
		prefixScanDir    = "Scan for additional .ini files in:"
		prefixAdditional = "Additional .ini files parsed:"
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inAdditionalIni {
			if line == "" ||
				strings.HasPrefix(line, prefixConfigPath) ||
				strings.HasPrefix(line, prefixLoadedFile) ||
				strings.HasPrefix(line, prefixScanDir) ||
				strings.HasPrefix(line, prefixAdditional) {
				inAdditionalIni = false
			} else {
				appendCommaSeparatedFiles(&res.AdditionalIniFiles, line)
				if !strings.HasSuffix(line, ",") {
					inAdditionalIni = false
				}
				continue
			}
		}

		switch {
		case strings.HasPrefix(line, prefixConfigPath):
			val := strings.TrimSpace(strings.TrimPrefix(line, prefixConfigPath))
			if !isNoneValue(val) {
				res.ConfigFilePath = val
			}
		case strings.HasPrefix(line, prefixLoadedFile):
			val := strings.TrimSpace(strings.TrimPrefix(line, prefixLoadedFile))
			if isNoneValue(val) {
				res.LoadedConfigNone = true
			} else {
				res.LoadedConfigFile = val
			}
		case strings.HasPrefix(line, prefixScanDir):
			val := strings.TrimSpace(strings.TrimPrefix(line, prefixScanDir))
			if isNoneValue(val) {
				res.ScanIniDirNone = true
			} else {
				res.ScanIniDir = val
			}
		case strings.HasPrefix(line, prefixAdditional):
			val := strings.TrimSpace(strings.TrimPrefix(line, prefixAdditional))
			if !isNoneValue(val) {
				appendCommaSeparatedFiles(&res.AdditionalIniFiles, val)
				if strings.HasSuffix(val, ",") {
					inAdditionalIni = true
				}
			}
		}
	}

	return res
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

		left, right, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}

		key := strings.TrimSpace(left)
		val := strings.TrimSpace(right)
		if firstVal, _, hasSecondArrow := strings.Cut(val, "=>"); hasSecondArrow {
			val = strings.TrimSpace(firstVal)
		}

		switch key {
		case "Server API":
			res.ServerAPI = val
		case "Configuration File (php.ini) Path":
			if !isNoneValue(val) {
				res.ConfigFilePath = val
			}
		case "Loaded Configuration File":
			if isNoneValue(val) {
				res.LoadedConfigNone = true
			} else {
				res.LoadedConfigFile = val
			}
		case "Scan this dir for additional .ini files":
			if isNoneValue(val) {
				res.ScanIniDirNone = true
			} else {
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
// recording tracked directives and their file:line origin on target.
func ParseIniReader(r io.Reader, sourceLabel string, target *inventory.PHPInstall) error {
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
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
		origin := sourceLabel
		if lineNum > 0 && !strings.Contains(sourceLabel, ":") {
			origin = fmt.Sprintf("%s:%d", sourceLabel, lineNum)
		}
		target.SetIniSetting(key, norm, origin)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse ini %s: %w", sourceLabel, err)
	}
	return nil
}

// FPMPoolSetting represents a single tracked PHP INI override inside an FPM pool section.
type FPMPoolSetting struct {
	Pool      string
	Directive string
	Key       string
	Value     string
	Line      int
	File      string
}

// FPMPoolParseResult holds the parsed include patterns, pool sections, and settings from an FPM config file.
type FPMPoolParseResult struct {
	Includes []string
	Pools    []string
	Settings []FPMPoolSetting
}

// ParseFPMPoolConfig parses an FPM configuration or pool file for [pool] sections, include= directives,
// and php_value/php_admin_value/php_flag/php_admin_flag directives with line numbers.
func ParseFPMPoolConfig(r io.Reader, absPath string) (FPMPoolParseResult, error) {
	var res FPMPoolParseResult
	seenPools := make(map[string]bool)
	addPool := func(name string) {
		if name == "" || strings.EqualFold(name, "global") {
			return
		}
		if !seenPools[name] {
			seenPools[name] = true
			res.Pools = append(res.Pools, name)
		}
	}

	scanner := bufio.NewScanner(r)
	currentSection := ""
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(stripIniComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.TrimSpace(line[1 : len(line)-1])
			currentSection = sec
			addPool(sec)
			continue
		}

		lhs, rhs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		lhs = strings.TrimSpace(lhs)
		rhs = strings.TrimSpace(rhs)

		if strings.EqualFold(lhs, "include") {
			inc := strings.TrimSpace(strings.Trim(rhs, `"'`))
			if inc != "" {
				res.Includes = append(res.Includes, inc)
			}
			continue
		}

		directive, key, okDir := parseFPMDirectiveKey(lhs)
		if !okDir || !isTrackedIniKey(key) {
			continue
		}
		poolName := currentSection
		if poolName == "" || strings.EqualFold(poolName, "global") {
			poolName = "www"
		}
		addPool(poolName)
		norm := NormalizeIniValue(rhs)
		res.Settings = append(res.Settings, FPMPoolSetting{
			Pool:      poolName,
			Directive: directive,
			Key:       key,
			Value:     norm,
			Line:      lineNum,
			File:      absPath,
		})
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("parse fpm pool %s: %w", absPath, err)
	}
	return res, nil
}

// ParseFPMPoolReader statically parses PHP-FPM pool configuration files for
// php_value, php_admin_value, php_flag, and php_admin_flag directives.
func ParseFPMPoolReader(r io.Reader, sourceLabel string, target *inventory.PHPInstall) error {
	res, err := ParseFPMPoolConfig(r, sourceLabel)
	if err != nil {
		return err
	}
	for _, s := range res.Settings {
		target.SetIniSetting(s.Key, s.Value, fmt.Sprintf("%s (%s) %s:%d", s.File, s.Directive, s.File, s.Line))
	}
	return nil
}

func parseFPMDirectiveKey(lhs string) (string, string, bool) {
	openIdx := strings.IndexByte(lhs, '[')
	closeIdx := strings.LastIndexByte(lhs, ']')
	if openIdx <= 0 || closeIdx <= openIdx+1 {
		return "", "", false
	}
	directive := strings.ToLower(strings.TrimSpace(lhs[:openIdx]))
	switch directive {
	case "php_value", "php_admin_value", "php_flag", "php_admin_flag":
	default:
		return "", "", false
	}
	key := strings.TrimSpace(lhs[openIdx+1 : closeIdx])
	return directive, key, key != ""
}

// ParseApacheConfigReader parses an Apache configuration file (/etc/apache2 or /etc/httpd)
// for php_admin_value, php_value, php_admin_flag, and php_flag directives.
func ParseApacheConfigReader(r io.Reader, absPath string, target *inventory.PHPInstall) error {
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(stripApacheComment(scanner.Text()))
		if line == "" {
			continue
		}

		// Support bracket syntax if used in Apache config, or standard space-separated Apache syntax.
		if lhs, rhs, ok := strings.Cut(line, "="); ok {
			if directive, key, okDir := parseFPMDirectiveKey(strings.TrimSpace(lhs)); okDir && isTrackedIniKey(key) {
				norm := NormalizeIniValue(rhs)
				target.SetIniSetting(key, norm, fmt.Sprintf("%s (%s) %s:%d", absPath, directive, absPath, lineNum))
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		switch directive {
		case "php_value", "php_admin_value", "php_flag", "php_admin_flag":
		default:
			continue
		}
		key := strings.Trim(fields[1], `"'`)
		if !isTrackedIniKey(key) {
			continue
		}
		valRaw := ""
		if len(fields) >= 3 {
			valRaw = strings.Join(fields[2:], " ")
		}
		norm := NormalizeIniValue(valRaw)
		target.SetIniSetting(key, norm, fmt.Sprintf("%s (%s) %s:%d", absPath, directive, absPath, lineNum))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse apache config %s: %w", absPath, err)
	}
	return nil
}

func stripApacheComment(s string) string {
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
		if !inQuotes && ch == '#' {
			return s[:i]
		}
	}
	return s
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
