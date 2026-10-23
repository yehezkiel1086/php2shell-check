package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// Collector discovers PHP installations on a local host in read-only mode.
type Collector interface {
	Collect(ctx context.Context) ([]inventory.PHPInstall, error)
}

// Config configures a HostCollector instance.
type Config struct {
	FS             fs.FS
	Runner         Runner
	PathEnv        string
	Locations      SearchLocations
	MaxModuleBytes int64
}

// HostCollector implements Collector using an injectable fs.FS and Runner.
type HostCollector struct {
	fsys           fs.FS
	runner         Runner
	pathEnv        string
	locations      SearchLocations
	maxModuleBytes int64
}

// NewCollector constructs a HostCollector with the provided configuration,
// applying safe defaults for any omitted fields.
func NewCollector(cfg Config) *HostCollector {
	if cfg.FS == nil {
		cfg.FS = os.DirFS("/")
	}
	if cfg.Runner == nil {
		cfg.Runner = NewExecRunner()
	}
	if len(cfg.Locations.BinaryGlobs) == 0 && len(cfg.Locations.ApacheModuleGlobs) == 0 {
		cfg.Locations = DefaultSearchLocations()
	}
	if cfg.MaxModuleBytes <= 0 {
		cfg.MaxModuleBytes = DefaultMaxModuleBytes
	}
	return &HostCollector{
		fsys:           cfg.FS,
		runner:         cfg.Runner,
		pathEnv:        cfg.PathEnv,
		locations:      cfg.Locations,
		maxModuleBytes: cfg.MaxModuleBytes,
	}
}

// NewDefaultCollector constructs a HostCollector configured for the live host.
func NewDefaultCollector() *HostCollector {
	return NewCollector(Config{
		FS:      os.DirFS("/"),
		Runner:  NewExecRunner(),
		PathEnv: os.Getenv("PATH"),
	})
}

// Collect discovers PHP binaries, FPM pools, Apache modules, INI settings, and package ownership.
// Permission errors are recorded in Evidence and never abort collection.
func (c *HostCollector) Collect(ctx context.Context) ([]inventory.PHPInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("local collect context: %w", err)
	}

	distro, osEv := c.detectDistro()

	binPaths, binPermEv := c.discoverBinaryPaths()
	var installs []inventory.PHPInstall

	for _, relPath := range binPaths {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("local collect binaries context: %w", err)
		}
		inst, ok := c.inspectBinary(ctx, relPath, distro)
		if !ok {
			continue
		}
		for _, ev := range osEv {
			inst.AddEvidence(ev)
		}
		for _, ev := range binPermEv {
			inst.AddEvidence(ev)
		}
		installs = append(installs, inst)
	}

	modPaths, modPermEv := c.discoverModulePaths()
	for _, relPath := range modPaths {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("local collect modules context: %w", err)
		}
		inst, ok := c.inspectApacheModule(ctx, relPath, distro)
		if !ok {
			continue
		}
		for _, ev := range osEv {
			inst.AddEvidence(ev)
		}
		for _, ev := range modPermEv {
			inst.AddEvidence(ev)
		}
		installs = append(installs, inst)
	}

	return installs, nil
}

func (c *HostCollector) detectDistro() (inventory.Distro, []string) {
	var evidence []string
	for _, rel := range c.locations.OSReleasePaths {
		f, err := c.fsys.Open(rel)
		if err != nil {
			if isPermissionError(err) {
				evidence = append(evidence, fmt.Sprintf("permission_denied: open /%s: %v", rel, err))
			}
			continue
		}
		d, parseErr := ParseOSRelease(f)
		_ = f.Close()
		if parseErr != nil {
			if isPermissionError(parseErr) {
				evidence = append(evidence, fmt.Sprintf("permission_denied: read /%s: %v", rel, parseErr))
			}
			continue
		}
		if d.ID != "" {
			return d, evidence
		}
	}
	return inventory.Distro{}, evidence
}

func (c *HostCollector) discoverBinaryPaths() ([]string, []string) {
	seen := make(map[string]struct{})
	var permEvidence []string

	var globs []string
	globs = append(globs, c.locations.BinaryGlobs...)

	for _, dir := range splitPathEnv(c.pathEnv) {
		relDir := toFSPath(dir)
		if relDir == "" || relDir == "." {
			continue
		}
		if runtime.GOOS != "windows" && isWSLMountPath(relDir) {
			continue
		}
		globs = append(globs,
			path.Join(relDir, "php*"),
			path.Join(relDir, "frankenphp*"),
			path.Join(relDir, "lsphp*"),
		)
	}

	for _, pattern := range globs {
		matches, err := fs.Glob(c.fsys, pattern)
		if err != nil {
			if isPermissionError(err) {
				permEvidence = append(permEvidence, fmt.Sprintf("permission_denied: glob /%s: %v", pattern, err))
			}
			continue
		}
		for _, m := range matches {
			if !isCandidatePHPBinary(path.Base(m)) {
				continue
			}
			seen[m] = struct{}{}
		}
	}

	sorted := make([]string, 0, len(seen))
	for m := range seen {
		sorted = append(sorted, m)
	}
	sort.Strings(sorted)
	return sorted, permEvidence
}

func (c *HostCollector) discoverModulePaths() ([]string, []string) {
	seen := make(map[string]struct{})
	var permEvidence []string

	for _, pattern := range c.locations.ApacheModuleGlobs {
		matches, err := fs.Glob(c.fsys, pattern)
		if err != nil {
			if isPermissionError(err) {
				permEvidence = append(permEvidence, fmt.Sprintf("permission_denied: glob /%s: %v", pattern, err))
			}
			continue
		}
		for _, m := range matches {
			seen[m] = struct{}{}
		}
	}

	sorted := make([]string, 0, len(seen))
	for m := range seen {
		sorted = append(sorted, m)
	}
	sort.Strings(sorted)
	return sorted, permEvidence
}

func (c *HostCollector) inspectBinary(ctx context.Context, relPath string, distro inventory.Distro) (inventory.PHPInstall, bool) {
	absPath := "/" + strings.TrimPrefix(relPath, "/")

	info, err := fs.Stat(c.fsys, relPath)
	if err != nil {
		if isPermissionError(err) {
			sapi := inferSAPIFromVersionText("", absPath)
			inst := inventory.PHPInstall{
				ID:         inventory.ComputeID(inventory.SourceLocal, sapi, absPath),
				BinaryPath: absPath,
				Distro:     distro,
				SAPI:       sapi,
				Source:     inventory.SourceLocal,
				Confidence: inventory.ConfidenceLow,
			}
			inst.AddEvidence(fmt.Sprintf("permission_denied: stat %s: %v", absPath, err))
			return inst, true
		}
		return inventory.PHPInstall{}, false
	}
	if info.IsDir() {
		return inventory.PHPInstall{}, false
	}

	stdout, stderr, runErr := c.runner.Run(ctx, absPath, "-v")
	if runErr != nil {
		if isPermissionError(runErr) {
			sapi := inferSAPIFromVersionText("", absPath)
			inst := inventory.PHPInstall{
				ID:         inventory.ComputeID(inventory.SourceLocal, sapi, absPath),
				BinaryPath: absPath,
				Distro:     distro,
				SAPI:       sapi,
				Source:     inventory.SourceLocal,
				Confidence: inventory.ConfidenceLow,
			}
			inst.AddEvidence(fmt.Sprintf("permission_denied: exec %s -v: %v", absPath, runErr))
			c.populatePackageOwnership(ctx, &inst, absPath, distro)
			return inst, true
		}
		return inventory.PHPInstall{}, false
	}

	combined := append(append([]byte{}, stdout...), stderr...)
	upstreamVer, rawVer, sapi, parseErr := ParsePHPVersionOutput(combined, absPath)
	if parseErr != nil {
		return inventory.PHPInstall{}, false
	}

	inst := inventory.PHPInstall{
		ID:              inventory.ComputeID(inventory.SourceLocal, sapi, absPath),
		BinaryPath:      absPath,
		UpstreamVersion: upstreamVer,
		Distro:          distro,
		SAPI:            sapi,
		IniSettings:     make(map[string]string),
		Source:          inventory.SourceLocal,
		Confidence:      inventory.ConfidenceHigh,
	}
	inst.AddEvidence(fmt.Sprintf("version_cmd: %s -v => %s", absPath, rawVer))

	if sapi == inventory.SAPICLI {
		c.inspectPHPInfo(ctx, absPath, "php -i", &inst)
	}

	if parsedVer, err := phpver.Parse(upstreamVer); err == nil {
		if sapi == inventory.SAPIFPM {
			c.inspectFPMStaticConfigs(parsedVer.Branch, absPath, &inst)
			if len(inst.IniSettings) == 0 {
				c.inspectPHPInfo(ctx, absPath, "php-fpm -i", &inst)
			}
		}
	}

	c.populatePackageOwnership(ctx, &inst, absPath, distro)
	return inst, true
}

func (c *HostCollector) inspectPHPInfo(ctx context.Context, absPath, sourceLabel string, inst *inventory.PHPInstall) {
	stdout, _, err := c.runner.Run(ctx, absPath, "-i")
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: exec %s -i: %v", absPath, err))
		}
		return
	}

	infoRes := ParsePHPInfoOutput(stdout)
	if infoRes.ServerAPI != "" {
		inst.AddEvidence(fmt.Sprintf("php_i: Server API => %s", infoRes.ServerAPI))
	}

	if infoRes.LoadedConfigFile != "" {
		inst.AddConfigFile(infoRes.LoadedConfigFile)
		c.parseStaticIniFile(toFSPath(infoRes.LoadedConfigFile), inst)
	}

	if infoRes.ScanIniDir != "" {
		inst.AddEvidence(fmt.Sprintf("php_i: Scan this dir for additional .ini files => %s", infoRes.ScanIniDir))
		c.parseStaticIniGlob(path.Join(toFSPath(infoRes.ScanIniDir), "*.ini"), inst)
	}

	for _, f := range infoRes.AdditionalIniFiles {
		inst.AddConfigFile(f)
		c.parseStaticIniFile(toFSPath(f), inst)
	}

	for k, v := range infoRes.IniSettings {
		inst.SetIniSetting(k, v, sourceLabel)
	}
}

func (c *HostCollector) inspectFPMStaticConfigs(branch, binaryPath string, inst *inventory.PHPInstall) {
	iniFiles, iniGlobs, poolGlobs := FPMConfigLocations(branch, binaryPath)

	for _, relFile := range iniFiles {
		c.parseStaticIniFile(relFile, inst)
	}
	for _, globPattern := range iniGlobs {
		c.parseStaticIniGlob(globPattern, inst)
	}
	for _, poolPattern := range poolGlobs {
		c.parseStaticFPMPoolGlob(poolPattern, inst)
	}
}

func (c *HostCollector) inspectApacheStaticConfigs(branch string, inst *inventory.PHPInstall) {
	iniFiles, iniGlobs := ApacheConfigLocations(branch)

	for _, relFile := range iniFiles {
		c.parseStaticIniFile(relFile, inst)
	}
	for _, globPattern := range iniGlobs {
		c.parseStaticIniGlob(globPattern, inst)
	}
}

func (c *HostCollector) parseStaticIniGlob(pattern string, inst *inventory.PHPInstall) {
	matches, err := fs.Glob(c.fsys, pattern)
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: glob /%s: %v", pattern, err))
		}
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		c.parseStaticIniFile(m, inst)
	}
}

func (c *HostCollector) parseStaticIniFile(relPath string, inst *inventory.PHPInstall) {
	if relPath == "" {
		return
	}
	absPath := "/" + strings.TrimPrefix(relPath, "/")

	f, err := c.fsys.Open(relPath)
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: open %s: %v", absPath, err))
		}
		return
	}
	defer func() { _ = f.Close() }()

	inst.AddConfigFile(absPath)
	if err := ParseIniReader(f, absPath, inst); err != nil && isPermissionError(err) {
		inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", absPath, err))
	}
}

func (c *HostCollector) parseStaticFPMPoolGlob(pattern string, inst *inventory.PHPInstall) {
	matches, err := fs.Glob(c.fsys, pattern)
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: glob /%s: %v", pattern, err))
		}
		return
	}
	sort.Strings(matches)
	for _, relPath := range matches {
		absPath := "/" + strings.TrimPrefix(relPath, "/")
		f, openErr := c.fsys.Open(relPath)
		if openErr != nil {
			if isPermissionError(openErr) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: open %s: %v", absPath, openErr))
			}
			continue
		}
		inst.AddConfigFile(absPath)
		if parseErr := ParseFPMPoolReader(f, absPath, inst); parseErr != nil && isPermissionError(parseErr) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", absPath, parseErr))
		}
		_ = f.Close()
	}
}

func (c *HostCollector) inspectApacheModule(ctx context.Context, relPath string, distro inventory.Distro) (inventory.PHPInstall, bool) {
	absPath := "/" + strings.TrimPrefix(relPath, "/")

	f, err := c.fsys.Open(relPath)
	if err != nil {
		if isPermissionError(err) {
			inst := inventory.PHPInstall{
				ID:         inventory.ComputeID(inventory.SourceLocal, inventory.SAPIApache2Handler, absPath),
				ModulePath: absPath,
				Distro:     distro,
				SAPI:       inventory.SAPIApache2Handler,
				Source:     inventory.SourceLocal,
				Confidence: inventory.ConfidenceLow,
			}
			inst.AddEvidence(fmt.Sprintf("permission_denied: open %s: %v", absPath, err))
			return inst, true
		}
		return inventory.PHPInstall{}, false
	}
	defer func() { _ = f.Close() }()

	upstreamVer, matched, scanErr := ScanModuleBytes(f, c.maxModuleBytes)
	if scanErr != nil {
		if isPermissionError(scanErr) {
			inst := inventory.PHPInstall{
				ID:         inventory.ComputeID(inventory.SourceLocal, inventory.SAPIApache2Handler, absPath),
				ModulePath: absPath,
				Distro:     distro,
				SAPI:       inventory.SAPIApache2Handler,
				Source:     inventory.SourceLocal,
				Confidence: inventory.ConfidenceLow,
			}
			inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", absPath, scanErr))
			return inst, true
		}
		return inventory.PHPInstall{}, false
	}

	inst := inventory.PHPInstall{
		ID:              inventory.ComputeID(inventory.SourceLocal, inventory.SAPIApache2Handler, absPath),
		ModulePath:      absPath,
		UpstreamVersion: upstreamVer,
		Distro:          distro,
		SAPI:            inventory.SAPIApache2Handler,
		IniSettings:     make(map[string]string),
		Source:          inventory.SourceLocal,
		Confidence:      inventory.ConfidenceHigh,
	}
	inst.AddEvidence(fmt.Sprintf("module_bytes: %s => %s", absPath, matched))

	if parsedVer, err := phpver.Parse(upstreamVer); err == nil {
		c.inspectApacheStaticConfigs(parsedVer.Branch, &inst)
	}

	c.populatePackageOwnership(ctx, &inst, absPath, distro)
	return inst, true
}

func (c *HostCollector) populatePackageOwnership(ctx context.Context, inst *inventory.PHPInstall, targetPath string, distro inventory.Distro) {
	switch distro.ID {
	case "debian", "ubuntu", "kali", "raspbian":
		if c.tryDpkgOwnership(ctx, inst, targetPath) {
			return
		}
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol", "amzn":
		if c.tryRPMOwnership(ctx, inst, targetPath) {
			return
		}
	case "alpine":
		if c.tryApkOwnership(ctx, inst, targetPath) {
			return
		}
	}

	// Fallback probe order if distro ID was unknown or primary manager did not own the file.
	if c.tryDpkgOwnership(ctx, inst, targetPath) {
		return
	}
	if c.tryRPMOwnership(ctx, inst, targetPath) {
		return
	}
	_ = c.tryApkOwnership(ctx, inst, targetPath)
}

func (c *HostCollector) tryDpkgOwnership(ctx context.Context, inst *inventory.PHPInstall, targetPath string) bool {
	out, _, err := c.runner.Run(ctx, "/usr/bin/dpkg-query", "-S", targetPath)
	if err != nil {
		return false
	}
	line := strings.TrimSpace(string(bytes.SplitN(out, []byte("\n"), 2)[0]))
	pkgPart, _, ok := strings.Cut(line, ":")
	if !ok {
		return false
	}
	// Handle architecture-qualified package names like "php8.3-cli:amd64: /usr/bin/php8.3".
	pkgName := strings.TrimSpace(strings.Split(pkgPart, ",")[0])
	if pkgName == "" {
		return false
	}

	verOut, _, verErr := c.runner.Run(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n", pkgName)
	if verErr != nil {
		return false
	}
	fields := strings.Split(strings.TrimSpace(string(verOut)), "\t")
	if len(fields) != 2 || fields[1] == "" {
		return false
	}

	inst.PackageManager = "deb"
	inst.PackageName = strings.TrimSpace(fields[0])
	inst.PackageVersion = strings.TrimSpace(fields[1])
	inst.AddEvidence(fmt.Sprintf("package: deb %s %s (dpkg-query)", inst.PackageName, inst.PackageVersion))
	return true
}

func (c *HostCollector) tryRPMOwnership(ctx context.Context, inst *inventory.PHPInstall, targetPath string) bool {
	out, _, err := c.runner.Run(ctx, "/usr/bin/rpm", "-qf", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n", targetPath)
	if err != nil {
		return false
	}
	line := strings.TrimSpace(string(bytes.SplitN(out, []byte("\n"), 2)[0]))
	fields := strings.Split(line, "\t")
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
		return false
	}

	inst.PackageManager = "rpm"
	inst.PackageName = strings.TrimSpace(fields[0])
	inst.PackageVersion = strings.TrimSpace(fields[1])
	inst.AddEvidence(fmt.Sprintf("package: rpm %s %s (rpm -qf)", inst.PackageName, inst.PackageVersion))
	return true
}

func (c *HostCollector) tryApkOwnership(ctx context.Context, inst *inventory.PHPInstall, targetPath string) bool {
	out, _, err := c.runner.Run(ctx, "/sbin/apk", "info", "--who-owns", targetPath)
	if err != nil {
		return false
	}
	text := strings.TrimSpace(string(out))
	const marker = "is owned by "
	idx := strings.Index(text, marker)
	if idx < 0 {
		return false
	}
	pkgVer := strings.Fields(text[idx+len(marker):])
	if len(pkgVer) == 0 {
		return false
	}
	name, ver, ok := splitApkPackageVersion(pkgVer[0])
	if !ok {
		return false
	}

	inst.PackageManager = "apk"
	inst.PackageName = name
	inst.PackageVersion = ver
	inst.AddEvidence(fmt.Sprintf("package: apk %s %s (apk info)", name, ver))
	return true
}

func splitApkPackageVersion(token string) (string, string, bool) {
	// Alpine format: <pkgname>-<version>-r<release>, e.g. "php83-8.3.35-r0" or "php83-fpm-8.3.35-r0".
	lastDash := strings.LastIndexByte(token, '-')
	if lastDash <= 0 {
		return "", "", false
	}
	beforeRel := token[:lastDash]
	verDash := strings.LastIndexByte(beforeRel, '-')
	if verDash <= 0 || verDash+1 >= len(token) {
		return "", "", false
	}
	return token[:verDash], token[verDash+1:], true
}

func isCandidatePHPBinary(base string) bool {
	lowerBase := strings.ToLower(base)
	if runtime.GOOS != "windows" && strings.HasSuffix(lowerBase, ".exe") {
		return false
	}
	lower := strings.TrimSuffix(lowerBase, ".exe")
	if lower == "" {
		return false
	}

	// Exclude build/dev scripts and config files that start with "php".
	excludedPrefixes := []string{
		"phpize",
		"php-config",
		"phpconfig",
		"phpdbg",
		"phpenmod",
		"phpdismod",
		"phpquery",
	}
	for _, ex := range excludedPrefixes {
		if strings.HasPrefix(lower, ex) {
			return false
		}
	}

	excludedSuffixes := []string{".ini", ".conf", ".so", ".dll", ".dylib", ".1", ".gz", ".bak"}
	for _, suf := range excludedSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}

	return strings.HasPrefix(lower, "php") ||
		strings.HasPrefix(lower, "frankenphp") ||
		strings.HasPrefix(lower, "lsphp")
}

// isWSLMountPath reports whether a relative root-fs path is under a Windows WSL drive mount (e.g. "mnt/c/...").
func isWSLMountPath(relDir string) bool {
	lower := strings.ToLower(strings.TrimPrefix(relDir, "/"))
	if !strings.HasPrefix(lower, "mnt/") {
		return false
	}
	rest := lower[len("mnt/"):]
	if len(rest) == 1 && rest[0] >= 'a' && rest[0] <= 'z' {
		return true
	}
	if len(rest) >= 2 && rest[0] >= 'a' && rest[0] <= 'z' && rest[1] == '/' {
		return true
	}
	return false
}

func splitPathEnv(pathEnv string) []string {
	if pathEnv == "" {
		return nil
	}
	sep := ":"
	if strings.Contains(pathEnv, ";") {
		sep = ";"
	}
	return strings.Split(pathEnv, sep)
}

func toFSPath(p string) string {
	cleaned := strings.ReplaceAll(p, `\`, "/")
	if idx := strings.IndexByte(cleaned, ':'); idx == 1 {
		cleaned = cleaned[2:]
	}
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" {
		return ""
	}
	return path.Clean(cleaned)
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) || os.IsPermission(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}
