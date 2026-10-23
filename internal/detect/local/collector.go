package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// ErrSymlinkEscape indicates that a symlink target escapes the inspected root filesystem.
var ErrSymlinkEscape = errors.New("symlink target escapes root directory")

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
	fsys                fs.FS
	runner              Runner
	pathEnv             string
	locations           SearchLocations
	maxModuleBytes      int64
	useHostEvalSymlinks bool
}

// NewCollector constructs a HostCollector with the provided configuration,
// applying safe defaults for any omitted fields.
func NewCollector(cfg Config) *HostCollector {
	useHostEval := false
	if cfg.FS == nil {
		cfg.FS = os.DirFS("/")
		useHostEval = runtime.GOOS != "windows"
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
		fsys:                cfg.FS,
		runner:              cfg.Runner,
		pathEnv:             cfg.PathEnv,
		locations:           cfg.Locations,
		maxModuleBytes:      cfg.MaxModuleBytes,
		useHostEvalSymlinks: useHostEval,
	}
}

// NewDefaultCollector constructs a HostCollector configured for the live host.
func NewDefaultCollector() *HostCollector {
	c := NewCollector(Config{
		FS:      os.DirFS("/"),
		Runner:  NewExecRunner(),
		PathEnv: os.Getenv("PATH"),
	})
	c.useHostEvalSymlinks = runtime.GOOS != "windows"
	return c
}

type binaryCandidate struct {
	resolvedRel string
	viaPaths    []string
}

// Collect discovers PHP binaries, FPM pools, Apache modules, INI settings, and package ownership.
// Permission errors are recorded in Evidence and never abort collection.
func (c *HostCollector) Collect(ctx context.Context) ([]inventory.PHPInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("local collect context: %w", err)
	}

	distro, osEv := c.detectDistro()

	binCandidates, binPermEv := c.discoverBinaryPaths()
	var installs []inventory.PHPInstall

	for _, cand := range binCandidates {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("local collect binaries context: %w", err)
		}
		inst, ok := c.inspectBinary(ctx, cand, distro)
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

func (c *HostCollector) discoverBinaryPaths() ([]binaryCandidate, []string) {
	rawSeen := make(map[string]struct{})
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
			rawSeen[m] = struct{}{}
		}
	}

	rawSorted := make([]string, 0, len(rawSeen))
	for m := range rawSeen {
		rawSorted = append(rawSorted, m)
	}
	sort.Strings(rawSorted)

	byResolved := make(map[string]*binaryCandidate)
	var resolvedOrder []string

	for _, rawRel := range rawSorted {
		resolvedRel, escaped, err := c.resolveRelPath(rawRel)
		if escaped {
			permEvidence = append(permEvidence, fmt.Sprintf("symlink_rejected: /%s escapes root", rawRel))
			continue
		}
		if err != nil {
			if isPermissionError(err) {
				permEvidence = append(permEvidence, fmt.Sprintf("permission_denied: resolve /%s: %v", rawRel, err))
			}
			continue
		}
		if resolvedRel == "" || !isCandidatePHPBinary(path.Base(resolvedRel)) {
			continue
		}

		cand, exists := byResolved[resolvedRel]
		if !exists {
			cand = &binaryCandidate{resolvedRel: resolvedRel}
			byResolved[resolvedRel] = cand
			resolvedOrder = append(resolvedOrder, resolvedRel)
		}
		if resolvedRel != rawRel {
			viaAbs := "/" + strings.TrimPrefix(rawRel, "/")
			if !containsString(cand.viaPaths, viaAbs) {
				cand.viaPaths = append(cand.viaPaths, viaAbs)
			}
		}
	}

	sort.Strings(resolvedOrder)
	out := make([]binaryCandidate, 0, len(resolvedOrder))
	for _, r := range resolvedOrder {
		cand := byResolved[r]
		sort.Strings(cand.viaPaths)
		out = append(out, *cand)
	}
	return out, permEvidence
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
			resolvedRel, escaped, resErr := c.resolveRelPath(m)
			if escaped {
				permEvidence = append(permEvidence, fmt.Sprintf("symlink_rejected: /%s escapes root", m))
				continue
			}
			if resErr != nil {
				seen[m] = struct{}{}
				continue
			}
			seen[resolvedRel] = struct{}{}
		}
	}

	sorted := make([]string, 0, len(seen))
	for m := range seen {
		sorted = append(sorted, m)
	}
	sort.Strings(sorted)
	return sorted, permEvidence
}

func (c *HostCollector) inspectBinary(ctx context.Context, cand binaryCandidate, distro inventory.Distro) (inventory.PHPInstall, bool) {
	relPath := cand.resolvedRel
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
			for _, via := range cand.viaPaths {
				inst.AddEvidence(fmt.Sprintf("found via %s", via))
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
	if runErr != nil && !isPermissionError(runErr) && len(cand.viaPaths) > 0 {
		for _, via := range cand.viaPaths {
			if out, errOut, viaErr := c.runner.Run(ctx, via, "-v"); viaErr == nil {
				stdout, stderr, runErr = out, errOut, nil
				break
			}
		}
	}
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
			for _, via := range cand.viaPaths {
				inst.AddEvidence(fmt.Sprintf("found via %s", via))
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
	for _, via := range cand.viaPaths {
		inst.AddEvidence(fmt.Sprintf("found via %s", via))
	}
	inst.AddEvidence(fmt.Sprintf("version_cmd: %s -v => %s", absPath, rawVer))

	var branch string
	if parsedVer, verErr := phpver.Parse(upstreamVer); verErr == nil {
		branch = parsedVer.Branch
	}

	c.discoverConfigsForInstall(ctx, &inst, branch, absPath)
	c.populatePackageOwnership(ctx, &inst, absPath, distro)
	return inst, true
}

// DiscoverStaticConfigs discovers and parses PHP configuration files statically from fsys
// (used by container image scanning where no binaries are executed).
func DiscoverStaticConfigs(fsys fs.FS, inst *inventory.PHPInstall, branch, targetAbsPath string) {
	c := NewCollector(Config{
		FS:     fsys,
		Runner: nopRunner{},
	})
	c.useHostEvalSymlinks = false
	c.discoverConfigsForInstall(context.Background(), inst, branch, targetAbsPath)
}

type nopRunner struct{}

func (nopRunner) Run(context.Context, string, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("command execution disabled")
}

func (c *HostCollector) queryBinaryIniInfo(ctx context.Context, absPath string, inst *inventory.PHPInstall) (PHPInfoResult, bool) {
	if c.runner == nil || inst.Source != inventory.SourceLocal || absPath == "" {
		return PHPInfoResult{}, false
	}

	// Prefer `php --ini` over `php -i` (Task 3).
	if stdout, _, err := c.runner.Run(ctx, absPath, "--ini"); err == nil && len(bytes.TrimSpace(stdout)) > 0 {
		res := ParsePHPIniOutput(stdout)
		if res.ConfigFilePath != "" || res.LoadedConfigFile != "" || res.LoadedConfigNone || res.ScanIniDir != "" || res.ScanIniDirNone || len(res.AdditionalIniFiles) > 0 {
			return res, true
		}
	}

	stdout, _, err := c.runner.Run(ctx, absPath, "-i")
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: exec %s -i: %v", absPath, err))
		}
		return PHPInfoResult{}, false
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		return PHPInfoResult{}, false
	}
	return ParsePHPInfoOutput(stdout), true
}

func (c *HostCollector) discoverConfigsForInstall(ctx context.Context, inst *inventory.PHPInstall, branch, targetAbsPath string) {
	if inst.IniSettings == nil {
		inst.IniSettings = make(map[string]string)
	}

	prefix := DeriveInstallPrefix(c.fsys, targetAbsPath)
	if prefix == "" {
		if inst.SAPI == inventory.SAPIApache2Handler || inst.PackageManager != "" {
			prefix = "/usr"
		}
	}

	isSystemPrefix := prefix == "/" || prefix == "/usr"
	isUsrLocalPrefix := prefix == "/usr/local"
	isVendorOptPrefix := strings.HasPrefix(prefix, "/opt/remi") ||
		strings.HasPrefix(prefix, "/opt/cpanel") ||
		strings.HasPrefix(prefix, "/opt/alt")
	isCustomPrefix := !isSystemPrefix && !isUsrLocalPrefix && !isVendorOptPrefix

	seenIniFiles := make(map[string]bool)
	seenScanDirs := make(map[string]bool)
	locatedAnyConfig := false
	confirmedCustomPrefix := inst.Source == inventory.SourceImage

	var stage1IniFiles []string
	var stage2ScanDirs []string
	var stage2ExplicitFiles []string
	var unconfirmedGuesses []string

	// (a) Loaded ini and scan dir the binary itself reports.
	infoRes, ranIni := c.queryBinaryIniInfo(ctx, inst.BinaryPath, inst)
	if ranIni {
		if infoRes.ServerAPI != "" {
			inst.AddEvidence(fmt.Sprintf("php_i: Server API => %s", infoRes.ServerAPI))
		}
		if infoRes.ConfigFilePath != "" && !isCLIOnlyConfigPath(infoRes.ConfigFilePath, inst.SAPI) {
			cfgDirRel := toFSPath(infoRes.ConfigFilePath)
			if c.dirExistsInFS(cfgDirRel) {
				confirmedCustomPrefix = true
				locatedAnyConfig = true
			}
			if prefix != "" && strings.HasPrefix("/"+cfgDirRel, prefix) {
				confirmedCustomPrefix = true
			}
		}
		if infoRes.LoadedConfigFile != "" && !isCLIOnlyConfigPath(infoRes.LoadedConfigFile, inst.SAPI) {
			loadedRel := toFSPath(infoRes.LoadedConfigFile)
			if c.fileExistsInFS(loadedRel) {
				confirmedCustomPrefix = true
				locatedAnyConfig = true
				stage1IniFiles = append(stage1IniFiles, loadedRel)
			}
		}
		if infoRes.ScanIniDir != "" && !isCLIOnlyConfigPath(infoRes.ScanIniDir, inst.SAPI) {
			if prefix != "" && strings.HasPrefix("/"+toFSPath(infoRes.ScanIniDir), prefix) {
				confirmedCustomPrefix = true
			}
			scanRel := toFSPath(infoRes.ScanIniDir)
			if c.dirExistsInFS(scanRel) {
				confirmedCustomPrefix = true
				locatedAnyConfig = true
				inst.AddEvidence(fmt.Sprintf("php_ini: scan dir => %s", infoRes.ScanIniDir))
				stage2ScanDirs = append(stage2ScanDirs, scanRel)
			} else {
				inst.AddEvidence("reported scan dir does not exist")
			}
		}
		for _, addFile := range infoRes.AdditionalIniFiles {
			if isCLIOnlyConfigPath(addFile, inst.SAPI) {
				continue
			}
			addRel := toFSPath(addFile)
			if c.fileExistsInFS(addRel) {
				confirmedCustomPrefix = true
				locatedAnyConfig = true
				stage2ExplicitFiles = append(stage2ExplicitFiles, addRel)
			}
		}
	}

	// For FPM in a custom prefix, presence of <prefix>/etc/php-fpm.conf or <prefix>/etc/php-fpm.d confirms the prefix layout.
	if isCustomPrefix && inst.SAPI == inventory.SAPIFPM && prefix != "" {
		relPref := toFSPath(prefix)
		if c.fileExistsInFS(path.Join(relPref, "etc/php-fpm.conf")) || c.dirExistsInFS(path.Join(relPref, "etc/php-fpm.d")) {
			confirmedCustomPrefix = true
		}
	}

	// (b) Prefix-relative defaults: <prefix>/etc/php.ini, <prefix>/etc/conf.d
	if prefix != "" && !isSystemPrefix {
		relPref := toFSPath(prefix)
		prefIni := path.Join(relPref, "etc/php.ini")
		prefConfD := path.Join(relPref, "etc/conf.d")

		if isCustomPrefix && (!confirmedCustomPrefix || infoRes.LoadedConfigNone) {
			// Files found by a prefix guess when not confirmed as loaded by the binary are marked
			// 'present but not confirmed as loaded' and keep UNKNOWN (Task 7).
			if c.fileExistsInFS(prefIni) && (!confirmedCustomPrefix || infoRes.LoadedConfigNone) {
				unconfirmedGuesses = append(unconfirmedGuesses, "/"+prefIni)
			}
			if !confirmedCustomPrefix && c.dirExistsInFS(prefConfD) {
				if matches, err := fs.Glob(c.fsys, path.Join(prefConfD, "*.ini")); err == nil {
					sort.Strings(matches)
					for _, m := range matches {
						unconfirmedGuesses = append(unconfirmedGuesses, "/"+m)
					}
				}
			}
		} else {
			if c.fileExistsInFS(prefIni) {
				locatedAnyConfig = true
				stage1IniFiles = append(stage1IniFiles, prefIni)
			}
			if c.dirExistsInFS(prefConfD) {
				locatedAnyConfig = true
				stage2ScanDirs = append(stage2ScanDirs, prefConfD)
			}
		}
	}

	// (c) Official-image layout: /usr/local/etc/php and /usr/local/etc/php/conf.d
	if isUsrLocalPrefix || (inst.Source == inventory.SourceImage && (strings.HasPrefix(targetAbsPath, "/usr/local/") || c.dirExistsInFS("usr/local/etc/php") || c.fileExistsInFS("usr/local/include/php/main/php_version.h"))) {
		if c.fileExistsInFS("usr/local/etc/php/php.ini") {
			locatedAnyConfig = true
			stage1IniFiles = append(stage1IniFiles, "usr/local/etc/php/php.ini")
		}
		if c.dirExistsInFS("usr/local/etc/php/conf.d") {
			locatedAnyConfig = true
			stage2ScanDirs = append(stage2ScanDirs, "usr/local/etc/php/conf.d")
		}
		if inst.Source == inventory.SourceImage && (c.dirExistsInFS("usr/local/etc/php") || c.fileExistsInFS("usr/local/include/php/main/php_version.h")) {
			locatedAnyConfig = true
		}
	}

	// (d) Debian/Ubuntu /etc/php/<branch>/<cli|fpm|apache2|cgi>/php.ini and conf.d (plus Alpine /etc/php<compact>)
	if isSystemPrefix && branch != "" {
		debSAPI := debianSAPIDir(inst.SAPI)
		if debSAPI != "" {
			debDir := fmt.Sprintf("etc/php/%s/%s", branch, debSAPI)
			debIni := path.Join(debDir, "php.ini")
			debConfD := path.Join(debDir, "conf.d")
			if c.fileExistsInFS(debIni) {
				locatedAnyConfig = true
				stage1IniFiles = append(stage1IniFiles, debIni)
			}
			if c.dirExistsInFS(debConfD) {
				locatedAnyConfig = true
				stage2ScanDirs = append(stage2ScanDirs, debConfD)
			}
		}
		compact := strings.ReplaceAll(branch, ".", "")
		alpIni := fmt.Sprintf("etc/php%s/php.ini", compact)
		alpConfD := fmt.Sprintf("etc/php%s/conf.d", compact)
		if c.fileExistsInFS(alpIni) {
			locatedAnyConfig = true
			stage1IniFiles = append(stage1IniFiles, alpIni)
		}
		if c.dirExistsInFS(alpConfD) {
			locatedAnyConfig = true
			stage2ScanDirs = append(stage2ScanDirs, alpConfD)
		}
	}

	// (e) RHEL-style /etc/php.ini, /etc/php.d, and /opt/remi, /opt/cpanel, /opt/alt equivalents
	if isSystemPrefix {
		if c.fileExistsInFS("etc/php.ini") {
			locatedAnyConfig = true
			stage1IniFiles = append(stage1IniFiles, "etc/php.ini")
		}
		if c.dirExistsInFS("etc/php.d") {
			locatedAnyConfig = true
			stage2ScanDirs = append(stage2ScanDirs, "etc/php.d")
		}
	}
	if (isVendorOptPrefix || isSystemPrefix) && branch != "" {
		compact := strings.ReplaceAll(branch, ".", "")
		vendorInis := []string{
			fmt.Sprintf("etc/opt/remi/php%s/php.ini", compact),
			fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.ini", compact),
			fmt.Sprintf("opt/alt/php%s/etc/php.ini", compact),
		}
		vendorConfDs := []string{
			fmt.Sprintf("etc/opt/remi/php%s/php.d", compact),
			fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.d", compact),
			fmt.Sprintf("opt/alt/php%s/etc/php.d", compact),
		}
		for _, vIni := range vendorInis {
			if c.fileExistsInFS(vIni) {
				locatedAnyConfig = true
				stage1IniFiles = append(stage1IniFiles, vIni)
			}
		}
		for _, vConfD := range vendorConfDs {
			if c.dirExistsInFS(vConfD) {
				locatedAnyConfig = true
				stage2ScanDirs = append(stage2ScanDirs, vConfD)
			}
		}
	}

	// Stage 1: Parse php.ini files in precedence order.
	for _, rel := range stage1IniFiles {
		c.parseStaticIniFileTracked(rel, inst, seenIniFiles)
	}

	// Stage 2: Parse conf.d/*.ini files in lexical order, resolving symlinks inside root only.
	for _, scanDir := range stage2ScanDirs {
		if seenScanDirs[scanDir] {
			continue
		}
		seenScanDirs[scanDir] = true
		c.parseStaticIniGlobTracked(path.Join(scanDir, "*.ini"), inst, seenIniFiles)
	}
	for _, rel := range stage2ExplicitFiles {
		c.parseStaticIniFileTracked(rel, inst, seenIniFiles)
	}

	// Stage 3a: FPM pool configs (only for SAPI == fpm).
	if inst.SAPI == inventory.SAPIFPM {
		if c.discoverAndParseFPMPools(inst, branch, prefix, isSystemPrefix, isUsrLocalPrefix, isVendorOptPrefix) {
			locatedAnyConfig = true
		}
	}

	// Stage 3b: Apache configuration files in /etc/apache2 and /etc/httpd (only for SAPI == apache2handler).
	if inst.SAPI == inventory.SAPIApache2Handler {
		inst.AddEvidence("limitation: .htaccess files are not scanned; per-directory php_value/php_flag overrides may apply")
		if c.discoverAndParseApacheConfigs(inst) {
			locatedAnyConfig = true
		}
	}

	// Finalize state rules (Task 7).
	if !locatedAnyConfig {
		clear(inst.IniSettings)
		inst.ConfigFiles = nil
		if len(unconfirmedGuesses) > 0 {
			for _, u := range unconfirmedGuesses {
				inst.AddEvidence(fmt.Sprintf("present but not confirmed as loaded: %s", u))
			}
		} else {
			inst.AddEvidence("config path not found")
		}
		return
	}

	// Ensure ConfigFiles is non-empty when a config directory was confirmed as loaded (even if conf.d had 0 .ini files).
	if len(inst.ConfigFiles) == 0 {
		switch {
		case len(stage2ScanDirs) > 0:
			inst.AddConfigFile("/" + stage2ScanDirs[0])
		case infoRes.ConfigFilePath != "":
			inst.AddConfigFile("/" + toFSPath(infoRes.ConfigFilePath))
		case isUsrLocalPrefix:
			inst.AddConfigFile("/usr/local/etc/php")
		}
	}

	// Populate built-in default ("1" = enabled) for any required setting that remained unset after parsing config files.
	if _, ok := inst.IniSettings["session.upload_progress.enabled"]; !ok {
		inst.SetIniSetting("session.upload_progress.enabled", "1", "built-in default")
	}
	if branch == "8.5" {
		if _, ok := inst.IniSettings["fatal_error_backtraces"]; !ok {
			inst.SetIniSetting("fatal_error_backtraces", "1", "built-in default")
		}
	}
}

func (c *HostCollector) discoverAndParseFPMPools(
	inst *inventory.PHPInstall,
	branch, prefix string,
	isSystemPrefix, isUsrLocalPrefix, isVendorOptPrefix bool,
) bool {
	var fpmConfCandidates []string
	if prefix != "" && !isSystemPrefix {
		fpmConfCandidates = append(fpmConfCandidates, path.Join(toFSPath(prefix), "etc/php-fpm.conf"))
	}
	if isUsrLocalPrefix {
		fpmConfCandidates = append(fpmConfCandidates, "usr/local/etc/php-fpm.conf")
	}
	if isSystemPrefix {
		if branch != "" {
			compact := strings.ReplaceAll(branch, ".", "")
			fpmConfCandidates = append(fpmConfCandidates,
				fmt.Sprintf("etc/php/%s/fpm/php-fpm.conf", branch),
				fmt.Sprintf("etc/php%s/php-fpm.conf", compact),
			)
		}
		fpmConfCandidates = append(fpmConfCandidates,
			"etc/php-fpm.conf",
			"usr/local/etc/php-fpm.conf",
		)
	}
	if (isVendorOptPrefix || isSystemPrefix) && branch != "" {
		compact := strings.ReplaceAll(branch, ".", "")
		fpmConfCandidates = append(fpmConfCandidates,
			fmt.Sprintf("etc/opt/remi/php%s/php-fpm.conf", compact),
			fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php-fpm.conf", compact),
			fmt.Sprintf("opt/alt/php%s/etc/php-fpm.conf", compact),
		)
	}

	var allPools []string
	seenPools := make(map[string]bool)
	addPool := func(name string) {
		if name == "" || strings.EqualFold(name, "global") {
			return
		}
		if !seenPools[name] {
			seenPools[name] = true
			allPools = append(allPools, name)
		}
	}
	var allSettings []FPMPoolSetting
	seenPoolFiles := make(map[string]bool)
	located := false

	parsePoolFile := func(rel string) (FPMPoolParseResult, bool) {
		resolvedRel, escaped, err := c.resolveRelPath(rel)
		if escaped {
			inst.AddEvidence(fmt.Sprintf("symlink_rejected: /%s escapes root", rel))
			return FPMPoolParseResult{}, false
		}
		if err != nil {
			if isPermissionError(err) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: open /%s: %v", rel, err))
			}
			return FPMPoolParseResult{}, false
		}
		if seenPoolFiles[resolvedRel] {
			return FPMPoolParseResult{}, false
		}
		f, openErr := c.fsys.Open(resolvedRel)
		if openErr != nil {
			if isPermissionError(openErr) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: open /%s: %v", resolvedRel, openErr))
			}
			return FPMPoolParseResult{}, false
		}
		defer func() { _ = f.Close() }()

		seenPoolFiles[resolvedRel] = true
		abs := "/" + strings.TrimPrefix(resolvedRel, "/")
		inst.AddConfigFile(abs)
		res, parseErr := ParseFPMPoolConfig(f, abs)
		if parseErr != nil {
			if isPermissionError(parseErr) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", abs, parseErr))
			}
			return FPMPoolParseResult{}, false
		}
		for _, p := range res.Pools {
			addPool(p)
		}
		allSettings = append(allSettings, res.Settings...)
		return res, true
	}

	var activeIncludes []string
	var foundFPMConfRel string
	for _, cand := range fpmConfCandidates {
		if !c.fileExistsInFS(cand) {
			continue
		}
		if res, ok := parsePoolFile(cand); ok {
			located = true
			foundFPMConfRel = cand
			activeIncludes = res.Includes
			break
		}
	}

	if len(activeIncludes) > 0 {
		for _, inc := range activeIncludes {
			var patterns []string
			if strings.HasPrefix(inc, "/") {
				patterns = append(patterns, toFSPath(inc))
			} else {
				if prefix != "" && prefix != "/" {
					patterns = append(patterns, path.Join(toFSPath(prefix), inc))
				}
				if foundFPMConfRel != "" {
					patterns = append(patterns, path.Join(path.Dir(foundFPMConfRel), inc))
				}
			}
			for _, pat := range patterns {
				matches, err := fs.Glob(c.fsys, pat)
				if err != nil || len(matches) == 0 {
					continue
				}
				sort.Strings(matches)
				for _, m := range matches {
					if _, ok := parsePoolFile(m); ok {
						located = true
					}
				}
				break
			}
		}
	} else {
		// Task 5: If php-fpm.conf is missing or has no active include, fall back to <prefix>/etc/php-fpm.d/*.conf
		// (or distro default pool.d) and note 'pool dir found by default location'.
		var fallbackGlobs []string
		if prefix != "" && !isSystemPrefix {
			fallbackGlobs = append(fallbackGlobs, path.Join(toFSPath(prefix), "etc/php-fpm.d/*.conf"))
		}
		if isUsrLocalPrefix {
			fallbackGlobs = append(fallbackGlobs, "usr/local/etc/php-fpm.d/*.conf")
		}
		if isSystemPrefix {
			if branch != "" {
				compact := strings.ReplaceAll(branch, ".", "")
				fallbackGlobs = append(fallbackGlobs,
					fmt.Sprintf("etc/php/%s/fpm/pool.d/*.conf", branch),
					fmt.Sprintf("etc/php%s/php-fpm.d/*.conf", compact),
				)
			}
			fallbackGlobs = append(fallbackGlobs,
				"etc/php-fpm.d/*.conf",
				"usr/local/etc/php-fpm.d/*.conf",
			)
		}
		if (isVendorOptPrefix || isSystemPrefix) && branch != "" {
			compact := strings.ReplaceAll(branch, ".", "")
			fallbackGlobs = append(fallbackGlobs,
				fmt.Sprintf("etc/opt/remi/php%s/php-fpm.d/*.conf", compact),
				fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php-fpm.d/*.conf", compact),
				fmt.Sprintf("opt/alt/php%s/etc/php-fpm.d/*.conf", compact),
			)
		}

		for _, pat := range fallbackGlobs {
			matches, err := fs.Glob(c.fsys, pat)
			if err != nil || len(matches) == 0 {
				continue
			}
			sort.Strings(matches)
			inst.AddEvidence("pool dir found by default location")
			for _, m := range matches {
				if _, ok := parsePoolFile(m); ok {
					located = true
				}
			}
			break
		}
	}

	if len(allPools) == 0 && len(allSettings) == 0 {
		return located
	}

	trackedKeys := []string{"session.upload_progress.enabled", "fatal_error_backtraces"}
	for _, key := range trackedKeys {
		var keySettings []FPMPoolSetting
		for _, s := range allSettings {
			if s.Key == key {
				keySettings = append(keySettings, s)
			}
		}
		if len(keySettings) == 0 {
			continue
		}

		baseVal := "1"
		if existing, ok := inst.IniSettings[key]; ok && existing != "" {
			baseVal = existing
		}

		poolVal := make(map[string]string, len(allPools))
		poolOrigin := make(map[string]string, len(allPools))
		for _, p := range allPools {
			poolVal[p] = baseVal
		}

		for _, s := range keySettings {
			poolVal[s.Pool] = s.Value
			poolOrigin[s.Pool] = fmt.Sprintf("%s (%s) at %s:%d", s.File, s.Directive, s.File, s.Line)
		}

		var offendingPools []string
		var lastDisabledOrigin string
		var firstEnabledOrigin string

		for _, p := range allPools {
			if poolVal[p] == "0" {
				if orig := poolOrigin[p]; orig != "" {
					lastDisabledOrigin = orig
				}
			} else {
				offendingPools = append(offendingPools, p)
				if firstEnabledOrigin == "" {
					if orig := poolOrigin[p]; orig != "" {
						firstEnabledOrigin = orig
					} else {
						firstEnabledOrigin = fmt.Sprintf("pool [%s] (inherits enabled setting)", p)
					}
				}
			}
		}

		switch {
		case len(offendingPools) == 0:
			inst.SetIniSetting(key, "0", lastDisabledOrigin)
		case len(allPools) == 1:
			inst.SetIniSetting(key, "1", firstEnabledOrigin)
		default:
			bracketed := make([]string, len(offendingPools))
			for i, p := range offendingPools {
				bracketed[i] = "[" + p + "]"
			}
			inst.SetIniSetting(key, "1", fmt.Sprintf("%s (offending pool: %s)", firstEnabledOrigin, strings.Join(bracketed, ", ")))
		}
	}

	return located
}

func (c *HostCollector) discoverAndParseApacheConfigs(inst *inventory.PHPInstall) bool {
	seen := make(map[string]bool)
	located := false

	for _, pat := range ApacheConfGlobs() {
		matches, err := fs.Glob(c.fsys, pat)
		if err != nil {
			if isPermissionError(err) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: glob /%s: %v", pat, err))
			}
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			resolvedRel, escaped, resErr := c.resolveRelPath(m)
			if escaped {
				inst.AddEvidence(fmt.Sprintf("symlink_rejected: /%s escapes root", m))
				continue
			}
			if resErr != nil || seen[resolvedRel] {
				continue
			}
			f, openErr := c.fsys.Open(resolvedRel)
			if openErr != nil {
				if isPermissionError(openErr) {
					inst.AddEvidence(fmt.Sprintf("permission_denied: open /%s: %v", resolvedRel, openErr))
				}
				continue
			}
			seen[resolvedRel] = true
			located = true
			abs := "/" + strings.TrimPrefix(resolvedRel, "/")
			inst.AddConfigFile(abs)
			if parseErr := ParseApacheConfigReader(f, abs, inst); parseErr != nil && isPermissionError(parseErr) {
				inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", abs, parseErr))
			}
			_ = f.Close()
		}
	}
	return located
}

func (c *HostCollector) parseStaticIniGlobTracked(pattern string, inst *inventory.PHPInstall, seen map[string]bool) {
	matches, err := fs.Glob(c.fsys, pattern)
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: glob /%s: %v", pattern, err))
		}
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		c.parseStaticIniFileTracked(m, inst, seen)
	}
}

func (c *HostCollector) parseStaticIniFileTracked(relPath string, inst *inventory.PHPInstall, seen map[string]bool) {
	if relPath == "" {
		return
	}
	resolvedRel, escaped, err := c.resolveRelPath(relPath)
	if escaped {
		inst.AddEvidence(fmt.Sprintf("symlink_rejected: /%s escapes root", relPath))
		return
	}
	if err != nil {
		if isPermissionError(err) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: open /%s: %v", relPath, err))
		}
		return
	}
	if seen[resolvedRel] {
		return
	}

	absPath := "/" + strings.TrimPrefix(resolvedRel, "/")
	f, openErr := c.fsys.Open(resolvedRel)
	if openErr != nil {
		if isPermissionError(openErr) {
			inst.AddEvidence(fmt.Sprintf("permission_denied: open %s: %v", absPath, openErr))
		}
		return
	}
	defer func() { _ = f.Close() }()

	seen[resolvedRel] = true
	seen[relPath] = true
	if resolvedRel != relPath {
		inst.AddEvidence(fmt.Sprintf("symlink: /%s -> %s", strings.TrimPrefix(relPath, "/"), absPath))
	}
	inst.AddConfigFile(absPath)
	if parseErr := ParseIniReader(f, absPath, inst); parseErr != nil && isPermissionError(parseErr) {
		inst.AddEvidence(fmt.Sprintf("permission_denied: read %s: %v", absPath, parseErr))
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

	var branch string
	if parsedVer, verErr := phpver.Parse(upstreamVer); verErr == nil {
		branch = parsedVer.Branch
	}
	c.discoverConfigsForInstall(ctx, &inst, branch, absPath)

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

func (c *HostCollector) resolveRelPath(relPath string) (string, bool, error) {
	return ResolvePathInFS(c.fsys, relPath, c.useHostEvalSymlinks)
}

// ResolvePathInFS resolves symlinks for relPath inside fsys, rejecting any symlink target
// that escapes the root directory (returning escaped=true and ErrSymlinkEscape).
func ResolvePathInFS(fsys fs.FS, relPath string, useHostEvalSymlinks bool) (string, bool, error) {
	if useHostEvalSymlinks {
		abs := "/" + strings.TrimPrefix(relPath, "/")
		if resolvedAbs, err := filepath.EvalSymlinks(abs); err == nil {
			return toFSPath(filepath.ToSlash(resolvedAbs)), false, nil
		}
	}

	type readLinkFS interface {
		ReadLink(name string) (string, error)
	}
	rlFS, hasReadLink := fsys.(readLinkFS)

	queue := strings.Split(strings.TrimPrefix(strings.ReplaceAll(relPath, `\`, "/"), "/"), "/")
	var stack []string
	hops := 0

	for len(queue) > 0 {
		seg := queue[0]
		queue = queue[1:]

		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			if len(stack) == 0 {
				return "", true, ErrSymlinkEscape
			}
			stack = stack[:len(stack)-1]
			continue
		}

		candidate := seg
		if len(stack) > 0 {
			candidate = strings.Join(stack, "/") + "/" + seg
		}

		var linkTarget string
		isLink := false

		if hasReadLink {
			if t, err := rlFS.ReadLink(candidate); err == nil && t != "" {
				linkTarget = t
				isLink = true
			}
		}
		if !isLink {
			info, err := fs.Stat(fsys, candidate)
			if err != nil {
				if len(queue) == 0 && isPermissionError(err) {
					return candidate, false, err
				}
				stack = append(stack, seg)
				continue
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				if data, readErr := fs.ReadFile(fsys, candidate); readErr == nil {
					linkTarget = strings.TrimSpace(string(data))
					isLink = linkTarget != ""
				}
			}
		}

		if isLink {
			hops++
			if hops > 40 {
				return "", false, errors.New("too many symlink hops")
			}
			normTarget := strings.ReplaceAll(linkTarget, `\`, "/")
			if strings.HasPrefix(normTarget, "/") {
				stack = nil
				targetSegs := strings.Split(strings.TrimPrefix(normTarget, "/"), "/")
				queue = append(targetSegs, queue...)
			} else {
				targetSegs := strings.Split(normTarget, "/")
				queue = append(targetSegs, queue...)
			}
			continue
		}

		stack = append(stack, seg)
	}

	if len(stack) == 0 {
		return "", false, nil
	}
	return strings.Join(stack, "/"), false, nil
}

func (c *HostCollector) fileExistsInFS(relPath string) bool {
	if relPath == "" {
		return false
	}
	resolvedRel, escaped, err := c.resolveRelPath(relPath)
	if escaped || err != nil || resolvedRel == "" {
		return false
	}
	info, statErr := fs.Stat(c.fsys, resolvedRel)
	if statErr != nil {
		// In permDenyFS tests, a permission error on Open still means the path exists on disk.
		return isPermissionError(statErr)
	}
	return !info.IsDir()
}

func (c *HostCollector) dirExistsInFS(relPath string) bool {
	if relPath == "" {
		return false
	}
	resolvedRel, escaped, err := c.resolveRelPath(relPath)
	if escaped || err != nil || resolvedRel == "" {
		return false
	}
	info, statErr := fs.Stat(c.fsys, resolvedRel)
	if statErr != nil {
		return false
	}
	return info.IsDir()
}

func debianSAPIDir(sapi inventory.SAPI) string {
	switch sapi {
	case inventory.SAPICLI:
		return "cli"
	case inventory.SAPIFPM:
		return "fpm"
	case inventory.SAPIApache2Handler:
		return "apache2"
	case inventory.SAPICGI:
		return "cgi"
	default:
		return ""
	}
}

// isCLIOnlyConfigPath reports whether p is a CLI-specific config path that must never
// count for fpm or apache2handler (Task 7).
func isCLIOnlyConfigPath(p string, sapi inventory.SAPI) bool {
	if sapi == inventory.SAPICLI {
		return false
	}
	norm := "/" + strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "/")
	return strings.Contains(norm, "/cli/") || strings.HasSuffix(norm, "/cli") || strings.HasSuffix(norm, "/php-cli.ini")
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
