package image

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// ErrOfflineRemoteImage indicates that a remote image pull was blocked by --offline.
var ErrOfflineRemoteImage = errors.New("cannot pull remote container image in --offline mode")

// Options configures container image inspection.
type Options struct {
	Offline       bool
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// Collector inspects container images (tarballs, OCI directories, or remote references)
// in strictly read-only mode without executing any image binaries.
type Collector struct {
	opts Options
}

// NewCollector constructs an image Collector with the provided options.
func NewCollector(opts Options) *Collector {
	return &Collector{opts: opts}
}

// Collect loads the target image and inspects its flattened filesystem and metadata.
func (c *Collector) Collect(ctx context.Context, target string) ([]inventory.PHPInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image collect context: %w", err)
	}

	img, cleanup, err := c.loadImage(ctx, target)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}

	return c.InspectImage(ctx, img, target)
}

func (c *Collector) loadImage(ctx context.Context, target string) (v1.Image, func(), error) {
	info, statErr := os.Stat(target)
	if statErr == nil {
		if info.IsDir() {
			img, err := loadOCILayoutImage(target)
			return img, nil, err
		}
		img, err := tarball.ImageFromPath(target, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("load docker tarball %q: %w", target, err)
		}
		return img, nil, nil
	}

	// Check local Docker daemon (supports local tags like lab/php-8.3.35-mitigated:latest and short/full IDs like 67ae1e29017f).
	if img, cleanup, ok := loadFromLocalDockerDaemon(ctx, target); ok {
		return img, cleanup, nil
	}

	if c.opts.Offline {
		return nil, nil, fmt.Errorf("load %q: %w", target, ErrOfflineRemoteImage)
	}

	if isBareHexImageID(target) {
		return nil, nil, fmt.Errorf("image ID %q not found in local Docker daemon", target)
	}

	ref, err := name.ParseReference(target)
	if err != nil {
		return nil, nil, fmt.Errorf("parse image reference %q: %w", target, err)
	}

	img, err := remote.Image(
		ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("pull remote image %q: %w", target, err)
	}
	return img, nil, nil
}

func loadFromLocalDockerDaemon(ctx context.Context, target string) (v1.Image, func(), bool) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" || strings.HasPrefix(trimmed, "-") {
		return nil, nil, false
	}

	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return nil, nil, false
	}
	absDocker, err := filepath.Abs(dockerPath)
	if err != nil {
		return nil, nil, false
	}

	inspectCtx, inspectCancel := context.WithTimeout(ctx, 5*time.Second)
	defer inspectCancel()

	inspectCmd := exec.CommandContext(inspectCtx, absDocker, "image", "inspect", "--format", "{{.Id}}", "--", trimmed)
	if runErr := inspectCmd.Run(); runErr != nil {
		return nil, nil, false
	}

	tmpFile, err := os.CreateTemp("", "php2shell-docker-image-*.tar")
	if err != nil {
		return nil, nil, false
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	cleanup := func() {
		_ = os.Remove(tmpPath)
	}

	saveCtx, saveCancel := context.WithTimeout(ctx, 60*time.Second)
	defer saveCancel()

	saveCmd := exec.CommandContext(saveCtx, absDocker, "image", "save", "-o", tmpPath, "--", trimmed)
	if saveErr := saveCmd.Run(); saveErr != nil {
		cleanup()
		return nil, nil, false
	}

	img, err := tarball.ImageFromPath(tmpPath, nil)
	if err != nil {
		cleanup()
		return nil, nil, false
	}
	return img, cleanup, true
}

func isBareHexImageID(s string) bool {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:")
	if len(trimmed) < 12 || len(trimmed) > 64 {
		return false
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func loadOCILayoutImage(dirPath string) (v1.Image, error) {
	ociLayoutFile := filepath.Join(dirPath, "oci-layout")
	if _, err := os.Stat(ociLayoutFile); err != nil {
		return nil, fmt.Errorf("directory %q is not a valid OCI layout: %w", dirPath, err)
	}
	idx, err := layout.ImageIndexFromPath(dirPath)
	if err != nil {
		return nil, fmt.Errorf("read OCI image index %q: %w", dirPath, err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read OCI index manifest %q: %w", dirPath, err)
	}
	for _, desc := range manifest.Manifests {
		img, imgErr := idx.Image(desc.Digest)
		if imgErr == nil {
			return img, nil
		}
	}
	return nil, fmt.Errorf("no runnable image manifest found in OCI layout %q", dirPath)
}

// InspectImage inspects an already-loaded v1.Image without executing anything from it.
func (c *Collector) InspectImage(ctx context.Context, img v1.Image, imageRef string) ([]inventory.PHPInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("inspect image context: %w", err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}

	flat, err := FlattenLayers(layers, FlattenOptions{
		MaxFileBytes:  c.opts.MaxFileBytes,
		MaxTotalBytes: c.opts.MaxTotalBytes,
	})
	if err != nil {
		return nil, err
	}

	distro := detectImageDistro(flat)
	sapiHint, sapiEv := inferImageSAPI(cfgFile, flat)

	var installs []inventory.PHPInstall

	// 1. Check source-built / official PHP image indicators (/usr/local/include/php/main/php_version.h, ENV PHP_VERSION, /usr/local/bin/php).
	if srcInst, ok := c.detectSourceBuiltPHP(flat, cfgFile, distro, sapiHint, sapiEv); ok {
		installs = append(installs, srcInst)
	}

	// 2. Check dpkg and apk package databases.
	pkgInstalls := c.detectPackageManagedPHP(flat, distro)
	installs = append(installs, pkgInstalls...)

	// 3. Check for unsupported RPM databases if no package-managed or source-built install covered it.
	if rpmPath, hasRPM := hasRPMDatabase(flat); hasRPM && len(pkgInstalls) == 0 {
		rpmInst := inventory.PHPInstall{
			ID:             inventory.ComputeID(inventory.SourceImage, sapiHint, imageRef+":rpm"),
			BinaryPath:     findFirstPHPBinary(flat),
			PackageManager: "rpm",
			Distro:         distro,
			SAPI:           sapiHint,
			Source:         inventory.SourceImage,
			Confidence:     inventory.ConfidenceLow,
			Evidence: []string{
				fmt.Sprintf("rpm_db_unsupported: /%s present; offline RPM database parsing is unsupported without guessing", rpmPath),
			},
		}
		parseAllImageStaticConfigs(flat, "", &rpmInst)
		installs = append(installs, rpmInst)
	}

	return installs, nil
}

func detectImageDistro(flat *FlatFS) inventory.Distro {
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		if r, ok := flat.Reader(rel); ok {
			if d, err := local.ParseOSRelease(r); err == nil && d.ID != "" {
				return d
			}
		}
	}
	return inventory.Distro{}
}

func inferImageSAPI(cfg *v1.ConfigFile, flat *FlatFS) (inventory.SAPI, string) {
	if cfg != nil {
		tokens := append([]string{}, cfg.Config.Entrypoint...)
		tokens = append(tokens, cfg.Config.Cmd...)
		joined := strings.ToLower(strings.Join(tokens, " "))
		switch {
		case strings.Contains(joined, "frankenphp"):
			return inventory.SAPIFrankenPHP, fmt.Sprintf("image_cmd: %s", strings.Join(tokens, " "))
		case strings.Contains(joined, "php-fpm"):
			return inventory.SAPIFPM, fmt.Sprintf("image_cmd: %s", strings.Join(tokens, " "))
		case strings.Contains(joined, "apache2") || strings.Contains(joined, "httpd"):
			return inventory.SAPIApache2Handler, fmt.Sprintf("image_cmd: %s", strings.Join(tokens, " "))
		}
	}

	for p := range flat.Files {
		base := strings.ToLower(path.Base(p))
		switch {
		case strings.Contains(base, "frankenphp"):
			return inventory.SAPIFrankenPHP, fmt.Sprintf("file_presence: /%s", p)
		case strings.HasPrefix(base, "php-fpm"):
			return inventory.SAPIFPM, fmt.Sprintf("file_presence: /%s", p)
		case strings.HasPrefix(base, "libphp") && strings.HasSuffix(base, ".so"):
			return inventory.SAPIApache2Handler, fmt.Sprintf("file_presence: /%s", p)
		}
	}

	return inventory.SAPICLI, ""
}

func (c *Collector) detectSourceBuiltPHP(
	flat *FlatFS,
	cfg *v1.ConfigFile,
	distro inventory.Distro,
	sapiHint inventory.SAPI,
	sapiEv string,
) (inventory.PHPInstall, bool) {
	var version string
	var evidence []string

	// Check /usr/local/include/php/main/php_version.h
	const headerPath = "usr/local/include/php/main/php_version.h"
	if data, ok := flat.Files[headerPath]; ok {
		if v, okVer := ParsePHPVersionHeader(data); okVer {
			version = v
			evidence = append(evidence, fmt.Sprintf("php_version_h: /%s => %s", headerPath, v))
		}
	}

	// Check ENV PHP_VERSION in image config
	if cfg != nil {
		for _, envEntry := range cfg.Config.Env {
			if k, v, ok := strings.Cut(envEntry, "="); ok && k == "PHP_VERSION" {
				if parsed, err := phpver.Parse(strings.TrimSpace(v)); err == nil {
					norm := fmt.Sprintf("%d.%d.%d%s", parsed.Major, parsed.Minor, parsed.Patch, parsed.PreRelease)
					if version == "" {
						version = norm
					}
					evidence = append(evidence, fmt.Sprintf("image_env: PHP_VERSION=%s", v))
				}
			}
		}
	}

	// Check binary byte scan for /usr/local/bin/php, /usr/local/sbin/php-fpm, or /usr/local/bin/frankenphp
	binCandidates := []string{
		"usr/local/sbin/php-fpm",
		"usr/local/bin/frankenphp",
		"usr/local/bin/php",
		"usr/lib/apache2/modules/libphp.so",
	}
	var primaryPath string
	for _, cand := range binCandidates {
		data, ok := flat.Files[cand]
		if !ok {
			continue
		}
		if primaryPath == "" {
			primaryPath = "/" + cand
		}
		if scannedVer, matched, err := local.ScanModuleBytes(bytes.NewReader(data), c.opts.MaxFileBytes); err == nil {
			if version == "" {
				version = scannedVer
			}
			evidence = append(evidence, fmt.Sprintf("binary_bytes: /%s => %s", cand, matched))
		}
	}

	if version == "" {
		return inventory.PHPInstall{}, false
	}

	if primaryPath == "" {
		primaryPath = "/" + headerPath
	}
	if sapiEv != "" {
		evidence = append(evidence, sapiEv)
	}

	inst := inventory.PHPInstall{
		ID:              inventory.ComputeID(inventory.SourceImage, sapiHint, primaryPath),
		BinaryPath:      primaryPath,
		UpstreamVersion: version,
		Distro:          distro,
		SAPI:            sapiHint,
		IniSettings:     make(map[string]string),
		Source:          inventory.SourceImage,
		Confidence:      inventory.ConfidenceHigh,
		Evidence:        evidence,
	}

	var branch string
	if parsed, err := phpver.Parse(version); err == nil {
		branch = parsed.Branch
	}
	parseAllImageStaticConfigs(flat, branch, &inst)

	// In official /usr/local PHP images, if no php.ini or conf.d/*.ini overrode the compiled-in
	// defaults, record PHP's default values so unmitigated images report NOT_APPLIED rather than UNKNOWN.
	if _, ok := inst.IniSettings["session.upload_progress.enabled"]; !ok {
		inst.SetIniSetting("session.upload_progress.enabled", "1", "/usr/local/etc/php (PHP compiled-in default)")
	}
	if branch == "8.5" {
		if _, ok := inst.IniSettings["fatal_error_backtraces"]; !ok {
			inst.SetIniSetting("fatal_error_backtraces", "1", "/usr/local/etc/php (PHP compiled-in default)")
		}
	}

	return inst, true
}

func (c *Collector) detectPackageManagedPHP(flat *FlatFS, distro inventory.Distro) []inventory.PHPInstall {
	var records []PackageRecord

	if data, ok := flat.Files["var/lib/dpkg/status"]; ok {
		records = append(records, ParseDpkgStatus(data, "/var/lib/dpkg/status")...)
	}
	for _, p := range flat.SortedPathsWithPrefix("var/lib/dpkg/status.d/") {
		records = append(records, ParseDpkgStatus(flat.Files[p], "/"+p)...)
	}
	if data, ok := flat.Files["lib/apk/db/installed"]; ok {
		records = append(records, ParseApkInstalled(data, "/lib/apk/db/installed")...)
	}

	var installs []inventory.PHPInstall
	for _, rec := range records {
		inst := inventory.PHPInstall{
			ID:              inventory.ComputeID(inventory.SourceImage, rec.SAPI, rec.Name+"@"+rec.Version),
			UpstreamVersion: rec.UpstreamVersion,
			PackageManager:  rec.Manager,
			PackageName:     rec.Name,
			PackageVersion:  rec.Version,
			Distro:          distro,
			SAPI:            rec.SAPI,
			IniSettings:     make(map[string]string),
			Source:          inventory.SourceImage,
			Confidence:      inventory.ConfidenceHigh,
			Evidence: []string{
				fmt.Sprintf("pkg_db: %s => %s %s (%s)", rec.SourceFile, rec.Name, rec.Version, rec.Manager),
			},
		}

		var branch string
		if parsed, err := phpver.Parse(rec.UpstreamVersion); err == nil {
			branch = parsed.Branch
		}
		parseAllImageStaticConfigs(flat, branch, &inst)
		installs = append(installs, inst)
	}

	return installs
}

func parseAllImageStaticConfigs(flat *FlatFS, branch string, inst *inventory.PHPInstall) {
	// Parse active /usr/local/etc/php/php.ini and distro /etc/php configs (never parse inactive php.ini-production templates).
	iniCandidates := []string{
		"usr/local/etc/php/php.ini",
		"etc/php.ini",
	}
	if branch != "" {
		switch inst.SAPI {
		case inventory.SAPIFPM:
			iniCandidates = append(iniCandidates, fmt.Sprintf("etc/php/%s/fpm/php.ini", branch))
		case inventory.SAPIApache2Handler:
			iniCandidates = append(iniCandidates, fmt.Sprintf("etc/php/%s/apache2/php.ini", branch))
		case inventory.SAPICLI:
			iniCandidates = append(iniCandidates, fmt.Sprintf("etc/php/%s/cli/php.ini", branch))
		default:
			iniCandidates = append(iniCandidates,
				fmt.Sprintf("etc/php/%s/fpm/php.ini", branch),
				fmt.Sprintf("etc/php/%s/apache2/php.ini", branch),
				fmt.Sprintf("etc/php/%s/cli/php.ini", branch),
			)
		}
	}

	for _, rel := range iniCandidates {
		if r, ok := flat.Reader(rel); ok {
			abs := "/" + rel
			inst.AddConfigFile(abs)
			_ = local.ParseIniReader(r, abs, inst)
		}
	}

	iniPrefixes := []string{
		"usr/local/etc/php/conf.d/",
		"etc/php.d/",
	}
	if branch != "" {
		switch inst.SAPI {
		case inventory.SAPIFPM:
			iniPrefixes = append(iniPrefixes, fmt.Sprintf("etc/php/%s/fpm/conf.d/", branch))
		case inventory.SAPIApache2Handler:
			iniPrefixes = append(iniPrefixes, fmt.Sprintf("etc/php/%s/apache2/conf.d/", branch))
		case inventory.SAPICLI:
			iniPrefixes = append(iniPrefixes, fmt.Sprintf("etc/php/%s/cli/conf.d/", branch))
		default:
			iniPrefixes = append(iniPrefixes,
				fmt.Sprintf("etc/php/%s/fpm/conf.d/", branch),
				fmt.Sprintf("etc/php/%s/apache2/conf.d/", branch),
				fmt.Sprintf("etc/php/%s/cli/conf.d/", branch),
			)
		}
	}

	for _, pref := range iniPrefixes {
		for _, rel := range flat.SortedPathsWithPrefix(pref) {
			if !strings.HasSuffix(rel, ".ini") {
				continue
			}
			if r, ok := flat.Reader(rel); ok {
				abs := "/" + rel
				inst.AddConfigFile(abs)
				_ = local.ParseIniReader(r, abs, inst)
			}
		}
	}

	poolPrefixes := []string{
		"usr/local/etc/php-fpm.d/",
		"etc/php-fpm.d/",
	}
	if branch != "" {
		poolPrefixes = append(poolPrefixes, fmt.Sprintf("etc/php/%s/fpm/pool.d/", branch))
	}

	for _, pref := range poolPrefixes {
		for _, rel := range flat.SortedPathsWithPrefix(pref) {
			if !strings.HasSuffix(rel, ".conf") {
				continue
			}
			if r, ok := flat.Reader(rel); ok {
				abs := "/" + rel
				inst.AddConfigFile(abs)
				_ = local.ParseFPMPoolReader(r, abs, inst)
			}
		}
	}
}

func hasRPMDatabase(flat *FlatFS) (string, bool) {
	rpmPaths := []string{
		"var/lib/rpm/rpmdb.sqlite",
		"var/lib/rpm/Packages",
		"var/lib/rpm/Packages.db",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
	}
	for _, p := range rpmPaths {
		if _, ok := flat.Files[p]; ok {
			return p, true
		}
	}
	return "", false
}

func findFirstPHPBinary(flat *FlatFS) string {
	for _, p := range []string{"usr/sbin/php-fpm", "usr/bin/php", "usr/local/bin/php"} {
		if _, ok := flat.Files[p]; ok {
			return "/" + p
		}
	}
	return "/usr/bin/php"
}
