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

	var digestStr string
	if d, dErr := img.Digest(); dErr == nil {
		digestStr = d.String()
	}

	var platform string
	if cfgFile != nil {
		switch {
		case cfgFile.OS != "" && cfgFile.Architecture != "":
			platform = fmt.Sprintf("%s/%s", cfgFile.OS, cfgFile.Architecture)
		case cfgFile.OS != "":
			platform = cfgFile.OS
		case cfgFile.Architecture != "":
			platform = cfgFile.Architecture
		}
	}

	resolvedFromTag := inventory.IsFloatingTag(imageRef)
	distro := detectImageDistro(flat)
	sapiHint, sapiEv := inferImageSAPI(cfgFile, flat)

	var installs []inventory.PHPInstall

	// 1. Check source-built / official PHP image indicators (/usr/local/include/php/main/php_version.h, ENV PHP_VERSION, /usr/local/bin/php).
	if srcInstalls, ok := c.detectSourceBuiltPHP(flat, cfgFile, distro, sapiHint, sapiEv); ok {
		installs = append(installs, srcInstalls...)
	}

	// 2. Check dpkg and apk package databases.
	pkgInstalls := c.detectPackageManagedPHP(flat, distro)
	installs = append(installs, pkgInstalls...)

	// 3. Check for unsupported RPM databases if no package-managed or source-built install covered it.
	if rpmPath, hasRPM := hasRPMDatabase(flat); hasRPM && len(pkgInstalls) == 0 {
		binPath := findFirstPHPBinary(flat)
		rpmInst := inventory.PHPInstall{
			ID:             inventory.ComputeID(inventory.SourceImage, sapiHint, imageRef+":rpm"),
			BinaryPath:     binPath,
			PackageManager: "rpm",
			Distro:         distro,
			SAPI:           sapiHint,
			Source:         inventory.SourceImage,
			Confidence:     inventory.ConfidenceLow,
			Evidence: []string{
				fmt.Sprintf("rpm_db_unsupported: /%s present; offline RPM database parsing is unsupported without guessing", rpmPath),
			},
		}
		local.DiscoverStaticConfigs(flat, &rpmInst, "", binPath)
		installs = append(installs, rpmInst)
	}

	for i := range installs {
		installs[i].ImageRef = imageRef
		installs[i].ImageDigest = digestStr
		installs[i].Platform = platform
		installs[i].ResolvedFromTag = resolvedFromTag
		installs[i].SplitEvidence()
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
) ([]inventory.PHPInstall, bool) {
	var version string
	var evidence []string

	// Check /usr/local/include/php/main/php_version.h and /opt/php/*/include/php/main/php_version.h
	headerCandidates := []string{"usr/local/include/php/main/php_version.h"}
	for _, p := range flat.SortedPathsWithPrefix("opt/php/") {
		if strings.HasSuffix(p, "/include/php/main/php_version.h") {
			headerCandidates = append(headerCandidates, p)
		}
	}
	var matchedHeaderPath string
	for _, hp := range headerCandidates {
		if data, ok := flat.Files[hp]; ok {
			if v, okVer := ParsePHPVersionHeader(data); okVer {
				version = v
				matchedHeaderPath = hp
				evidence = append(evidence, fmt.Sprintf("php_version_h: /%s => %s", hp, v))
				break
			}
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

	// Check binary byte scan for /usr/local/bin/php, /usr/local/sbin/php-fpm, /usr/local/bin/frankenphp, or /opt/php/*
	binCandidates := []string{
		"usr/local/sbin/php-fpm",
		"usr/local/bin/frankenphp",
		"usr/local/bin/php",
		"usr/lib/apache2/modules/libphp.so",
	}
	for _, p := range flat.SortedPathsWithPrefix("opt/php/") {
		if strings.HasSuffix(p, "/sbin/php-fpm") || strings.HasSuffix(p, "/bin/php") {
			binCandidates = append(binCandidates, p)
		}
	}

	var primaryPath string
	seenResolvedBin := make(map[string]bool)
	for _, cand := range binCandidates {
		resolvedRel, escaped, resErr := local.ResolvePathInFS(flat, cand, false)
		if escaped || resErr != nil || resolvedRel == "" {
			continue
		}
		data, ok := flat.Files[resolvedRel]
		if !ok {
			continue
		}
		if primaryPath == "" {
			primaryPath = "/" + resolvedRel
		}
		if resolvedRel != cand {
			evidence = append(evidence, fmt.Sprintf("found via /%s", cand))
		}
		if seenResolvedBin[resolvedRel] {
			continue
		}
		seenResolvedBin[resolvedRel] = true
		if scannedVer, matched, err := local.ScanModuleBytes(bytes.NewReader(data), c.opts.MaxFileBytes); err == nil {
			if version == "" {
				version = scannedVer
			}
			evidence = append(evidence, fmt.Sprintf("binary_bytes: /%s => %s", resolvedRel, matched))
		}
	}

	if version == "" {
		return nil, false
	}

	if primaryPath == "" {
		if matchedHeaderPath != "" {
			primaryPath = "/" + matchedHeaderPath
		} else {
			primaryPath = "/usr/local/include/php/main/php_version.h"
		}
	}
	if sapiEv != "" {
		evidence = append(evidence, sapiEv)
	}

	var branch string
	if parsed, err := phpver.Parse(version); err == nil {
		branch = parsed.Branch
	}

	isApache := sapiHint == inventory.SAPIApache2Handler || isApacheImage(cfg, flat)
	if isApache {
		var apacheInstalls []inventory.PHPInstall
		cliBinPath := findCLIBinary(flat)
		if cliBinPath != "" {
			cliEvidence := append([]string(nil), evidence...)
			cliInst := inventory.PHPInstall{
				ID:              inventory.ComputeID(inventory.SourceImage, inventory.SAPICLI, cliBinPath),
				BinaryPath:      cliBinPath,
				UpstreamVersion: version,
				Distro:          distro,
				SAPI:            inventory.SAPICLI,
				IniSettings:     make(map[string]string),
				Source:          inventory.SourceImage,
				Confidence:      inventory.ConfidenceHigh,
				Evidence:        cliEvidence,
			}
			local.DiscoverStaticConfigs(flat, &cliInst, branch, cliBinPath)
			apacheInstalls = append(apacheInstalls, cliInst)
		}

		modPath, cfgPath, isFallback := findApacheModuleOrConfig(flat)
		apacheEvidence := append([]string(nil), evidence...)
		apacheTarget := modPath
		if isFallback {
			apacheTarget = cfgPath
			apacheEvidence = append(apacheEvidence, fmt.Sprintf("apache module file not found on disk; discovered via config %s", cfgPath))
		}
		apacheInst := inventory.PHPInstall{
			ID:              inventory.ComputeID(inventory.SourceImage, inventory.SAPIApache2Handler, apacheTarget),
			ModulePath:      apacheTarget,
			UpstreamVersion: version,
			Distro:          distro,
			SAPI:            inventory.SAPIApache2Handler,
			IniSettings:     make(map[string]string),
			Source:          inventory.SourceImage,
			Confidence:      inventory.ConfidenceHigh,
			Evidence:        apacheEvidence,
		}
		local.DiscoverStaticConfigs(flat, &apacheInst, branch, apacheTarget)
		apacheInstalls = append(apacheInstalls, apacheInst)

		return apacheInstalls, true
	}

	targetBin := primaryPath
	effectiveSAPI := sapiHint
	switch sapiHint {
	case inventory.SAPIFPM:
		if fpmBin := findFPMBinary(flat); fpmBin != "" {
			targetBin = fpmBin
		}
	case inventory.SAPIFrankenPHP:
		if frankenBin := findFrankenBinary(flat); frankenBin != "" {
			targetBin = frankenBin
		}
	case inventory.SAPICLI:
		if cliBin := findCLIBinary(flat); cliBin != "" {
			targetBin = cliBin
		}
	}

	inst := inventory.PHPInstall{
		ID:              inventory.ComputeID(inventory.SourceImage, effectiveSAPI, targetBin),
		BinaryPath:      targetBin,
		UpstreamVersion: version,
		Distro:          distro,
		SAPI:            effectiveSAPI,
		IniSettings:     make(map[string]string),
		Source:          inventory.SourceImage,
		Confidence:      inventory.ConfidenceHigh,
		Evidence:        evidence,
	}
	local.DiscoverStaticConfigs(flat, &inst, branch, targetBin)

	return []inventory.PHPInstall{inst}, true
}

func (c *Collector) detectPackageManagedPHP(flat *FlatFS, distro inventory.Distro) []inventory.PHPInstall {
	var records []PackageRecord

	if data, ok := flat.Files["var/lib/dpkg/status"]; ok {
		records = append(records, ParseDpkgStatus(data, "/var/lib/dpkg/status")...)
	}
	for _, p := range flat.SortedPathsWithPrefix("var/lib/dpkg/status.d/") {
		if data, ok := flat.Files[p]; ok {
			records = append(records, ParseDpkgStatus(data, "/"+p)...)
		}
	}
	if data, ok := flat.Files["lib/apk/db/installed"]; ok {
		records = append(records, ParseApkInstalled(data, "/lib/apk/db/installed")...)
	}

	// Filter redundant Debian bare metapackages (e.g. "php8.3", "php") when concrete SAPI packages
	// (e.g. "php8.3-cli", "php8.3-fpm", "libapache2-mod-php8.3") for the same upstream version exist.
	hasConcreteDebPkg := make(map[string]bool)
	for _, rec := range records {
		if rec.Manager == "deb" && !isBareVersionedPHPPkg(strings.ToLower(rec.Name)) {
			hasConcreteDebPkg[rec.UpstreamVersion] = true
		}
	}

	var installs []inventory.PHPInstall
	for _, rec := range records {
		if rec.Manager == "deb" && isBareVersionedPHPPkg(strings.ToLower(rec.Name)) && hasConcreteDebPkg[rec.UpstreamVersion] {
			continue
		}

		binPath, modPath, evNote := resolvePackageTarget(flat, rec)
		primaryTarget := binPath
		if primaryTarget == "" {
			primaryTarget = modPath
		}
		if primaryTarget == "" {
			primaryTarget = rec.Name + "@" + rec.Version
		}

		evidence := []string{
			fmt.Sprintf("pkg_db: %s => %s %s (%s)", rec.SourceFile, rec.Name, rec.Version, rec.Manager),
		}
		if evNote != "" {
			evidence = append(evidence, evNote)
		}

		inst := inventory.PHPInstall{
			ID:              inventory.ComputeID(inventory.SourceImage, rec.SAPI, primaryTarget),
			BinaryPath:      binPath,
			ModulePath:      modPath,
			UpstreamVersion: rec.UpstreamVersion,
			PackageManager:  rec.Manager,
			PackageName:     rec.Name,
			PackageVersion:  rec.Version,
			Distro:          distro,
			SAPI:            rec.SAPI,
			IniSettings:     make(map[string]string),
			Source:          inventory.SourceImage,
			Confidence:      inventory.ConfidenceHigh,
			Evidence:        evidence,
		}

		var branch string
		if parsed, err := phpver.Parse(rec.UpstreamVersion); err == nil {
			branch = parsed.Branch
		}
		local.DiscoverStaticConfigs(flat, &inst, branch, primaryTarget)
		installs = append(installs, inst)
	}

	return installs
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

func isApacheImage(cfg *v1.ConfigFile, flat *FlatFS) bool {
	if cfg != nil {
		tokens := append([]string{}, cfg.Config.Entrypoint...)
		tokens = append(tokens, cfg.Config.Cmd...)
		joined := strings.ToLower(strings.Join(tokens, " "))
		if strings.Contains(joined, "apache2") || strings.Contains(joined, "httpd") {
			return true
		}
	}
	for p := range flat.Files {
		base := strings.ToLower(path.Base(p))
		if strings.HasPrefix(base, "libphp") && strings.HasSuffix(base, ".so") {
			return true
		}
		if strings.HasPrefix(p, "etc/apache2/mods-enabled/") && strings.Contains(p, "php") {
			return true
		}
	}
	return false
}

func findCLIBinary(flat *FlatFS) string {
	for _, cand := range []string{
		"usr/local/bin/php",
		"usr/bin/php",
	} {
		resolvedRel, escaped, err := local.ResolvePathInFS(flat, cand, false)
		if !escaped && err == nil && resolvedRel != "" {
			if _, ok := flat.Files[resolvedRel]; ok {
				return "/" + resolvedRel
			}
		}
	}
	for _, p := range flat.SortedPathsWithPrefix("opt/php/") {
		if strings.HasSuffix(p, "/bin/php") {
			resolvedRel, escaped, err := local.ResolvePathInFS(flat, p, false)
			if !escaped && err == nil && resolvedRel != "" {
				if _, ok := flat.Files[resolvedRel]; ok {
					return "/" + resolvedRel
				}
			}
		}
	}
	return ""
}

func findFPMBinary(flat *FlatFS) string {
	for _, cand := range []string{
		"usr/local/sbin/php-fpm",
		"usr/sbin/php-fpm",
	} {
		resolvedRel, escaped, err := local.ResolvePathInFS(flat, cand, false)
		if !escaped && err == nil && resolvedRel != "" {
			if _, ok := flat.Files[resolvedRel]; ok {
				return "/" + resolvedRel
			}
		}
	}
	for _, p := range flat.SortedPathsWithPrefix("opt/php/") {
		if strings.HasSuffix(p, "/sbin/php-fpm") {
			resolvedRel, escaped, err := local.ResolvePathInFS(flat, p, false)
			if !escaped && err == nil && resolvedRel != "" {
				if _, ok := flat.Files[resolvedRel]; ok {
					return "/" + resolvedRel
				}
			}
		}
	}
	return ""
}

func findFrankenBinary(flat *FlatFS) string {
	for _, cand := range []string{
		"usr/local/bin/frankenphp",
		"usr/bin/frankenphp",
	} {
		resolvedRel, escaped, err := local.ResolvePathInFS(flat, cand, false)
		if !escaped && err == nil && resolvedRel != "" {
			if _, ok := flat.Files[resolvedRel]; ok {
				return "/" + resolvedRel
			}
		}
	}
	return ""
}

func findApacheModuleOrConfig(flat *FlatFS) (modulePath, configPath string, isFallback bool) {
	for _, cand := range []string{
		"usr/lib/apache2/modules/libphp.so",
		"usr/local/apache2/modules/libphp.so",
		"usr/lib/apache2/modules/libphp8.so",
		"usr/lib/apache2/modules/libphp8.3.so",
		"usr/lib/apache2/modules/libphp8.2.so",
		"usr/lib/apache2/modules/libphp8.4.so",
		"usr/lib/apache2/modules/libphp8.5.so",
	} {
		resolvedRel, escaped, err := local.ResolvePathInFS(flat, cand, false)
		if !escaped && err == nil && resolvedRel != "" {
			if _, ok := flat.Files[resolvedRel]; ok {
				return "/" + resolvedRel, "", false
			}
		}
	}
	for p := range flat.Files {
		base := strings.ToLower(path.Base(p))
		if strings.HasPrefix(base, "libphp") && strings.HasSuffix(base, ".so") {
			return "/" + p, "", false
		}
	}

	for _, p := range flat.SortedPathsWithPrefix("etc/apache2/mods-enabled/") {
		if strings.Contains(p, "php") && strings.HasSuffix(p, ".load") {
			return "", "/" + p, true
		}
	}
	for _, p := range flat.SortedPathsWithPrefix("etc/apache2/mods-available/") {
		if strings.Contains(p, "php") && strings.HasSuffix(p, ".load") {
			return "", "/" + p, true
		}
	}
	for _, cand := range []string{
		"etc/apache2/apache2.conf",
		"etc/apache2/httpd.conf",
		"usr/local/apache2/conf/httpd.conf",
		"etc/httpd/conf/httpd.conf",
	} {
		if _, ok := flat.Files[cand]; ok {
			return "", "/" + cand, true
		}
	}
	return "", "/etc/apache2/apache2.conf", true
}

func resolvePackageTarget(flat *FlatFS, rec PackageRecord) (binPath, modPath, evNote string) {
	var branch string
	if parsed, err := phpver.Parse(rec.UpstreamVersion); err == nil {
		branch = parsed.Branch
	}
	cleanBranch := strings.ReplaceAll(branch, ".", "")

	switch rec.SAPI {
	case inventory.SAPIApache2Handler:
		for _, cand := range []string{
			"usr/lib/apache2/modules/libphp" + branch + ".so",
			"usr/lib/apache2/modules/libphp.so",
			"usr/lib/apache2/libphp" + branch + ".so",
			"usr/lib/apache2/mod_php" + cleanBranch + ".so",
		} {
			if _, ok := flat.Files[cand]; ok {
				return "", "/" + cand, ""
			}
		}
		for p := range flat.Files {
			base := strings.ToLower(path.Base(p))
			if strings.HasPrefix(base, "libphp") && strings.HasSuffix(base, ".so") {
				return "", "/" + p, ""
			}
		}
		for _, p := range flat.SortedPathsWithPrefix("etc/apache2/mods-enabled/") {
			if strings.Contains(p, "php") && strings.HasSuffix(p, ".load") {
				return "", "/" + p, fmt.Sprintf("apache module file not found on disk; discovered via config /%s", p)
			}
		}
		for _, p := range flat.SortedPathsWithPrefix("etc/apache2/mods-available/") {
			if strings.Contains(p, "php") && strings.HasSuffix(p, ".load") {
				return "", "/" + p, fmt.Sprintf("apache module file not found on disk; discovered via config /%s", p)
			}
		}
		if _, ok := flat.Files["etc/apache2/apache2.conf"]; ok {
			return "", "/etc/apache2/apache2.conf", "apache module file not found on disk; discovered via config /etc/apache2/apache2.conf"
		}
		if branch != "" {
			return "", "/usr/lib/apache2/modules/libphp" + branch + ".so", ""
		}
		return "", "/usr/lib/apache2/modules/libphp.so", ""

	case inventory.SAPIFPM:
		for _, cand := range []string{
			"usr/sbin/php-fpm" + branch,
			"usr/sbin/php-fpm" + cleanBranch,
			"usr/sbin/php-fpm",
			"usr/local/sbin/php-fpm",
		} {
			if _, ok := flat.Files[cand]; ok {
				return "/" + cand, "", ""
			}
		}
		for p := range flat.Files {
			base := strings.ToLower(path.Base(p))
			if strings.HasPrefix(base, "php-fpm") && !strings.Contains(base, ".") {
				return "/" + p, "", ""
			}
		}
		if branch != "" {
			return "/usr/sbin/php-fpm" + branch, "", ""
		}
		return "/usr/sbin/php-fpm", "", ""

	case inventory.SAPICGI:
		for _, cand := range []string{
			"usr/bin/php-cgi" + branch,
			"usr/bin/php-cgi" + cleanBranch,
			"usr/bin/php-cgi",
		} {
			if _, ok := flat.Files[cand]; ok {
				return "/" + cand, "", ""
			}
		}
		if branch != "" {
			return "/usr/bin/php-cgi" + branch, "", ""
		}
		return "/usr/bin/php-cgi", "", ""

	default:
		for _, cand := range []string{
			"usr/bin/php" + branch,
			"usr/bin/php" + cleanBranch,
			"usr/bin/php",
			"usr/local/bin/php",
		} {
			if _, ok := flat.Files[cand]; ok {
				return "/" + cand, "", ""
			}
		}
		for p := range flat.Files {
			base := strings.ToLower(path.Base(p))
			if base == "php" || base == "php"+branch {
				return "/" + p, "", ""
			}
		}
		if branch != "" {
			return "/usr/bin/php" + branch, "", ""
		}
		return "/usr/bin/php", "", ""
	}
}
