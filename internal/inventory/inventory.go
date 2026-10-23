package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SAPI represents the PHP Server API type of a discovered installation.
type SAPI string

// Supported SAPI values.
const (
	SAPICLI            SAPI = "cli"
	SAPIFPM            SAPI = "fpm"
	SAPIApache2Handler SAPI = "apache2handler"
	SAPICGI            SAPI = "cgi"
	SAPILiteSpeed      SAPI = "litespeed"
	SAPIFrankenPHP     SAPI = "frankenphp"
	SAPIUnknown        SAPI = "unknown"
)

// Source identifies the discovery mode that produced a PHPInstall record.
type Source string

// Supported discovery sources.
const (
	SourceLocal  Source = "local"
	SourceImage  Source = "image"
	SourceSBOM   Source = "sbom"
	SourcePath   Source = "path"
	SourceRemote Source = "remote"
)

// Confidence indicates how reliable the version and configuration discovery is.
type Confidence string

// Supported confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Distro identifies the operating system distribution from /etc/os-release.
type Distro struct {
	ID        string `json:"id,omitempty"`
	VersionID string `json:"version_id,omitempty"`
}

// PHPInstall represents a single discovered PHP runtime, module, or package installation.
type PHPInstall struct {
	ID              string            `json:"id"`
	BinaryPath      string            `json:"binary_path,omitempty"`
	ModulePath      string            `json:"module_path,omitempty"`
	UpstreamVersion string            `json:"upstream_version"`
	PackageManager  string            `json:"package_manager,omitempty"`
	PackageName     string            `json:"package_name,omitempty"`
	PackageVersion  string            `json:"package_version,omitempty"`
	Distro          Distro            `json:"distro"`
	SAPI            SAPI              `json:"sapi"`
	ConfigFiles     []string          `json:"config_files,omitempty"`
	IniSettings     map[string]string `json:"ini_settings,omitempty"`
	Source          Source            `json:"source"`
	Confidence      Confidence        `json:"confidence"`
	Evidence        []string          `json:"evidence,omitempty"`
}

// ComputeID returns a deterministic identifier for a PHPInstall based on its
// source, SAPI, and primary artifact path or package name.
func ComputeID(source Source, sapi SAPI, primaryTarget string) string {
	raw := fmt.Sprintf("%s:%s:%s", source, sapi, primaryTarget)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%s-%s-%s", source, sapi, hex.EncodeToString(sum[:6]))
}

// AddConfigFile appends path to ConfigFiles if it is non-empty and not already present.
func (p *PHPInstall) AddConfigFile(path string) {
	if path == "" {
		return
	}
	for _, existing := range p.ConfigFiles {
		if existing == path {
			return
		}
	}
	p.ConfigFiles = append(p.ConfigFiles, path)
}

// AddEvidence appends an evidence line if non-empty.
func (p *PHPInstall) AddEvidence(ev string) {
	if ev == "" {
		return
	}
	p.Evidence = append(p.Evidence, ev)
}

// SetIniSetting sets an INI key/value pair and records its origin in Evidence.
func (p *PHPInstall) SetIniSetting(key, value, origin string) {
	if p.IniSettings == nil {
		p.IniSettings = make(map[string]string)
	}
	p.IniSettings[key] = value
	p.AddEvidence(fmt.Sprintf("ini:%s=%s (source: %s)", key, value, origin))
}

// NormalizeImageRef strips default Docker Hub library prefixes (such as docker.io/library/,
// index.docker.io/library/, registry-1.docker.io/library/, and library/) for display.
func NormalizeImageRef(ref string) string {
	s := strings.TrimSpace(ref)
	lower := strings.ToLower(s)
	for _, prefix := range []string{
		"index.docker.io/library/",
		"docker.io/library/",
		"registry-1.docker.io/library/",
		"library/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return s[len(prefix):]
		}
	}
	return s
}
