package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// ErrUnsupportedSBOM indicates that the input file is neither CycloneDX JSON nor SPDX JSON.
var ErrUnsupportedSBOM = errors.New("unsupported or unrecognized SBOM format (expected CycloneDX JSON or SPDX JSON)")

type cycloneDXDoc struct {
	BOMFormat  string               `json:"bomFormat"`
	Metadata   cycloneDXMetadata    `json:"metadata"`
	Components []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Component *cycloneDXComponent `json:"component"`
}

type cycloneDXComponent struct {
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	Components []cycloneDXComponent `json:"components"`
}

type spdxDoc struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceType    string `json:"referenceType"`
	ReferenceLocator string `json:"referenceLocator"`
}

// Collector parses CycloneDX and SPDX JSON SBOM files for PHP components.
type Collector struct{}

// NewCollector constructs an SBOM Collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect reads and parses an SBOM file from disk.
func (c *Collector) Collect(ctx context.Context, filePath string) ([]inventory.PHPInstall, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("sbom collect context: %w", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read sbom file %q: %w", filePath, err)
	}
	return ParseBytes(data, filePath)
}

// ParseBytes parses raw CycloneDX JSON or SPDX JSON bytes into PHPInstall records
// with Source sbom and Confidence medium.
func ParseBytes(data []byte, sourceLabel string) ([]inventory.PHPInstall, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty SBOM payload: %w", ErrUnsupportedSBOM)
	}

	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, fmt.Errorf("decode SBOM JSON: %w: %w", err, ErrUnsupportedSBOM)
	}

	switch {
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDX(trimmed, sourceLabel)
	case strings.HasPrefix(strings.ToUpper(probe.SPDXVersion), "SPDX-"):
		return parseSPDX(trimmed, sourceLabel)
	default:
		return nil, fmt.Errorf("file %q: %w", sourceLabel, ErrUnsupportedSBOM)
	}
}

func parseCycloneDX(data []byte, sourceLabel string) ([]inventory.PHPInstall, error) {
	var doc cycloneDXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode CycloneDX JSON: %w", err)
	}

	var all []cycloneDXComponent
	if doc.Metadata.Component != nil {
		all = append(all, flattenCycloneComponents(*doc.Metadata.Component)...)
	}
	for _, comp := range doc.Components {
		all = append(all, flattenCycloneComponents(comp)...)
	}

	var installs []inventory.PHPInstall
	for _, comp := range all {
		inst, ok := evaluateSBOMComponent(comp.Name, comp.Version, comp.PURL, sourceLabel, "CycloneDX")
		if ok {
			installs = append(installs, inst)
		}
	}
	return installs, nil
}

func flattenCycloneComponents(c cycloneDXComponent) []cycloneDXComponent {
	out := []cycloneDXComponent{c}
	for _, sub := range c.Components {
		out = append(out, flattenCycloneComponents(sub)...)
	}
	return out
}

func parseSPDX(data []byte, sourceLabel string) ([]inventory.PHPInstall, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode SPDX JSON: %w", err)
	}

	var installs []inventory.PHPInstall
	for _, pkg := range doc.Packages {
		var purlStr string
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") || strings.HasPrefix(ref.ReferenceLocator, "pkg:") {
				purlStr = ref.ReferenceLocator
				break
			}
		}
		inst, ok := evaluateSBOMComponent(pkg.Name, pkg.VersionInfo, purlStr, sourceLabel, "SPDX")
		if ok {
			installs = append(installs, inst)
		}
	}
	return installs, nil
}

func evaluateSBOMComponent(name, version, purlRaw, sourceLabel, formatName string) (inventory.PHPInstall, bool) {
	pkgName := strings.TrimSpace(name)
	pkgVer := strings.TrimSpace(version)
	var pkgMgr string
	var distro inventory.Distro

	if purlRaw != "" {
		if parsedPURL, err := packageurl.FromString(purlRaw); err == nil {
			if parsedPURL.Name != "" {
				pkgName = parsedPURL.Name
			}
			if parsedPURL.Version != "" {
				pkgVer = parsedPURL.Version
			}
			pkgMgr = normalizePURLType(parsedPURL.Type)
			distro = extractDistroFromPURL(parsedPURL)
		}
	}

	sapi, isPHP := matchPHPComponentName(pkgName)
	if !isPHP {
		return inventory.PHPInstall{}, false
	}

	upstream := extractUpstreamFromVersion(pkgVer)
	primaryID := fmt.Sprintf("%s:%s@%s", sourceLabel, pkgName, pkgVer)

	inst := inventory.PHPInstall{
		ID:              inventory.ComputeID(inventory.SourceSBOM, sapi, primaryID),
		UpstreamVersion: upstream,
		PackageManager:  pkgMgr,
		PackageName:     pkgName,
		PackageVersion:  pkgVer,
		Distro:          distro,
		SAPI:            sapi,
		Source:          inventory.SourceSBOM,
		Confidence:      inventory.ConfidenceMedium,
	}

	if purlRaw != "" {
		inst.AddEvidence(fmt.Sprintf("sbom (%s): %s => %s", formatName, sourceLabel, purlRaw))
	} else {
		inst.AddEvidence(fmt.Sprintf("sbom (%s): %s => %s@%s", formatName, sourceLabel, pkgName, pkgVer))
	}

	return inst, true
}

func matchPHPComponentName(name string) (inventory.SAPI, bool) {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return inventory.SAPIUnknown, false
	}

	// Match libphp and libapache2-mod-php variants
	if strings.HasPrefix(lower, "libphp") || strings.HasPrefix(lower, "libapache2-mod-php") {
		return inventory.SAPIApache2Handler, true
	}

	// Strip optional Remi/cPanel prefixes like "ea-php82-" or "php83-php-"
	normalized := lower
	for _, pref := range []string{"ea-", "alt-"} {
		normalized = strings.TrimPrefix(normalized, pref)
	}

	if !strings.HasPrefix(normalized, "php") {
		return inventory.SAPIUnknown, false
	}

	switch {
	case strings.HasSuffix(normalized, "-fpm"):
		return inventory.SAPIFPM, true
	case strings.HasSuffix(normalized, "-cli"):
		return inventory.SAPICLI, true
	case strings.HasSuffix(normalized, "-cgi"):
		return inventory.SAPICGI, true
	case strings.HasSuffix(normalized, "-apache2"):
		return inventory.SAPIApache2Handler, true
	case normalized == "php" || isPHPVersionedName(normalized):
		return inventory.SAPICLI, true
	default:
		return inventory.SAPIUnknown, false
	}
}

func isPHPVersionedName(s string) bool {
	rest := strings.TrimPrefix(s, "php")
	rest = strings.TrimPrefix(rest, "-")
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

func normalizePURLType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "deb", "dpkg":
		return "deb"
	case "rpm":
		return "rpm"
	case "apk":
		return "apk"
	default:
		return ""
	}
}

func extractDistroFromPURL(p packageurl.PackageURL) inventory.Distro {
	var d inventory.Distro
	if p.Namespace != "" {
		d.ID = strings.ToLower(p.Namespace)
	}
	qMap := p.Qualifiers.Map()
	if rawDistro, ok := qMap["distro"]; ok && rawDistro != "" {
		if id, ver, hasDash := strings.Cut(rawDistro, "-"); hasDash {
			if d.ID == "" {
				d.ID = strings.ToLower(id)
			}
			d.VersionID = ver
		} else if d.VersionID == "" {
			d.VersionID = rawDistro
		}
	}
	return d
}

func extractUpstreamFromVersion(raw string) string {
	cleaned := strings.TrimSpace(raw)
	if idx := strings.IndexByte(cleaned, ':'); idx > 0 {
		cleaned = cleaned[idx+1:]
	}
	v, err := phpver.Parse(cleaned)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d%s", v.Major, v.Minor, v.Patch, v.PreRelease)
}
