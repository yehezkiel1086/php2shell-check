package advisory

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

//go:embed data/advisories.json
var embeddedAdvisoriesJSON []byte

// ErrInvalidAdvisory indicates that an advisory payload failed schema or semantic validation.
var ErrInvalidAdvisory = errors.New("invalid advisory data")

// Advisory represents the structured advisory metadata for PHP2Shell CVEs.
type Advisory struct {
	ID                   string           `json:"id"`
	CVEs                 []string         `json:"cves"`
	Title                string           `json:"title"`
	Severity             string           `json:"severity"`
	CVSSv4               string           `json:"cvss_v4"`
	Summary              string           `json:"summary"`
	AffectedMin          string           `json:"affected_min"`
	AffectedMaxInclusive string           `json:"affected_max_inclusive"`
	Branches             []BranchAdvisory `json:"branches"`
	DistroFixes          []DistroFix      `json:"distro_fixes"`
	Mitigations          []Mitigation     `json:"mitigations"`
	References           []Reference      `json:"references"`
	LastVerified         string           `json:"last_verified"`
	Verified             bool             `json:"verified"`
}

// BranchAdvisory describes vulnerability and upstream fix status for a PHP minor branch.
type BranchAdvisory struct {
	Branch               string `json:"branch"`
	FixedIn              string `json:"fixed_in"`
	EOL                  bool   `json:"eol"`
	UpstreamFixAvailable *bool  `json:"upstream_fix_available"`
	Notes                string `json:"notes"`
}

// DistroFix describes a distribution-specific package version that backports a fix.
type DistroFix struct {
	Distro       string `json:"distro"`
	Release      string `json:"release"`
	Package      string `json:"package"`
	FixedVersion string `json:"fixed_version"`
	Verified     bool   `json:"verified"`
}

// Mitigation describes an optional php.ini configuration mitigation for a specific CVE.
// A configuration mitigation is reported separately and never changes a verdict.
type Mitigation struct {
	CVE              string `json:"cve"`
	IniKey           string `json:"ini_key"`
	RecommendedValue string `json:"recommended_value"`
	AppliesToBranch  string `json:"applies_to_branch"`
	Note             string `json:"note"`
}

// Reference represents an external advisory link.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Load loads the advisory from overridePath if non-empty, or from the embedded
// data/advisories.json otherwise.
func Load(overridePath string) (Advisory, error) {
	if overridePath == "" {
		return LoadEmbedded()
	}
	return LoadFile(overridePath)
}

// LoadEmbedded parses and validates the embedded data/advisories.json payload.
func LoadEmbedded() (Advisory, error) {
	return Parse(embeddedAdvisoriesJSON)
}

// LoadFile reads, parses, and validates an advisory JSON file from disk.
func LoadFile(path string) (Advisory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Advisory{}, fmt.Errorf("read advisory file %q: %w", path, err)
	}
	adv, err := Parse(data)
	if err != nil {
		return Advisory{}, fmt.Errorf("parse advisory file %q: %w", path, err)
	}
	return adv, nil
}

// Parse strictly unmarshals and validates raw JSON bytes into an Advisory,
// rejecting unknown fields, trailing JSON data, and invalid version strings.
func Parse(data []byte) (Advisory, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Advisory{}, fmt.Errorf("empty JSON payload: %w", ErrInvalidAdvisory)
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()

	var adv Advisory
	if err := dec.Decode(&adv); err != nil {
		return Advisory{}, fmt.Errorf("decode advisory JSON: %w: %w", err, ErrInvalidAdvisory)
	}

	// Ensure no trailing tokens exist after the root JSON object.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Advisory{}, fmt.Errorf("unexpected trailing JSON content: %w", ErrInvalidAdvisory)
	}

	if err := adv.Validate(); err != nil {
		return Advisory{}, err
	}

	return adv, nil
}

// Validate checks semantic invariants of the Advisory struct.
func (a Advisory) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("missing advisory id: %w", ErrInvalidAdvisory)
	}
	if len(a.CVEs) == 0 {
		return fmt.Errorf("advisory %q must list at least one CVE: %w", a.ID, ErrInvalidAdvisory)
	}
	for _, cve := range a.CVEs {
		if cve == "" {
			return fmt.Errorf("advisory %q contains empty CVE identifier: %w", a.ID, ErrInvalidAdvisory)
		}
	}

	minVer, err := phpver.Parse(a.AffectedMin)
	if err != nil {
		return fmt.Errorf("invalid affected_min %q: %w: %w", a.AffectedMin, err, ErrInvalidAdvisory)
	}
	maxVer, err := phpver.Parse(a.AffectedMaxInclusive)
	if err != nil {
		return fmt.Errorf("invalid affected_max_inclusive %q: %w: %w", a.AffectedMaxInclusive, err, ErrInvalidAdvisory)
	}
	if phpver.Compare(minVer, maxVer) > 0 {
		return fmt.Errorf("affected_min %q is greater than affected_max_inclusive %q: %w", a.AffectedMin, a.AffectedMaxInclusive, ErrInvalidAdvisory)
	}

	for _, b := range a.Branches {
		if b.Branch == "" {
			return fmt.Errorf("branch entry with empty branch name: %w", ErrInvalidAdvisory)
		}
		if b.FixedIn != "" {
			fixedVer, err := phpver.Parse(b.FixedIn)
			if err != nil {
				return fmt.Errorf("branch %q has invalid fixed_in %q: %w: %w", b.Branch, b.FixedIn, err, ErrInvalidAdvisory)
			}
			if fixedVer.Branch != b.Branch {
				return fmt.Errorf("branch %q fixed_in %q does not match branch %q: %w", b.Branch, b.FixedIn, fixedVer.Branch, ErrInvalidAdvisory)
			}
		}
	}

	for _, df := range a.DistroFixes {
		if df.Distro == "" || df.Package == "" || df.FixedVersion == "" {
			return fmt.Errorf("distro_fixes entry missing required fields: %w", ErrInvalidAdvisory)
		}
	}

	for _, m := range a.Mitigations {
		if m.CVE == "" || m.IniKey == "" {
			return fmt.Errorf("mitigation entry missing cve or ini_key: %w", ErrInvalidAdvisory)
		}
	}

	return nil
}
