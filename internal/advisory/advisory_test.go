package advisory_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
)

func TestLoadEmbeddedSeedData(t *testing.T) {
	t.Parallel()

	adv, err := advisory.Load("")
	if err != nil {
		t.Fatalf("Load(\"\") unexpected error: %v", err)
	}

	if adv.Verified {
		t.Errorf("seed advisory Verified = true, want false")
	}
	if adv.AffectedMin != "5.4.0" {
		t.Errorf("AffectedMin = %q, want 5.4.0", adv.AffectedMin)
	}
	if adv.AffectedMaxInclusive != "8.5.11" {
		t.Errorf("AffectedMaxInclusive = %q, want 8.5.11", adv.AffectedMaxInclusive)
	}
	if len(adv.DistroFixes) != 0 {
		t.Errorf("DistroFixes len = %d, want 0", len(adv.DistroFixes))
	}

	wantFixed := map[string]string{
		"8.5": "8.5.12",
		"8.4": "8.4.27",
		"8.3": "8.3.36",
		"8.2": "8.2.35",
	}
	wantNullUpstream := map[string]bool{
		"8.1": true,
		"8.0": true,
		"7.4": true,
	}

	branchByID := make(map[string]advisory.BranchAdvisory, len(adv.Branches))
	for _, b := range adv.Branches {
		branchByID[b.Branch] = b
	}

	for br, fixed := range wantFixed {
		b, ok := branchByID[br]
		if !ok {
			t.Fatalf("missing branch %q in seed data", br)
		}
		if b.FixedIn != fixed {
			t.Errorf("branch %q FixedIn = %q, want %q", br, b.FixedIn, fixed)
		}
		if b.UpstreamFixAvailable == nil || !*b.UpstreamFixAvailable {
			t.Errorf("branch %q UpstreamFixAvailable = %v, want true", br, b.UpstreamFixAvailable)
		}
	}

	for br := range wantNullUpstream {
		b, ok := branchByID[br]
		if !ok {
			t.Fatalf("missing branch %q in seed data", br)
		}
		if b.UpstreamFixAvailable != nil {
			t.Errorf("branch %q UpstreamFixAvailable = %v, want nil", br, *b.UpstreamFixAvailable)
		}
		if b.FixedIn != "" {
			t.Errorf("branch %q FixedIn = %q, want empty", br, b.FixedIn)
		}
	}

	if len(adv.Mitigations) != 2 {
		t.Fatalf("Mitigations len = %d, want 2", len(adv.Mitigations))
	}
	for _, m := range adv.Mitigations {
		if m.CVE != "CVE-2026-109619" {
			t.Errorf("unexpected mitigation for CVE %q; CVE-2026-109618 must have no config mitigation", m.CVE)
		}
	}
}

func TestLoadOverrideFile(t *testing.T) {
	t.Parallel()

	customJSON := `{
  "id": "CUSTOM-ADV-1",
  "cves": ["CVE-2026-109618"],
  "title": "Custom Advisory",
  "severity": "",
  "cvss_v4": "",
  "summary": "Custom test advisory",
  "affected_min": "5.4.0",
  "affected_max_inclusive": "8.5.11",
  "branches": [
    {
      "branch": "8.3",
      "fixed_in": "8.3.36",
      "eol": false,
      "upstream_fix_available": true,
      "notes": ""
    }
  ],
  "distro_fixes": [],
  "mitigations": [],
  "references": [],
  "last_verified": "",
  "verified": false
}`

	tmpFile := filepath.Join(t.TempDir(), "custom-advisories.json")
	if err := os.WriteFile(tmpFile, []byte(customJSON), 0o600); err != nil {
		t.Fatalf("write temp advisory file: %v", err)
	}

	adv, err := advisory.Load(tmpFile)
	if err != nil {
		t.Fatalf("Load(%q) unexpected error: %v", tmpFile, err)
	}
	if adv.ID != "CUSTOM-ADV-1" {
		t.Errorf("adv.ID = %q, want CUSTOM-ADV-1", adv.ID)
	}
}

func TestParseRejectsMalformedAndUnknownFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "empty input",
			payload: "   ",
		},
		{
			name:    "malformed JSON syntax",
			payload: `{"id": "PHP2SHELL-2026", "cves": [`,
		},
		{
			name: "unknown top-level field",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11",
				"unknown_field": true
			}`,
		},
		{
			name: "unknown nested branch field",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11",
				"branches": [{"branch": "8.3", "extra": "bad"}]
			}`,
		},
		{
			name: "trailing JSON object",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11"
			} {"extra": 1}`,
		},
		{
			name: "missing id",
			payload: `{
				"id": "",
				"cves": ["CVE-2026-109618"],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11"
			}`,
		},
		{
			name: "empty cves array",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": [],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11"
			}`,
		},
		{
			name: "invalid affected_min version string",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "not-a-version",
				"affected_max_inclusive": "8.5.11"
			}`,
		},
		{
			name: "affected_min greater than affected_max_inclusive",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "8.5.12",
				"affected_max_inclusive": "5.4.0"
			}`,
		},
		{
			name: "branch fixed_in mismatch",
			payload: `{
				"id": "PHP2SHELL-2026",
				"cves": ["CVE-2026-109618"],
				"affected_min": "5.4.0",
				"affected_max_inclusive": "8.5.11",
				"branches": [{"branch": "8.3", "fixed_in": "8.4.27"}]
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := advisory.Parse([]byte(tc.payload))
			if err == nil {
				t.Fatalf("Parse() succeeded for %s, expected error", tc.name)
			}
			if !errors.Is(err, advisory.ErrInvalidAdvisory) {
				t.Fatalf("Parse() error = %v, want errors.Is(..., ErrInvalidAdvisory)", err)
			}
		})
	}
}
