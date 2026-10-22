package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
	"github.com/yehezkiel1086/php2shell-check/internal/report"
)

func buildSampleReport(t *testing.T, includeHunt bool) report.Report {
	t.Helper()
	adv, err := advisory.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() failed: %v", err)
	}

	installs := []inventory.PHPInstall{
		{
			ID:              "local-fpm-111111111111",
			BinaryPath:      "/usr/sbin/php-fpm8.4",
			UpstreamVersion: "8.4.26",
			SAPI:            inventory.SAPIFPM,
			Source:          inventory.SourceLocal,
			Confidence:      inventory.ConfidenceHigh,
			IniSettings: map[string]string{
				"session.upload_progress.enabled": "1",
			},
			Evidence: []string{
				"version_cmd: /usr/sbin/php-fpm8.4 -v => 8.4.26",
				"ini:session.upload_progress.enabled=1 (source: /etc/php/8.4/fpm/php.ini)",
			},
		},
		{
			ID:              "local-cli-222222222222",
			BinaryPath:      "/usr/bin/php8.3",
			UpstreamVersion: "8.3.35",
			PackageManager:  "deb",
			PackageName:     "php8.3-cli",
			PackageVersion:  "8.3.35-1+deb12u1",
			Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourceLocal,
			Confidence:      inventory.ConfidenceHigh,
			IniSettings: map[string]string{
				"session.upload_progress.enabled": "0",
			},
			Evidence: []string{
				"version_cmd: /usr/bin/php8.3 -v => 8.3.35-1+deb12u1",
				"ini:session.upload_progress.enabled=0 (source: php -i)",
			},
		},
		{
			ID:         "local-apache2handler-333333333333",
			ModulePath: "/usr/lib/apache2/modules/libphp.so",
			SAPI:       inventory.SAPIApache2Handler,
			Source:     inventory.SourceLocal,
			Confidence: inventory.ConfidenceLow,
			Evidence: []string{
				"permission_denied: open /usr/lib/apache2/modules/libphp.so: permission denied",
			},
		},
		{
			ID:              "local-cli-444444444444",
			BinaryPath:      "/usr/local/bin/php8.5",
			UpstreamVersion: "8.5.12",
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourceLocal,
			Confidence:      inventory.ConfidenceHigh,
			Evidence: []string{
				"version_cmd: /usr/local/bin/php8.5 -v => 8.5.12",
			},
		},
	}

	findings := match.EvaluateAll(installs, adv)
	recs := remediate.BuildAll(findings, adv, remediate.Options{IncludeHuntHints: includeHunt})

	return report.Build(findings, recs, adv, report.Options{
		ToolVersion: "0.1.0-test",
		Mode:        "local",
		IncludeHunt: includeHunt,
	})
}

func assertGolden(t *testing.T, goldenName, got string) {
	t.Helper()
	goldenPath := filepath.Join("..", "..", "testdata", "report", goldenName)
	gotNorm := strings.ReplaceAll(got, "\r\n", "\n")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o750); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(gotNorm), 0o600); err != nil {
			t.Fatalf("write golden %s: %v", goldenPath, err)
		}
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}
	wantNorm := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")

	if gotNorm != wantNorm {
		t.Fatalf("output mismatch vs golden %s\ngot:\n%s\nwant:\n%s", goldenName, gotNorm, wantNorm)
	}
}

func TestGoldenAllFourFormats(t *testing.T) {
	t.Parallel()

	rep := buildSampleReport(t, false)

	formats := []struct {
		format     string
		goldenFile string
	}{
		{format: report.FormatTable, goldenFile: "report.table.golden"},
		{format: report.FormatJSON, goldenFile: "report.json.golden"},
		{format: report.FormatSARIF, goldenFile: "report.sarif.golden"},
		{format: report.FormatMD, goldenFile: "report.md.golden"},
	}

	for _, tc := range formats {
		t.Run(tc.format, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := report.Render(&buf, rep, report.Options{
				Format:  tc.format,
				NoColor: true,
			})
			if err != nil {
				t.Fatalf("Render(%s) unexpected error: %v", tc.format, err)
			}
			assertGolden(t, tc.goldenFile, buf.String())
		})
	}
}

func TestSARIF210SchemaAndSemantics(t *testing.T) {
	t.Parallel()

	rep := buildSampleReport(t, false)
	var buf bytes.Buffer
	if err := report.RenderSARIF(&buf, rep); err != nil {
		t.Fatalf("RenderSARIF() unexpected error: %v", err)
	}

	parsed, err := sarif.FromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("sarif.FromBytes() failed: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", parsed.Version)
	}
	if !strings.Contains(parsed.Schema, "2.1.0") {
		t.Errorf("SARIF $schema = %q, want 2.1.0 schema reference", parsed.Schema)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("SARIF runs len = %d, want 1", len(parsed.Runs))
	}

	run := parsed.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("SARIF driver rules len = %d, want 2 (one per CVE)", len(run.Tool.Driver.Rules))
	}

	// 3 non-patched findings (VULNERABLE, LIKELY_VULNERABLE, UNKNOWN) x 2 CVEs = 6 results.
	if len(run.Results) != 6 {
		t.Fatalf("SARIF results len = %d, want 6", len(run.Results))
	}

	wantLevels := map[string]int{
		"error":   2, // VULNERABLE finding x 2 CVEs
		"warning": 2, // LIKELY_VULNERABLE finding x 2 CVEs
		"note":    2, // UNKNOWN finding x 2 CVEs
	}
	gotLevels := make(map[string]int)
	for _, r := range run.Results {
		if r.Level == nil {
			t.Fatal("SARIF result has nil level")
		}
		gotLevels[*r.Level]++
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation == nil || r.Locations[0].PhysicalLocation.ArtifactLocation == nil || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == nil {
			t.Fatalf("SARIF result missing physical location artifact URI: %+v", r)
		}
	}

	for lvl, wantCount := range wantLevels {
		if gotLevels[lvl] != wantCount {
			t.Errorf("SARIF level %q count = %d, want %d", lvl, gotLevels[lvl], wantCount)
		}
	}
}

func TestTableColorQuietAndSecretRedaction(t *testing.T) {
	t.Parallel()

	rep := buildSampleReport(t, true)
	// Inject a fake secret into evidence and verify Build redacts it.
	adv, _ := advisory.LoadEmbedded()
	secretFinding := match.Finding{
		AdvisoryID: adv.ID,
		CVEs:       adv.CVEs,
		Install: inventory.PHPInstall{
			BinaryPath:      "/usr/bin/php",
			UpstreamVersion: "8.3.35",
			SAPI:            inventory.SAPICLI,
			Evidence: []string{
				"ini:api_key=super_secret_token_12345",
				"password: hunter2_secret",
			},
		},
		Verdict: match.VerdictVulnerable,
		FixedIn: "8.3.36",
	}

	sanitizedRep := report.Build([]match.Finding{secretFinding}, nil, adv, report.Options{ToolVersion: "0.1.0"})
	var jsonBuf bytes.Buffer
	if err := report.RenderJSON(&jsonBuf, sanitizedRep); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.Contains(jsonBuf.String(), "super_secret_token_12345") || strings.Contains(jsonBuf.String(), "hunter2_secret") {
		t.Fatalf("secret leaked into JSON output:\n%s", jsonBuf.String())
	}
	if !strings.Contains(jsonBuf.String(), "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker in JSON output:\n%s", jsonBuf.String())
	}

	// Verify ANSI color is present when NoColor is false, and absent when NoColor is true.
	var colorBuf, plainBuf, quietBuf bytes.Buffer
	if err := report.RenderTable(&colorBuf, rep, report.Options{NoColor: false}); err != nil {
		t.Fatalf("RenderTable(color): %v", err)
	}
	if !strings.Contains(colorBuf.String(), "\x1b[") {
		t.Error("expected ANSI color sequences when NoColor is false")
	}

	if err := report.RenderTable(&plainBuf, rep, report.Options{NoColor: true}); err != nil {
		t.Fatalf("RenderTable(no-color): %v", err)
	}
	if strings.Contains(plainBuf.String(), "\x1b[") {
		t.Error("unexpected ANSI color sequences when NoColor is true")
	}

	// Verify --quiet suppresses Remediation Guidance and Log-Review Indicators while keeping Summary footer.
	if err := report.RenderTable(&quietBuf, rep, report.Options{NoColor: true, Quiet: true}); err != nil {
		t.Fatalf("RenderTable(quiet): %v", err)
	}
	if strings.Contains(quietBuf.String(), "Remediation Guidance:") {
		t.Error("expected --quiet to suppress Remediation Guidance block")
	}
	if !strings.Contains(quietBuf.String(), "Summary: total=4 vulnerable=1 likely_vulnerable=1 unknown=1 patched=1") {
		t.Errorf("missing summary footer in quiet output:\n%s", quietBuf.String())
	}

	// Verify WriteToFileOrWriter writes to disk when outputFile is specified.
	outPath := filepath.Join(t.TempDir(), "report.json")
	var fallback bytes.Buffer
	if err := report.WriteToFileOrWriter(outPath, &fallback, rep, report.Options{Format: report.FormatJSON}); err != nil {
		t.Fatalf("WriteToFileOrWriter: %v", err)
	}
	diskData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read written output file: %v", err)
	}
	var decoded report.Report
	if err := json.Unmarshal(diskData, &decoded); err != nil {
		t.Fatalf("unmarshal written JSON report: %v", err)
	}
	if decoded.SchemaVersion != report.SchemaVersion {
		t.Errorf("decoded SchemaVersion = %q, want %q", decoded.SchemaVersion, report.SchemaVersion)
	}
}
