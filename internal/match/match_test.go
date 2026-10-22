package match_test

import (
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
)

func mustLoadSeedAdvisory(t *testing.T) advisory.Advisory {
	t.Helper()
	adv, err := advisory.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() failed: %v", err)
	}
	return adv
}

func TestEvaluateGoldenTable(t *testing.T) {
	t.Parallel()

	seedAdv := mustLoadSeedAdvisory(t)

	// Advisory copy with Verified DistroFixes for deb, rpm, and apk testing, plus an unverified entry.
	advWithDistroFixes := seedAdv
	advWithDistroFixes.DistroFixes = []advisory.DistroFix{
		{
			Distro:       "debian",
			Release:      "12",
			Package:      "php8.2-fpm",
			FixedVersion: "8.2.30-1+deb12u2",
			Verified:     true,
		},
		{
			Distro:       "ubuntu",
			Release:      "22.04",
			Package:      "php8.1-fpm",
			FixedVersion: "8.1.2-1ubuntu2.20",
			Verified:     false, // unverified entry must not produce PATCHED or VULNERABLE
		},
		{
			Distro:       "rocky",
			Release:      "9",
			Package:      "php-fpm",
			FixedVersion: "8.3.30-2.el9_4",
			Verified:     true,
		},
		{
			Distro:       "alpine",
			Release:      "3.20",
			Package:      "php83-fpm",
			FixedVersion: "8.3.30-r2",
			Verified:     true,
		},
	}

	type testCase struct {
		name           string
		adv            advisory.Advisory
		inst           inventory.PHPInstall
		wantVerdict    match.Verdict
		wantReason     string
		wantFixedIn    string
		wantMitigation map[string]match.MitigationStatus
	}

	cases := []testCase{
		// --- Branch 8.5 boundaries (FixedIn 8.5.12) ---
		{
			name:        "01_upstream_8.5.12_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.5.12", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.5.12",
		},
		{
			name:        "02_upstream_8.5.13_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.5.13", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.5.12",
		},
		{
			name:        "03_upstream_8.5.12RC1_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.5.12RC1", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
		},
		{
			name:        "04_upstream_8.5.11_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.5.11", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
		},
		{
			name:        "05_upstream_8.5.0_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.5.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
		},

		// --- Branch 8.4 boundaries (FixedIn 8.4.27) ---
		{
			name:        "06_upstream_8.4.27_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.4.27", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.4.27",
		},
		{
			name:        "07_upstream_8.4.28_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.4.28", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.4.27",
		},
		{
			name:        "08_upstream_8.4.27RC1_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.4.27RC1", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.4.27",
		},
		{
			name:        "09_upstream_8.4.26_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.4.26", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.4.27",
		},
		{
			name:        "10_upstream_8.4.0_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.4.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.4.27",
		},

		// --- Branch 8.3 boundaries (FixedIn 8.3.36) ---
		{
			name:        "11_upstream_8.3.36_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.3.36", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.36",
		},
		{
			name:        "12_upstream_8.3.37_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.3.37", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.36",
		},
		{
			name:        "13_upstream_8.3.36RC1_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.3.36RC1", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
		},
		{
			name:        "14_upstream_8.3.35_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.3.35", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
		},
		{
			name:        "15_upstream_8.3.0_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.3.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
		},

		// --- Branch 8.2 boundaries (FixedIn 8.2.35) ---
		{
			name:        "16_upstream_8.2.35_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.2.35", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.2.35",
		},
		{
			name:        "17_upstream_8.2.36_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.2.36", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.2.35",
		},
		{
			name:        "18_upstream_8.2.35RC1_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.2.35RC1", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.2.35",
		},
		{
			name:        "19_upstream_8.2.34_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.2.34", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.2.35",
		},
		{
			name:        "20_upstream_8.2.0_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.2.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.2.35",
		},

		// --- EOL / Unclear upstream branches (8.1, 8.0, 7.4 and older) ---
		{
			name:        "21_branch_8.1.31_no_verified_upstream_fix",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.1.31", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "22_branch_8.0.30_no_verified_upstream_fix",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.0.30", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "23_branch_7.4.33_no_verified_upstream_fix",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "7.4.33", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "24_branch_7.3.33_older_branch_likely_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "7.3.33", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "25_branch_7.2.34_older_branch_likely_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "7.2.34", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "26_branch_5.6.40_older_branch_likely_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "5.6.40", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "27_branch_5.4.0_affected_min_likely_vulnerable",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "5.4.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},
		{
			name:        "28_branch_8.6.0_newer_than_affected_range_patched",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "8.6.0", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictPatched,
		},

		// --- Unparseable versions ---
		{
			name:        "29_unparseable_empty_version_unknown",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictUnknown,
		},
		{
			name:        "30_unparseable_garbage_version_unknown",
			adv:         seedAdv,
			inst:        inventory.PHPInstall{UpstreamVersion: "not-a-version", SAPI: inventory.SAPICLI},
			wantVerdict: match.VerdictUnknown,
		},

		// --- Distro-managed WITHOUT matching DistroFixes ---
		{
			name: "31_distro_managed_no_distrofix_below_fixed_in_is_likely_vulnerable",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.35",
				PackageManager:  "deb",
				PackageName:     "php8.3-cli",
				PackageVersion:  "8.3.35-1+deb12u1",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPICLI,
			},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantFixedIn: "8.3.36",
		},
		{
			name: "32_distro_managed_no_distrofix_at_fixed_in_is_patched",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.36",
				PackageManager:  "deb",
				PackageName:     "php8.3-cli",
				PackageVersion:  "8.3.36-1+deb12u1",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPICLI,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.36",
		},
		{
			name: "33_distro_managed_unverified_distrofix_falls_back_to_likely_vulnerable",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.1.2",
				PackageManager:  "deb",
				PackageName:     "php8.1-fpm",
				PackageVersion:  "8.1.2-1ubuntu2.20",
				Distro:          inventory.Distro{ID: "ubuntu", VersionID: "22.04"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictLikelyVulnerable,
			wantReason:  match.NoVerifiedUpstreamFixReason,
		},

		// --- Distro-managed WITH Verified DistroFixes (deb, rpm, apk) ---
		{
			name: "34_distro_deb_below_verified_fix_is_vulnerable",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.2.30",
				PackageManager:  "deb",
				PackageName:     "php8.2-fpm",
				PackageVersion:  "8.2.30-1+deb12u1",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.2.30-1+deb12u2",
		},
		{
			name: "35_distro_deb_equal_verified_fix_is_patched",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.2.30",
				PackageManager:  "deb",
				PackageName:     "php8.2-fpm",
				PackageVersion:  "8.2.30-1+deb12u2",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.2.30-1+deb12u2",
		},
		{
			name: "36_distro_deb_above_verified_fix_is_patched",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.2.30",
				PackageManager:  "deb",
				PackageName:     "php8.2-fpm",
				PackageVersion:  "8.2.30-1+deb12u3",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.2.30-1+deb12u2",
		},
		{
			name: "37_distro_rpm_below_verified_fix_is_vulnerable",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageManager:  "rpm",
				PackageName:     "php-fpm",
				PackageVersion:  "8.3.30-1.el9_4",
				Distro:          inventory.Distro{ID: "rocky", VersionID: "9.4"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.30-2.el9_4",
		},
		{
			name: "38_distro_rpm_equal_verified_fix_is_patched",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageManager:  "rpm",
				PackageName:     "php-fpm",
				PackageVersion:  "8.3.30-2.el9_4",
				Distro:          inventory.Distro{ID: "rocky", VersionID: "9.4"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.30-2.el9_4",
		},
		{
			name: "39_distro_apk_below_verified_fix_is_vulnerable",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageManager:  "apk",
				PackageName:     "php83-fpm",
				PackageVersion:  "8.3.30-r1",
				Distro:          inventory.Distro{ID: "alpine", VersionID: "3.20.3"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.30-r2",
		},
		{
			name: "40_distro_apk_above_verified_fix_is_patched",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageManager:  "apk",
				PackageName:     "php83-fpm",
				PackageVersion:  "8.3.30-r3",
				Distro:          inventory.Distro{ID: "alpine", VersionID: "3.20.3"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.30-r2",
		},

		// --- Mitigations per CVE (never changes verdict) ---
		{
			name: "41_mitigation_applied_on_8.3_does_not_change_vulnerable_verdict",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.35",
				SAPI:            inventory.SAPICLI,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
				},
				Evidence: []string{
					"ini:session.upload_progress.enabled=0 (source: php -i)",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationApplied,
			},
		},
		{
			name: "42_mitigation_not_applied_on_8.3",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.35",
				SAPI:            inventory.SAPICLI,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "1",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationNotApplied,
			},
		},
		{
			name: "43_mitigation_8.5_requires_both_settings_applied",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.5.11",
				SAPI:            inventory.SAPIFPM,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
					"fatal_error_backtraces":          "0",
				},
				Evidence: []string{
					"ini:session.upload_progress.enabled=0 (source: /etc/php/8.5/fpm/php.ini)",
					"ini:fatal_error_backtraces=0 (source: /etc/php/8.5/fpm/php.ini)",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationApplied,
			},
		},
		{
			name: "44_mitigation_8.5_partial_not_applied",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.5.11",
				SAPI:            inventory.SAPIFPM,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
					"fatal_error_backtraces":          "1",
				},
				Evidence: []string{
					"ini:session.upload_progress.enabled=0 (source: /etc/php/8.5/fpm/php.ini)",
					"ini:fatal_error_backtraces=1 (source: /etc/php/8.5/fpm/php.ini)",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationNotApplied,
			},
		},
		{
			name: "45_mitigation_from_cli_ini_only_is_unknown_for_fpm_sapi",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.35",
				SAPI:            inventory.SAPIFPM,
				ConfigFiles:     []string{"/etc/php/8.3/cli/php.ini"},
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
				},
				Evidence: []string{
					"ini:session.upload_progress.enabled=0 (source: /etc/php/8.3/cli/php.ini)",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationUnknown,
			},
		},
		{
			name: "46_mitigation_from_php_i_only_is_unknown_for_apache_sapi",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.35",
				SAPI:            inventory.SAPIApache2Handler,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
				},
				Evidence: []string{
					"ini:session.upload_progress.enabled=0 (source: php -i)",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.3.36",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationUnknown,
			},
		},
		{
			name: "47_distro_fallback_by_distro_id_when_package_manager_empty_deb",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.2.30",
				PackageName:     "php8.2-fpm",
				PackageVersion:  "8.2.30-1+deb12u2",
				Distro:          inventory.Distro{ID: "debian", VersionID: "12"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.2.30-1+deb12u2",
		},
		{
			name: "48_distro_fallback_by_distro_id_when_package_manager_empty_rpm",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageName:     "php-fpm",
				PackageVersion:  "8.3.30-2.el9_4",
				Distro:          inventory.Distro{ID: "rocky", VersionID: "9.4"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.30-2.el9_4",
		},
		{
			name: "49_distro_fallback_by_distro_id_when_package_manager_empty_apk",
			adv:  advWithDistroFixes,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.3.30",
				PackageName:     "php83-fpm",
				PackageVersion:  "8.3.30-r2",
				Distro:          inventory.Distro{ID: "alpine", VersionID: "3.20"},
				SAPI:            inventory.SAPIFPM,
			},
			wantVerdict: match.VerdictPatched,
			wantFixedIn: "8.3.30-r2",
		},
		{
			name: "50_mitigation_8.5_missing_second_setting_is_unknown",
			adv:  seedAdv,
			inst: inventory.PHPInstall{
				UpstreamVersion: "8.5.11",
				SAPI:            inventory.SAPICLI,
				IniSettings: map[string]string{
					"session.upload_progress.enabled": "0",
				},
			},
			wantVerdict: match.VerdictVulnerable,
			wantFixedIn: "8.5.12",
			wantMitigation: map[string]match.MitigationStatus{
				"CVE-2026-109618": match.MitigationNoneAvailable,
				"CVE-2026-109619": match.MitigationUnknown,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := match.Evaluate(tc.inst, tc.adv)

			if got.Verdict != tc.wantVerdict {
				t.Errorf("Verdict = %q, want %q (reason: %s)", got.Verdict, tc.wantVerdict, got.Reason)
			}
			if tc.wantReason != "" && got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if tc.wantFixedIn != "" && got.FixedIn != tc.wantFixedIn {
				t.Errorf("FixedIn = %q, want %q", got.FixedIn, tc.wantFixedIn)
			}
			for cve, wantMit := range tc.wantMitigation {
				if gotMit := got.Mitigation[cve]; gotMit != wantMit {
					t.Errorf("Mitigation[%s] = %q, want %q", cve, gotMit, wantMit)
				}
			}
		})
	}
}

func TestAggregationSeverityOrder(t *testing.T) {
	t.Parallel()

	// Order must be: VULNERABLE > LIKELY_VULNERABLE > UNKNOWN > PATCHED
	order := []match.Verdict{
		match.VerdictVulnerable,
		match.VerdictLikelyVulnerable,
		match.VerdictUnknown,
		match.VerdictPatched,
	}

	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			if match.CompareVerdictSeverity(order[i], order[j]) <= 0 {
				t.Errorf("expected %s > %s", order[i], order[j])
			}
			if match.CompareVerdictSeverity(order[j], order[i]) >= 0 {
				t.Errorf("expected %s < %s", order[j], order[i])
			}
		}
	}

	findings := []match.Finding{
		{Install: inventory.PHPInstall{ID: "3"}, Verdict: match.VerdictPatched},
		{Install: inventory.PHPInstall{ID: "2"}, Verdict: match.VerdictUnknown},
		{Install: inventory.PHPInstall{ID: "4"}, Verdict: match.VerdictLikelyVulnerable},
		{Install: inventory.PHPInstall{ID: "1"}, Verdict: match.VerdictVulnerable},
	}

	if got := match.HighestVerdict(findings); got != match.VerdictVulnerable {
		t.Fatalf("HighestVerdict = %q, want VULNERABLE", got)
	}

	match.SortFindings(findings)
	for i := range order {
		if findings[i].Verdict != order[i] {
			t.Errorf("sorted findings[%d].Verdict = %q, want %q", i, findings[i].Verdict, order[i])
		}
	}
}

func TestPathAndRemoteSourceVerdicts(t *testing.T) {
	t.Parallel()

	seedAdv := mustLoadSeedAdvisory(t)

	// Path mode floating tag -> UNKNOWN with FixedIn populated
	pathFloating := match.Evaluate(inventory.PHPInstall{
		UpstreamVersion: "php:8.3-fpm",
		Source:          inventory.SourcePath,
		Confidence:      inventory.ConfidenceMedium,
	}, seedAdv)
	if pathFloating.Verdict != match.VerdictUnknown {
		t.Errorf("pathFloating.Verdict = %q, want UNKNOWN", pathFloating.Verdict)
	}
	if pathFloating.FixedIn != "8.3.36" {
		t.Errorf("pathFloating.FixedIn = %q, want 8.3.36", pathFloating.FixedIn)
	}

	// Remote mode banner < FixedIn -> capped at LIKELY_VULNERABLE (never VULNERABLE) and labeled
	remoteBelow := match.Evaluate(inventory.PHPInstall{
		UpstreamVersion: "8.3.10",
		Source:          inventory.SourceRemote,
		Confidence:      inventory.ConfidenceLow,
	}, seedAdv)
	if remoteBelow.Verdict != match.VerdictLikelyVulnerable {
		t.Errorf("remoteBelow.Verdict = %q, want LIKELY_VULNERABLE", remoteBelow.Verdict)
	}
	if remoteBelow.Reason == "" {
		t.Error("remoteBelow.Reason should not be empty")
	}
}
