package cli_test

import (
	"errors"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/cli"
)

func TestExitCodeForFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []cli.Finding
		failOn   cli.FailOn
		want     int
	}{
		{
			name:     "no findings returns clean",
			findings: nil,
			failOn:   cli.FailOnLikely,
			want:     cli.ExitCodeClean,
		},
		{
			name: "only patched findings returns clean",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictPatched, Verified: true},
				{CVE: "CVE-2026-109619", Verdict: cli.VerdictPatched, Verified: true},
			},
			failOn: cli.FailOnUnknown,
			want:   cli.ExitCodeClean,
		},
		{
			name: "vulnerable finding fails on vulnerable threshold",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictVulnerable, Verified: true},
			},
			failOn: cli.FailOnVulnerable,
			want:   cli.ExitCodeVulnerable,
		},
		{
			name: "vulnerable finding fails on likely threshold",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictVulnerable, Verified: true},
			},
			failOn: cli.FailOnLikely,
			want:   cli.ExitCodeVulnerable,
		},
		{
			name: "vulnerable finding fails on unknown threshold",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictVulnerable, Verified: true},
			},
			failOn: cli.FailOnUnknown,
			want:   cli.ExitCodeVulnerable,
		},
		{
			name: "vulnerable finding returns clean when fail-on is never",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictVulnerable, Verified: true},
			},
			failOn: cli.FailOnNever,
			want:   cli.ExitCodeClean,
		},
		{
			name: "config mitigation never changes vulnerable verdict or exit code",
			findings: []cli.Finding{
				{
					CVE:              "CVE-2026-109618",
					Verdict:          cli.VerdictVulnerable,
					Verified:         true,
					ConfigMitigated:  true,
					ConfigMitigation: "file_uploads = Off",
				},
			},
			failOn: cli.FailOnVulnerable,
			want:   cli.ExitCodeVulnerable,
		},
		{
			name: "likely vulnerable returns clean when fail-on is vulnerable",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
			},
			failOn: cli.FailOnVulnerable,
			want:   cli.ExitCodeClean,
		},
		{
			name: "likely vulnerable returns exit code 2 when fail-on is likely",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
			},
			failOn: cli.FailOnLikely,
			want:   cli.ExitCodeLikelyOrUnknown,
		},
		{
			name: "likely vulnerable with empty fail-on defaults to likely and returns 2",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
			},
			failOn: "",
			want:   cli.ExitCodeLikelyOrUnknown,
		},
		{
			name: "config mitigation never changes likely vulnerable exit code",
			findings: []cli.Finding{
				{
					CVE:              "CVE-2026-109619",
					Verdict:          cli.VerdictLikelyVulnerable,
					Verified:         false,
					ConfigMitigated:  true,
					ConfigMitigation: "disable_functions configured",
				},
			},
			failOn: cli.FailOnLikely,
			want:   cli.ExitCodeLikelyOrUnknown,
		},
		{
			name: "likely vulnerable returns exit code 2 when fail-on is unknown",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
			},
			failOn: cli.FailOnUnknown,
			want:   cli.ExitCodeLikelyOrUnknown,
		},
		{
			name: "unknown finding returns clean when fail-on is vulnerable",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
			},
			failOn: cli.FailOnVulnerable,
			want:   cli.ExitCodeClean,
		},
		{
			name: "unknown finding returns clean when fail-on is likely",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
			},
			failOn: cli.FailOnLikely,
			want:   cli.ExitCodeClean,
		},
		{
			name: "unknown finding returns exit code 2 when fail-on is unknown",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
			},
			failOn: cli.FailOnUnknown,
			want:   cli.ExitCodeLikelyOrUnknown,
		},
		{
			name: "unknown finding returns clean when fail-on is never",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
			},
			failOn: cli.FailOnNever,
			want:   cli.ExitCodeClean,
		},
		{
			name: "mixed findings prioritizes vulnerable exit code 1 over likely and unknown",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictPatched, Verified: true},
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
				{CVE: "CVE-2026-109619", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
				{CVE: "CVE-2026-109619", Verdict: cli.VerdictVulnerable, Verified: true},
			},
			failOn: cli.FailOnUnknown,
			want:   cli.ExitCodeVulnerable,
		},
		{
			name: "mixed likely and unknown returns exit code 2 on likely threshold",
			findings: []cli.Finding{
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictPatched, Verified: true},
				{CVE: "CVE-2026-109618", Verdict: cli.VerdictUnknown, Verified: false},
				{CVE: "CVE-2026-109619", Verdict: cli.VerdictLikelyVulnerable, Verified: false},
			},
			failOn: cli.FailOnLikely,
			want:   cli.ExitCodeLikelyOrUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := cli.ExitCodeForFindings(tc.findings, tc.failOn)
			if got != tc.want {
				t.Fatalf("ExitCodeForFindings() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseFailOn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		want    cli.FailOn
		wantErr bool
	}{
		{raw: "vulnerable", want: cli.FailOnVulnerable},
		{raw: "likely", want: cli.FailOnLikely},
		{raw: "unknown", want: cli.FailOnUnknown},
		{raw: "never", want: cli.FailOnNever},
		{raw: "invalid", wantErr: true},
		{raw: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := cli.ParseFailOn(tc.raw)
			if tc.wantErr {
				if !errors.Is(err, cli.ErrInvalidFailOn) {
					t.Fatalf("ParseFailOn(%q) error = %v, want %v", tc.raw, err, cli.ErrInvalidFailOn)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFailOn(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseFailOn(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseOutputFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		want    cli.OutputFormat
		wantErr bool
	}{
		{raw: "table", want: cli.FormatTable},
		{raw: "json", want: cli.FormatJSON},
		{raw: "sarif", want: cli.FormatSARIF},
		{raw: "md", want: cli.FormatMD},
		{raw: "xml", wantErr: true},
		{raw: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, err := cli.ParseOutputFormat(tc.raw)
			if tc.wantErr {
				if !errors.Is(err, cli.ErrInvalidFormat) {
					t.Fatalf("ParseOutputFormat(%q) error = %v, want %v", tc.raw, err, cli.ErrInvalidFormat)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOutputFormat(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseOutputFormat(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
