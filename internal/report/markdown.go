package report

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

// RenderMarkdown renders a comprehensive Markdown assessment report suitable for a pentest appendix.
func RenderMarkdown(w io.Writer, rep Report, _ Options) error {
	var b bytes.Buffer

	_, _ = fmt.Fprintf(&b, "# PHP2Shell Assessment Report (%s)\n\n", rep.Advisory.ID)
	_, _ = fmt.Fprintf(&b, "- **Tool Version:** `%s`\n", rep.ToolVersion)
	_, _ = fmt.Fprintf(&b, "- **Scan Mode:** `%s`\n", rep.Mode)
	_, _ = fmt.Fprintf(&b, "- **CVEs Assessed:** `%s`\n", strings.Join(rep.Advisory.CVEs, "`, `"))
	_, _ = fmt.Fprintf(&b, "- **Advisory Verified:** `%t`\n", rep.Advisory.Verified)
	_, _ = fmt.Fprintf(&b, "- **Affected Upstream Range:** `%s` through `%s` (inclusive)\n\n", rep.Advisory.AffectedMin, rep.Advisory.AffectedMaxInclusive)

	_, _ = fmt.Fprintln(&b, "## Executive Summary")
	_, _ = fmt.Fprintln(&b)
	_, _ = fmt.Fprintln(&b, "| Metric | Value |")
	_, _ = fmt.Fprintln(&b, "| :--- | :--- |")
	_, _ = fmt.Fprintf(&b, "| Total Installations Discovered | %d |\n", rep.Summary.Total)
	_, _ = fmt.Fprintf(&b, "| `VULNERABLE` | %d |\n", rep.Summary.Vulnerable)
	_, _ = fmt.Fprintf(&b, "| `LIKELY_VULNERABLE` | %d |\n", rep.Summary.LikelyVulnerable)
	_, _ = fmt.Fprintf(&b, "| `UNKNOWN` | %d |\n", rep.Summary.Unknown)
	_, _ = fmt.Fprintf(&b, "| `PATCHED` | %d |\n", rep.Summary.Patched)
	_, _ = fmt.Fprintf(&b, "| **Highest Severity Verdict** | `%s` |\n\n", rep.Summary.HighestVerdict)
	if isPathReport(rep) {
		_, _ = fmt.Fprintf(&b, "> **Note:** %s\n\n", PathModeSummaryNote)
	}

	_, _ = fmt.Fprintln(&b, "## Findings Overview")
	_, _ = fmt.Fprintln(&b)
	if len(rep.Results) == 0 {
		_, _ = fmt.Fprintln(&b, "_No PHP installations were discovered in the target scope._")
		_, _ = fmt.Fprintln(&b)
	} else {
		_, _ = fmt.Fprintln(&b, "| Target | SAPI | Version | Verdict | Fixed In | Mitigation | Priority |")
		_, _ = fmt.Fprintln(&b, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
		hasInferredSAPI := false
		for _, item := range rep.Results {
			f := item.Finding
			fixedIn := f.FixedIn
			if fixedIn == "" {
				fixedIn = "-"
			}
			sapiStr, inferred := displaySAPI(f)
			if inferred {
				hasInferredSAPI = true
			}
			ver := displayVersion(f)
			_, _ = fmt.Fprintf(
				&b,
				"| `%s` | `%s` | `%s` | **`%s`** | `%s` | `%s` | `%s` |\n",
				primaryTarget(f),
				sapiStr,
				ver,
				f.Verdict,
				fixedIn,
				displayMitigation(f),
				item.Recommendation.Priority,
			)
		}
		_, _ = fmt.Fprintln(&b)
		if hasInferredSAPI {
			_, _ = fmt.Fprintf(&b, "_%s_\n\n", InferredSAPIFootnote)
		}

		_, _ = fmt.Fprintln(&b, "## Per-Finding Evidence & Remediation")
		_, _ = fmt.Fprintln(&b)
		for i, item := range rep.Results {
			f := item.Finding
			rec := item.Recommendation
			sapiStr, _ := displaySAPI(f)
			_, _ = fmt.Fprintf(&b, "### %d. `%s` (%s)\n\n", i+1, primaryTarget(f), f.Verdict)
			_, _ = fmt.Fprintf(&b, "- **Priority:** `%s`\n", rec.Priority)
			_, _ = fmt.Fprintf(&b, "- **SAPI:** `%s`\n", sapiStr)
			upstreamVer := inventory.NormalizeImageRef(f.Install.UpstreamVersion)
			if f.Install.Source == inventory.SourcePath && upstreamVer != "" {
				upstreamVer = displayVersion(f)
			}
			_, _ = fmt.Fprintf(&b, "- **Upstream Version:** `%s`\n", upstreamVer)
			if f.Install.PackageName != "" {
				_, _ = fmt.Fprintf(&b, "- **Package:** `%s` (`%s`, manager: `%s`)\n", inventory.NormalizeImageRef(f.Install.PackageName), f.Install.PackageVersion, f.Install.PackageManager)
			}
			if f.Install.Distro.ID != "" {
				_, _ = fmt.Fprintf(&b, "- **Distribution:** `%s %s`\n", f.Install.Distro.ID, f.Install.Distro.VersionID)
			}
			_, _ = fmt.Fprintf(&b, "- **Reason:** %s\n", f.Reason)
			_, _ = fmt.Fprintf(&b, "- **Mitigation Status:** `%s`\n\n", displayMitigation(f))

			if len(f.Install.Evidence) > 0 {
				_, _ = fmt.Fprintln(&b, "#### Evidence")
				_, _ = fmt.Fprintln(&b)
				for _, ev := range f.Install.Evidence {
					_, _ = fmt.Fprintf(&b, "- `%s`\n", ev)
				}
				_, _ = fmt.Fprintln(&b)
			}

			_, _ = fmt.Fprintln(&b, "#### Recommended Remediation")
			_, _ = fmt.Fprintln(&b)
			for _, step := range rec.Steps {
				if strings.Contains(step, "\n") {
					lines := strings.SplitN(step, "\n", 2)
					_, _ = fmt.Fprintf(&b, "- %s\n\n```diff\n%s\n```\n\n", lines[0], lines[1])
				} else {
					_, _ = fmt.Fprintf(&b, "- %s\n", step)
				}
			}
			if len(rec.Commands) > 0 {
				_, _ = fmt.Fprintln(&b, "\n**Commands (display only):**")
				for _, cmd := range rec.Commands {
					_, _ = fmt.Fprintf(&b, "- %s: `%s`\n", cmd.Label, cmd.Text)
				}
			}
			if len(rec.RestartHints) > 0 {
				_, _ = fmt.Fprintln(&b, "\n**Restart Hints:**")
				for _, rh := range rec.RestartHints {
					_, _ = fmt.Fprintf(&b, "- %s\n", rh)
				}
			}
			if rec.Notes != "" {
				_, _ = fmt.Fprintf(&b, "\n> %s\n", rec.Notes)
			}
			_, _ = fmt.Fprintln(&b)
		}
	}

	if len(rep.HuntHints) > 0 {
		_, _ = fmt.Fprintln(&b, "## Log-Review Indicators (`--hunt`)")
		_, _ = fmt.Fprintln(&b)
		for _, h := range rep.HuntHints {
			_, _ = fmt.Fprintf(&b, "- %s\n", h)
		}
		_, _ = fmt.Fprintln(&b)
	}

	_, _ = fmt.Fprintln(&b, "## Limitations & Assessment Notes")
	_, _ = fmt.Fprintln(&b)
	_, _ = fmt.Fprintln(&b, "- **Read-Only Discovery:** `php2shell-check` performs passive version and configuration inspection without sending exploit payloads or executing untrusted binaries.")
	_, _ = fmt.Fprintln(&b, "- **Configuration Mitigations:** INI or FPM pool mitigations apply only to `CVE-2026-109619` and never alter the vulnerability verdict. `CVE-2026-109618` has no known configuration mitigation.")
	_, _ = fmt.Fprintf(&b, "- **Vendor Backports:** When `advisory.verified` is `false` or distribution backport versions are not listed in `distro_fixes`, distro-managed packages below the upstream fix version are reported as `LIKELY_VULNERABLE`.\n")
	if len(rep.HuntHints) > 0 {
		_, _ = fmt.Fprintf(&b, "- **Log Hunting Disclaimer:** %s\n", remediate.HuntDisclaimer)
	}

	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}
