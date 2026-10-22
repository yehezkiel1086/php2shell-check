package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/yehezkiel1086/php2shell-check/internal/match"
)

// RenderSARIF serializes the Report as a SARIF 2.1.0 document using github.com/owenrumney/go-sarif/v2.
// One rule is registered per CVE, results are anchored to the binary/module path or image reference,
// and level is mapped from verdict (VULNERABLE -> error, LIKELY_VULNERABLE -> warning, UNKNOWN -> note).
func RenderSARIF(w io.Writer, rep Report) error {
	doc, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("initialize sarif 2.1.0 report: %w", err)
	}

	driver := sarif.NewVersionedDriver("php2shell-check", rep.ToolVersion)
	run := sarif.NewRun(*sarif.NewTool(driver))

	for _, cve := range rep.Advisory.CVEs {
		shortDesc := fmt.Sprintf("%s: %s", cve, rep.Advisory.Title)
		fullDesc := rep.Advisory.Summary
		if fullDesc == "" {
			fullDesc = shortDesc
		}
		run.AddRule(cve).
			WithName(cve).
			WithShortDescription(sarif.NewMultiformatMessageString(shortDesc)).
			WithFullDescription(sarif.NewMultiformatMessageString(fullDesc)).
			WithTextHelp(fmt.Sprintf("Affected PHP range: %s through %s (inclusive).", rep.Advisory.AffectedMin, rep.Advisory.AffectedMaxInclusive))
	}

	for _, item := range rep.Results {
		f := item.Finding
		level, include := sarifLevelForVerdict(f.Verdict)
		if !include {
			continue
		}

		uri := strings.TrimPrefix(primaryTarget(f), "/")
		if uri == "" {
			uri = "php"
		}

		cves := f.CVEs
		if len(cves) == 0 {
			cves = rep.Advisory.CVEs
		}

		for _, cve := range cves {
			mitStatus := f.Mitigation[cve]
			msgText := fmt.Sprintf(
				"[%s] %s on %s (SAPI: %s, version: %s): %s (mitigation: %s, priority: %s)",
				f.Verdict,
				cve,
				primaryTarget(f),
				f.Install.SAPI,
				f.Install.UpstreamVersion,
				f.Reason,
				mitStatus,
				item.Recommendation.Priority,
			)

			physLoc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(uri))
			loc := sarif.NewLocationWithPhysicalLocation(physLoc)

			res := sarif.NewRuleResult(cve).
				WithLevel(level).
				WithMessage(sarif.NewTextMessage(msgText)).
				WithLocations([]*sarif.Location{loc})

			run.AddResult(res)
		}
	}

	doc.AddRun(run)
	if err := doc.PrettyWrite(w); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	return nil
}

func sarifLevelForVerdict(v match.Verdict) (string, bool) {
	switch v {
	case match.VerdictVulnerable:
		return "error", true
	case match.VerdictLikelyVulnerable:
		return "warning", true
	case match.VerdictUnknown:
		return "note", true
	case match.VerdictPatched:
		return "none", false
	default:
		return "note", true
	}
}
