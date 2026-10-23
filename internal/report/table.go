package report

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[1;31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
)

// RenderTable renders the report in human-readable tabular format with optional ANSI colors
// and a summary footer counting findings per verdict.
func RenderTable(w io.Writer, rep Report, opts Options) error {
	var buf bytes.Buffer

	if len(rep.Results) == 0 {
		_, _ = fmt.Fprintln(&buf, "No PHP installations discovered.")
	} else {
		var tableBuf bytes.Buffer
		tw := tabwriter.NewWriter(&tableBuf, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TARGET\tSAPI\tVERSION\tVERDICT\tFIXED IN\tMITIGATION\tREASON")
		for _, item := range rep.Results {
			f := item.Finding
			target := primaryTarget(f)
			fixedIn := f.FixedIn
			if fixedIn == "" {
				fixedIn = "-"
			}
			ver := f.Install.UpstreamVersion
			if ver == "" {
				ver = "unknown"
			}
			mitStr := formatMitigationMap(f.Mitigation)
			_, _ = fmt.Fprintf(
				tw,
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				target,
				f.Install.SAPI,
				ver,
				f.Verdict,
				fixedIn,
				mitStr,
				f.Reason,
			)
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flush report table: %w", err)
		}

		renderedTable := tableBuf.String()
		if !opts.NoColor {
			renderedTable = colorizeVerdicts(renderedTable)
		}
		_, _ = buf.WriteString(renderedTable)
	}

	summaryLine := fmt.Sprintf(
		"\nSummary: total=%d vulnerable=%d likely_vulnerable=%d unknown=%d patched=%d highest_verdict=%s\n",
		rep.Summary.Total,
		rep.Summary.Vulnerable,
		rep.Summary.LikelyVulnerable,
		rep.Summary.Unknown,
		rep.Summary.Patched,
		rep.Summary.HighestVerdict,
	)
	if !opts.NoColor {
		summaryLine = colorizeSummaryVerdict(summaryLine)
	}
	_, _ = buf.WriteString(summaryLine)

	if !opts.Quiet && len(rep.Results) > 0 {
		_, _ = fmt.Fprintln(&buf, "\nRemediation Guidance:")
		for i, item := range rep.Results {
			if i > 0 {
				_, _ = fmt.Fprintln(&buf)
			}
			recText := remediate.FormatText(item.Recommendation)
			if !opts.NoColor {
				recText = colorizeRemediationText(recText)
			}
			_, _ = buf.WriteString(recText)
		}
	}

	if !opts.Quiet && len(rep.HuntHints) > 0 {
		_, _ = fmt.Fprintln(&buf, "\nLog-Review Indicators (--hunt):")
		for _, h := range rep.HuntHints {
			_, _ = fmt.Fprintf(&buf, "  - %s\n", h)
		}
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write table report: %w", err)
	}
	return nil
}

func colorizeVerdicts(tableText string) string {
	replacer := strings.NewReplacer(
		"  LIKELY_VULNERABLE  ", "  "+ansiYellow+"LIKELY_VULNERABLE"+ansiReset+"  ",
		"  VULNERABLE  ", "  "+ansiRed+"VULNERABLE"+ansiReset+"  ",
		"  UNKNOWN  ", "  "+ansiCyan+"UNKNOWN"+ansiReset+"  ",
		"  PATCHED  ", "  "+ansiGreen+"PATCHED"+ansiReset+"  ",
		"=NOT_APPLIED", "="+ansiRed+"NOT_APPLIED"+ansiReset,
		"=APPLIED", "="+ansiGreen+"APPLIED"+ansiReset,
	)
	return replacer.Replace(tableText)
}

func colorizeSummaryVerdict(summaryLine string) string {
	replacer := strings.NewReplacer(
		"highest_verdict=VULNERABLE", "highest_verdict="+ansiRed+"VULNERABLE"+ansiReset,
		"highest_verdict=LIKELY_VULNERABLE", "highest_verdict="+ansiYellow+"LIKELY_VULNERABLE"+ansiReset,
		"highest_verdict=UNKNOWN", "highest_verdict="+ansiCyan+"UNKNOWN"+ansiReset,
		"highest_verdict=PATCHED", "highest_verdict="+ansiGreen+"PATCHED"+ansiReset,
	)
	return replacer.Replace(summaryLine)
}

func colorizeRemediationText(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		indent := line[:len(line)-len(trimmed)]

		switch {
		case strings.HasPrefix(trimmed, "--- ") || (strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "- ")):
			lines[i] = indent + ansiRed + trimmed + ansiReset
		case strings.HasPrefix(trimmed, "+++ ") || strings.HasPrefix(trimmed, "+"):
			lines[i] = indent + ansiGreen + trimmed + ansiReset
		case strings.HasPrefix(line, "Priority: P0"):
			lines[i] = "Priority: " + ansiRed + "P0" + ansiReset
		case strings.HasPrefix(line, "Priority: P1"), strings.HasPrefix(line, "Priority: P2"):
			p := strings.TrimPrefix(line, "Priority: ")
			lines[i] = "Priority: " + ansiYellow + p + ansiReset
		case strings.HasPrefix(line, "Priority: P3"):
			lines[i] = "Priority: " + ansiCyan + "P3" + ansiReset
		case strings.HasPrefix(line, "Notes:    WARNING:"):
			lines[i] = strings.Replace(line, "WARNING:", ansiYellow+"WARNING:"+ansiReset, 1)
		}
	}
	return strings.Join(lines, "\n")
}

func formatMitigationMap(m map[string]match.MitigationStatus) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
