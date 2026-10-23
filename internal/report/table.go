package report

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

var fileLineRefRe = regexp.MustCompile(`([^\s()\[\],]+:\d+)`)

// PathModeSummaryNote is the required summary note displayed for path scans.
const PathModeSummaryNote = "Path mode reports what the repository declares, not what is running."

// InferredSAPIFootnote is the footnote printed when SAPI is inferred from an image tag.
const InferredSAPIFootnote = "* inferred from image tag"

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

	imgHeader, resolvedNote := formatImageHeaderAndNote(rep)
	if imgHeader != "" {
		_, _ = fmt.Fprintln(&buf, imgHeader)
		if resolvedNote != "" {
			_, _ = fmt.Fprintln(&buf, resolvedNote)
		}
	}

	if len(rep.Results) == 0 {
		_, _ = fmt.Fprintln(&buf, "No PHP installations discovered.")
	} else {
		var tableBuf bytes.Buffer
		tw := tabwriter.NewWriter(&tableBuf, 0, 0, 2, ' ', 0)
		hasPkg := hasDistroPackage(rep)
		if hasPkg {
			_, _ = fmt.Fprintln(tw, "TARGET\tSAPI\tVERSION\tPACKAGE\tVERDICT\tFIXED IN\tMITIGATION\tREASON")
		} else {
			_, _ = fmt.Fprintln(tw, "TARGET\tSAPI\tVERSION\tVERDICT\tFIXED IN\tMITIGATION\tREASON")
		}
		hasInferredSAPI := false
		for _, item := range rep.Results {
			f := item.Finding
			target := primaryTarget(f)
			fixedIn := displayFixedIn(f, rep.Advisory)
			sapiStr, inferred := displaySAPI(f)
			if inferred {
				hasInferredSAPI = true
			}
			ver := displayVersion(f)
			mitStr := displayMitigationVerbose(f, opts.Verbose)
			if hasPkg {
				pkgStr := formatPackageColumn(f)
				_, _ = fmt.Fprintf(
					tw,
					"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					target,
					sapiStr,
					ver,
					pkgStr,
					f.Verdict,
					fixedIn,
					mitStr,
					f.Reason,
				)
			} else {
				_, _ = fmt.Fprintf(
					tw,
					"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					target,
					sapiStr,
					ver,
					f.Verdict,
					fixedIn,
					mitStr,
					f.Reason,
				)
			}
			if opts.Verbose && len(f.Install.Evidence) > 0 {
				for _, ev := range f.Install.Evidence {
					_, _ = fmt.Fprintf(tw, "    %s\n", ev)
				}
			}
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flush report table: %w", err)
		}

		renderedTable := tableBuf.String()
		if !opts.NoColor {
			renderedTable = colorizeVerdicts(renderedTable)
		}
		_, _ = buf.WriteString(renderedTable)
		if hasInferredSAPI {
			_, _ = fmt.Fprintf(&buf, "%s\n", InferredSAPIFootnote)
		}
		if opts.Verbose {
			renderVerboseConfigFiles(&buf, rep.Results)
		}
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
	if isPathReport(rep) {
		_, _ = fmt.Fprintf(&buf, "%s\n", PathModeSummaryNote)
	}

	if !opts.Quiet && len(rep.Results) > 0 {
		_, _ = fmt.Fprintln(&buf, "\nRemediation Guidance:")
		recs := groupRemediations(rep.Results)
		for i, rec := range recs {
			if i > 0 {
				_, _ = fmt.Fprintln(&buf)
			}
			recText := remediate.FormatText(rec)
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
		"highest_verdict=NONE", "highest_verdict="+ansiCyan+"NONE"+ansiReset,
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

func displayVersion(f match.Finding) string {
	ver := strings.TrimSpace(f.Install.UpstreamVersion)
	if ver == "" {
		return "unknown"
	}
	norm := inventory.NormalizeImageRef(ver)
	if f.Install.Source == inventory.SourcePath && f.Install.PackageManager == "container" {
		if _, err := phpver.Parse(ver); err != nil {
			return fmt.Sprintf("unresolved (%s)", norm)
		}
	}
	return norm
}

func displaySAPI(f match.Finding) (string, bool) {
	sapi := string(f.Install.SAPI)
	if f.Install.Source == inventory.SourcePath &&
		f.Install.PackageManager == "container" &&
		f.Install.SAPI != "" &&
		f.Install.SAPI != inventory.SAPIUnknown {
		return sapi + "*", true
	}
	return sapi, false
}

func displayMitigation(f match.Finding) string {
	return displayMitigationVerbose(f, false)
}

func displayMitigationVerbose(f match.Finding, verbose bool) string {
	if f.Verdict == match.VerdictPatched {
		return "n/a (patched)"
	}
	if f.Install.Source == inventory.SourcePath {
		return string(match.MitigationUnknown)
	}
	if !verbose {
		return formatMitigationMap(f.Mitigation)
	}
	if len(f.Mitigation) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(f.Mitigation))
	for k := range f.Mitigation {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	winRef := winningMitigationFileLine(f.Install.Evidence)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		st := f.Mitigation[k]
		entry := fmt.Sprintf("%s=%s", k, st)
		if winRef != "" && (st == match.MitigationApplied || st == match.MitigationNotApplied) {
			entry = fmt.Sprintf("%s (%s)", entry, winRef)
		}
		parts = append(parts, entry)
	}
	return strings.Join(parts, ", ")
}

func winningMitigationFileLine(evidence []string) string {
	var best string
	for _, ev := range evidence {
		if !strings.HasPrefix(ev, "ini: ") {
			continue
		}
		matches := fileLineRefRe.FindAllString(ev, -1)
		if len(matches) > 0 {
			last := matches[len(matches)-1]
			best = path.Base(strings.ReplaceAll(last, `\`, "/"))
		}
	}
	return best
}

func renderVerboseConfigFiles(buf *bytes.Buffer, items []Item) {
	_, _ = fmt.Fprintln(buf, "\nConfig Files Parsed (precedence order):")
	for _, item := range items {
		f := item.Finding
		target := primaryTarget(f)
		sapi, _ := displaySAPI(f)
		if len(f.Install.ConfigFiles) == 0 {
			_, _ = fmt.Fprintf(buf, "  %s (%s): (none)\n", target, sapi)
			continue
		}
		_, _ = fmt.Fprintf(buf, "  %s (%s):\n", target, sapi)
		for i, cf := range f.Install.ConfigFiles {
			_, _ = fmt.Fprintf(buf, "    %d. %s\n", i+1, cf)
		}
	}
}

func isPathReport(rep Report) bool {
	if strings.EqualFold(rep.Mode, "path") {
		return true
	}
	for _, item := range rep.Results {
		if item.Finding.Install.Source == inventory.SourcePath {
			return true
		}
	}
	return false
}
