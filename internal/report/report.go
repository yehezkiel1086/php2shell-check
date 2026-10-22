package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

// SchemaVersion is the semantic version of the JSON report schema.
const SchemaVersion = "1.0.0"

// Supported output format names.
const (
	FormatTable = "table"
	FormatJSON  = "json"
	FormatSARIF = "sarif"
	FormatMD    = "md"
)

// ErrUnsupportedFormat indicates an unknown report rendering format.
var ErrUnsupportedFormat = errors.New("unsupported report format")

var secretAssignmentRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key)\s*([:=])\s*\S+`)

// Summary aggregates finding counts by verdict and tracks the highest severity verdict.
type Summary struct {
	Total            int           `json:"total"`
	Vulnerable       int           `json:"vulnerable"`
	LikelyVulnerable int           `json:"likely_vulnerable"`
	Unknown          int           `json:"unknown"`
	Patched          int           `json:"patched"`
	HighestVerdict   match.Verdict `json:"highest_verdict"`
}

// Item pairs a single assessment Finding with its Remediation Recommendation.
type Item struct {
	Finding        match.Finding            `json:"finding"`
	Recommendation remediate.Recommendation `json:"recommendation"`
}

// Report is the top-level assessment report structure serialized across formats.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	ToolVersion   string            `json:"tool_version"`
	Mode          string            `json:"mode"`
	Advisory      advisory.Advisory `json:"advisory"`
	Summary       Summary           `json:"summary"`
	Results       []Item            `json:"results"`
	HuntHints     []string          `json:"hunt_hints,omitempty"`
}

// Options controls report construction and rendering behavior.
type Options struct {
	Format      string
	NoColor     bool
	Quiet       bool
	IncludeHunt bool
	ToolVersion string
	Mode        string
}

// Build constructs a sanitized Report from findings, recommendations, and advisory metadata.
func Build(findings []match.Finding, recs []remediate.Recommendation, adv advisory.Advisory, opts Options) Report {
	toolVer := opts.ToolVersion
	if toolVer == "" {
		toolVer = "dev"
	}
	mode := opts.Mode
	if mode == "" {
		mode = "local"
	}

	items := make([]Item, 0, len(findings))
	var summary Summary
	summary.Total = len(findings)
	summary.HighestVerdict = match.HighestVerdict(findings)

	for i, f := range findings {
		sanitizedFinding := sanitizeFinding(f)
		var rec remediate.Recommendation
		if i < len(recs) {
			rec = recs[i]
		} else {
			rec = remediate.Build(sanitizedFinding, adv, remediate.Options{IncludeHuntHints: opts.IncludeHunt})
		}

		switch sanitizedFinding.Verdict {
		case match.VerdictVulnerable:
			summary.Vulnerable++
		case match.VerdictLikelyVulnerable:
			summary.LikelyVulnerable++
		case match.VerdictUnknown:
			summary.Unknown++
		case match.VerdictPatched:
			summary.Patched++
		}

		items = append(items, Item{
			Finding:        sanitizedFinding,
			Recommendation: rec,
		})
	}

	var huntHints []string
	if opts.IncludeHunt {
		huntHints = remediate.HuntHints()
	}

	return Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   toolVer,
		Mode:          mode,
		Advisory:      adv,
		Summary:       summary,
		Results:       items,
		HuntHints:     huntHints,
	}
}

// Render writes rep in the requested format to w.
func Render(w io.Writer, rep Report, opts Options) error {
	format := opts.Format
	if format == "" {
		format = FormatTable
	}

	switch format {
	case FormatTable:
		return RenderTable(w, rep, opts)
	case FormatJSON:
		return RenderJSON(w, rep)
	case FormatSARIF:
		return RenderSARIF(w, rep)
	case FormatMD:
		return RenderMarkdown(w, rep, opts)
	default:
		return fmt.Errorf("%q: %w", format, ErrUnsupportedFormat)
	}
}

// WriteToFileOrWriter renders rep to outputFile if non-empty, or to fallbackWriter otherwise.
func WriteToFileOrWriter(outputFile string, fallbackWriter io.Writer, rep Report, opts Options) error {
	var buf bytes.Buffer
	if err := Render(&buf, rep, opts); err != nil {
		return err
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, buf.Bytes(), 0o600); err != nil {
			return fmt.Errorf("write report file %q: %w", outputFile, err)
		}
		return nil
	}

	if _, err := fallbackWriter.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write report output: %w", err)
	}
	return nil
}

// RedactSecrets scrubs potential credential or token assignments from an evidence line.
func RedactSecrets(line string) string {
	return secretAssignmentRe.ReplaceAllString(line, "$1$2[REDACTED]")
}

func sanitizeFinding(f match.Finding) match.Finding {
	out := f
	if len(f.Install.Evidence) > 0 {
		ev := make([]string, len(f.Install.Evidence))
		for i, line := range f.Install.Evidence {
			ev[i] = RedactSecrets(line)
		}
		out.Install.Evidence = ev
	}
	return out
}

func primaryTarget(f match.Finding) string {
	if f.Install.BinaryPath != "" {
		return f.Install.BinaryPath
	}
	if f.Install.ModulePath != "" {
		return f.Install.ModulePath
	}
	if f.Install.PackageName != "" {
		return f.Install.PackageName
	}
	if f.Install.ID != "" {
		return f.Install.ID
	}
	return "unknown"
}
