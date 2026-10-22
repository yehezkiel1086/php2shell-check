package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
)

func newAdvisoriesCmd(opts *GlobalOptions) *cobra.Command {
	advisoriesCmd := &cobra.Command{
		Use:   "advisories",
		Short: "Inspect embedded or custom CVE advisories",
	}

	advisoriesCmd.AddCommand(newAdvisoriesListCmd(opts))
	return advisoriesCmd
}

func newAdvisoriesListCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List advisories for CVE-2026-109618 and CVE-2026-109619",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("load advisories: %w", err)
			}

			var buf bytes.Buffer
			format, err := ParseOutputFormat(opts.Format)
			if err != nil {
				return err
			}

			switch format {
			case FormatJSON:
				enc := json.NewEncoder(&buf)
				enc.SetIndent("", "  ")
				if err := enc.Encode(adv); err != nil {
					return fmt.Errorf("encode advisories JSON: %w", err)
				}
			case FormatTable, FormatMD, FormatSARIF:
				if err := renderAdvisoryTable(&buf, adv); err != nil {
					return fmt.Errorf("render advisories: %w", err)
				}
			}

			if opts.OutputFile != "" {
				if err := os.WriteFile(opts.OutputFile, buf.Bytes(), 0o600); err != nil {
					return fmt.Errorf("write output file %q: %w", opts.OutputFile, err)
				}
				return nil
			}

			if _, err := cmd.OutOrStdout().Write(buf.Bytes()); err != nil {
				return fmt.Errorf("write advisories output: %w", err)
			}
			return nil
		},
	}
}

func renderAdvisoryTable(buf *bytes.Buffer, adv advisory.Advisory) error {
	_, _ = fmt.Fprintf(buf, "ID:             %s\n", adv.ID)
	_, _ = fmt.Fprintf(buf, "CVEs:           %s\n", strings.Join(adv.CVEs, ", "))
	_, _ = fmt.Fprintf(buf, "Title:          %s\n", adv.Title)
	_, _ = fmt.Fprintf(buf, "Verified:       %t\n", adv.Verified)
	_, _ = fmt.Fprintf(buf, "Affected Range: %s .. %s (inclusive)\n", adv.AffectedMin, adv.AffectedMaxInclusive)
	if adv.Summary != "" {
		_, _ = fmt.Fprintf(buf, "Summary:        %s\n", adv.Summary)
	}

	_, _ = fmt.Fprintln(buf, "\nBranches:")
	tw := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  BRANCH\tFIXED IN\tEOL\tUPSTREAM FIX\tNOTES")
	for _, b := range adv.Branches {
		fixedIn := b.FixedIn
		if fixedIn == "" {
			fixedIn = "-"
		}
		upstreamFix := "null"
		if b.UpstreamFixAvailable != nil {
			upstreamFix = fmt.Sprintf("%t", *b.UpstreamFixAvailable)
		}
		notes := b.Notes
		if notes == "" {
			notes = "-"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%t\t%s\t%s\n", b.Branch, fixedIn, b.EOL, upstreamFix, notes)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush branch table: %w", err)
	}

	_, _ = fmt.Fprintln(buf, "\nMitigations:")
	if len(adv.Mitigations) == 0 {
		_, _ = fmt.Fprintln(buf, "  (none)")
	} else {
		mtw := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(mtw, "  CVE\tINI KEY\tRECOMMENDED\tBRANCH\tNOTE")
		for _, m := range adv.Mitigations {
			_, _ = fmt.Fprintf(mtw, "  %s\t%s\t%s\t%s\t%s\n", m.CVE, m.IniKey, m.RecommendedValue, m.AppliesToBranch, m.Note)
		}
		if err := mtw.Flush(); err != nil {
			return fmt.Errorf("flush mitigations table: %w", err)
		}
	}

	_, _ = fmt.Fprintf(buf, "\nDistro Fixes:   %d\n", len(adv.DistroFixes))
	return nil
}
