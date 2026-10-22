package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
)

func newScanCmd(opts *GlobalOptions) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan targets for CVE-2026-109618 and CVE-2026-109619 exposure",
		Long:  "Scan local hosts, container images, SBOM files, filesystem paths, or remote HTTP headers.",
	}

	scanCmd.AddCommand(
		newScanLocalCmd(opts),
		newScanImageCmd(opts),
		newScanSBOMCmd(opts),
		newScanPathCmd(opts),
		newScanRemoteCmd(opts),
	)

	return scanCmd
}

func newScanLocalCmd(opts *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Scan the local host for PHP installations, packages, and configuration (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("scan local load advisory: %w", err)
			}

			collector := local.NewDefaultCollector()
			installs, err := collector.Collect(cmd.Context())
			if err != nil {
				return fmt.Errorf("scan local collect: %w", err)
			}

			findings := match.EvaluateAll(installs, adv)
			if writeErr := writeFindingsOutput(cmd, opts, findings); writeErr != nil {
				return writeErr
			}

			failOn, err := ParseFailOn(opts.FailOn)
			if err != nil {
				return err
			}
			code := ExitCodeForFindings(FromMatchFindings(findings), failOn)
			if code != ExitCodeClean {
				return &findingExitError{code: code}
			}
			return nil
		},
	}
}

func writeFindingsOutput(cmd *cobra.Command, opts *GlobalOptions, findings []match.Finding) error {
	format, err := ParseOutputFormat(opts.Format)
	if err != nil {
		return err
	}

	if findings == nil {
		findings = []match.Finding{}
	}

	var buf bytes.Buffer
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			return fmt.Errorf("encode findings JSON: %w", err)
		}
	case FormatTable, FormatMD, FormatSARIF:
		if err := renderFindingsTable(&buf, findings); err != nil {
			return fmt.Errorf("render findings table: %w", err)
		}
	}

	if opts.OutputFile != "" {
		if err := os.WriteFile(opts.OutputFile, buf.Bytes(), 0o600); err != nil {
			return fmt.Errorf("write output file %q: %w", opts.OutputFile, err)
		}
		return nil
	}

	if _, err := cmd.OutOrStdout().Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write scan output: %w", err)
	}
	return nil
}

func renderFindingsTable(buf *bytes.Buffer, findings []match.Finding) error {
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(buf, "No PHP installations discovered.")
		return nil
	}

	tw := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TARGET\tSAPI\tVERSION\tVERDICT\tFIXED IN\tMITIGATION\tREASON")
	for _, f := range findings {
		target := f.Install.BinaryPath
		if target == "" {
			target = f.Install.ModulePath
		}
		fixedIn := f.FixedIn
		if fixedIn == "" {
			fixedIn = "-"
		}
		mitStr := formatMitigationMap(f.Mitigation)
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			target,
			f.Install.SAPI,
			f.Install.UpstreamVersion,
			f.Verdict,
			fixedIn,
			mitStr,
			f.Reason,
		)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush findings table: %w", err)
	}
	return nil
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

func newScanImageCmd(_ *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "image [IMAGE_OR_TAR]",
		Short: "Scan a container image or archive for PHP installations (read-only, no binary execution)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("scan image: %w", ErrNotImplemented)
		},
	}
}

func newScanSBOMCmd(_ *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sbom [FILE]",
		Short: "Scan an SBOM (CycloneDX or SPDX) for PHP packages",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("scan sbom: %w", ErrNotImplemented)
		},
	}
}

func newScanPathCmd(_ *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "path [DIR]",
		Short: "Scan a filesystem path or rootfs directory for PHP installations",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("scan path: %w", ErrNotImplemented)
		},
	}
}

func newScanRemoteCmd(_ *GlobalOptions) *cobra.Command {
	var authorized bool

	cmd := &cobra.Command{
		Use:   "remote [URL]",
		Short: "Passively inspect HTTP response headers of a remote target (requires --authorized)",
		RunE: func(_ *cobra.Command, _ []string) error {
			_ = authorized
			return fmt.Errorf("scan remote: %w", ErrNotImplemented)
		},
	}

	cmd.Flags().BoolVar(&authorized, "authorized", false, "Confirm explicit authorization to perform a passive header check")
	return cmd
}
