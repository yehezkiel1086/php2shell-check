package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
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
			collector := local.NewDefaultCollector()
			installs, err := collector.Collect(cmd.Context())
			if err != nil {
				return fmt.Errorf("scan local: %w", err)
			}

			return writeInstallsOutput(cmd, opts, installs)
		},
	}
}

func writeInstallsOutput(cmd *cobra.Command, opts *GlobalOptions, installs []inventory.PHPInstall) error {
	format, err := ParseOutputFormat(opts.Format)
	if err != nil {
		return err
	}

	if installs == nil {
		installs = []inventory.PHPInstall{}
	}

	var buf bytes.Buffer
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(installs); err != nil {
			return fmt.Errorf("encode installs JSON: %w", err)
		}
	case FormatTable, FormatMD, FormatSARIF:
		if err := renderInstallsTable(&buf, installs); err != nil {
			return fmt.Errorf("render installs table: %w", err)
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

func renderInstallsTable(buf *bytes.Buffer, installs []inventory.PHPInstall) error {
	if len(installs) == 0 {
		_, _ = fmt.Fprintln(buf, "No PHP installations discovered.")
		return nil
	}

	tw := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tSAPI\tVERSION\tTARGET\tPACKAGE\tCONFIDENCE\tINI SETTINGS")
	for _, inst := range installs {
		target := inst.BinaryPath
		if target == "" {
			target = inst.ModulePath
		}
		pkg := "-"
		if inst.PackageName != "" {
			pkg = fmt.Sprintf("%s (%s)", inst.PackageName, inst.PackageVersion)
		}
		var iniPairs []string
		for k, v := range inst.IniSettings {
			iniPairs = append(iniPairs, fmt.Sprintf("%s=%s", k, v))
		}
		iniSummary := "-"
		if len(iniPairs) > 0 {
			iniSummary = strings.Join(iniPairs, ", ")
		}
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			inst.ID,
			inst.SAPI,
			inst.UpstreamVersion,
			target,
			pkg,
			inst.Confidence,
			iniSummary,
		)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush installs table: %w", err)
	}
	return nil
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
