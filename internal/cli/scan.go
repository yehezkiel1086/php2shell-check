package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
	"github.com/yehezkiel1086/php2shell-check/internal/report"
)

func newScanCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan targets for CVE-2026-109618 and CVE-2026-109619 exposure",
		Long:  "Scan local hosts, container images, SBOM files, filesystem paths, or remote HTTP headers.",
	}

	scanCmd.AddCommand(
		newScanLocalCmd(opts, info),
		newScanImageCmd(opts),
		newScanSBOMCmd(opts),
		newScanPathCmd(opts),
		newScanRemoteCmd(opts),
	)

	return scanCmd
}

func newScanLocalCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
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

			return evaluateAndRenderScan(cmd, opts, info, "local", installs, adv)
		},
	}
}

func evaluateAndRenderScan(
	cmd *cobra.Command,
	opts *GlobalOptions,
	info BuildInfo,
	mode string,
	installs []inventory.PHPInstall,
	adv advisory.Advisory,
) error {
	findings := match.EvaluateAll(installs, adv)
	recs := remediate.BuildAll(findings, adv, remediate.Options{IncludeHuntHints: opts.Hunt})

	repOpts := report.Options{
		Format:      opts.Format,
		NoColor:     opts.NoColor,
		Quiet:       opts.Quiet,
		IncludeHunt: opts.Hunt,
		ToolVersion: info.Version,
		Mode:        mode,
	}

	rep := report.Build(findings, recs, adv, repOpts)
	if err := report.WriteToFileOrWriter(opts.OutputFile, cmd.OutOrStdout(), rep, repOpts); err != nil {
		return fmt.Errorf("scan %s render report: %w", mode, err)
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
