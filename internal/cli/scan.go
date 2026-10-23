package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/image"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/local"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/path"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/remote"
	"github.com/yehezkiel1086/php2shell-check/internal/detect/sbom"
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
		newScanImageCmd(opts, info),
		newScanSBOMCmd(opts, info),
		newScanPathCmd(opts, info),
		newScanRemoteCmd(opts, info),
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
		Verbose:     opts.Verbose,
		IncludeHunt: opts.Hunt,
		ToolVersion: info.Version,
		Mode:        mode,
	}

	rep := report.Build(findings, recs, adv, repOpts)
	if err := report.WriteToFileOrWriter(opts.OutputFile, cmd.OutOrStdout(), rep, repOpts); err != nil {
		return fmt.Errorf("scan %s render report: %w", mode, err)
	}

	if len(findings) == 0 {
		if opts.FailOnEmpty {
			return &findingExitError{code: ExitCodeLikelyOrUnknown}
		}
		return nil
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

func newScanImageCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "image <ref|tarball|oci-dir>",
		Short: "Scan a container image or archive for PHP installations (read-only, no binary execution)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("scan image load advisory: %w", err)
			}

			collector := image.NewCollector(image.Options{
				Offline: opts.Offline,
			})
			installs, err := collector.Collect(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("scan image %q: %w", args[0], err)
			}

			return evaluateAndRenderScan(cmd, opts, info, "image", installs, adv)
		},
	}
}

func newScanSBOMCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "sbom <FILE>",
		Short: "Scan an SBOM (CycloneDX or SPDX JSON) for PHP packages",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("scan sbom load advisory: %w", err)
			}

			collector := sbom.NewCollector()
			installs, err := collector.Collect(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("scan sbom %q: %w", args[0], err)
			}

			return evaluateAndRenderScan(cmd, opts, info, "sbom", installs, adv)
		},
	}
}

func newScanPathCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
	var exclude []string

	cmd := &cobra.Command{
		Use:   "path [DIR]",
		Short: "Scan a filesystem path or repository directory for PHP manifests and version files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) == 1 {
				targetDir = args[0]
			}

			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("scan path load advisory: %w", err)
			}

			collector := path.NewCollector(path.Options{
				RootPath: targetDir,
				Exclude:  exclude,
			})
			installs, err := collector.Collect(cmd.Context())
			if err != nil {
				return fmt.Errorf("scan path %q: %w", targetDir, err)
			}

			return evaluateAndRenderScan(cmd, opts, info, "path", installs, adv)
		},
	}

	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "Glob or directory patterns to exclude when walking the path")
	return cmd
}

func newScanRemoteCmd(opts *GlobalOptions, info BuildInfo) *cobra.Command {
	var authorized bool

	cmd := &cobra.Command{
		Use:   "remote <URL> [URL...]",
		Short: "Passively inspect HTTP response headers of remote targets (requires --authorized)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Offline {
				return fmt.Errorf("scan remote: cannot run remote scan when --offline is enabled")
			}

			adv, err := advisory.Load(opts.AdvisoryFile)
			if err != nil {
				return fmt.Errorf("scan remote load advisory: %w", err)
			}

			collector := remote.NewCollector(remote.Options{
				Authorized: authorized,
				Targets:    args,
			})
			installs, err := collector.Collect(cmd.Context())
			if err != nil {
				return fmt.Errorf("scan remote: %w", err)
			}

			return evaluateAndRenderScan(cmd, opts, info, "remote", installs, adv)
		},
	}

	cmd.Flags().BoolVar(&authorized, "authorized", false, "Confirm explicit authorization to perform a passive header check")
	return cmd
}
