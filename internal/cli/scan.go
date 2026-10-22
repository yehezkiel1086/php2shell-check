package cli

import (
	"fmt"

	"github.com/spf13/cobra"
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

func newScanLocalCmd(_ *GlobalOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "local",
		Short: "Scan the local host for PHP installations, packages, and configuration (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("scan local: %w", ErrNotImplemented)
		},
	}
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
