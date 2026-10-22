package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build metadata of php2shell-check",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info = info.Normalize()
			_, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"php2shell-check %s (commit: %s, date: %s)\n",
				info.Version,
				info.Commit,
				info.Date,
			)
			if err != nil {
				return fmt.Errorf("write version output: %w", err)
			}
			return nil
		},
	}
}
