package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAdvisoriesCmd(_ *GlobalOptions) *cobra.Command {
	advisoriesCmd := &cobra.Command{
		Use:   "advisories",
		Short: "Inspect embedded or custom CVE advisories",
	}

	advisoriesCmd.AddCommand(newAdvisoriesListCmd())
	return advisoriesCmd
}

func newAdvisoriesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List advisories for CVE-2026-109618 and CVE-2026-109619",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("advisories list: %w", ErrNotImplemented)
		},
	}
}
