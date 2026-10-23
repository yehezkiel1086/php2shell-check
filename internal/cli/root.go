package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// ErrNotImplemented is returned by command stubs that have not been implemented yet.
var ErrNotImplemented = errors.New("not implemented yet")

type findingExitError struct {
	code int
}

func (e *findingExitError) Error() string {
	return fmt.Sprintf("findings triggered exit code %d", e.code)
}

// BuildInfo holds version and build metadata injected via linker flags.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Normalize returns a copy of BuildInfo with sensible defaults for empty fields.
func (b BuildInfo) Normalize() BuildInfo {
	if b.Version == "" {
		b.Version = "dev"
	}
	if b.Commit == "" {
		b.Commit = "none"
	}
	if b.Date == "" {
		b.Date = "unknown"
	}
	return b
}

// NewRootCmd constructs the root cobra.Command and wires all subcommands and global flags.
func NewRootCmd(info BuildInfo) (*cobra.Command, *GlobalOptions) {
	info = info.Normalize()
	opts := &GlobalOptions{
		Format: string(FormatTable),
		FailOn: string(FailOnLikely),
	}

	rootCmd := &cobra.Command{
		Use:   "php2shell-check",
		Short: "Detect, assess, and remediate CVE-2026-109618 and CVE-2026-109619 (PHP2Shell)",
		Long: "php2shell-check is a defensive security CLI that detects, assesses, and recommends " +
			"remediation for CVE-2026-109618 and CVE-2026-109619 (PHP engine RCE flaws, aka PHP2Shell).",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Validate()
		},
	}

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&opts.Format, "format", string(FormatTable), "Output format: table|json|sarif|md")
	pf.StringVar(&opts.OutputFile, "output", "", "Write output to FILE instead of stdout")
	pf.StringVar(&opts.FailOn, "fail-on", string(FailOnLikely), "Fail threshold: vulnerable|likely|unknown|never")
	pf.BoolVar(&opts.Offline, "offline", false, "Run in offline mode without network access")
	pf.BoolVar(&opts.Quiet, "quiet", false, "Suppress non-essential output")
	pf.BoolVar(&opts.NoColor, "no-color", false, "Disable ANSI color output")
	pf.StringVar(&opts.AdvisoryFile, "advisory-file", "", "Path to custom advisories JSON file")
	pf.BoolVar(&opts.Hunt, "hunt", false, "Include passive log-review indicators for known PHP2Shell samples")
	pf.BoolVarP(&opts.Verbose, "verbose", "v", false, "Enable verbose output listing configuration files and origins")
	pf.BoolVar(&opts.FailOnEmpty, "fail-on-empty", false, "Exit with code 2 if no PHP installations are found")

	rootCmd.AddCommand(
		newScanCmd(opts, info),
		newAdvisoriesCmd(opts),
		newVersionCmd(info),
	)

	return rootCmd, opts
}

// Run executes the CLI with the given context, arguments, and standard streams,
// returning the process exit code.
func Run(ctx context.Context, info BuildInfo, args []string, stdout, stderr io.Writer) int {
	rootCmd, _ := NewRootCmd(info)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	rootCmd.SetArgs(args)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		var exitErr *findingExitError
		if errors.As(err, &exitErr) {
			return exitErr.code
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return ExitCodeError
	}

	return ExitCodeClean
}
