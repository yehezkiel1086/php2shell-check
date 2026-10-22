package cli

import (
	"errors"
	"fmt"
)

// OutputFormat represents a supported report rendering format.
type OutputFormat string

// Supported values for the --format flag.
const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatSARIF OutputFormat = "sarif"
	FormatMD    OutputFormat = "md"
)

// ErrInvalidFormat indicates an unsupported --format value.
var ErrInvalidFormat = errors.New("invalid --format value (must be table, json, sarif, or md)")

// ParseOutputFormat validates and normalizes a raw --format flag string.
func ParseOutputFormat(raw string) (OutputFormat, error) {
	switch OutputFormat(raw) {
	case FormatTable, FormatJSON, FormatSARIF, FormatMD:
		return OutputFormat(raw), nil
	default:
		return "", fmt.Errorf("%q: %w", raw, ErrInvalidFormat)
	}
}

// GlobalOptions holds the parsed global flags shared across all commands.
type GlobalOptions struct {
	Format       string
	OutputFile   string
	FailOn       string
	Offline      bool
	Quiet        bool
	NoColor      bool
	AdvisoryFile string
}

// Validate checks that the global option values are valid.
func (o *GlobalOptions) Validate() error {
	if _, err := ParseOutputFormat(o.Format); err != nil {
		return fmt.Errorf("validate format flag: %w", err)
	}
	if _, err := ParseFailOn(o.FailOn); err != nil {
		return fmt.Errorf("validate fail-on flag: %w", err)
	}
	return nil
}
