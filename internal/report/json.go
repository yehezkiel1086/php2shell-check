package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// RenderJSON serializes the Report in indented JSON format with schema_version.
func RenderJSON(w io.Writer, rep Report) error {
	if rep.Results == nil {
		rep.Results = []Item{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}
