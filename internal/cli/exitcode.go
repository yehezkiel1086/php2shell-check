package cli

import (
	"errors"
	"fmt"
)

// Process exit codes as defined by the CLI specification.
const (
	ExitCodeClean           = 0
	ExitCodeVulnerable      = 1
	ExitCodeLikelyOrUnknown = 2
	ExitCodeError           = 3
)

// Verdict represents the assessment outcome for a PHP installation against a CVE.
type Verdict string

// Supported assessment verdicts.
const (
	VerdictVulnerable       Verdict = "VULNERABLE"
	VerdictPatched          Verdict = "PATCHED"
	VerdictLikelyVulnerable Verdict = "LIKELY_VULNERABLE"
	VerdictUnknown          Verdict = "UNKNOWN"
)

// FailOn controls which finding verdicts cause a non-zero exit code.
type FailOn string

// Supported values for the --fail-on flag.
const (
	FailOnVulnerable FailOn = "vulnerable"
	FailOnLikely     FailOn = "likely"
	FailOnUnknown    FailOn = "unknown"
	FailOnNever      FailOn = "never"
)

// ErrInvalidFailOn indicates an unsupported --fail-on value.
var ErrInvalidFailOn = errors.New("invalid --fail-on value (must be vulnerable, likely, unknown, or never)")

// ParseFailOn validates and normalizes a raw --fail-on flag string.
func ParseFailOn(raw string) (FailOn, error) {
	switch FailOn(raw) {
	case FailOnVulnerable, FailOnLikely, FailOnUnknown, FailOnNever:
		return FailOn(raw), nil
	default:
		return "", fmt.Errorf("%q: %w", raw, ErrInvalidFailOn)
	}
}

// Finding represents an assessment result for a discovered PHP target.
// A configuration mitigation is reported separately and never changes a Verdict.
type Finding struct {
	CVE              string
	Target           string
	Verdict          Verdict
	Verified         bool
	ConfigMitigated  bool
	ConfigMitigation string
}

// ExitCodeForFindings is a pure function that maps a slice of findings and the
// --fail-on threshold to an exit code (0, 1, or 2).
// Configuration mitigations never change the verdict or resulting exit code.
func ExitCodeForFindings(findings []Finding, failOn FailOn) int {
	if failOn == "" {
		failOn = FailOnLikely
	}
	if failOn == FailOnNever {
		return ExitCodeClean
	}

	var hasVulnerable, hasLikely, hasUnknown bool
	for _, f := range findings {
		switch f.Verdict {
		case VerdictVulnerable:
			hasVulnerable = true
		case VerdictLikelyVulnerable:
			hasLikely = true
		case VerdictUnknown:
			hasUnknown = true
		case VerdictPatched:
			// Patched target does not trigger a failure exit code.
		}
	}

	if hasVulnerable {
		return ExitCodeVulnerable
	}

	switch failOn {
	case FailOnLikely:
		if hasLikely {
			return ExitCodeLikelyOrUnknown
		}
	case FailOnUnknown:
		if hasLikely || hasUnknown {
			return ExitCodeLikelyOrUnknown
		}
	case FailOnVulnerable, FailOnNever:
		// Only VULNERABLE (handled above) or nothing triggers a non-zero exit code.
	}

	return ExitCodeClean
}
