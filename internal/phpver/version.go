package phpver

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidVersion is the sentinel error wrapped by ParseError for invalid version strings.
var ErrInvalidVersion = errors.New("invalid PHP version")

// ParseError is a typed error returned when a PHP version string cannot be parsed.
type ParseError struct {
	Input  string
	Reason string
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	return fmt.Sprintf("invalid PHP version %q: %s", e.Input, e.Reason)
}

// Unwrap allows errors.Is(err, ErrInvalidVersion) checks.
func (e *ParseError) Unwrap() error {
	return ErrInvalidVersion
}

// Version represents a parsed PHP version string.
type Version struct {
	Major        int
	Minor        int
	Patch        int
	PreRelease   string
	DistroSuffix string
	Raw          string
	Branch       string
}

// String returns the original raw version string if set, or formats the version components.
func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	base := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		base += v.PreRelease
	}
	if v.DistroSuffix != "" {
		base += "-" + v.DistroSuffix
	}
	return base
}

// Parse parses a PHP version string (e.g. "8.3.36", "8.4.0RC1", "8.2.30-1+deb12u1",
// "7.4.33-nmm1", "8.1.2-1ubuntu2.19") into a normalized Version struct.
// Malformed or garbage inputs return a *ParseError.
func Parse(raw string) (Version, error) {
	if raw == "" {
		return Version{}, &ParseError{Input: raw, Reason: "empty input"}
	}
	if len(raw) > 128 {
		return Version{}, &ParseError{Input: raw, Reason: "input exceeds maximum length"}
	}

	// Parse Major.Minor.Patch prefix.
	firstDot := strings.IndexByte(raw, '.')
	if firstDot <= 0 {
		return Version{}, &ParseError{Input: raw, Reason: "missing major.minor separator"}
	}
	major, err := parseNumericComponent(raw[:firstDot], raw, "major")
	if err != nil {
		return Version{}, err
	}

	rest := raw[firstDot+1:]
	secondDot := strings.IndexByte(rest, '.')
	if secondDot <= 0 {
		return Version{}, &ParseError{Input: raw, Reason: "missing minor.patch separator"}
	}
	minor, err := parseNumericComponent(rest[:secondDot], raw, "minor")
	if err != nil {
		return Version{}, err
	}

	afterMinor := rest[secondDot+1:]
	if afterMinor == "" {
		return Version{}, &ParseError{Input: raw, Reason: "missing patch version"}
	}

	// Scan leading digits of patch component.
	patchEnd := 0
	for patchEnd < len(afterMinor) && isDigit(afterMinor[patchEnd]) {
		patchEnd++
	}
	if patchEnd == 0 {
		return Version{}, &ParseError{Input: raw, Reason: "non-numeric patch version"}
	}
	patch, err := parseNumericComponent(afterMinor[:patchEnd], raw, "patch")
	if err != nil {
		return Version{}, err
	}

	tail := afterMinor[patchEnd:]
	preRelease, distroSuffix, err := parseTail(tail, raw)
	if err != nil {
		return Version{}, err
	}

	return Version{
		Major:        major,
		Minor:        minor,
		Patch:        patch,
		PreRelease:   preRelease,
		DistroSuffix: distroSuffix,
		Raw:          raw,
		Branch:       fmt.Sprintf("%d.%d", major, minor),
	}, nil
}

func parseNumericComponent(part, raw, name string) (int, error) {
	if part == "" {
		return 0, &ParseError{Input: raw, Reason: "empty " + name + " component"}
	}
	if len(part) > 1 && part[0] == '0' {
		return 0, &ParseError{Input: raw, Reason: "leading zero in " + name + " component"}
	}
	if len(part) > 9 {
		return 0, &ParseError{Input: raw, Reason: name + " component too large"}
	}
	for i := 0; i < len(part); i++ {
		if !isDigit(part[i]) {
			return 0, &ParseError{Input: raw, Reason: "non-digit in " + name + " component"}
		}
	}
	val, err := strconv.Atoi(part)
	if err != nil {
		return 0, &ParseError{Input: raw, Reason: "invalid " + name + " component"}
	}
	return val, nil
}

func parseTail(tail, raw string) (string, string, error) {
	if tail == "" {
		return "", "", nil
	}

	// Case 1: Attached directly to patch without separator, e.g. "8.4.0RC1" or "8.4.0RC1-1+deb12u1".
	if isAlpha(tail[0]) {
		seg, rem := splitAtSeparator(tail)
		if !isValidPreRelease(seg) {
			return "", "", &ParseError{Input: raw, Reason: "invalid pre-release tag " + strconv.Quote(seg)}
		}
		if rem == "" {
			return seg, "", nil
		}
		distro, err := parseDistroSuffix(rem, raw)
		if err != nil {
			return "", "", err
		}
		return seg, distro, nil
	}

	// Case 2: Separated by '-', '+', or '~', e.g. "-1+deb12u1", "-RC1", "~rc1-1".
	if tail[0] == '-' || tail[0] == '+' || tail[0] == '~' {
		afterSep := tail[1:]
		if afterSep == "" {
			return "", "", &ParseError{Input: raw, Reason: "dangling version separator"}
		}
		seg, rem := splitAtSeparator(afterSep)
		if (tail[0] == '-' || tail[0] == '~') && isValidPreRelease(seg) {
			if rem == "" {
				return seg, "", nil
			}
			distro, err := parseDistroSuffix(rem, raw)
			if err != nil {
				return "", "", err
			}
			return seg, distro, nil
		}

		distro, err := parseDistroSuffix(tail, raw)
		if err != nil {
			return "", "", err
		}
		return "", distro, nil
	}

	return "", "", &ParseError{Input: raw, Reason: "unexpected trailing characters"}
}

func splitAtSeparator(s string) (string, string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' || s[i] == '+' || s[i] == '~' {
			return s[:i], s[i:]
		}
	}
	return s, ""
}

func parseDistroSuffix(rem, raw string) (string, error) {
	if rem == "" {
		return "", nil
	}
	if rem[0] != '-' && rem[0] != '+' && rem[0] != '~' {
		return "", &ParseError{Input: raw, Reason: "invalid distro suffix separator"}
	}
	body := rem[1:]
	if body == "" {
		return "", &ParseError{Input: raw, Reason: "empty distro suffix"}
	}
	last := body[len(body)-1]
	if !isAlphaNum(last) {
		return "", &ParseError{Input: raw, Reason: "distro suffix must end with alphanumeric character"}
	}

	hasAlphaNum := false
	for i := 0; i < len(body); i++ {
		ch := body[i]
		if isAlphaNum(ch) {
			hasAlphaNum = true
			continue
		}
		if ch != '.' && ch != '+' && ch != '-' && ch != '~' && ch != '_' {
			return "", &ParseError{Input: raw, Reason: "invalid character in distro suffix"}
		}
	}
	if !hasAlphaNum {
		return "", &ParseError{Input: raw, Reason: "distro suffix lacks alphanumeric characters"}
	}
	return body, nil
}

type preReleaseKind int

const (
	preNone preReleaseKind = iota
	preDev
	preAlpha
	preBeta
	preRC
)

func parsePreReleaseToken(s string) (preReleaseKind, int, bool) {
	lower := strings.ToLower(s)
	var kind preReleaseKind
	var numStr string

	switch {
	case strings.HasPrefix(lower, "alpha"):
		kind = preAlpha
		numStr = lower[len("alpha"):]
	case strings.HasPrefix(lower, "beta"):
		kind = preBeta
		numStr = lower[len("beta"):]
	case strings.HasPrefix(lower, "rc"):
		kind = preRC
		numStr = lower[len("rc"):]
	case strings.HasPrefix(lower, "dev"):
		kind = preDev
		numStr = lower[len("dev"):]
	default:
		return preNone, 0, false
	}

	if numStr == "" {
		return kind, 0, true
	}
	if len(numStr) > 6 || numStr[0] == '0' {
		return preNone, 0, false
	}
	for i := 0; i < len(numStr); i++ {
		if !isDigit(numStr[i]) {
			return preNone, 0, false
		}
	}
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return preNone, 0, false
	}
	return kind, n, true
}

func isValidPreRelease(s string) bool {
	_, _, ok := parsePreReleaseToken(s)
	return ok
}

// Compare compares two parsed PHP versions a and b.
// It returns -1 if a < b, 0 if a == b, and +1 if a > b.
// Pre-releases sort below their corresponding release (dev < alpha < beta < rc < release).
func Compare(a, b Version) int {
	if c := cmp.Compare(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Patch, b.Patch); c != 0 {
		return c
	}

	if a.PreRelease == "" && b.PreRelease == "" {
		return 0
	}
	if a.PreRelease != "" && b.PreRelease == "" {
		return -1
	}
	if a.PreRelease == "" && b.PreRelease != "" {
		return 1
	}

	aKind, aNum, aOK := parsePreReleaseToken(a.PreRelease)
	bKind, bNum, bOK := parsePreReleaseToken(b.PreRelease)
	if aOK && bOK {
		if c := cmp.Compare(aKind, bKind); c != 0 {
			return c
		}
		return cmp.Compare(aNum, bNum)
	}

	return cmp.Compare(strings.ToLower(a.PreRelease), strings.ToLower(b.PreRelease))
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isAlphaNum(b byte) bool {
	return isDigit(b) || isAlpha(b)
}
