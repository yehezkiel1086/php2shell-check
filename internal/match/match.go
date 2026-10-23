package match

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// BannerCaveat is the required label noting that remote HTTP banners are low-confidence.
const BannerCaveat = "banner, may be hidden or spoofed"

var floatingBranchRe = regexp.MustCompile(`(\d+\.\d+)`)

// Verdict represents the assessment verdict for a discovered PHP installation.
type Verdict string

// Supported assessment verdicts.
const (
	VerdictVulnerable       Verdict = "VULNERABLE"
	VerdictLikelyVulnerable Verdict = "LIKELY_VULNERABLE"
	VerdictUnknown          Verdict = "UNKNOWN"
	VerdictPatched          Verdict = "PATCHED"
	VerdictNone             Verdict = "NONE"
)

// NoVerifiedUpstreamFixReason is the required reason when a branch has no verified upstream fix.
const NoVerifiedUpstreamFixReason = "no verified upstream fix for this branch, check your vendor"

// MitigationStatus describes whether an INI configuration mitigation is applied for a CVE.
// Mitigation status never changes a Verdict.
type MitigationStatus string

// Supported mitigation statuses.
const (
	MitigationNoneAvailable MitigationStatus = "NONE_AVAILABLE"
	MitigationNotApplied    MitigationStatus = "NOT_APPLIED"
	MitigationApplied       MitigationStatus = "APPLIED"
	MitigationUnknown       MitigationStatus = "UNKNOWN"
)

// Finding pairs a discovered PHP installation with its advisory assessment verdict and mitigation state.
type Finding struct {
	AdvisoryID string                      `json:"advisory_id"`
	CVEs       []string                    `json:"cves"`
	Install    inventory.PHPInstall        `json:"install"`
	Verdict    Verdict                     `json:"verdict"`
	Reason     string                      `json:"reason"`
	FixedIn    string                      `json:"fixed_in,omitempty"`
	Mitigation map[string]MitigationStatus `json:"mitigation"`
}

// VerdictRank returns the numeric severity priority of a Verdict
// following the order VULNERABLE > LIKELY_VULNERABLE > UNKNOWN > PATCHED.
func VerdictRank(v Verdict) int {
	switch v {
	case VerdictVulnerable:
		return 4
	case VerdictLikelyVulnerable:
		return 3
	case VerdictUnknown:
		return 2
	case VerdictPatched:
		return 1
	default:
		return 0
	}
}

// CompareVerdictSeverity compares two verdicts by severity order:
// VULNERABLE > LIKELY_VULNERABLE > UNKNOWN > PATCHED.
// Returns +1 if a is more severe than b, -1 if less severe, and 0 if equal.
func CompareVerdictSeverity(a, b Verdict) int {
	ra := VerdictRank(a)
	rb := VerdictRank(b)
	switch {
	case ra > rb:
		return 1
	case ra < rb:
		return -1
	default:
		return 0
	}
}

// HighestVerdict returns the most severe verdict across findings
// using the order VULNERABLE > LIKELY_VULNERABLE > UNKNOWN > PATCHED.
// If findings is empty, it returns VerdictNone.
func HighestVerdict(findings []Finding) Verdict {
	if len(findings) == 0 {
		return VerdictNone
	}
	best := VerdictPatched
	for _, f := range findings {
		if CompareVerdictSeverity(f.Verdict, best) > 0 {
			best = f.Verdict
		}
	}
	return best
}

// SortFindings sorts findings in-place from highest severity verdict to lowest.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if c := CompareVerdictSeverity(findings[i].Verdict, findings[j].Verdict); c != 0 {
			return c > 0
		}
		return findings[i].Install.ID < findings[j].Install.ID
	})
}

// EvaluateAll evaluates a slice of discovered PHP installations against an advisory.
func EvaluateAll(installs []inventory.PHPInstall, adv advisory.Advisory) []Finding {
	findings := make([]Finding, 0, len(installs))
	for _, inst := range installs {
		findings = append(findings, Evaluate(inst, adv))
	}
	SortFindings(findings)
	return findings
}

// Evaluate assesses a single PHPInstall against an Advisory.
// Mitigation status is computed per CVE and never alters Verdict.
func Evaluate(inst inventory.PHPInstall, adv advisory.Advisory) Finding {
	cves := append([]string(nil), adv.CVEs...)

	upstreamVer, err := phpver.Parse(inst.UpstreamVersion)
	if err != nil {
		reason, fixedIn, hintedBranch := evaluateUnparseableVersion(inst, adv)
		return Finding{
			AdvisoryID: adv.ID,
			CVEs:       cves,
			Install:    inst,
			Verdict:    VerdictUnknown,
			Reason:     reason,
			FixedIn:    fixedIn,
			Mitigation: evaluateMitigations(inst, hintedBranch, adv),
		}
	}

	mitigations := evaluateMitigations(inst, upstreamVer.Branch, adv)
	verdict, reason, fixedIn := evaluateVerdict(inst, upstreamVer, adv)
	if inst.Source == inventory.SourceRemote {
		if verdict == VerdictVulnerable {
			verdict = VerdictLikelyVulnerable
		}
		if !strings.Contains(reason, BannerCaveat) {
			reason = fmt.Sprintf("%s (%s)", reason, BannerCaveat)
		}
	}

	return Finding{
		AdvisoryID: adv.ID,
		CVEs:       cves,
		Install:    inst,
		Verdict:    verdict,
		Reason:     reason,
		FixedIn:    fixedIn,
		Mitigation: mitigations,
	}
}

func evaluateUnparseableVersion(inst inventory.PHPInstall, adv advisory.Advisory) (string, string, string) {
	if inst.Source == inventory.SourceRemote {
		return fmt.Sprintf("unparseable or unexposed remote PHP version %q (%s)", inst.UpstreamVersion, BannerCaveat), "", ""
	}
	if inst.Source == inventory.SourcePath {
		displayRef := inventory.NormalizeImageRef(inst.UpstreamVersion)
		hintedBranch := ""
		if m := floatingBranchRe.FindStringSubmatch(displayRef); len(m) == 2 {
			hintedBranch = m[1]
		}
		fixedIn := ""
		if hintedBranch != "" {
			if b, ok := findBranchAdvisory(hintedBranch, adv.Branches); ok && hasVerifiedUpstreamFix(b) {
				fixedIn = b.FixedIn
			}
		}
		if fixedIn != "" {
			return fmt.Sprintf("floating version constraint or tag %q cannot prove a patched version; pin to %s or scan the resolved image digest", displayRef, fixedIn), fixedIn, hintedBranch
		}
		return fmt.Sprintf("floating version constraint or tag %q cannot prove a patched version; pin to FixedIn version or scan the resolved image digest", displayRef), "", hintedBranch
	}
	return fmt.Sprintf("unparseable upstream PHP version %q", inst.UpstreamVersion), "", ""
}

func evaluateVerdict(inst inventory.PHPInstall, upstreamVer phpver.Version, adv advisory.Advisory) (Verdict, string, string) {
	distroManaged := strings.TrimSpace(inst.PackageVersion) != ""

	// 1. If distro-managed, check for a matching Verified DistroFixes entry first.
	if distroManaged {
		if df, ok := findVerifiedDistroFix(inst, adv.DistroFixes); ok {
			cmp, err := compareDistroVersions(inst.PackageManager, inst.Distro.ID, inst.PackageVersion, df.FixedVersion)
			if err != nil {
				return VerdictUnknown, fmt.Sprintf("cannot compare distro package version %q with %q: %v", inst.PackageVersion, df.FixedVersion, err), df.FixedVersion
			}
			if cmp >= 0 {
				return VerdictPatched, fmt.Sprintf("distro package %s %s >= fixed version %s", inst.PackageName, inst.PackageVersion, df.FixedVersion), df.FixedVersion
			}
			return VerdictVulnerable, fmt.Sprintf("distro package %s %s < fixed version %s", inst.PackageName, inst.PackageVersion, df.FixedVersion), df.FixedVersion
		}
	}

	// 2. Lookup branch advisory entry.
	branchAdv, hasBranch := findBranchAdvisory(upstreamVer.Branch, adv.Branches)
	if hasBranch && hasVerifiedUpstreamFix(branchAdv) {
		fixedVer, err := phpver.Parse(branchAdv.FixedIn)
		if err != nil {
			return VerdictUnknown, fmt.Sprintf("invalid branch fixed_in %q", branchAdv.FixedIn), branchAdv.FixedIn
		}
		if phpver.Compare(upstreamVer, fixedVer) >= 0 {
			return VerdictPatched, fmt.Sprintf("upstream version %s >= branch fix %s", upstreamVer.Raw, branchAdv.FixedIn), branchAdv.FixedIn
		}
		if distroManaged {
			return VerdictLikelyVulnerable, fmt.Sprintf("upstream version %s < %s on distro-managed package (backports possible)", upstreamVer.Raw, branchAdv.FixedIn), branchAdv.FixedIn
		}
		return VerdictVulnerable, fmt.Sprintf("upstream version %s < branch fix %s", upstreamVer.Raw, branchAdv.FixedIn), branchAdv.FixedIn
	}

	// 3. If branch is explicitly listed without a verified upstream fix (e.g. 8.1, 8.0, 7.4).
	if hasBranch {
		return VerdictLikelyVulnerable, NoVerifiedUpstreamFixReason, ""
	}

	// 4. Branch not explicitly listed: check against AffectedMin and AffectedMaxInclusive.
	if minVer, err := phpver.Parse(adv.AffectedMin); err == nil {
		if phpver.Compare(upstreamVer, minVer) < 0 {
			return VerdictLikelyVulnerable, NoVerifiedUpstreamFixReason, ""
		}
	}
	if maxVer, err := phpver.Parse(adv.AffectedMaxInclusive); err == nil {
		if phpver.Compare(upstreamVer, maxVer) > 0 {
			return VerdictPatched, fmt.Sprintf("upstream version %s is newer than affected range %s", upstreamVer.Raw, adv.AffectedMaxInclusive), ""
		}
	}

	// Older branch within affected range (e.g. 5.4 .. 7.3) with no upstream fix.
	return VerdictLikelyVulnerable, NoVerifiedUpstreamFixReason, ""
}

func findBranchAdvisory(branch string, branches []advisory.BranchAdvisory) (advisory.BranchAdvisory, bool) {
	for _, b := range branches {
		if b.Branch == branch {
			return b, true
		}
	}
	return advisory.BranchAdvisory{}, false
}

func hasVerifiedUpstreamFix(b advisory.BranchAdvisory) bool {
	if b.FixedIn == "" {
		return false
	}
	if b.UpstreamFixAvailable != nil && !*b.UpstreamFixAvailable {
		return false
	}
	return true
}

func findVerifiedDistroFix(inst inventory.PHPInstall, fixes []advisory.DistroFix) (advisory.DistroFix, bool) {
	if inst.Distro.ID == "" || inst.Distro.VersionID == "" || inst.PackageName == "" {
		return advisory.DistroFix{}, false
	}
	for _, df := range fixes {
		if !df.Verified {
			continue
		}
		if !strings.EqualFold(df.Distro, inst.Distro.ID) {
			continue
		}
		if !releaseMatches(inst.Distro.VersionID, df.Release) {
			continue
		}
		if df.Package != inst.PackageName {
			continue
		}
		return df, true
	}
	return advisory.DistroFix{}, false
}

func releaseMatches(actual, expected string) bool {
	if strings.EqualFold(actual, expected) {
		return true
	}
	// Allow major release matching for RHEL/Rocky/Alma/Alpine when advisory specifies e.g. "9" vs "9.4" or "3.20" vs "3.20.3".
	if strings.HasPrefix(actual, expected+".") {
		return true
	}
	return false
}
