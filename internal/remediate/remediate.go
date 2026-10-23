package remediate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

// Priority represents the urgency level of a remediation recommendation.
type Priority string

// Supported remediation priorities from highest (P0) to lowest (P3).
const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
)

// MitigationWarning is the mandatory notice attached whenever configuration mitigations are discussed.
const MitigationWarning = "WARNING: A configuration mitigation is a temporary risk reduction only and is NOT a fix. CVE-2026-109618 has no known configuration mitigation; upgrading PHP is required."

// HuntDisclaimer is the mandatory label for passive log-review indicators.
const HuntDisclaimer = "Indicators of known samples only; absence of matches in logs is NOT proof of safety."

// ErrUnsafePackageToken is returned when a package name or version fails strict regex validation.
var ErrUnsafePackageToken = errors.New("package token failed strict safety validation")

// safePackageTokenRe enforces ^[a-z0-9][a-z0-9+.-]*$ on any untrusted package or version string
// before it can be interpolated into command text.
var safePackageTokenRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

// ValidatePackageToken validates a package name or version string against ^[a-z0-9][a-z0-9+.-]*$.
func ValidatePackageToken(token string) error {
	if !safePackageTokenRe.MatchString(token) {
		return fmt.Errorf("invalid token %q: %w", token, ErrUnsafePackageToken)
	}
	return nil
}

// Command represents a display-only remediation command or instruction.
// Commands are rendered as text for human operators and are never executed by php2shell-check.
type Command struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

// Recommendation contains concrete, safe remediation and mitigation guidance for a Finding.
type Recommendation struct {
	Priority     Priority             `json:"priority"`
	Title        string               `json:"title"`
	Steps        []string             `json:"steps,omitempty"`
	Commands     []Command            `json:"commands,omitempty"`
	RestartHints []string             `json:"restart_hints,omitempty"`
	Notes        string               `json:"notes,omitempty"`
	References   []advisory.Reference `json:"references,omitempty"`
}

// Options configures optional remediation output features such as log-hunting hints.
type Options struct {
	IncludeHuntHints bool
}

// BuildAll generates recommendations for a slice of findings.
func BuildAll(findings []match.Finding, adv advisory.Advisory, opts Options) []Recommendation {
	recs := make([]Recommendation, 0, len(findings))
	for _, f := range findings {
		recs = append(recs, Build(f, adv, opts))
	}
	return recs
}

// Build produces a concrete Recommendation for a single Finding against an Advisory.
func Build(f match.Finding, adv advisory.Advisory, opts Options) Recommendation {
	refs := append([]advisory.Reference(nil), adv.References...)

	if f.Verdict == match.VerdictPatched {
		steps := []string{"Installation meets or exceeds the patched version threshold."}
		if f.Install.Source == inventory.SourceRemote {
			steps = append(steps, "Extra hardening: set expose_php = Off in php.ini to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
		}
		rec := Recommendation{
			Priority:   PriorityP3,
			Title:      fmt.Sprintf("No remediation required for %s (PATCHED)", targetDisplayName(f.Install)),
			Steps:      steps,
			References: refs,
		}
		if opts.IncludeHuntHints {
			rec.Steps = append(rec.Steps, HuntHints()...)
		}
		return rec
	}

	if f.Verdict == match.VerdictUnknown {
		steps := []string{
			"verify manually: inspect the PHP binary version, SAPI configuration, and vendor changelog.",
		}
		var cmds []Command
		if f.Install.Source == inventory.SourcePath {
			pinTarget := f.FixedIn
			if pinTarget == "" {
				_, pinTarget = deriveHighestFixedIn(adv)
			}
			if pinTarget != "" {
				steps = append(steps, fmt.Sprintf("Floating constraint or tag %q cannot prove a patched version: pin to FixedIn version %s or scan the resolved image digest.", f.Install.UpstreamVersion, pinTarget))
			} else {
				steps = append(steps, fmt.Sprintf("Floating constraint or tag %q cannot prove a patched version: pin to the FixedIn version or scan the resolved image digest.", f.Install.UpstreamVersion))
			}
			cmds, _ = buildCommands(f.Install, pinTarget)
		}
		if f.Install.Source == inventory.SourceRemote {
			steps = append(steps, "Extra hardening: set expose_php = Off in php.ini to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
		}
		if diffStep := buildMitigationDiffStep(f.Install, "", adv); diffStep != "" {
			steps = append(steps, diffStep)
		}
		rec := Recommendation{
			Priority:     PriorityP3,
			Title:        fmt.Sprintf("Verify PHP installation manually for %s", targetDisplayName(f.Install)),
			Steps:        steps,
			Commands:     cmds,
			RestartHints: restartHintsForSAPI(f.Install.SAPI),
			Notes:        MitigationWarning,
			References:   refs,
		}
		if opts.IncludeHuntHints {
			rec.Steps = append(rec.Steps, HuntHints()...)
		}
		return rec
	}

	priority := computePriority(f.Verdict, f.Install.SAPI)
	branch := parseInstallBranch(f.Install.UpstreamVersion)
	upgradeStep, targetVer := buildUpgradeStep(f, branch, adv)

	commands, validationNotes := buildCommands(f.Install, targetVer)
	mitigationStep := buildMitigationDiffStep(f.Install, branch, adv)

	steps := []string{upgradeStep}
	if f.Install.Source == inventory.SourceRemote {
		steps = append(steps, "Extra hardening: set expose_php = Off in php.ini to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
	}
	if mitigationStep != "" {
		steps = append(steps, mitigationStep)
	}
	if opts.IncludeHuntHints {
		steps = append(steps, HuntHints()...)
	}

	notes := MitigationWarning
	if validationNotes != "" {
		notes = validationNotes + " " + notes
	}

	return Recommendation{
		Priority:     priority,
		Title:        fmt.Sprintf("[%s] Remediate %s (%s, SAPI: %s)", priority, targetDisplayName(f.Install), f.Verdict, f.Install.SAPI),
		Steps:        steps,
		Commands:     commands,
		RestartHints: restartHintsForSAPI(f.Install.SAPI),
		Notes:        notes,
		References:   refs,
	}
}

// HuntHints returns passive log-review indicators for known PHP2Shell samples.
func HuntHints() []string {
	return []string{
		"Log review (HTTP access / WAF logs): search for User-Agent header values beginning with 'php2shell-'.",
		"Log review (HTTP access / application logs): inspect multipart/form-data POST requests touching session upload progress fields (PHP_SESSION_UPLOAD_PROGRESS).",
		"Hunt note: " + HuntDisclaimer,
	}
}

func computePriority(verdict match.Verdict, sapi inventory.SAPI) Priority {
	if verdict == match.VerdictUnknown {
		return PriorityP3
	}
	if verdict == match.VerdictVulnerable || verdict == match.VerdictLikelyVulnerable {
		if isWebSAPI(sapi) {
			return PriorityP0
		}
		if sapi == inventory.SAPICLI {
			return PriorityP2
		}
		return PriorityP1
	}
	return PriorityP3
}

func isWebSAPI(sapi inventory.SAPI) bool {
	switch sapi {
	case inventory.SAPIApache2Handler,
		inventory.SAPIFPM,
		inventory.SAPICGI,
		inventory.SAPILiteSpeed,
		inventory.SAPIFrankenPHP:
		return true
	default:
		return false
	}
}

func parseInstallBranch(upstreamVersion string) string {
	v, err := phpver.Parse(upstreamVersion)
	if err != nil {
		return ""
	}
	return v.Branch
}

func buildUpgradeStep(f match.Finding, branch string, adv advisory.Advisory) (string, string) {
	if f.FixedIn != "" {
		return fmt.Sprintf("Upgrade PHP on branch %s to >= %s.", branchOrUnknown(branch), f.FixedIn), f.FixedIn
	}

	for _, b := range adv.Branches {
		if b.Branch == branch && b.FixedIn != "" && (b.UpstreamFixAvailable == nil || *b.UpstreamFixAvailable) {
			return fmt.Sprintf("Upgrade PHP on branch %s to >= %s.", branch, b.FixedIn), b.FixedIn
		}
	}

	// EOL or no-fix branch: derive the migration target from the highest FixedIn in the advisory data.
	highestBranch, highestFixedIn := deriveHighestFixedIn(adv)
	if highestFixedIn != "" {
		return fmt.Sprintf(
			"Branch %s has no verified upstream fix (EOL/unfixed); migrate to a supported PHP branch such as %s (>= %s).",
			branchOrUnknown(branch),
			highestBranch,
			highestFixedIn,
		), highestFixedIn
	}

	return fmt.Sprintf("Branch %s has no verified upstream fix; migrate to a supported PHP branch.", branchOrUnknown(branch)), ""
}

func deriveHighestFixedIn(adv advisory.Advisory) (string, string) {
	var bestVer phpver.Version
	var bestBranch, bestRaw string
	found := false

	for _, b := range adv.Branches {
		if b.FixedIn == "" {
			continue
		}
		if b.UpstreamFixAvailable != nil && !*b.UpstreamFixAvailable {
			continue
		}
		parsed, err := phpver.Parse(b.FixedIn)
		if err != nil {
			continue
		}
		if !found || phpver.Compare(parsed, bestVer) > 0 {
			bestVer = parsed
			bestBranch = b.Branch
			bestRaw = b.FixedIn
			found = true
		}
	}
	return bestBranch, bestRaw
}

func buildCommands(inst inventory.PHPInstall, targetVersion string) ([]Command, string) {
	var cmds []Command
	var notes []string

	// 1. Check for cPanel or CloudLinux paths/packages first.
	if isCPanelOrCloudLinux(inst) {
		cmds = append(cmds, Command{
			Label: "Vendor update tooling (cPanel / CloudLinux)",
			Text:  "use your vendor's update tooling",
		})
		return cmds, ""
	}

	// 2. Check for container image source or container manifest in path mode.
	if inst.Source == inventory.SourceImage || (inst.Source == inventory.SourcePath && inst.PackageManager == "container") {
		if targetVersion != "" {
			if err := ValidatePackageToken(strings.ToLower(targetVersion)); err != nil {
				notes = append(notes, fmt.Sprintf("Rejected unsafe target version %q from command output.", targetVersion))
			} else {
				cmds = append(cmds, Command{
					Label: "Update container base image",
					Text:  fmt.Sprintf("bump the base image tag to %s", strings.ToLower(targetVersion)),
				})
				return cmds, strings.Join(notes, " ")
			}
		}
		cmds = append(cmds, Command{
			Label: "Update container base image",
			Text:  "bump the base image tag to a patched release",
		})
		return cmds, strings.Join(notes, " ")
	}

	// 3. Source/custom build under /usr/local with no OS package manager ownership.
	if inst.PackageManager == "" && inst.PackageName == "" && strings.HasPrefix(inst.BinaryPath, "/usr/local/") {
		if targetVersion != "" && ValidatePackageToken(strings.ToLower(targetVersion)) == nil {
			cmds = append(cmds, Command{
				Label: "Upgrade source/custom PHP build in /usr/local",
				Text:  fmt.Sprintf("rebuild and install PHP >= %s into /usr/local from official source", strings.ToLower(targetVersion)),
			})
		} else {
			cmds = append(cmds, Command{
				Label: "Upgrade source/custom PHP build in /usr/local",
				Text:  "rebuild and install a patched PHP release into /usr/local from official source",
			})
		}
		return cmds, strings.Join(notes, " ")
	}

	// 4. Validate package name if present before interpolating into any package manager command.
	pkgName := inst.PackageName
	if pkgName != "" {
		if err := ValidatePackageToken(pkgName); err != nil {
			notes = append(notes, fmt.Sprintf("Rejected unsafe package name %q from command generation.", pkgName))
			return nil, strings.Join(notes, " ")
		}
	}

	if inst.PackageVersion != "" {
		if err := ValidatePackageToken(strings.ToLower(inst.PackageVersion)); err != nil {
			notes = append(notes, fmt.Sprintf("Rejected unsafe package version %q from command generation.", inst.PackageVersion))
			return nil, strings.Join(notes, " ")
		}
	}

	pm := resolvePackageManagerFamily(inst.PackageManager, inst.Distro.ID)
	switch pm {
	case "deb":
		if pkgName != "" {
			cmds = append(cmds, Command{
				Label: "Upgrade Debian/Ubuntu package",
				Text:  fmt.Sprintf("apt-get install --only-upgrade %s", pkgName),
			})
		} else {
			cmds = append(cmds, Command{
				Label: "Upgrade Debian/Ubuntu PHP packages",
				Text:  "apt-get install --only-upgrade php",
			})
		}
	case "rpm":
		if pkgName != "" {
			cmds = append(cmds, Command{
				Label: "Upgrade RPM package",
				Text:  fmt.Sprintf("dnf upgrade %s", pkgName),
			})
		} else {
			cmds = append(cmds, Command{
				Label: "Upgrade RPM PHP packages",
				Text:  "dnf upgrade php",
			})
		}
	case "apk":
		if pkgName != "" {
			cmds = append(cmds, Command{
				Label: "Upgrade Alpine package",
				Text:  fmt.Sprintf("apk upgrade %s", pkgName),
			})
		} else {
			cmds = append(cmds, Command{
				Label: "Upgrade Alpine PHP packages",
				Text:  "apk upgrade php",
			})
		}
	}

	return cmds, strings.Join(notes, " ")
}

func isCPanelOrCloudLinux(inst inventory.PHPInstall) bool {
	paths := []string{inst.BinaryPath, inst.ModulePath, inst.PackageName}
	for _, p := range paths {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "/opt/cpanel/") ||
			strings.Contains(lower, "ea-php") ||
			strings.Contains(lower, "/opt/alt/php") ||
			strings.HasPrefix(lower, "alt-php") {
			return true
		}
	}
	return false
}

func resolvePackageManagerFamily(pkgManager, distroID string) string {
	switch strings.ToLower(strings.TrimSpace(pkgManager)) {
	case "deb", "dpkg", "apt":
		return "deb"
	case "rpm", "dnf", "yum":
		return "rpm"
	case "apk":
		return "apk"
	}

	switch strings.ToLower(strings.TrimSpace(distroID)) {
	case "debian", "ubuntu", "kali", "raspbian":
		return "deb"
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol", "amzn":
		return "rpm"
	case "alpine":
		return "apk"
	default:
		return ""
	}
}

func buildMitigationDiffStep(inst inventory.PHPInstall, branch string, adv advisory.Advisory) string {
	var applicable []advisory.Mitigation
	for _, m := range adv.Mitigations {
		if m.AppliesToBranch == "" || m.AppliesToBranch == "*" || branch == "" || m.AppliesToBranch == branch {
			applicable = append(applicable, m)
		}
	}
	if len(applicable) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Temporary configuration mitigation diff (applies to CVE-2026-109619 only; not a fix):\n")
	b.WriteString("--- a/php.ini\n")
	b.WriteString("+++ b/php.ini\n")
	for _, m := range applicable {
		fmt.Fprintf(&b, "-%s = 1\n", m.IniKey)
		fmt.Fprintf(&b, "+%s = %s\n", m.IniKey, m.RecommendedValue)
	}

	if inst.SAPI == inventory.SAPIFPM {
		b.WriteString("--- a/pool.d/www.conf\n")
		b.WriteString("+++ b/pool.d/www.conf\n")
		for _, m := range applicable {
			fmt.Fprintf(&b, "+php_admin_value[%s] = %s\n", m.IniKey, m.RecommendedValue)
		}
	}

	return strings.TrimSuffix(b.String(), "\n")
}

func restartHintsForSAPI(sapi inventory.SAPI) []string {
	switch sapi {
	case inventory.SAPIFPM:
		return []string{"reload php-fpm (e.g. systemctl reload php-fpm)"}
	case inventory.SAPIApache2Handler:
		return []string{"reload Apache (e.g. systemctl reload apache2 or systemctl reload httpd)"}
	case inventory.SAPILiteSpeed:
		return []string{"reload LiteSpeed (e.g. systemctl reload lsws)"}
	case inventory.SAPIFrankenPHP:
		return []string{"restart FrankenPHP (e.g. systemctl restart frankenphp)"}
	default:
		return []string{"reload php-fpm or Apache if web SAPIs share this PHP installation"}
	}
}

func targetDisplayName(inst inventory.PHPInstall) string {
	if inst.BinaryPath != "" {
		return inst.BinaryPath
	}
	if inst.ModulePath != "" {
		return inst.ModulePath
	}
	if inst.PackageName != "" {
		return inst.PackageName
	}
	if inst.ID != "" {
		return inst.ID
	}
	return "php"
}

func branchOrUnknown(branch string) string {
	if branch == "" {
		return "unknown"
	}
	return branch
}

// FormatText renders a Recommendation into a deterministic human-readable text block.
func FormatText(rec Recommendation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Priority: %s\n", rec.Priority)
	fmt.Fprintf(&b, "Title:    %s\n", rec.Title)

	if len(rec.Steps) > 0 {
		b.WriteString("Steps:\n")
		for i, s := range rec.Steps {
			lines := strings.Split(s, "\n")
			fmt.Fprintf(&b, "  %d. %s\n", i+1, lines[0])
			for _, cont := range lines[1:] {
				fmt.Fprintf(&b, "     %s\n", cont)
			}
		}
	}

	if len(rec.Commands) > 0 {
		b.WriteString("Commands:\n")
		for _, c := range rec.Commands {
			fmt.Fprintf(&b, "  [%s] %s\n", c.Label, c.Text)
		}
	}

	if len(rec.RestartHints) > 0 {
		b.WriteString("Restart Hints:\n")
		for _, h := range rec.RestartHints {
			fmt.Fprintf(&b, "  - %s\n", h)
		}
	}

	if rec.Notes != "" {
		fmt.Fprintf(&b, "Notes:    %s\n", rec.Notes)
	}

	return b.String()
}
