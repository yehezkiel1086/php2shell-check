package remediate

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
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

// PathMitigationNotice is the mandatory mitigation message for Source=path findings.
const PathMitigationNotice = "config mitigation cannot be assessed from build files, scan the built image"

// PathRestartHint is the mandatory restart hint for Source=path findings.
const PathRestartHint = "rebuild and redeploy the image"

// PathBranchChoiceNotice instructs operators to choose the branch their application is tested on.
const PathBranchChoiceNotice = "choose the branch your application is tested on"

var (
	safeImageRefRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$`)
	evidenceFromRe     = regexp.MustCompile(`(?i)^FROM\s+(?:--[a-z0-9-]+=\S+\s+)*(\S+)`)
	evidenceComposeRe  = regexp.MustCompile(`^-?\s*image\s*:\s*["']?([^\s"'#]+)["']?`)
	tagVersionPrefixRe = regexp.MustCompile(`^(\d+(?:\.\d+)*(?:(?:RC|alpha|beta|dev)\d*)?)(.*)$`)
	branchHintRe       = regexp.MustCompile(`(\d+\.\d+)`)
)

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
	AppliesTo    []string             `json:"applies_to,omitempty"`
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
	if f.Install.Source == inventory.SourcePath {
		return buildPathRecommendation(f, adv, opts)
	}

	refs := append([]advisory.Reference(nil), adv.References...)

	if f.Verdict == match.VerdictPatched {
		steps := []string{"No remediation required: installation meets or exceeds the patched version threshold."}
		if f.Install.Source == inventory.SourceRemote {
			steps = append(steps, "Extra hardening: set expose_php = Off to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
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
		if f.Install.Source == inventory.SourceRemote {
			steps = append(steps, "Extra hardening: set expose_php = Off to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
		} else {
			branch := parseInstallBranch(f.Install.UpstreamVersion)
			if mitStep := buildMitigationStep(f, branch, adv); mitStep != "" {
				steps = append(steps, mitStep)
			}
		}
		rec := Recommendation{
			Priority:     PriorityP3,
			Title:        fmt.Sprintf("Verify PHP installation manually for %s", targetDisplayName(f.Install)),
			Steps:        steps,
			RestartHints: restartHints(f),
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

	commands, validationNotes := buildCommands(f, targetVer, adv)
	mitigationStep := buildMitigationStep(f, branch, adv)

	steps := []string{upgradeStep}
	if f.Install.Source == inventory.SourceRemote {
		steps = append(steps, "Extra hardening: set expose_php = Off to suppress X-Powered-By HTTP version banners (banner, may be hidden or spoofed).")
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
		RestartHints: restartHints(f),
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

func isEOLOrNoFix(branch string, adv advisory.Advisory) bool {
	if branch == "" {
		return false
	}
	for _, b := range adv.Branches {
		if b.Branch == branch {
			return b.EOL || (b.UpstreamFixAvailable != nil && !*b.UpstreamFixAvailable) || b.FixedIn == ""
		}
	}
	v, err := phpver.Parse(branch + ".0")
	if err == nil {
		if minV, errMin := phpver.Parse(adv.AffectedMin); errMin == nil && phpver.Compare(v, minV) >= 0 {
			if maxV, errMax := phpver.Parse(adv.AffectedMaxInclusive); errMax == nil && phpver.Compare(v, maxV) <= 0 {
				return true
			}
		}
	}
	return false
}

func isDistroManaged(inst inventory.PHPInstall) bool {
	if isCPanelOrCloudLinux(inst) {
		return false
	}
	pm := strings.ToLower(strings.TrimSpace(inst.PackageManager))
	if pm == "deb" || pm == "apk" || pm == "rpm" || pm == "dpkg" || pm == "apt" || pm == "dnf" || pm == "yum" {
		return true
	}
	if pm == "container" || pm == "composer" || pm == "path" || pm == "sbom" {
		return false
	}
	if inst.PackageName != "" || inst.PackageVersion != "" {
		return true
	}
	return false
}

func isSourceBuild(inst inventory.PHPInstall) bool {
	if isCPanelOrCloudLinux(inst) {
		return false
	}
	return !isDistroManaged(inst)
}

func formatDistroName(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "debian":
		return "Debian"
	case "ubuntu":
		return "Ubuntu"
	case "alpine":
		return "Alpine"
	case "rhel":
		return "RHEL"
	case "rocky":
		return "Rocky"
	case "centos":
		return "CentOS"
	case "almalinux":
		return "AlmaLinux"
	case "fedora":
		return "Fedora"
	case "kali":
		return "Kali"
	case "":
		return "distro"
	default:
		lower := strings.ToLower(strings.TrimSpace(id))
		return strings.ToUpper(lower[:1]) + lower[1:]
	}
}

func detectSourceBuildPrefix(inst inventory.PHPInstall) (string, string) {
	p := inst.BinaryPath
	if p == "" {
		p = inst.ModulePath
	}
	if p == "" && len(inst.ConfigFiles) > 0 {
		p = inst.ConfigFiles[0]
	}
	p = filepath.ToSlash(p)

	var prefix string
	if idx := strings.Index(p, "/bin/"); idx >= 0 {
		prefix = p[:idx]
	} else if idx := strings.Index(p, "/sbin/"); idx >= 0 {
		prefix = p[:idx]
	} else if idx := strings.Index(p, "/etc/"); idx >= 0 {
		prefix = p[:idx]
	} else if idx := strings.Index(p, "/lib/"); idx >= 0 {
		prefix = p[:idx]
	} else {
		prefix = filepath.ToSlash(filepath.Dir(p))
	}

	if prefix == "" || prefix == "." || prefix == "/usr" {
		prefix = "/usr/local"
	}

	parent := filepath.ToSlash(filepath.Dir(prefix))
	if prefix == "/usr/local" || parent == "/" || parent == "." {
		parent = prefix
	}
	return prefix, parent
}

func deriveRelatedPhpPackages(inst inventory.PHPInstall, branch string) []string {
	pkg := inst.PackageName
	pm := resolvePackageManagerFamily(inst.PackageManager, inst.Distro.ID)

	var prefix string
	if pkg != "" {
		if idx := strings.LastIndexByte(pkg, '-'); idx >= 0 {
			prefix = pkg[:idx]
		} else if strings.HasPrefix(pkg, "php") {
			prefix = pkg
		}
	}
	if prefix == "" {
		switch pm {
		case "apk":
			if branch != "" {
				prefix = "php" + strings.ReplaceAll(branch, ".", "")
			} else {
				prefix = "php"
			}
		case "deb":
			if branch != "" {
				prefix = "php" + branch
			} else {
				prefix = "php"
			}
		default:
			prefix = "php"
		}
	}

	var candidates []string
	switch pm {
	case "apk":
		candidates = []string{prefix + "-cli", prefix + "-fpm", prefix + "-common"}
	case "rpm":
		candidates = []string{"php-cli", "php-fpm", "php-common"}
	default:
		candidates = []string{prefix + "-cli", prefix + "-fpm", prefix + "-common"}
	}

	var valid []string
	for _, c := range candidates {
		if ValidatePackageToken(c) == nil {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		return []string{"php"}
	}
	return valid
}

func buildUpgradeStep(f match.Finding, branch string, adv advisory.Advisory) (string, string) {
	inst := f.Install

	// 1. EOL or no-fix branch
	if isEOLOrNoFix(branch, adv) {
		highestBranch, highestFixedIn := deriveHighestFixedIn(adv)
		if highestFixedIn != "" {
			return fmt.Sprintf(
				"Branch %s has no verified upstream fix (EOL/unfixed); major-version migration, needs application testing (target: %s (>= %s)). Check for vendor or LTS backports, and keep configuration mitigations as a stop-gap.",
				branchOrUnknown(branch),
				highestBranch,
				highestFixedIn,
			), ""
		}
		return fmt.Sprintf("Branch %s has no verified upstream fix; major-version migration, needs application testing.", branchOrUnknown(branch)), ""
	}

	// 2. Distro-managed install
	if isDistroManaged(inst) {
		if df, ok := match.FindVerifiedDistroFix(inst, adv.DistroFixes); ok {
			pkg := inst.PackageName
			if pkg == "" {
				pkg = "php"
			}
			return fmt.Sprintf("Upgrade %s to >= %s via distro package manager.", pkg, df.FixedVersion), df.FixedVersion
		}
		distroName := formatDistroName(inst.Distro.ID)
		step := fmt.Sprintf("No verified %s fix is recorded yet; check vendor security trackers for backported package updates.", distroName)
		if inst.Source == inventory.SourceImage {
			step += " Rebuild the layer without cache once updated packages are available."
		}
		return step, ""
	}

	// 3. Fixable branch
	fixedIn := f.FixedIn
	if fixedIn == "" {
		for _, b := range adv.Branches {
			if b.Branch == branch && b.FixedIn != "" && (b.UpstreamFixAvailable == nil || *b.UpstreamFixAvailable) {
				fixedIn = b.FixedIn
				break
			}
		}
	}

	// Local source build:
	if inst.Source == inventory.SourceLocal && isSourceBuild(inst) && fixedIn != "" {
		_, parentPrefix := detectSourceBuildPrefix(inst)
		targetEx := fmt.Sprintf("%s/%s", parentPrefix, fixedIn)
		return fmt.Sprintf("Rebuild PHP >= %s with the same configure options into a new prefix (for example %s), switch symlinks or service paths, then restart php-fpm.", fixedIn, targetEx), fixedIn
	}

	if fixedIn != "" {
		return fmt.Sprintf("Upgrade PHP on branch %s to >= %s.", branchOrUnknown(branch), fixedIn), fixedIn
	}

	return fmt.Sprintf("Upgrade PHP on branch %s to a patched release.", branchOrUnknown(branch)), ""
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

func buildCommands(f match.Finding, targetVersion string, adv advisory.Advisory) ([]Command, string) {
	inst := f.Install
	branch := parseInstallBranch(inst.UpstreamVersion)
	var cmds []Command
	var notes []string

	// 1. Remote findings have NO commands.
	if inst.Source == inventory.SourceRemote {
		return nil, ""
	}

	// 2. Check for cPanel or CloudLinux paths/packages first.
	if isCPanelOrCloudLinux(inst) {
		cmds = append(cmds, Command{
			Label: "Vendor update tooling (cPanel / CloudLinux)",
			Text:  "use your vendor's update tooling",
		})
		return cmds, ""
	}

	// 3. EOL or no-fix branch (no bump-the-tag command!).
	if isEOLOrNoFix(branch, adv) {
		highestBranch, highestFixedIn := deriveHighestFixedIn(adv)
		cmds = append(cmds, Command{
			Label: "Migrate PHP runtime",
			Text:  fmt.Sprintf("major-version migration, needs application testing (target: PHP %s >= %s)", highestBranch, highestFixedIn),
		})
		return cmds, ""
	}

	// 4. Distro-managed install
	if isDistroManaged(inst) {
		if inst.PackageName != "" {
			if err := ValidatePackageToken(inst.PackageName); err != nil {
				notes = append(notes, fmt.Sprintf("Rejected unsafe package name %q from command generation.", inst.PackageName))
				return nil, strings.Join(notes, " ")
			}
		}

		pm := resolvePackageManagerFamily(inst.PackageManager, inst.Distro.ID)
		if _, ok := match.FindVerifiedDistroFix(inst, adv.DistroFixes); ok {
			pkg := inst.PackageName
			switch pm {
			case "deb":
				if pkg == "" {
					pkg = "php"
				}
				cmds = append(cmds, Command{
					Label: "Upgrade Debian/Ubuntu package",
					Text:  fmt.Sprintf("apt-get install --only-upgrade %s", pkg),
				})
			case "rpm":
				if pkg == "" {
					pkg = "php"
				}
				cmds = append(cmds, Command{
					Label: "Upgrade RPM package",
					Text:  fmt.Sprintf("dnf upgrade %s", pkg),
				})
			case "apk":
				if pkg == "" {
					pkg = "php"
				}
				cmds = append(cmds, Command{
					Label: "Upgrade Alpine package",
					Text:  fmt.Sprintf("apk upgrade %s", pkg),
				})
			}
		} else {
			pkgs := deriveRelatedPhpPackages(inst, branch)
			switch pm {
			case "deb":
				cmds = append(cmds, Command{
					Label: "Upgrade Debian/Ubuntu PHP packages",
					Text:  fmt.Sprintf("apt-get update && apt-get install --only-upgrade %s", strings.Join(pkgs, " ")),
				})
			case "rpm":
				cmds = append(cmds, Command{
					Label: "Upgrade RPM PHP packages",
					Text:  fmt.Sprintf("dnf check-update; dnf upgrade %s", strings.Join(pkgs, " ")),
				})
			case "apk":
				cmds = append(cmds, Command{
					Label: "Upgrade Alpine PHP packages",
					Text:  fmt.Sprintf("apk update && apk upgrade %s", strings.Join(pkgs, " ")),
				})
			}
		}

		if inst.Source == inventory.SourceImage {
			cmds = append(cmds, Command{
				Label: "Rebuild container layer",
				Text:  "rebuild the layer without cache",
			})
		}
		return cmds, strings.Join(notes, " ")
	}

	// 5. Container image source build (e.g. official PHP image):
	if inst.Source == inventory.SourceImage {
		if targetVersion != "" {
			safeRef := sanitizeImageRefForDisplay(inst.ImageRef)
			if safeRef == "" || safeRef == "php" {
				safeRef = extractContainerImageRef(inst)
			}
			_, tag := splitContainerRepoTag(safeRef)
			variantSuffix := extractTagVariantSuffix(tag, inst.SAPI)
			fixedTag := formatContainerTag("php", targetVersion, variantSuffix)
			cmds = append(cmds, Command{
				Label: "Update container base image",
				Text:  fmt.Sprintf("bump the base image tag to %s", fixedTag),
			})
			return cmds, strings.Join(notes, " ")
		}
		cmds = append(cmds, Command{
			Label: "Update container base image",
			Text:  "bump the base image tag to a patched release",
		})
		return cmds, strings.Join(notes, " ")
	}

	// 6. Local / standalone source build (fixable branch):
	if isSourceBuild(inst) {
		prefix, prefixParent := detectSourceBuildPrefix(inst)
		if targetVersion != "" && ValidatePackageToken(strings.ToLower(targetVersion)) == nil {
			examplePrefix := fmt.Sprintf("%s/%s", prefixParent, strings.ToLower(targetVersion))
			cmds = append(cmds, Command{
				Label: fmt.Sprintf("Upgrade source/custom PHP build in %s", prefix),
				Text:  fmt.Sprintf("rebuild PHP >= %s with the same configure options into a new prefix (for example %s), switch symlinks or service paths, then restart php-fpm", strings.ToLower(targetVersion), examplePrefix),
			})
		} else {
			cmds = append(cmds, Command{
				Label: fmt.Sprintf("Upgrade source/custom PHP build in %s", prefix),
				Text:  "rebuild PHP with the same configure options into a new prefix, switch symlinks or service paths, then restart php-fpm",
			})
		}
		return cmds, strings.Join(notes, " ")
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

var sourceFileLineRe = regexp.MustCompile(`ini:session\.upload_progress\.enabled=[^\s(]+\s+\(source:\s*([^)]+)\)`)

func findMitigationSourceFileLine(f match.Finding) string {
	for _, ev := range f.ConfigEvidence {
		if m := sourceFileLineRe.FindStringSubmatch(ev); len(m) == 2 {
			return m[1]
		}
	}
	for _, ev := range f.Install.Evidence {
		if m := sourceFileLineRe.FindStringSubmatch(ev); len(m) == 2 {
			return m[1]
		}
	}
	if len(f.Install.ConfigFiles) > 0 {
		return f.Install.ConfigFiles[0]
	}
	return ""
}

func findMitigationUnknownReason(f match.Finding) string {
	inst := f.Install
	if len(inst.ConfigFiles) == 0 && len(inst.IniSettings) == 0 {
		return "config path not found"
	}
	if inst.SAPI != inventory.SAPICLI && isSettingFromCLIOnly(inst) {
		return "CLI configuration only, web SAPI config not found"
	}
	return "config path not found"
}

func isSettingFromCLIOnly(inst inventory.PHPInstall) bool {
	prefix := "ini:session.upload_progress.enabled="
	var sources []string
	for _, ev := range inst.Evidence {
		if !strings.HasPrefix(ev, prefix) {
			continue
		}
		idx := strings.Index(ev, "(source: ")
		if idx < 0 {
			continue
		}
		src := strings.TrimSuffix(ev[idx+len("(source: "):], ")")
		sources = append(sources, strings.ToLower(strings.ReplaceAll(src, `\`, "/")))
	}
	if len(sources) > 0 {
		for _, src := range sources {
			if !isCLISource(src) {
				return false
			}
		}
		return true
	}
	if len(inst.ConfigFiles) > 0 {
		for _, cf := range inst.ConfigFiles {
			norm := strings.ToLower(strings.ReplaceAll(cf, `\`, "/"))
			if !isCLISource(norm) {
				return false
			}
		}
		return true
	}
	return false
}

func isCLISource(src string) bool {
	return src == "php -i" ||
		strings.Contains(src, "/cli/") ||
		strings.HasSuffix(src, "/cli/php.ini")
}

func detectDropInIniPath(inst inventory.PHPInstall, branch string) string {
	for _, cf := range inst.ConfigFiles {
		norm := filepath.ToSlash(cf)
		if idx := strings.Index(norm, "/conf.d/"); idx >= 0 {
			return norm[:idx+len("/conf.d")] + "/99-mitigation.ini"
		}
	}

	if (inst.Distro.ID == "debian" || inst.Distro.ID == "ubuntu") && !strings.HasPrefix(inst.BinaryPath, "/opt/") {
		sapiStr := string(inst.SAPI)
		if sapiStr == "" || sapiStr == "unknown" {
			sapiStr = "cli"
		}
		b := branch
		if b == "" {
			b = parseInstallBranch(inst.UpstreamVersion)
		}
		if b != "" {
			return fmt.Sprintf("/etc/php/%s/%s/conf.d/99-mitigation.ini", b, sapiStr)
		}
	}

	if strings.HasPrefix(inst.BinaryPath, "/usr/local/") || strings.HasPrefix(inst.ModulePath, "/usr/local/") || inst.Source == inventory.SourceImage {
		return "/usr/local/etc/php/conf.d/99-mitigation.ini"
	}

	if isSourceBuild(inst) {
		prefix, _ := detectSourceBuildPrefix(inst)
		if prefix != "" && prefix != "/" {
			return fmt.Sprintf("%s/etc/conf.d/99-mitigation.ini", prefix)
		}
	}

	return "/etc/php/conf.d/99-mitigation.ini"
}

func detectFpmPoolPath(inst inventory.PHPInstall, branch string) string {
	for _, cf := range inst.ConfigFiles {
		norm := filepath.ToSlash(cf)
		if strings.HasSuffix(norm, "/www.conf") || strings.Contains(norm, "/pool.d/") || strings.Contains(norm, "/php-fpm.d/") {
			return norm
		}
	}
	poolRe := regexp.MustCompile(`source:\s*([^\s)]+www\.conf[^\s)]*)`)
	for _, ev := range inst.Evidence {
		if m := poolRe.FindStringSubmatch(ev); len(m) == 2 {
			p := m[1]
			if idx := strings.Index(p, ":"); idx >= 0 {
				p = p[:idx]
			}
			return filepath.ToSlash(p)
		}
	}
	if (inst.Distro.ID == "debian" || inst.Distro.ID == "ubuntu") && !strings.HasPrefix(inst.BinaryPath, "/opt/") {
		b := branch
		if b == "" {
			b = parseInstallBranch(inst.UpstreamVersion)
		}
		if b != "" {
			return fmt.Sprintf("/etc/php/%s/fpm/pool.d/www.conf", b)
		}
		return "/etc/php/fpm/pool.d/www.conf"
	}
	if isSourceBuild(inst) {
		prefix, _ := detectSourceBuildPrefix(inst)
		if prefix != "" && prefix != "/usr/local" && prefix != "/" {
			return fmt.Sprintf("%s/etc/php-fpm.d/www.conf", prefix)
		}
	}
	return "/usr/local/etc/php-fpm.d/www.conf"
}

func buildMitigationStep(f match.Finding, branch string, adv advisory.Advisory) string {
	if f.Verdict == match.VerdictPatched {
		return ""
	}

	inst := f.Install
	if inst.Source == inventory.SourceRemote {
		return "Temporary configuration mitigation (CVE-2026-109619): config mitigation cannot be assessed remotely, run scan local on the host."
	}

	status, exists := f.Mitigation["CVE-2026-109619"]
	if !exists {
		status = match.MitigationNotApplied
	}
	switch status {
	case match.MitigationApplied:
		source := findMitigationSourceFileLine(f)
		if source != "" {
			return fmt.Sprintf("Temporary configuration mitigation (CVE-2026-109619): already applied via %s, still upgrade.", source)
		}
		return "Temporary configuration mitigation (CVE-2026-109619): already applied, still upgrade."

	case match.MitigationNotApplied:
		dropInPath := detectDropInIniPath(inst, branch)
		var b strings.Builder
		b.WriteString("Temporary configuration mitigation (applies to CVE-2026-109619 only; not a fix):\n")
		fmt.Fprintf(&b, "Create drop-in INI file %s:\n", dropInPath)
		b.WriteString("  session.upload_progress.enabled = 0\n")
		if branch == "8.5" {
			b.WriteString("  fatal_error_backtraces = 0\n")
		}
		if inst.SAPI == inventory.SAPIFPM {
			poolPath := detectFpmPoolPath(inst, branch)
			fmt.Fprintf(&b, "Alternatively, in FPM pool config (%s):\n", poolPath)
			b.WriteString("  php_admin_value[session.upload_progress.enabled] = 0\n")
			if branch == "8.5" {
				b.WriteString("  php_admin_value[fatal_error_backtraces] = 0\n")
			}
		} else if inst.SAPI == inventory.SAPIApache2Handler {
			b.WriteString("Alternatively, in Apache configuration:\n")
			b.WriteString("  php_admin_flag session.upload_progress.enabled off\n")
			if branch == "8.5" {
				b.WriteString("  php_admin_value fatal_error_backtraces 0\n")
			}
		}
		return strings.TrimSuffix(b.String(), "\n")

	case match.MitigationUnknown:
		reason := findMitigationUnknownReason(f)
		return fmt.Sprintf("Temporary configuration mitigation (CVE-2026-109619): UNKNOWN (%s).", reason)

	default:
		return ""
	}
}

func restartHints(f match.Finding) []string {
	if f.Verdict == match.VerdictPatched {
		return nil
	}
	inst := f.Install
	if inst.Source == inventory.SourceRemote {
		return nil
	}
	if inst.Source == inventory.SourceImage {
		return []string{"rebuild and redeploy the image, restarting a container does not change PHP baked into the image"}
	}
	if inst.Source == inventory.SourcePath {
		return []string{PathRestartHint}
	}
	return localRestartHints(inst)
}

func localRestartHints(inst inventory.PHPInstall) []string {
	switch inst.SAPI {
	case inventory.SAPIFPM:
		unit := "php-fpm"
		if inst.PackageName != "" && strings.HasPrefix(inst.PackageName, "php") && strings.HasSuffix(inst.PackageName, "-fpm") {
			unit = inst.PackageName
		} else if strings.Contains(inst.BinaryPath, "php-fpm") {
			base := filepath.Base(inst.BinaryPath)
			if strings.HasPrefix(base, "php-fpm") {
				unit = base
			}
		}
		if unit != "php-fpm" {
			return []string{fmt.Sprintf("reload php-fpm (e.g. systemctl reload %s)", unit)}
		}
		return []string{"reload php-fpm (e.g. systemctl reload php-fpm)"}

	case inventory.SAPIApache2Handler:
		switch strings.ToLower(inst.Distro.ID) {
		case "rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn":
			return []string{"reload Apache (e.g. systemctl reload httpd)"}
		case "debian", "ubuntu", "kali":
			return []string{"reload Apache (e.g. systemctl reload apache2)"}
		default:
			return []string{"reload Apache (e.g. systemctl reload apache2 or systemctl reload httpd)"}
		}

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
	if len(rec.AppliesTo) > 0 {
		fmt.Fprintf(&b, "Applies to: %s\n", strings.Join(rec.AppliesTo, ", "))
	}

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

func buildPathRecommendation(f match.Finding, adv advisory.Advisory, opts Options) Recommendation {
	refs := append([]advisory.Reference(nil), adv.References...)
	inst := f.Install
	restartHints := []string{PathRestartHint}
	priority := computePriority(f.Verdict, inst.SAPI)

	var title string
	switch f.Verdict {
	case match.VerdictPatched:
		title = fmt.Sprintf("No remediation required for %s (PATCHED)", targetDisplayName(inst))
	case match.VerdictUnknown:
		title = fmt.Sprintf("Verify PHP installation manually for %s", targetDisplayName(inst))
	default:
		title = fmt.Sprintf("[%s] Remediate %s (%s, SAPI: %s)", priority, targetDisplayName(inst), f.Verdict, inst.SAPI)
	}

	var steps []string
	var cmds []Command

	switch {
	case inst.PackageManager == "container":
		rawRef := extractContainerImageRef(inst)
		normRef := inventory.NormalizeImageRef(rawRef)
		safeRef := sanitizeImageRefForDisplay(normRef)
		displayRepo, tag := splitContainerRepoTag(safeRef)
		variantSuffix := extractTagVariantSuffix(tag, inst.SAPI)

		switch f.Verdict {
		case match.VerdictPatched:
			steps = append(steps, fmt.Sprintf("Declared container image tag %s meets or exceeds the patched version threshold (%s).", safeRef, f.FixedIn))
		case match.VerdictUnknown:
			scanCmd := fmt.Sprintf("php2shell-check scan image %s", safeRef)
			steps = append(steps, fmt.Sprintf("%s — resolve the floating tag and inspect the built image (verify manually).", scanCmd))
			cmds = append(cmds, Command{
				Label: "Scan resolved image",
				Text:  scanCmd,
			})
			if f.FixedIn != "" {
				fixedTag := formatContainerTag(displayRepo, f.FixedIn, variantSuffix)
				steps = append(steps, fmt.Sprintf("Pin the image tag to %s and pin by digest (@sha256:...) after an image scan (scan the resolved image digest).", fixedTag))
				cmds = append(cmds, Command{
					Label: "Update container base image",
					Text:  fmt.Sprintf("bump the base image tag to %s", fixedTag),
				})
			} else {
				allTags := buildAllSupportedBranchTags(displayRepo, variantSuffix, adv)
				steps = append(steps, fmt.Sprintf("Pin the image tag to a fixed release (%s — %s) and pin by digest after scanning the resolved image digest.", strings.Join(allTags, ", "), PathBranchChoiceNotice))
				cmds = append(cmds, Command{
					Label: "Update container base image",
					Text:  fmt.Sprintf("bump the base image tag to one of: %s (%s)", strings.Join(allTags, ", "), PathBranchChoiceNotice),
				})
			}
		default:
			branch := parseInstallBranch(inst.UpstreamVersion)
			fixedIn := f.FixedIn
			if fixedIn == "" && branch != "" {
				fixedIn = findFixedInForBranch(branch, adv)
			}
			if fixedIn != "" {
				fixedTag := formatContainerTag(displayRepo, fixedIn, variantSuffix)
				steps = append(steps, fmt.Sprintf("Upgrade the container image tag on branch %s from %s to %s.", branchOrUnknown(branch), safeRef, fixedTag))
				cmds = append(cmds, Command{
					Label: "Update container base image",
					Text:  fmt.Sprintf("bump the base image tag to %s", fixedTag),
				})
			} else {
				allTags := buildAllSupportedBranchTags(displayRepo, variantSuffix, adv)
				steps = append(steps, fmt.Sprintf("Branch %s has no verified upstream fix; migrate to a supported branch tag (%s — %s).", branchOrUnknown(branch), strings.Join(allTags, ", "), PathBranchChoiceNotice))
				cmds = append(cmds, Command{
					Label: "Update container base image",
					Text:  fmt.Sprintf("bump the base image tag to one of: %s (%s)", strings.Join(allTags, ", "), PathBranchChoiceNotice),
				})
			}
		}

	case inst.PackageManager == "composer" || strings.Contains(strings.ToLower(inst.BinaryPath), "composer.json"):
		fixedIn := f.FixedIn
		if fixedIn == "" {
			if branch := extractBranchHint(inst.UpstreamVersion); branch != "" {
				fixedIn = findFixedInForBranch(branch, adv)
			}
		}
		if fixedIn != "" {
			steps = append(steps, fmt.Sprintf("A composer.json constraint is not an installed version and composer platform settings don't change the runtime; pin the runtime PHP version (e.g. >= %s) and scan the built image (verify manually).", fixedIn))
		} else {
			allVers := listSupportedFixedVersions(adv)
			steps = append(steps, fmt.Sprintf("A composer.json constraint is not an installed version and composer platform settings don't change the runtime; pin the runtime PHP version (%s — %s) and scan the built image (verify manually).", strings.Join(allVers, ", "), PathBranchChoiceNotice))
		}

	default:
		branch := parseInstallBranch(inst.UpstreamVersion)
		if branch == "" {
			branch = extractBranchHint(inst.UpstreamVersion)
		}
		fixedIn := f.FixedIn
		if fixedIn == "" && branch != "" {
			fixedIn = findFixedInForBranch(branch, adv)
		}
		switch {
		case f.Verdict == match.VerdictPatched:
			steps = append(steps, fmt.Sprintf("Declared version %s in %s meets or exceeds the patched version threshold (%s).", inst.UpstreamVersion, targetDisplayName(inst), fixedIn))
		case fixedIn != "":
			steps = append(steps, fmt.Sprintf("Update %s to the fixed version for branch %s (%s), and verify manually by scanning the built image or deployed runtime.", targetDisplayName(inst), branchOrUnknown(branch), fixedIn))
			cmds = append(cmds, Command{
				Label: "Pin PHP version",
				Text:  fmt.Sprintf("set PHP version to %s", fixedIn),
			})
		default:
			allVers := listSupportedFixedVersions(adv)
			steps = append(steps, fmt.Sprintf("Update %s to a supported fixed version (%s — %s), and verify manually by scanning the built image or deployed runtime.", targetDisplayName(inst), strings.Join(allVers, ", "), PathBranchChoiceNotice))
		}
	}

	notes := ""
	if f.Verdict != match.VerdictPatched {
		steps = append(steps, PathMitigationNotice)
		notes = PathMitigationNotice
	}
	if opts.IncludeHuntHints {
		steps = append(steps, HuntHints()...)
	}

	return Recommendation{
		Priority:     priority,
		Title:        title,
		Steps:        steps,
		Commands:     cmds,
		RestartHints: restartHints,
		Notes:        notes,
		References:   refs,
	}
}

func extractContainerImageRef(inst inventory.PHPInstall) string {
	for _, ev := range inst.Evidence {
		idx := strings.Index(ev, " -> ")
		if idx < 0 {
			continue
		}
		line := strings.TrimSpace(ev[idx+len(" -> "):])
		if m := evidenceFromRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1]
		}
		if m := evidenceComposeRe.FindStringSubmatch(line); len(m) == 2 {
			return m[1]
		}
	}
	if strings.Contains(inst.UpstreamVersion, ":") || strings.Contains(inst.UpstreamVersion, "@") {
		return inst.UpstreamVersion
	}
	if strings.Contains(inst.PackageName, ":") {
		return inst.PackageName
	}
	repo := inst.PackageName
	if repo == "" {
		repo = "php"
	}
	suffix := sapiVariantSuffix(inst.SAPI)
	if inst.UpstreamVersion != "" {
		return fmt.Sprintf("%s:%s%s", repo, inst.UpstreamVersion, suffix)
	}
	return repo
}

func sanitizeImageRefForDisplay(ref string) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" || !safeImageRefRe.MatchString(trimmed) {
		return "php"
	}
	return trimmed
}

func splitContainerRepoTag(imageRef string) (string, string) {
	ref := imageRef
	if atIdx := strings.IndexByte(ref, '@'); atIdx >= 0 {
		ref = ref[:atIdx]
	}
	lastSlash := strings.LastIndexByte(ref, '/')
	lastColon := strings.LastIndexByte(ref, ':')
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	if ref == "" {
		return "php", ""
	}
	return ref, ""
}

func extractTagVariantSuffix(tag string, sapi inventory.SAPI) string {
	if m := tagVersionPrefixRe.FindStringSubmatch(tag); len(m) == 3 {
		return m[2]
	}
	return sapiVariantSuffix(sapi)
}

func sapiVariantSuffix(sapi inventory.SAPI) string {
	switch sapi {
	case inventory.SAPIApache2Handler:
		return "-apache"
	case inventory.SAPIFPM:
		return "-fpm"
	case inventory.SAPICLI:
		return "-cli"
	default:
		return ""
	}
}

func formatContainerTag(repo, fixedIn, variantSuffix string) string {
	if repo == "" {
		repo = "php"
	}
	return fmt.Sprintf("%s:%s%s", repo, fixedIn, variantSuffix)
}

func listSupportedFixedVersions(adv advisory.Advisory) []string {
	type parsedFix struct {
		raw string
		ver phpver.Version
	}
	var fixes []parsedFix
	for _, b := range adv.Branches {
		if b.FixedIn == "" {
			continue
		}
		if b.UpstreamFixAvailable != nil && !*b.UpstreamFixAvailable {
			continue
		}
		v, err := phpver.Parse(b.FixedIn)
		if err != nil {
			continue
		}
		fixes = append(fixes, parsedFix{raw: b.FixedIn, ver: v})
	}
	sort.Slice(fixes, func(i, j int) bool {
		return phpver.Compare(fixes[i].ver, fixes[j].ver) < 0
	})
	out := make([]string, 0, len(fixes))
	for _, f := range fixes {
		out = append(out, f.raw)
	}
	return out
}

func buildAllSupportedBranchTags(repo, variantSuffix string, adv advisory.Advisory) []string {
	vers := listSupportedFixedVersions(adv)
	tags := make([]string, 0, len(vers))
	for _, v := range vers {
		tags = append(tags, formatContainerTag(repo, v, variantSuffix))
	}
	return tags
}

func findFixedInForBranch(branch string, adv advisory.Advisory) string {
	for _, b := range adv.Branches {
		if b.Branch == branch && b.FixedIn != "" && (b.UpstreamFixAvailable == nil || *b.UpstreamFixAvailable) {
			return b.FixedIn
		}
	}
	return ""
}

func extractBranchHint(raw string) string {
	if m := branchHintRe.FindStringSubmatch(raw); len(m) == 2 {
		return m[1]
	}
	return ""
}
