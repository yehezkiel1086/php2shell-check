package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
	"github.com/yehezkiel1086/php2shell-check/internal/match"
	"github.com/yehezkiel1086/php2shell-check/internal/remediate"
)

func formatImageHeaderAndNote(rep Report) (string, string) {
	imgRef := rep.ImageRef
	digest := rep.ImageDigest
	platform := rep.Platform
	resolvedFromTag := rep.ResolvedFromTag

	if imgRef == "" && len(rep.Results) > 0 {
		imgRef = rep.Results[0].Finding.ImageRef
		if imgRef == "" {
			imgRef = rep.Results[0].Finding.Install.ImageRef
		}
		if digest == "" {
			digest = rep.Results[0].Finding.ImageDigest
			if digest == "" {
				digest = rep.Results[0].Finding.Install.ImageDigest
			}
		}
		if platform == "" {
			platform = rep.Results[0].Finding.Platform
			if platform == "" {
				platform = rep.Results[0].Finding.Install.Platform
			}
		}
		if !resolvedFromTag {
			resolvedFromTag = rep.Results[0].Finding.ResolvedFromTag || rep.Results[0].Finding.Install.ResolvedFromTag
		}
	}

	if imgRef == "" {
		return "", ""
	}

	parts := []string{fmt.Sprintf("Image: %s", imgRef)}
	if digest != "" {
		parts = append(parts, fmt.Sprintf("digest: %s", digest))
	}
	if platform != "" {
		parts = append(parts, fmt.Sprintf("platform: %s", platform))
	}
	header := strings.Join(parts, "  ")

	var note string
	if resolvedFromTag {
		ver := getReportPHPVersion(rep)
		if ver != "" {
			note = fmt.Sprintf("note: floating tag resolved to PHP %s for this digest only, pin the digest in deployments", ver)
		} else {
			note = "note: floating tag resolved for this digest only, pin the digest in deployments"
		}
	}

	return header, note
}

func getReportPHPVersion(rep Report) string {
	for _, item := range rep.Results {
		v := item.Finding.Install.UpstreamVersion
		if v != "" {
			return v
		}
	}
	return ""
}

func isDistroManaged(f match.Finding) bool {
	pm := strings.ToLower(strings.TrimSpace(f.Install.PackageManager))
	if pm == "deb" || pm == "apk" || pm == "rpm" || pm == "dpkg" {
		return true
	}
	if pm == "container" || pm == "composer" || pm == "path" || pm == "sbom" {
		return false
	}
	if f.Install.Distro.ID != "" && (strings.TrimSpace(f.PackageVersion) != "" || strings.TrimSpace(f.Install.PackageVersion) != "") {
		return true
	}
	return false
}

func hasDistroPackage(rep Report) bool {
	for _, item := range rep.Results {
		if isDistroManaged(item.Finding) {
			return true
		}
	}
	return false
}

func formatPackageColumn(f match.Finding) string {
	if !isDistroManaged(f) {
		return "-"
	}
	name := strings.TrimSpace(f.PackageName)
	if name == "" {
		name = strings.TrimSpace(f.Install.PackageName)
	}
	name = inventory.NormalizeImageRef(name)
	ver := strings.TrimSpace(f.PackageVersion)
	if ver == "" {
		ver = strings.TrimSpace(f.Install.PackageVersion)
	}
	if name != "" && ver != "" {
		return fmt.Sprintf("%s %s", name, ver)
	}
	if name != "" {
		return name
	}
	if ver != "" {
		return ver
	}
	return "-"
}

func displayFixedIn(f match.Finding, adv advisory.Advisory) string {
	if f.FixedIn == "" {
		return "-"
	}
	if !isDistroManaged(f) {
		return f.FixedIn
	}
	for _, df := range adv.DistroFixes {
		if df.Verified && df.FixedVersion == f.FixedIn {
			return f.FixedIn
		}
	}
	return fmt.Sprintf("unverified (upstream %s)", f.FixedIn)
}

type remediationGroup struct {
	key      string
	verdict  match.Verdict
	fixedIn  string
	priority remediate.Priority
	targets  []string
	baseRec  remediate.Recommendation
	cmds     []remediate.Command
	hints    []string
}

func groupRemediations(items []Item) []remediate.Recommendation {
	if len(items) == 0 {
		return nil
	}

	var groupOrder []string
	groups := make(map[string]*remediationGroup)

	for _, item := range items {
		f := item.Finding
		mitKey := formatMitigationMap(f.Mitigation)
		key := fmt.Sprintf("%s|%s|%s", f.Verdict, f.FixedIn, mitKey)

		target := primaryTarget(f)
		g, exists := groups[key]
		if !exists {
			g = &remediationGroup{
				key:      key,
				verdict:  f.Verdict,
				fixedIn:  f.FixedIn,
				priority: item.Recommendation.Priority,
				targets:  []string{target},
				baseRec:  item.Recommendation,
				cmds:     append([]remediate.Command(nil), item.Recommendation.Commands...),
				hints:    append([]string(nil), item.Recommendation.RestartHints...),
			}
			groups[key] = g
			groupOrder = append(groupOrder, key)
		} else {
			if !containsString(g.targets, target) {
				g.targets = append(g.targets, target)
			}
			if comparePriority(item.Recommendation.Priority, g.priority) > 0 {
				g.priority = item.Recommendation.Priority
			}
			for _, cmd := range item.Recommendation.Commands {
				if !containsCommand(g.cmds, cmd) {
					g.cmds = append(g.cmds, cmd)
				}
			}
			for _, hint := range item.Recommendation.RestartHints {
				if !containsString(g.hints, hint) {
					g.hints = append(g.hints, hint)
				}
			}
		}
	}

	out := make([]remediate.Recommendation, 0, len(groupOrder))
	for _, key := range groupOrder {
		g := groups[key]
		rec := g.baseRec
		rec.Priority = g.priority
		rec.Commands = g.cmds
		rec.RestartHints = g.hints

		if len(g.targets) > 1 {
			sort.Strings(g.targets)
			rec.AppliesTo = g.targets
			switch g.verdict {
			case match.VerdictPatched:
				rec.Title = "No remediation required for PHP installations (PATCHED)"
			case match.VerdictUnknown:
				rec.Title = "Verify PHP installations manually (UNKNOWN)"
			default:
				rec.Title = fmt.Sprintf("[%s] Remediate PHP installations (%s)", g.priority, g.verdict)
			}
		}
		out = append(out, rec)
	}
	return out
}

func priorityRank(p remediate.Priority) int {
	switch p {
	case remediate.PriorityP0:
		return 4
	case remediate.PriorityP1:
		return 3
	case remediate.PriorityP2:
		return 2
	case remediate.PriorityP3:
		return 1
	default:
		return 0
	}
}

func comparePriority(a, b remediate.Priority) int {
	return priorityRank(a) - priorityRank(b)
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsCommand(slice []remediate.Command, cmd remediate.Command) bool {
	for _, c := range slice {
		if c.Label == cmd.Label && c.Text == cmd.Text {
			return true
		}
	}
	return false
}
