package match

import (
	"strings"

	"github.com/yehezkiel1086/php2shell-check/internal/advisory"
	"github.com/yehezkiel1086/php2shell-check/internal/inventory"
)

func evaluateMitigations(inst inventory.PHPInstall, branch string, adv advisory.Advisory) map[string]MitigationStatus {
	result := make(map[string]MitigationStatus, len(adv.CVEs))

	for _, cve := range adv.CVEs {
		applicable := applicableMitigationsForCVE(cve, branch, adv.Mitigations)
		if len(applicable) == 0 {
			result[cve] = MitigationNoneAvailable
			continue
		}
		result[cve] = evaluateCVEMitigations(inst, applicable)
	}

	return result
}

func applicableMitigationsForCVE(cve, branch string, all []advisory.Mitigation) []advisory.Mitigation {
	var out []advisory.Mitigation
	for _, m := range all {
		if m.CVE != cve {
			continue
		}
		if m.AppliesToBranch == "" || m.AppliesToBranch == "*" || (branch != "" && m.AppliesToBranch == branch) {
			out = append(out, m)
		}
	}
	return out
}

func evaluateCVEMitigations(inst inventory.PHPInstall, applicable []advisory.Mitigation) MitigationStatus {
	if len(inst.IniSettings) == 0 {
		return MitigationUnknown
	}

	hasUnknown := false
	for _, m := range applicable {
		rawVal, exists := inst.IniSettings[m.IniKey]
		if !exists {
			hasUnknown = true
			continue
		}

		// Rule: When the setting came from CLI ini only, mark UNKNOWN for non-CLI SAPIs.
		if inst.SAPI != inventory.SAPICLI && isSettingFromCLIOnly(inst, m.IniKey) {
			hasUnknown = true
			continue
		}

		if normalizeIniBool(rawVal) != normalizeIniBool(m.RecommendedValue) {
			return MitigationNotApplied
		}
	}

	if hasUnknown {
		return MitigationUnknown
	}
	return MitigationApplied
}

func isSettingFromCLIOnly(inst inventory.PHPInstall, key string) bool {
	prefix := "ini:" + key + "="
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

	// If no explicit evidence lines were attached, check ConfigFiles.
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

func normalizeIniBool(s string) string {
	val := strings.ToLower(strings.Trim(strings.TrimSpace(s), `"'`))
	switch val {
	case "0", "off", "false", "no", "none":
		return "0"
	case "1", "on", "true", "yes":
		return "1"
	default:
		return val
	}
}
