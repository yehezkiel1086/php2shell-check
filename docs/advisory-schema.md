# Advisory JSON Schema (`data/advisories.json`)

`php2shell-check` embeds `data/advisories.json` using `go:embed` and allows overriding it at runtime via `--advisory-file PATH`.

The loader in [`internal/advisory`](../internal/advisory/advisory.go) enforces strict JSON decoding (`DisallowUnknownFields`) and structural validation. Unknown fields, missing required fields, or unparseable PHP version strings cause `advisory.Load` to return a `ValidationError`.

---

## Top-Level `Advisory` Object

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | `string` | Yes | Unique advisory identifier (e.g. `"PHP2SHELL-2026"`). |
| `cves` | `string[]` | Yes | Non-empty list of CVE identifiers (`^CVE-\d{4}-\d{4,}$`), e.g. `["CVE-2026-109618", "CVE-2026-109619"]`. |
| `title` | `string` | Yes | Short descriptive title of the advisory. |
| `severity` | `string` | Yes | Severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `cvss_v4` | `number` | Yes | CVSS v4 base score in the range `(0.0, 10.0]`. |
| `summary` | `string` | Yes | Concise technical summary of the flaws. |
| `affected_min` | `string` | Yes | Minimum affected upstream PHP version (inclusive), e.g. `"5.4.0"`. |
| `affected_max_inclusive` | `string` | Yes | Maximum affected upstream PHP version (inclusive) on the highest affected branch, e.g. `"8.5.11"`. Must be `>= affected_min`. |
| `branches` | `BranchAdvisory[]` | Yes | Per-branch fix availability and EOL status. |
| `distro_fixes` | `DistroFix[]` | No | Distribution-specific package fix thresholds. |
| `mitigations` | `Mitigation[]` | No | Per-CVE INI configuration mitigations. |
| `references` | `Reference[]` | No | Advisory URLs and documentation links. |
| `last_verified` | `string` | Yes | ISO-8601 date (`YYYY-MM-DD`) when the advisory data was last reviewed. |
| `verified` | `boolean` | Yes | Whether the top-level advisory dataset has been verified against published upstream announcements. |

---

## `BranchAdvisory` Object (`branches[]`)

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `branch` | `string` | Yes | PHP `major.minor` branch (e.g. `"8.5"`, `"8.4"`, `"8.3"`, `"8.2"`, `"8.1"`). |
| `fixed_in` | `string` | No | First patched upstream version on this branch (e.g. `"8.3.36"`). If set, its parsed branch must match `branch`. |
| `eol` | `boolean` | Yes | `true` if the branch is end-of-life upstream. |
| `upstream_fix_available` | `boolean \| null` | No | `true` if an upstream release fixes the branch, `false` if confirmed unfixed, or `null` if unclear (check vendor backports or upgrade). |
| `notes` | `string` | No | Branch-specific notes. |

---

## `DistroFix` Object (`distro_fixes[]`)

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `distro` | `string` | Yes | OS distribution ID matching `/etc/os-release` `ID` (e.g. `"debian"`, `"ubuntu"`, `"rhel"`, `"rocky"`, `"almalinux"`, `"alpine"`). |
| `release` | `string` | Yes | OS release version matching `/etc/os-release` `VERSION_ID` (e.g. `"12"`, `"24.04"`, `"9"`, `"3.20"`). |
| `package` | `string` | Yes | Package name (e.g. `"php8.2-fpm"`, `"php-fpm"`, `"php83"`). |
| `fixed_version` | `string` | Conditional | First patched distro package version (required when `verified: true`). |
| `verified` | `boolean` | Yes | Only entries with `verified: true` are used by `internal/match` to return `PATCHED` or `VULNERABLE` for distro packages. Unverified entries (`verified: false`) are ignored during matching. |

---

## `Mitigation` Object (`mitigations[]`)

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `cve` | `string` | Yes | CVE identifier that this mitigation applies to (`CVE-2026-109618` or `CVE-2026-109619`). |
| `ini_key` | `string` | Yes | PHP INI directive name (e.g. `"session.upload_progress.enabled"` or `"fatal_error_backtraces"`). |
| `recommended_value` | `string` | Yes | Recommended safe directive value (e.g. `"0"` or `"Off"`). |
| `applies_to_branch` | `string` | Yes | `"*"` for all branches, or a specific `major.minor` branch (e.g. `"8.5"`). |
| `note` | `string` | No | Caveats explaining why the mitigation is a temporary risk reduction and not a patch. |

---

## `Reference` Object (`references[]`)

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `title` | `string` | Yes | Human-readable reference title. |
| `url` | `string` | Yes | Reference URL (empty string allowed when `verified: false`). |
