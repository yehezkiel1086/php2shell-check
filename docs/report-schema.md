# `php2shell-check` JSON Report Schema (`v1.0.0`)

This document specifies the stable JSON output schema produced by `php2shell-check --format json`.

## Top-Level Object (`Report`)

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | `string` | Yes | Semantic version of the report schema (`"1.0.0"`). |
| `tool_version` | `string` | Yes | Build version of `php2shell-check`. |
| `mode` | `string` | Yes | Discovery subcommand (`"local"`, `"image"`, `"sbom"`, `"path"`, `"remote"`). |
| `advisory` | `Advisory` | Yes | Loaded advisory metadata used during evaluation. |
| `summary` | `Summary` | Yes | Aggregated counts per verdict and overall highest severity verdict. |
| `results` | `Item[]` | Yes | Array of assessed findings paired with remediation guidance (never `null`). |
| `hunt_hints` | `string[]` | No | Present when `--hunt` is enabled; passive log-review indicators. |

## `Summary` Object

| Field | Type | Description |
| :--- | :--- | :--- |
| `total` | `integer` | Total number of discovered PHP installations evaluated. |
| `vulnerable` | `integer` | Count of installations with verdict `VULNERABLE`. |
| `likely_vulnerable` | `integer` | Count of installations with verdict `LIKELY_VULNERABLE`. |
| `unknown` | `integer` | Count of installations with verdict `UNKNOWN`. |
| `patched` | `integer` | Count of installations with verdict `PATCHED`. |
| `highest_verdict` | `string` | Most severe verdict across all findings (`VULNERABLE > LIKELY_VULNERABLE > UNKNOWN > PATCHED`). |

## `Item` Object (`results[]`)

Each element of `results` contains:

- `finding` (`Finding`):
  - `advisory_id` (`string`): Advisory identifier (e.g., `"PHP2SHELL-2026"`).
  - `cves` (`string[]`): Assessed CVE identifiers (`["CVE-2026-109618", "CVE-2026-109619"]`).
  - `install` (`PHPInstall`): Normalized inventory record (`id`, `binary_path`, `module_path`, `upstream_version`, `package_manager`, `package_name`, `package_version`, `distro`, `sapi`, `config_files`, `ini_settings`, `source`, `confidence`, `evidence`).
  - `verdict` (`string`): One of `"VULNERABLE"`, `"LIKELY_VULNERABLE"`, `"UNKNOWN"`, `"PATCHED"`.
  - `reason` (`string`): Human-readable explanation for the verdict.
  - `fixed_in` (`string`, optional): Patched upstream or distro package version for the target branch.
  - `mitigation` (`map[string]string`): Per-CVE mitigation status (`"NONE_AVAILABLE"`, `"NOT_APPLIED"`, `"APPLIED"`, `"UNKNOWN"`). Never alters `verdict`.
- `recommendation` (`Recommendation`):
  - `priority` (`string`): Remediation urgency (`"P0"`, `"P1"`, `"P2"`, `"P3"`).
  - `title` (`string`): Short remediation headline.
  - `steps` (`string[]`): Ordered action items and INI/FPM pool diffs.
  - `commands` (`Command[]`, optional): Validated, display-only upgrade commands (`label`, `text`).
  - `restart_hints` (`string[]`, optional): Service reload/restart hints.
  - `notes` (`string`, optional): Safety notes and warnings.
  - `references` (`Reference[]`, optional): External advisory links.

## Safety Guarantees

- Credentials, tokens, or secret assignments encountered in configuration evidence are automatically redacted to `[REDACTED]`.
- Full process environment dumps are never collected or serialized.
