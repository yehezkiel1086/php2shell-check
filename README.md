# php2shell-check

`php2shell-check` is a defensive security CLI that detects, assesses, and recommends remediation for **CVE-2026-109618** and **CVE-2026-109619** (PHP engine remote code execution flaws, aka **PHP2Shell**). Built for authorized security assessments and DevSecOps pipelines.

---

## Authorized-Use & Safety Statement

`php2shell-check` is strictly a **detection and remediation assessment tool**:
- **No exploit payloads**: It never generates, includes, or transmits proof-of-concept payloads, out-of-memory or crash triggers, or crafted `multipart/form-data` requests.
- **Read-only local and container inspection**: `scan local`, `scan image`, `scan sbom`, and `scan path` never modify target files or execute binaries extracted from container images. Local binary inspection uses `exec.CommandContext` with an absolute path, no shell, and a 10-second timeout.
- **Passive remote inspection**: `scan remote` requires an explicit `--authorized` flag, sends a single benign `GET` request per target with no query parameters and no body, follows same-host redirects only, and reads only `Server` and `X-Powered-By` headers.
- **Display-only remediation**: Remediation commands are rendered as text for human operators and are never executed by the tool. All package names and version tokens are validated against a strict regular expression (`^[a-z0-9][a-z0-9+.-]*$`).
- Only use `scan remote` against systems you own or have explicit written authorization to assess.

---

## Installation

### From Source (Go 1.25+)

```bash
go install github.com/yehezkiel1086/php2shell-check/cmd/php2shell-check@latest

# Ensure Go's bin directory is in your PATH (Ubuntu/Debian/macOS):
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Build Locally

```bash
git clone https://github.com/yehezkiel1086/php2shell-check.git
cd php2shell-check
make build
./bin/php2shell-check version
```

---

## Usage Per Mode

### Global Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--format` | `table` | Output format: `table`, `json`, `sarif`, `md` |
| `--output` | *(stdout)* | Write report to `FILE` instead of stdout |
| `--fail-on` | `likely` | Exit non-zero threshold: `vulnerable`, `likely`, `unknown`, `never` |
| `--offline` | `false` | Disable network access (blocks remote registry pulls and `scan remote`) |
| `--quiet` | `false` | Suppress non-essential output in human-readable table mode |
| `--no-color` | `false` | Disable ANSI color sequences in table output |
| `--advisory-file` | *(embedded)* | Override embedded advisory database with a custom JSON file |
| `--hunt` | `false` | Include passive log-review indicators for known PHP2Shell samples |

### 1. Local Host Mode (`scan local`)

Discovers PHP CLI, FPM, FrankenPHP, and Apache `libphp*.so` installations on the local host, maps package ownership (`dpkg-query`, `rpm`, `apk`), and inspects `php.ini`, `conf.d/*.ini`, and FPM pool configurations (`php_value` / `php_admin_value`).

```bash
php2shell-check scan local
php2shell-check scan local --format sarif --output out.sarif
php2shell-check scan local --hunt
```

### 2. Container Image Mode (`scan image`)

Streams and flattens container image layers in memory without executing any binary inside the image. Supports `docker save` tarballs, OCI layout directories, and remote registry references.

```bash
php2shell-check scan image ./php-app.tar
php2shell-check scan image ./oci-layout-dir --offline
php2shell-check scan image php:8.3.10-fpm-alpine
```

### 3. SBOM Mode (`scan sbom`)

Reads CycloneDX JSON and SPDX JSON software bills of materials and matches `pkg:` PURLs and component names (`php`, `php-cli`, `php-fpm`, `php8.x-*`, `libphp*`).

```bash
php2shell-check scan sbom ./bom.cdx.json
php2shell-check scan sbom ./bom.spdx.json --format json
```

### 4. Filesystem Path / Manifest Mode (`scan path`)

Walks a source repository or filesystem tree (honoring `--exclude` and never following symlinks outside the root) for `Dockerfile*`, `docker-compose*.y*ml`, `composer.json` (`require.php` and `config.platform.php`), `.php-version`, and `.tool-versions`.

```bash
php2shell-check scan path . --exclude vendor --exclude node_modules
```

### 5. Passive Remote Mode (`scan remote`)

Requires `--authorized` and an explicit list of target URLs. Sends one `GET` request per target (no query parameters, no body, same-host redirects only, rate-limited across targets) and inspects only `Server` and `X-Powered-By` response headers.

```bash
php2shell-check scan remote --authorized https://app.example.com
```

### 6. Advisory Inspection (`advisories list`)

Displays the embedded (or `--advisory-file` overridden) advisory metadata, branch fix versions, and configuration mitigations.

```bash
php2shell-check advisories list
```

---

## Verdict Meanings & Exit Codes

### Verdicts

| Verdict | Severity Order | Meaning |
| --- | --- | --- |
| `VULNERABLE` | 1 (Highest) | Upstream PHP version is below the branch `FixedIn` release on a non-distro-managed install, or a distro package version is below a verified `DistroFixes` threshold. |
| `LIKELY_VULNERABLE` | 2 | Upstream version is below `FixedIn` on a distro-managed package without a verified `DistroFixes` entry (vendor backports possible), or the PHP branch is EOL/unfixed upstream (`8.1`, `8.0`, `7.4` and older), or the version was observed from a remote HTTP banner (`scan remote` never emits `VULNERABLE` from a banner alone). |
| `UNKNOWN` | 3 | Version string is unparseable, missing, or comes from a floating constraint/tag (`^8.2`, `php:8.3-fpm`), or an unsupported binary package database (e.g. raw RPM BDB/SQLite in `scan image`). |
| `PATCHED` | 4 (Lowest) | Upstream PHP version is at or above its branch `FixedIn` release (`8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`), or the distro package version meets or exceeds a verified `DistroFixes` threshold. |

> **Note**: Configuration mitigations (`session.upload_progress.enabled=0` for CVE-2026-109619, `fatal_error_backtraces=0` on PHP 8.5 for CVE-2026-109618) are reported per CVE (`APPLIED`, `NOT_APPLIED`, `UNKNOWN`, `NONE_AVAILABLE`) and **never change a verdict**.

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Clean (no findings met the `--fail-on` threshold) |
| `1` | One or more `VULNERABLE` findings (when `--fail-on` is `vulnerable`, `likely`, or `unknown`) |
| `2` | One or more `LIKELY_VULNERABLE` or `UNKNOWN` findings met the `--fail-on` threshold |
| `3` | Runtime, CLI flag, file I/O, or validation error |

---

## Limitations

1. **Distribution Security Backports**: Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux, and Alpine often backport CVE patches into older upstream PHP versions (e.g., `8.2.30-1+deb12u2`). Unless a verified `DistroFixes` entry is present in the advisory database, distro-managed installs below the upstream `FixedIn` release are reported as `LIKELY_VULNERABLE` rather than `VULNERABLE`.
2. **CLI vs. Web SAPI INI Configuration**: `php -i` reflects the CLI SAPI configuration, which frequently uses a separate `php.ini` from `php-fpm` or Apache `mod_php`. For non-CLI SAPIs (`fpm`, `apache2handler`, `cgi`, `litespeed`, `frankenphp`), `php2shell-check` only marks a mitigation as `APPLIED` or `NOT_APPLIED` if it was statically verified from that SAPI's `php.ini`, `conf.d/*.ini`, or FPM pool (`php_value` / `php_admin_value`) files; CLI-only INI evidence is marked `UNKNOWN` for web SAPIs.
3. **Floating Constraints and Container Tags (`scan path`)**: A `composer.json` constraint like `^8.2` or a floating image tag like `php:8.3-fpm` cannot prove that the deployed runtime is patched. `scan path` reports `UNKNOWN` and recommends pinning to the exact `FixedIn` release or scanning the resolved container image digest with `scan image`.
4. **HTTP Banners (`scan remote`)**: `Server` and `X-Powered-By` headers are low-confidence indicators that may be suppressed (`expose_php = Off`), reverse-proxied, or spoofed. `scan remote` caps verdicts at `LIKELY_VULNERABLE` and labels all findings `banner, may be hidden or spoofed`.
