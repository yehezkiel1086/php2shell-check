# Security Policy

## Scope and Purpose

`php2shell-check` is a defensive detection and remediation guidance tool for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

### Hard Safety Guarantees

1. **Detection and Remediation Only**: This repository never contains, generates, or transmits exploit code, proof-of-concept payloads, crash/out-of-memory triggers, or crafted `multipart/form-data` requests.
2. **Read-Only Local & Image Inspection**:
   - Container images (`scan image`) are inspected purely in memory via tar layer streaming with strict per-file (`64 MiB`) and total (`512 MiB`) byte caps, path-traversal rejection, and root-escape symlink rejection. No binary from an image is ever executed.
   - Local host inspection (`scan local`) executes discovered host binaries (`php -v`, `php -i`, `dpkg-query`, `rpm`, `apk`) exclusively via `exec.CommandContext` using resolved absolute paths, no shell invocation, and a 10-second timeout.
3. **Passive Remote Mode**:
   - `scan remote` requires the explicit `--authorized` flag and at least one target URL.
   - It sends a single `GET` request per target with query parameters and fragments stripped, `http.NoBody`, same-host redirect enforcement, and inter-target rate limiting.
   - Only `Server` and `X-Powered-By` response headers are inspected; response bodies are closed immediately without reading.
4. **Command-Generation Input Validation**:
   - Remediation commands are display-only text and are never executed by `php2shell-check`.
   - Any untrusted package name or version string is validated against `^[a-z0-9][a-z0-9+.-]*$` before interpolation into remediation command text.

## Reporting a Vulnerability

If you discover a security issue in `php2shell-check` (such as archive traversal bypasses, command injection in remediation text rendering, or unintended network activity in `--offline` mode):

1. **Do not open a public issue** with exploit details.
2. Report the finding privately via GitHub Security Advisories (`Security` -> `Report a vulnerability`) on the repository.
3. Include minimal reproduction steps, affected subcommand/mode, and the output of `php2shell-check version`.
