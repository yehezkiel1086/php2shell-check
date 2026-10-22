# Adding or Updating an Advisory

`php2shell-check` uses a structured JSON advisory file (`data/advisories.json` by default, or any file passed via `--advisory-file PATH`).

## Hard Honesty Rules

- **Never invent version numbers, distro package versions, URLs, or CVE facts.**
- If a branch or distribution fix is not yet confirmed by an authoritative upstream or vendor security notice, leave `fixed_version` or `url` empty, set `"verified": false`, and allow `php2shell-check` to emit `LIKELY_VULNERABLE` or `UNKNOWN`.

---

## Step-by-Step Workflow

### 1. Edit `data/advisories.json` (or create a custom advisory file)

Follow the schema documented in [`docs/advisory-schema.md`](advisory-schema.md).

#### Updating an Upstream Branch Fix

When an upstream PHP release is verified:
1. Locate the branch entry under `"branches"` (e.g. `"branch": "8.3"`).
2. Set `"fixed_in"` to the exact 3-part PHP release (e.g. `"8.3.36"`).
3. Set `"upstream_fix_available": true`.

#### Adding a Verified Distribution Fix (`distro_fixes`)

When a Linux distribution publishes a security update (DSA, USN, RHSA, or Alpine SecDB):
1. Add or update an entry under `"distro_fixes"`:
   ```json
   {
     "distro": "debian",
     "release": "12",
     "package": "php8.2-fpm",
     "fixed_version": "8.2.30-1+deb12u2",
     "verified": true
   }
   ```
2. Ensure `"distro"` matches `/etc/os-release` `ID` (`debian`, `ubuntu`, `rhel`, `rocky`, `almalinux`, `alpine`) and `"release"` matches `VERSION_ID`.
3. Only set `"verified": true` once the exact package version string has been confirmed from the vendor's official security tracker.

### 2. Validate with the CLI

Test your updated file using `--advisory-file` before rebuilding:

```bash
php2shell-check advisories list --advisory-file ./data/advisories.json
```

If any unknown JSON field, missing required property, or invalid version string is present, `php2shell-check` exits with code `3` and reports the exact validation error.

### 3. Run the Test Suite

Because `data/advisories.json` is embedded at compile time via `go:embed`, rebuild and run the unit and golden tests:

```bash
make test
make lint
```
