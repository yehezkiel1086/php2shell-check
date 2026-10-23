# PHP Mitigation Precedence and Boolean Normalization

This document details the configuration evaluation order and boolean normalization semantics implemented by `php2shell-check` for assessing PHP mitigations (specifically CVE-2026-109619).

## Precedence Hierarchy

PHP runtime settings are evaluated in strict hierarchical order where later stages override earlier ones (**last writer wins**):

```
built-in default (enabled) < php.ini < conf.d in lexical order < pool or Apache overrides
```

1. **Built-in Default (Enabled):**
   - In unconfigured PHP installations, security-sensitive settings have compiled-in defaults.
   - For CVE-2026-109619:
     - `session.upload_progress.enabled` defaults to `1` (enabled).
     - On PHP 8.5, `fatal_error_backtraces` defaults to `1` (enabled).
   - If configuration directories or files exist but do not explicitly disable these directives, the built-in default (`1`) applies, resulting in a verdict of `NOT_APPLIED`.

2. **Loaded `php.ini`:**
   - The primary configuration file loaded by the binary or inferred from the installation prefix:
     - Binary-reported loaded configuration file (e.g. from `php --ini` / `php -i`).
     - Prefix-relative `<prefix>/etc/php.ini`.
     - Official image `/usr/local/etc/php/php.ini`.
     - Debian/Ubuntu `/etc/php/<branch>/<sapi>/php.ini` and Alpine `/etc/php<compact>/php.ini`.
     - RHEL/CentOS/Rocky/Alma `/etc/php.ini` and Remi/cPanel/Alt-PHP paths.

3. **Scan Directory `conf.d/*.ini` (Lexical Order):**
   - Additional `.ini` files found in the confirmed scan directory (e.g. `/etc/php/<branch>/<sapi>/conf.d/` or `<prefix>/etc/conf.d/`).
   - Files are parsed strictly in **lexical order by entry filename** (e.g., `10-opcache.ini` < `20-upload.ini` < `99-hardening.ini`).
   - Symbolic links (such as Debian's `conf.d` links into `../mods-available/`) are followed as long as they do not escape the filesystem root. Symlinks escaping root are rejected.

4. **SAPI Overrides (Pool or Apache Configurations):**
   - **PHP-FPM Pools:**
     - PHP-FPM reads pool configurations specified in `include=` directives inside `php-fpm.conf` (or default fallback directory `<prefix>/etc/php-fpm.d/*.conf`).
     - Pool files are expanded in lexical order.
     - Directives supported: `php_admin_value[KEY]`, `php_value[KEY]`, `php_admin_flag[KEY]`, and `php_flag[KEY]`.
     - Each `[section]` (except `[global]`) represents an independent worker pool.
     - **Multi-Pool Rule:** Mitigation is considered `APPLIED` only if **every** pool disables the required setting. If any pool leaves the setting enabled or overrides it back to enabled, the mitigation state is `NOT_APPLIED`, naming the offending pool(s).
   - **Apache Handler (`mod_php`):**
     - Scans `/etc/apache2` and `/etc/httpd` server configurations (`apache2.conf`, `conf-enabled/*.conf`, `sites-enabled/*.conf`, `httpd.conf`, `conf.d/*.conf`).
     - Directives supported: `php_admin_value`, `php_admin_flag`, `php_value`, and `php_flag`.
     - *Limitation:* `.htaccess` files are not scanned due to per-directory dynamic overrides.

---

## Boolean Normalization

Directive values undergo normalization, trimming surrounding quotes and whitespace, and converting case-insensitively:

| Raw Value | Normalized Value | Semantic Meaning |
| :--- | :---: | :--- |
| `0`, `off`, `false`, `no`, `none`, `""` (empty) | `"0"` | **Disabled** (Mitigated) |
| `1`, `on`, `true`, `yes` | `"1"` | **Enabled** (Vulnerable / Unmitigated) |

---

## Advisory Mitigation Evaluation Rules

1. **APPLIED:** Every listed setting for the detected branch must be normalized to `"0"` for that SAPI. On PHP 8.5, both `session.upload_progress.enabled` and `fatal_error_backtraces` must be `"0"`.
2. **NOT_APPLIED:** At least one configuration file for that SAPI was located and parsed, and a required setting remains `"1"` (or unset, inheriting the built-in default).
3. **UNKNOWN:**
   - No configuration file or directory was located (`config path not found`).
   - Files found only by a prefix guess that were not confirmed as loaded by the binary (`present but not confirmed as loaded`).
   - A setting was configured only in a CLI `.ini` file when assessing a non-CLI SAPI (e.g. `fpm` or `apache2handler`).
4. **PATCHED Verdicts:** When a PHP target is patched (upstream version meets or exceeds `FixedIn`), the mitigation column displays `n/a (patched)` and no mitigation instructions are generated.
