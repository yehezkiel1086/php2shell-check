package local

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// SearchLocations holds the filesystem glob patterns and paths searched during local discovery.
// All paths are relative to the root of the inspected fs.FS (no leading slash).
type SearchLocations struct {
	BinaryGlobs       []string
	ApacheModuleGlobs []string
	OSReleasePaths    []string
}

// DefaultSearchLocations returns the standard table of common PHP binary, module,
// and OS metadata locations across Debian/Ubuntu, RHEL/Rocky/Alma (including Remi),
// Alpine, cPanel EasyApache, CloudLinux Alt-PHP, LiteSpeed, and FrankenPHP.
func DefaultSearchLocations() SearchLocations {
	return SearchLocations{
		BinaryGlobs: []string{
			// Standard system binary directories
			"usr/bin/php*",
			"usr/local/bin/php*",
			"bin/php*",
			"usr/sbin/php-fpm*",
			"usr/sbin/php*fpm*",
			"usr/local/sbin/php-fpm*",
			"sbin/php-fpm*",

			// FrankenPHP binaries
			"usr/bin/frankenphp*",
			"usr/local/bin/frankenphp*",
			"bin/frankenphp*",

			// LiteSpeed binaries
			"usr/local/lsws/lsphp*/bin/php*",
			"usr/local/lsws/lsphp*/bin/lsphp*",

			// Remi SCL repositories (RHEL/CentOS/Rocky/Alma)
			"opt/remi/php*/root/usr/bin/php*",
			"opt/remi/php*/root/usr/sbin/php-fpm*",

			// cPanel EasyApache 4
			"opt/cpanel/ea-php*/root/usr/bin/php*",
			"opt/cpanel/ea-php*/root/usr/sbin/php-fpm*",

			// CloudLinux Alt-PHP
			"opt/alt/php*/usr/bin/php*",
			"opt/alt/php*/usr/sbin/php-fpm*",

			// Custom /opt/php/<version> builds
			"opt/php/*/bin/php*",
			"opt/php/*/sbin/php-fpm*",
		},
		ApacheModuleGlobs: []string{
			"usr/lib/apache2/modules/libphp*.so",
			"usr/lib64/httpd/modules/libphp*.so",
			"usr/lib/httpd/modules/libphp*.so",
			"usr/libexec/apache2/libphp*.so",
			"usr/local/libexec/apache24/libphp*.so",
			"opt/cpanel/ea-apache24/root/usr/lib64/httpd/modules/libphp*.so",
			"opt/remi/php*/root/usr/lib64/httpd/modules/libphp*.so",
		},
		OSReleasePaths: []string{
			"etc/os-release",
			"usr/lib/os-release",
		},
	}
}

// FPMConfigLocations returns candidate static configuration files and glob patterns
// (relative to root fs.FS) for a PHP-FPM installation of a given branch (e.g. "8.3").
func FPMConfigLocations(branch, binaryPath string) (iniFiles, iniGlobs, poolGlobs []string) {
	compact := strings.ReplaceAll(branch, ".", "")

	iniFiles = []string{
		fmt.Sprintf("etc/php/%s/fpm/php.ini", branch),
		fmt.Sprintf("etc/php%s/php.ini", compact),
		"etc/php.ini",
		"usr/local/etc/php/php.ini",
		"usr/local/etc/php.ini",
		"usr/local/lib/php.ini",
		fmt.Sprintf("etc/opt/remi/php%s/php.ini", compact),
		fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.ini", compact),
		fmt.Sprintf("opt/alt/php%s/etc/php.ini", compact),
	}

	iniGlobs = []string{
		fmt.Sprintf("etc/php/%s/fpm/conf.d/*.ini", branch),
		fmt.Sprintf("etc/php%s/conf.d/*.ini", compact),
		"etc/php.d/*.ini",
		"usr/local/etc/php/conf.d/*.ini",
		"usr/local/etc/php.d/*.ini",
		fmt.Sprintf("etc/opt/remi/php%s/php.d/*.ini", compact),
		fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.d/*.ini", compact),
		fmt.Sprintf("opt/alt/php%s/etc/php.d/*.ini", compact),
	}

	poolGlobs = []string{
		fmt.Sprintf("etc/php/%s/fpm/pool.d/*.conf", branch),
		fmt.Sprintf("etc/php%s/php-fpm.d/*.conf", compact),
		"etc/php-fpm.d/*.conf",
		"usr/local/etc/php-fpm.conf",
		"usr/local/etc/php-fpm.d/*.conf",
		fmt.Sprintf("etc/opt/remi/php%s/php-fpm.d/*.conf", compact),
		fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php-fpm.d/*.conf", compact),
		fmt.Sprintf("opt/alt/php%s/etc/php-fpm.d/*.conf", compact),
	}

	_ = binaryPath
	return iniFiles, iniGlobs, poolGlobs
}

// ApacheConfigLocations returns candidate static php.ini and conf.d/*.ini patterns
// (relative to root fs.FS) for an Apache mod_php installation of a given branch.
func ApacheConfigLocations(branch string) (iniFiles, iniGlobs []string) {
	compact := strings.ReplaceAll(branch, ".", "")

	iniFiles = []string{
		fmt.Sprintf("etc/php/%s/apache2/php.ini", branch),
		fmt.Sprintf("etc/php%s/apache2/php.ini", compact),
		"etc/php.ini",
		fmt.Sprintf("etc/opt/remi/php%s/php.ini", compact),
		fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.ini", compact),
	}

	iniGlobs = []string{
		fmt.Sprintf("etc/php/%s/apache2/conf.d/*.ini", branch),
		fmt.Sprintf("etc/php%s/conf.d/*.ini", compact),
		"etc/php.d/*.ini",
		fmt.Sprintf("etc/opt/remi/php%s/php.d/*.ini", compact),
		fmt.Sprintf("opt/cpanel/ea-php%s/root/etc/php.d/*.ini", compact),
	}

	return iniFiles, iniGlobs
}

// ApacheConfGlobs returns Apache server configuration file patterns (/etc/apache2 and /etc/httpd)
// that may contain php_admin_value, php_admin_flag, php_value, and php_flag directives.
func ApacheConfGlobs() []string {
	return []string{
		"etc/apache2/apache2.conf",
		"etc/apache2/conf-enabled/*.conf",
		"etc/apache2/mods-enabled/*.conf",
		"etc/apache2/sites-enabled/*.conf",
		"etc/apache2/conf.d/*.conf",
		"etc/httpd/conf/httpd.conf",
		"etc/httpd/conf.d/*.conf",
		"etc/httpd/conf.modules.d/*.conf",
	}
}

// DeriveInstallPrefix derives the installation prefix from a resolved binary path
// (the parent directory that contains bin/ or sbin/, or the parent containing bin/ plus sbin/ or etc/).
func DeriveInstallPrefix(fsys fs.FS, resolvedAbsPath string) string {
	rel := toFSPath(resolvedAbsPath)
	if rel == "" {
		return ""
	}
	dir := path.Dir(rel)
	base := path.Base(dir)
	if base != "bin" && base != "sbin" {
		return ""
	}
	parent := path.Dir(dir)
	if parent == "." || parent == "" {
		return "/"
	}

	// For /opt/remi/php83/root/usr or /opt/cpanel/ea-php83/root/usr or /opt/alt/php83/usr,
	// if parent ends in /usr and its parent has etc/, return the root prefix.
	if path.Base(parent) == "usr" && strings.HasPrefix(parent, "opt/") {
		grand := path.Dir(parent)
		if grand != "." && grand != "" && fsys != nil {
			if info, err := fs.Stat(fsys, path.Join(grand, "etc")); err == nil && info.IsDir() {
				return "/" + grand
			}
		}
	}

	return "/" + parent
}
