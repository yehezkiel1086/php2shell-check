package match

import (
	"errors"
	"fmt"
	"strings"

	apkversion "github.com/knqyf263/go-apk-version"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

// ErrUnsupportedPackageManager indicates that no comparator exists for the given package manager.
var ErrUnsupportedPackageManager = errors.New("unsupported package manager for version comparison")

func compareDistroVersions(pkgManager, distroID, installedVer, fixedVer string) (int, error) {
	kind := resolveComparatorKind(pkgManager, distroID)
	switch kind {
	case "deb":
		v1, err := debversion.NewVersion(installedVer)
		if err != nil {
			return 0, fmt.Errorf("invalid deb installed version %q: %w", installedVer, err)
		}
		v2, err := debversion.NewVersion(fixedVer)
		if err != nil {
			return 0, fmt.Errorf("invalid deb fixed version %q: %w", fixedVer, err)
		}
		return v1.Compare(v2), nil

	case "rpm":
		if strings.TrimSpace(installedVer) == "" || strings.TrimSpace(fixedVer) == "" {
			return 0, fmt.Errorf("empty rpm version: %w", ErrUnsupportedPackageManager)
		}
		v1 := rpmversion.NewVersion(installedVer)
		v2 := rpmversion.NewVersion(fixedVer)
		return v1.Compare(v2), nil

	case "apk":
		v1, err := apkversion.NewVersion(installedVer)
		if err != nil {
			return 0, fmt.Errorf("invalid apk installed version %q: %w", installedVer, err)
		}
		v2, err := apkversion.NewVersion(fixedVer)
		if err != nil {
			return 0, fmt.Errorf("invalid apk fixed version %q: %w", fixedVer, err)
		}
		return v1.Compare(v2), nil

	default:
		return 0, fmt.Errorf("package manager %q (distro %q): %w", pkgManager, distroID, ErrUnsupportedPackageManager)
	}
}

func resolveComparatorKind(pkgManager, distroID string) string {
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
