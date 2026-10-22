package phpver_test

import (
	"errors"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

func TestParseValidVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want phpver.Version
	}{
		{
			name: "standard 8.3.36",
			raw:  "8.3.36",
			want: phpver.Version{Major: 8, Minor: 3, Patch: 36, Raw: "8.3.36", Branch: "8.3"},
		},
		{
			name: "pre-release 8.4.0RC1",
			raw:  "8.4.0RC1",
			want: phpver.Version{Major: 8, Minor: 4, Patch: 0, PreRelease: "RC1", Raw: "8.4.0RC1", Branch: "8.4"},
		},
		{
			name: "debian suffix 8.2.30-1+deb12u1",
			raw:  "8.2.30-1+deb12u1",
			want: phpver.Version{Major: 8, Minor: 2, Patch: 30, DistroSuffix: "1+deb12u1", Raw: "8.2.30-1+deb12u1", Branch: "8.2"},
		},
		{
			name: "custom suffix 7.4.33-nmm1",
			raw:  "7.4.33-nmm1",
			want: phpver.Version{Major: 7, Minor: 4, Patch: 33, DistroSuffix: "nmm1", Raw: "7.4.33-nmm1", Branch: "7.4"},
		},
		{
			name: "ubuntu suffix 8.1.2-1ubuntu2.19",
			raw:  "8.1.2-1ubuntu2.19",
			want: phpver.Version{Major: 8, Minor: 1, Patch: 2, DistroSuffix: "1ubuntu2.19", Raw: "8.1.2-1ubuntu2.19", Branch: "8.1"},
		},
		{
			name: "affected minimum 5.4.0",
			raw:  "5.4.0",
			want: phpver.Version{Major: 5, Minor: 4, Patch: 0, Raw: "5.4.0", Branch: "5.4"},
		},
		{
			name: "below affected minimum 5.3.29",
			raw:  "5.3.29",
			want: phpver.Version{Major: 5, Minor: 3, Patch: 29, Raw: "5.3.29", Branch: "5.3"},
		},
		{
			name: "boundary 8.2.34 vulnerable",
			raw:  "8.2.34",
			want: phpver.Version{Major: 8, Minor: 2, Patch: 34, Raw: "8.2.34", Branch: "8.2"},
		},
		{
			name: "boundary 8.2.35 patched",
			raw:  "8.2.35",
			want: phpver.Version{Major: 8, Minor: 2, Patch: 35, Raw: "8.2.35", Branch: "8.2"},
		},
		{
			name: "boundary 8.3.35 vulnerable",
			raw:  "8.3.35",
			want: phpver.Version{Major: 8, Minor: 3, Patch: 35, Raw: "8.3.35", Branch: "8.3"},
		},
		{
			name: "boundary 8.4.26 vulnerable",
			raw:  "8.4.26",
			want: phpver.Version{Major: 8, Minor: 4, Patch: 26, Raw: "8.4.26", Branch: "8.4"},
		},
		{
			name: "boundary 8.4.27 patched",
			raw:  "8.4.27",
			want: phpver.Version{Major: 8, Minor: 4, Patch: 27, Raw: "8.4.27", Branch: "8.4"},
		},
		{
			name: "boundary 8.5.11 vulnerable",
			raw:  "8.5.11",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 11, Raw: "8.5.11", Branch: "8.5"},
		},
		{
			name: "boundary 8.5.12 patched",
			raw:  "8.5.12",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 12, Raw: "8.5.12", Branch: "8.5"},
		},
		{
			name: "pre-release lowercase rc2",
			raw:  "8.5.12rc2",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 12, PreRelease: "rc2", Raw: "8.5.12rc2", Branch: "8.5"},
		},
		{
			name: "pre-release hyphenated -RC1",
			raw:  "8.5.12-RC1",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 12, PreRelease: "RC1", Raw: "8.5.12-RC1", Branch: "8.5"},
		},
		{
			name: "pre-release alpha1",
			raw:  "8.5.0alpha1",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 0, PreRelease: "alpha1", Raw: "8.5.0alpha1", Branch: "8.5"},
		},
		{
			name: "pre-release beta3",
			raw:  "8.5.0beta3",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 0, PreRelease: "beta3", Raw: "8.5.0beta3", Branch: "8.5"},
		},
		{
			name: "pre-release dev",
			raw:  "8.5.0dev",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 0, PreRelease: "dev", Raw: "8.5.0dev", Branch: "8.5"},
		},
		{
			name: "pre-release hyphenated -dev",
			raw:  "8.5.0-dev",
			want: phpver.Version{Major: 8, Minor: 5, Patch: 0, PreRelease: "dev", Raw: "8.5.0-dev", Branch: "8.5"},
		},
		{
			name: "pre-release with debian suffix 8.4.0~rc1-1+deb13u1",
			raw:  "8.4.0~rc1-1+deb13u1",
			want: phpver.Version{Major: 8, Minor: 4, Patch: 0, PreRelease: "rc1", DistroSuffix: "1+deb13u1", Raw: "8.4.0~rc1-1+deb13u1", Branch: "8.4"},
		},
		{
			name: "pre-release attached with debian suffix 8.4.0RC1-1",
			raw:  "8.4.0RC1-1",
			want: phpver.Version{Major: 8, Minor: 4, Patch: 0, PreRelease: "RC1", DistroSuffix: "1", Raw: "8.4.0RC1-1", Branch: "8.4"},
		},
		{
			name: "alpine suffix 8.3.36-r0",
			raw:  "8.3.36-r0",
			want: phpver.Version{Major: 8, Minor: 3, Patch: 36, DistroSuffix: "r0", Raw: "8.3.36-r0", Branch: "8.3"},
		},
		{
			name: "rhel suffix 8.0.30-1.el9_2",
			raw:  "8.0.30-1.el9_2",
			want: phpver.Version{Major: 8, Minor: 0, Patch: 30, DistroSuffix: "1.el9_2", Raw: "8.0.30-1.el9_2", Branch: "8.0"},
		},
		{
			name: "sury debian suffix 7.4.33-8+0~20230904.88+debian11~1.gbp87c414",
			raw:  "7.4.33-8+0~20230904.88+debian11~1.gbp87c414",
			want: phpver.Version{
				Major:        7,
				Minor:        4,
				Patch:        33,
				DistroSuffix: "8+0~20230904.88+debian11~1.gbp87c414",
				Raw:          "7.4.33-8+0~20230904.88+debian11~1.gbp87c414",
				Branch:       "7.4",
			},
		},
		{
			name: "dfsg suffix 5.6.40+dfsg-0+deb8u12",
			raw:  "5.6.40+dfsg-0+deb8u12",
			want: phpver.Version{
				Major:        5,
				Minor:        6,
				Patch:        40,
				DistroSuffix: "dfsg-0+deb8u12",
				Raw:          "5.6.40+dfsg-0+deb8u12",
				Branch:       "5.6",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := phpver.Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseInvalidVersions(t *testing.T) {
	t.Parallel()

	invalidInputs := []string{
		"",
		"8",
		"8.3",
		"8.3.",
		".8.3.0",
		"8..3",
		"8.3.36.1",
		"v8.3.36",
		"PHP 8.3.36",
		"08.3.36",
		"8.03.36",
		"8.3.036",
		"-8.3.36",
		"8.-3.36",
		"8.3.-36",
		"8.3.36-",
		"8.3.36+",
		"8.3.36~",
		"8.3.36foo",
		"8.3.36RC0",
		"8.3.36RC01",
		"8.3.36RC1-",
		"8.3.36-1+deb12u1-",
		"8.3.36;id",
		"8.3.36\x00",
		"9999999999999.1.1",
	}

	for _, raw := range invalidInputs {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			_, err := phpver.Parse(raw)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, expected *ParseError", raw)
			}
			var parseErr *phpver.ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse(%q) error = %T (%v), want *phpver.ParseError", raw, err, err)
			}
			if !errors.Is(err, phpver.ErrInvalidVersion) {
				t.Fatalf("Parse(%q) error does not unwrap to ErrInvalidVersion: %v", raw, err)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "boundary 8.2.34 < 8.2.35", a: "8.2.34", b: "8.2.35", want: -1},
		{name: "boundary 8.2.35 > 8.2.34", a: "8.2.35", b: "8.2.34", want: 1},
		{name: "boundary 8.2.35 == 8.2.35", a: "8.2.35", b: "8.2.35", want: 0},
		{name: "boundary 8.3.35 < 8.3.36", a: "8.3.35", b: "8.3.36", want: -1},
		{name: "boundary 8.4.26 < 8.4.27", a: "8.4.26", b: "8.4.27", want: -1},
		{name: "boundary 8.5.11 < 8.5.12", a: "8.5.11", b: "8.5.12", want: -1},
		{name: "boundary 8.5.12 > 8.5.11", a: "8.5.12", b: "8.5.11", want: 1},
		{name: "boundary 5.3.29 < 5.4.0", a: "5.3.29", b: "5.4.0", want: -1},
		{name: "pre-release sorts below release 8.4.0RC1 < 8.4.0", a: "8.4.0RC1", b: "8.4.0", want: -1},
		{name: "release sorts above pre-release 8.5.12 > 8.5.12RC1", a: "8.5.12", b: "8.5.12RC1", want: 1},
		{name: "pre-release ordering dev < alpha1", a: "8.5.0dev", b: "8.5.0alpha1", want: -1},
		{name: "pre-release ordering alpha1 < alpha2", a: "8.5.0alpha1", b: "8.5.0alpha2", want: -1},
		{name: "pre-release ordering alpha2 < beta1", a: "8.5.0alpha2", b: "8.5.0beta1", want: -1},
		{name: "pre-release ordering beta2 < RC1", a: "8.5.0beta2", b: "8.5.0RC1", want: -1},
		{name: "pre-release ordering RC2 < RC10", a: "8.5.0RC2", b: "8.5.0RC10", want: -1},
		{name: "case-insensitive pre-release equality RC1 == rc1", a: "8.4.0RC1", b: "8.4.0-rc1", want: 0},
		{name: "distro suffix has same upstream version 8.2.30-1+deb12u1 == 8.2.30", a: "8.2.30-1+deb12u1", b: "8.2.30", want: 0},
		{name: "major version difference 7.4.33 < 8.0.0", a: "7.4.33-nmm1", b: "8.0.0", want: -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			va, err := phpver.Parse(tc.a)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.a, err)
			}
			vb, err := phpver.Parse(tc.b)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.b, err)
			}
			got := phpver.Compare(va, vb)
			if got != tc.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
