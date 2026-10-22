package phpver_test

import (
	"errors"
	"testing"

	"github.com/yehezkiel1086/php2shell-check/internal/phpver"
)

func FuzzParse(f *testing.F) {
	seeds := []string{
		"8.3.36",
		"8.4.0RC1",
		"8.2.30-1+deb12u1",
		"7.4.33-nmm1",
		"8.1.2-1ubuntu2.19",
		"8.2.34",
		"8.2.35",
		"8.5.11",
		"8.5.12",
		"5.4.0",
		"8.5.0alpha1",
		"8.5.0beta2",
		"8.5.0-dev",
		"8.4.0~rc1-1+deb13u1",
		"",
		"invalid",
		"8.3.36-",
		"08.01.00",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		v, err := phpver.Parse(input)
		if err != nil {
			var parseErr *phpver.ParseError
			if !errors.As(err, &parseErr) {
				t.Fatalf("Parse(%q) returned non-ParseError %T: %v", input, err, err)
			}
			return
		}

		if v.Major < 0 || v.Minor < 0 || v.Patch < 0 {
			t.Fatalf("Parse(%q) produced negative version numbers: %+v", input, v)
		}
		if v.Branch == "" {
			t.Fatalf("Parse(%q) produced empty Branch", input)
		}
		if v.Raw != input {
			t.Fatalf("Parse(%q) Raw = %q, want %q", input, v.Raw, input)
		}
		if phpver.Compare(v, v) != 0 {
			t.Fatalf("Compare(v, v) != 0 for %+v", v)
		}
	})
}
