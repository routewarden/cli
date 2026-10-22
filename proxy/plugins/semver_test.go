package plugins_test

import (
	"testing"

	"github.com/routewarden/cli/proxy/plugins"
)

func TestParseSemVer(t *testing.T) {
	tests := []struct {
		input       string
		wantMajor   int
		wantMinor   int
		wantPatch   int
		wantPre     string
		wantBuild   string
		shouldError bool
	}{
		{"1.0.0", 1, 0, 0, "", "", false},
		{"v1.2.3", 1, 2, 3, "", "", false},
		{"V2.10.4", 2, 10, 4, "", "", false},
		{"1.2.3-rc.1", 1, 2, 3, "rc.1", "", false},
		{"1.0.0+20130313144700", 1, 0, 0, "", "20130313144700", false},
		{"1.2.3-beta.2+exp.sha.5114f85", 1, 2, 3, "beta.2", "exp.sha.5114f85", false},
		{"", 0, 0, 0, "", "", true},
		{"invalid", 0, 0, 0, "", "", true},
		{"1.2.3.4", 0, 0, 0, "", "", true},
	}

	for _, tt := range tests {
		got, err := plugins.ParseSemVer(tt.input)
		if tt.shouldError {
			if err == nil {
				t.Errorf("ParseSemVer(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSemVer(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got.Major != tt.wantMajor || got.Minor != tt.wantMinor || got.Patch != tt.wantPatch ||
			got.Prerelease != tt.wantPre || got.Build != tt.wantBuild {
			t.Errorf("ParseSemVer(%q) = %+v, want Major=%d Minor=%d Patch=%d Pre=%q Build=%q",
				tt.input, got, tt.wantMajor, tt.wantMinor, tt.wantPatch, tt.wantPre, tt.wantBuild)
		}
	}
}

func TestCheckSemVerCompatibility(t *testing.T) {
	tests := []struct {
		host        string
		constraint  string
		shouldPass  bool
		description string
	}{
		// Same version
		{"1.0.0", "1.0.0", true, "Exact match is compatible"},
		{"v1.0.0", "1.0.0", true, "v-prefix handled cleanly"},
		{"1.2.3", "1.2.3", true, "Exact match patch"},

		// Backwards-compatible minor/patch updates in same major
		{"1.2.0", "1.0.0", true, "Host newer minor in same major is compatible"},
		{"1.0.5", "1.0.0", true, "Host newer patch in same major is compatible"},
		{"1.5.0", "^1.2.0", true, "Caret allows higher minor in same major"},

		// Host is older than required
		{"1.0.0", "1.2.0", false, "Host older minor is incompatible"},
		{"1.0.1", "1.0.5", false, "Host older patch is incompatible"},

		// Breaking change across major versions
		{"2.0.0", "1.0.0", false, "Host bumped major introduces breaking changes"},
		{"1.0.0", "2.0.0", false, "Plugin requires future major version"},

		// 0.x versions (breaking on minor)
		{"0.1.0", "0.1.0", true, "0.1.0 exact matches 0.1.0"},
		{"0.1.5", "0.1.0", true, "0.1.5 matches 0.1.0 patch"},
		{"0.2.0", "0.1.0", false, "0.2.0 incompatible with 0.1.0"},

		// Ranges & comparison operators
		{"1.5.0", ">=1.0.0, <2.0.0", true, "Satisfies explicit range"},
		{"2.1.0", ">=1.0.0, <2.0.0", false, "Exceeds explicit range ceiling"},
		{"1.3.0", "~1.3.0", true, "Tilde matches same minor"},
		{"1.4.0", "~1.3.0", false, "Tilde rejects different minor"},
		{"1.0.0", "=1.0.0", true, "= matches exact version"},
		{"1.2.0", "=1.0.0", false, "= rejects different minor"},
		{"1.0.0", "==1.0.0", true, "== matches exact version"},
		{"1.0.5", "==1.0.0", false, "== rejects different patch"},
		{"1.0.0", "*", true, "Wildcard matches anything"},
		{"1.0.0", "", true, "Empty constraint matches anything"},
	}

	for _, tt := range tests {
		err := plugins.CheckSemVerCompatibility(tt.host, tt.constraint)
		if tt.shouldPass && err != nil {
			t.Errorf("[%s] CheckSemVerCompatibility(%q, %q) unexpected error: %v", tt.description, tt.host, tt.constraint, err)
		}
		if !tt.shouldPass && err == nil {
			t.Errorf("[%s] CheckSemVerCompatibility(%q, %q) expected error, got nil", tt.description, tt.host, tt.constraint)
		}
	}
}
