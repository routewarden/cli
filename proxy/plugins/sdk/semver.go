package sdk

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// SemVer represents a parsed Semantic Version conforming to SemVer 2.0.0.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Build      string
	Raw        string
}

// ParseSemVer parses a semver string (e.g., "1.2.3", "v1.2.3", "1.0.0-rc.1+build.12").
func ParseSemVer(s string) (SemVer, error) {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	if s == "" {
		return SemVer{}, fmt.Errorf("empty version string")
	}

	var build string
	if idx := strings.Index(s, "+"); idx != -1 {
		build = s[idx+1:]
		s = s[:idx]
	}

	var prerelease string
	if idx := strings.Index(s, "-"); idx != -1 {
		prerelease = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return SemVer{}, fmt.Errorf("invalid semver string %q: too many dot-separated segments", raw)
	}

	var major, minor, patch int
	var err error

	if len(parts) >= 1 && parts[0] != "" {
		major, err = strconv.Atoi(parts[0])
		if err != nil || major < 0 {
			return SemVer{}, fmt.Errorf("invalid major version %q in %q", parts[0], raw)
		}
	}
	if len(parts) >= 2 && parts[1] != "" {
		minor, err = strconv.Atoi(parts[1])
		if err != nil || minor < 0 {
			return SemVer{}, fmt.Errorf("invalid minor version %q in %q", parts[1], raw)
		}
	}
	if len(parts) >= 3 && parts[2] != "" {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return SemVer{}, fmt.Errorf("invalid patch version %q in %q", parts[2], raw)
		}
	}

	return SemVer{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: prerelease,
		Build:      build,
		Raw:        raw,
	}, nil
}

// String returns the normalized canonical string of SemVer.
func (v SemVer) String() string {
	res := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		res += "-" + v.Prerelease
	}
	if v.Build != "" {
		res += "+" + v.Build
	}
	return res
}

// CompareSemVer compares two SemVer versions according to SemVer 2.0.0 precedence.
// Returns:
//   -1 if v1 < v2
//    0 if v1 == v2
//    1 if v1 > v2
func CompareSemVer(v1, v2 SemVer) int {
	canon1 := "v" + v1.String()
	canon2 := "v" + v2.String()
	if semver.IsValid(canon1) && semver.IsValid(canon2) {
		return semver.Compare(canon1, canon2)
	}

	if v1.Major != v2.Major {
		if v1.Major < v2.Major {
			return -1
		}
		return 1
	}
	if v1.Minor != v2.Minor {
		if v1.Minor < v2.Minor {
			return -1
		}
		return 1
	}
	if v1.Patch != v2.Patch {
		if v1.Patch < v2.Patch {
			return -1
		}
		return 1
	}

	// In SemVer 2.0.0: a normal version has higher precedence than a pre-release version.
	if v1.Prerelease == "" && v2.Prerelease != "" {
		return 1
	}
	if v1.Prerelease != "" && v2.Prerelease == "" {
		return -1
	}
	if v1.Prerelease != "" && v2.Prerelease != "" {
		if v1.Prerelease < v2.Prerelease {
			return -1
		}
		if v1.Prerelease > v2.Prerelease {
			return 1
		}
	}

	return 0
}

// CheckSemVerCompatibility checks if hostVersion satisfies the constraint or required version
// according to Semantic Versioning (SemVer 2.0.0) rules:
//
// 1. If constraint has comparator operators (e.g., ">=1.0.0, <2.0.0" or "^1.2.0" or "~1.2.0"):
//    It evaluates according to the specified range.
// 2. If constraint is a standard version (e.g. "1.0.0"):
//    Default SemVer compatibility applies:
//    - Host and target must share the same Major version (breaking change boundary).
//      (For 0.x.x pre-1.0, Minor must match).
//    - Host version must be >= required version (Host has all required features/fixes).
func CheckSemVerCompatibility(hostVersion, constraint string) error {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return nil
	}

	host, err := ParseSemVer(hostVersion)
	if err != nil {
		return fmt.Errorf("invalid host semver %q: %w", hostVersion, err)
	}

	// Handle comma-separated clauses (e.g. ">=1.0.0, <2.0.0")
	if strings.Contains(constraint, ",") {
		clauses := strings.SplitSeq(constraint, ",")
		for clause := range clauses {
			if err := checkSingleClause(host, strings.TrimSpace(clause)); err != nil {
				return err
			}
		}
		return nil
	}

	return checkSingleClause(host, constraint)
}

func checkSingleClause(host SemVer, clause string) error {
	clause = strings.TrimSpace(clause)
	if clause == "" || clause == "*" {
		return nil
	}

	// Caret operator: ^1.2.3 -> >= 1.2.3 and < (Major+1).0.0
	if strings.HasPrefix(clause, "^") {
		target, err := ParseSemVer(clause[1:])
		if err != nil {
			return fmt.Errorf("invalid caret semver %q: %w", clause, err)
		}
		return checkCaretCompatibility(host, target)
	}

	// Tilde operator: ~1.2.3 -> >= 1.2.3 and < Major.(Minor+1).0
	if strings.HasPrefix(clause, "~") {
		target, err := ParseSemVer(clause[1:])
		if err != nil {
			return fmt.Errorf("invalid tilde semver %q: %w", clause, err)
		}
		return checkTildeCompatibility(host, target)
	}

	// Comparison operators
	if strings.HasPrefix(clause, ">=") {
		target, err := ParseSemVer(clause[2:])
		if err != nil {
			return fmt.Errorf("invalid >= semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) < 0 {
			return fmt.Errorf("host version %s is lower than required %s", host, clause)
		}
		return nil
	}
	if strings.HasPrefix(clause, "<=") {
		target, err := ParseSemVer(clause[2:])
		if err != nil {
			return fmt.Errorf("invalid <= semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) > 0 {
			return fmt.Errorf("host version %s is greater than allowed %s", host, clause)
		}
		return nil
	}
	if strings.HasPrefix(clause, ">") {
		target, err := ParseSemVer(clause[1:])
		if err != nil {
			return fmt.Errorf("invalid > semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) <= 0 {
			return fmt.Errorf("host version %s is not greater than %s", host, clause)
		}
		return nil
	}
	if strings.HasPrefix(clause, "<") {
		target, err := ParseSemVer(clause[1:])
		if err != nil {
			return fmt.Errorf("invalid < semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) >= 0 {
			return fmt.Errorf("host version %s is not less than %s", host, clause)
		}
		return nil
	}
	if after, ok := strings.CutPrefix(clause, "=="); ok {
		target, err := ParseSemVer(after)
		if err != nil {
			return fmt.Errorf("invalid == semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) != 0 {
			return fmt.Errorf("host version %s does not equal required %s", host, target)
		}
		return nil
	}
	if after, ok := strings.CutPrefix(clause, "="); ok {
		target, err := ParseSemVer(after)
		if err != nil {
			return fmt.Errorf("invalid = semver %q: %w", clause, err)
		}
		if CompareSemVer(host, target) != 0 {
			return fmt.Errorf("host version %s does not equal required %s", host, target)
		}
		return nil
	}

	// Default SemVer compatibility:
	target, err := ParseSemVer(clause)
	if err != nil {
		return fmt.Errorf("invalid semver %q: %w", clause, err)
	}

	return checkCaretCompatibility(host, target)
}

func checkCaretCompatibility(host, target SemVer) error {
	// Major 0: initial development, minor bumps break compatibility
	if target.Major == 0 {
		if host.Major != 0 || host.Minor != target.Minor {
			return fmt.Errorf("incompatible with host %s: 0.x versions require exact minor match (%d.%d.x)", host, target.Major, target.Minor)
		}
		if CompareSemVer(host, target) < 0 {
			return fmt.Errorf("host version %s is lower than required %s", host, target)
		}
		return nil
	}

	// Major > 0: breaking change if major versions do not match
	if host.Major != target.Major {
		if host.Major < target.Major {
			return fmt.Errorf("requires future major version %d.x.x, but running host is %s", target.Major, host)
		}
		return fmt.Errorf("target version %s is incompatible with newer host major version %d.x.x", target, host.Major)
	}

	// Same major version: host must be >= target
	if CompareSemVer(host, target) < 0 {
		return fmt.Errorf("host version %s is lower than required %s", host, target)
	}

	return nil
}

func checkTildeCompatibility(host, target SemVer) error {
	if host.Major != target.Major || host.Minor != target.Minor {
		return fmt.Errorf("host %s does not match required tilde range ~%s (requires %d.%d.x)", host, target, target.Major, target.Minor)
	}
	if CompareSemVer(host, target) < 0 {
		return fmt.Errorf("host version %s is lower than required %s", host, target)
	}
	return nil
}
