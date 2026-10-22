package plugins

import "github.com/routewarden/cli/proxy/plugins/sdk"

// SemVer represents a parsed Semantic Version conforming to SemVer 2.0.0.
type SemVer = sdk.SemVer

var (
	// ParseSemVer parses a semver string (e.g., "1.2.3", "v1.2.3", "1.0.0-rc.1+build.12").
	ParseSemVer = sdk.ParseSemVer

	// CompareSemVer compares two SemVer versions according to SemVer 2.0.0 precedence.
	CompareSemVer = sdk.CompareSemVer

	// CheckSemVerCompatibility checks if hostVersion satisfies the constraint according to SemVer 2.0.0.
	CheckSemVerCompatibility = sdk.CheckSemVerCompatibility
)
