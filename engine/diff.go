package engine

import (
	"fmt"
	"sort"
	"strings"
)

// DiffImpact describes the security posture impact of a policy diff.
type DiffImpact string

const (
	DiffImpactRelaxed  DiffImpact = "RELAXED"  // Protections were weakened or removed
	DiffImpactHardened DiffImpact = "HARDENED" // Protections were strengthened
	DiffImpactNeutral  DiffImpact = "NEUTRAL"  // Equivalent or cosmetic changes
)

// SliceDiff represents added and removed items in a list attribute.
type SliceDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// ScalarDiff represents before and after values for a scalar property.
type ScalarDiff struct {
	Old interface{} `json:"old"`
	New interface{} `json:"new"`
}

// PolicyDiff represents the structural and security difference between two policies.
type PolicyDiff struct {
	AllowedASNs       SliceDiff             `json:"allowedASNs"`
	BaseFile          string                `json:"baseFile"`
	CandidateFile     string                `json:"candidateFile"`
	Impact            DiffImpact            `json:"impact"`
	ImpactReasons     []string              `json:"impactReasons"`
	BlockPatterns     SliceDiff             `json:"blockPatterns"`
	AllowPatterns     SliceDiff             `json:"allowPatterns"`
	AllowedIPs        SliceDiff             `json:"allowedIps"`
	TrustedProxies    SliceDiff             `json:"trustedProxies"`
	Methods           SliceDiff             `json:"methods"`
	CheckHeaders      SliceDiff             `json:"checkHeaders"`
	CheckBodyPatterns SliceDiff             `json:"checkBodyPatterns"`
	Properties        map[string]ScalarDiff `json:"properties"`
	HasDifferences    bool                  `json:"hasDifferences"`
}

// DiffConfigs compares two RouteWarden configurations and evaluates the security impact.
func DiffConfigs(base, candidate *Config, baseName, candidateName string) *PolicyDiff {
	if base == nil {
		base = CreateConfig()
	}
	if candidate == nil {
		candidate = CreateConfig()
	}
	diff := &PolicyDiff{
		BaseFile:          baseName,
		CandidateFile:     candidateName,
		Impact:            DiffImpactNeutral,
		ImpactReasons:     make([]string, 0),
		Properties:        make(map[string]ScalarDiff),
		BlockPatterns:     diffStringSlices(base.BlockPatterns, candidate.BlockPatterns),
		AllowPatterns:     diffStringSlices(base.AllowPatterns, candidate.AllowPatterns),
		AllowedASNs:       diffStringSlices(base.AllowedASNs, candidate.AllowedASNs),
		AllowedIPs:        diffStringSlices(base.AllowedIPs, candidate.AllowedIPs),
		TrustedProxies:    diffStringSlices(base.TrustedProxies, candidate.TrustedProxies),
		Methods:           diffStringSlices(base.Methods, candidate.Methods),
		CheckHeaders:      diffStringSlices(base.CheckHeaders, candidate.CheckHeaders),
		CheckBodyPatterns: diffStringSlices(base.CheckBodyPatterns, candidate.CheckBodyPatterns),
	}

	if base.ASNDB != candidate.ASNDB {
		diff.Properties["asnDB"] = ScalarDiff{Old: base.ASNDB, New: candidate.ASNDB}
		diff.ImpactReasons = append(diff.ImpactReasons, "ASN database path changed; review routing data for bypass changes.")
	}
	if len(diff.AllowedASNs.Added) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, "ASN allowlist bypasses were added.")
	}
	if len(diff.AllowedASNs.Removed) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, "ASN allowlist bypasses were removed.")
	}
	// ── Compare Scalar Properties ───────────────────────────────────────────
	if base.Enabled != candidate.Enabled {
		diff.Properties["enabled"] = ScalarDiff{Old: base.Enabled, New: candidate.Enabled}
		if !candidate.Enabled {
			diff.ImpactReasons = append(diff.ImpactReasons, "CRITICAL: RouteWarden protection was disabled in candidate policy.")
		} else {
			diff.ImpactReasons = append(diff.ImpactReasons, "RouteWarden protection was re-enabled.")
		}
	}

	if base.EnableDefaultPatterns != candidate.EnableDefaultPatterns {
		diff.Properties["enableDefaultPatterns"] = ScalarDiff{Old: base.EnableDefaultPatterns, New: candidate.EnableDefaultPatterns}
		if !candidate.EnableDefaultPatterns {
			diff.ImpactReasons = append(diff.ImpactReasons, "HIGH: Built-in sensitive file block patterns were disabled.")
		} else {
			diff.ImpactReasons = append(diff.ImpactReasons, "Built-in sensitive file block patterns were enabled.")
		}
	}

	if base.EnableDefaultAllowPatterns != candidate.EnableDefaultAllowPatterns {
		diff.Properties["enableDefaultAllowPatterns"] = ScalarDiff{Old: base.EnableDefaultAllowPatterns, New: candidate.EnableDefaultAllowPatterns}
	}

	if base.StatusCode != candidate.StatusCode {
		diff.Properties["statusCode"] = ScalarDiff{Old: base.StatusCode, New: candidate.StatusCode}
	}

	if base.Mode != candidate.Mode {
		diff.Properties["mode"] = ScalarDiff{Old: base.Mode, New: candidate.Mode}
	}

	if base.CheckQuery != candidate.CheckQuery {
		diff.Properties["checkQuery"] = ScalarDiff{Old: base.CheckQuery, New: candidate.CheckQuery}
		if !candidate.CheckQuery {
			diff.ImpactReasons = append(diff.ImpactReasons, "MEDIUM: Query string anti-evasion inspection was disabled.")
		} else {
			diff.ImpactReasons = append(diff.ImpactReasons, "Query string anti-evasion inspection was enabled.")
		}
	}

	if base.CheckBody != candidate.CheckBody {
		diff.Properties["checkBody"] = ScalarDiff{Old: base.CheckBody, New: candidate.CheckBody}
		if !candidate.CheckBody {
			diff.ImpactReasons = append(diff.ImpactReasons, "HIGH: Request body inspection was disabled.")
		} else {
			diff.ImpactReasons = append(diff.ImpactReasons, "Request body inspection was enabled.")
		}
	}

	if base.CheckBodyMaxBytes != candidate.CheckBodyMaxBytes {
		diff.Properties["checkBodyMaxBytes"] = ScalarDiff{Old: base.CheckBodyMaxBytes, New: candidate.CheckBodyMaxBytes}
	}

	if base.CustomResponseText != candidate.CustomResponseText {
		diff.Properties["customResponseText"] = ScalarDiff{Old: base.CustomResponseText, New: candidate.CustomResponseText}
	}

	baseMode, baseStatus, baseBody := base.ResolveResponse()
	candMode, candStatus, candBody := candidate.ResolveResponse()
	if baseMode != candMode {
		diff.Properties["response.mode"] = ScalarDiff{Old: baseMode, New: candMode}
	}
	if baseStatus != candStatus {
		diff.Properties["response.statusCode"] = ScalarDiff{Old: baseStatus, New: candStatus}
	}
	if baseBody != candBody {
		diff.Properties["response.body"] = ScalarDiff{Old: baseBody, New: candBody}
	}

	// ── Evaluate List Changes on Security Posture ───────────────────────────
	if len(diff.BlockPatterns.Removed) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("HIGH: %d custom block pattern(s) were removed: %s", len(diff.BlockPatterns.Removed), strings.Join(diff.BlockPatterns.Removed, ", ")))
	}
	if len(diff.BlockPatterns.Added) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("HARDENED: %d new block pattern(s) were added: %s", len(diff.BlockPatterns.Added), strings.Join(diff.BlockPatterns.Added, ", ")))
	}

	if len(diff.CheckBodyPatterns.Removed) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("HIGH: %d custom body inspection pattern(s) were removed: %s", len(diff.CheckBodyPatterns.Removed), strings.Join(diff.CheckBodyPatterns.Removed, ", ")))
	}
	if len(diff.CheckBodyPatterns.Added) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("HARDENED: %d new body inspection pattern(s) were added: %s", len(diff.CheckBodyPatterns.Added), strings.Join(diff.CheckBodyPatterns.Added, ", ")))
	}

	if len(diff.AllowPatterns.Added) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("WARNING: %d allow pattern(s) were added: %s (may bypass security rules)", len(diff.AllowPatterns.Added), strings.Join(diff.AllowPatterns.Added, ", ")))
	}

	if len(diff.AllowedIPs.Added) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("ALLOWED IPs: %d IP/CIDR entry(ies) were added to whitelist.", len(diff.AllowedIPs.Added)))
	}
	if len(diff.AllowedIPs.Removed) > 0 {
		diff.ImpactReasons = append(diff.ImpactReasons, fmt.Sprintf("HARDENED: %d IP/CIDR entry(ies) were removed from whitelist.", len(diff.AllowedIPs.Removed)))
	}

	// ── Determine Overall Impact ────────────────────────────────────────────
	diff.HasDifferences = len(diff.AllowedASNs.Added) > 0 || len(diff.AllowedASNs.Removed) > 0 || len(diff.BlockPatterns.Added) > 0 ||
		len(diff.BlockPatterns.Removed) > 0 ||
		len(diff.AllowPatterns.Added) > 0 ||
		len(diff.AllowPatterns.Removed) > 0 ||
		len(diff.AllowedIPs.Added) > 0 ||
		len(diff.AllowedIPs.Removed) > 0 ||
		len(diff.TrustedProxies.Added) > 0 ||
		len(diff.TrustedProxies.Removed) > 0 ||
		len(diff.Methods.Added) > 0 ||
		len(diff.Methods.Removed) > 0 ||
		len(diff.CheckHeaders.Added) > 0 ||
		len(diff.CheckHeaders.Removed) > 0 ||
		len(diff.CheckBodyPatterns.Added) > 0 ||
		len(diff.CheckBodyPatterns.Removed) > 0 ||
		len(diff.Properties) > 0

	hasRelaxing := false
	hasHardening := false

	if (base.Enabled && !candidate.Enabled) ||
		(base.EnableDefaultPatterns && !candidate.EnableDefaultPatterns) ||
		(base.CheckQuery && !candidate.CheckQuery) ||
		(base.CheckBody && !candidate.CheckBody) ||
		len(diff.BlockPatterns.Removed) > 0 ||
		len(diff.CheckBodyPatterns.Removed) > 0 ||
		len(diff.AllowPatterns.Added) > 0 {
		hasRelaxing = true
	}

	if (!base.Enabled && candidate.Enabled) ||
		(!base.EnableDefaultPatterns && candidate.EnableDefaultPatterns) ||
		(!base.CheckQuery && candidate.CheckQuery) ||
		(!base.CheckBody && candidate.CheckBody) ||
		len(diff.BlockPatterns.Added) > 0 ||
		len(diff.CheckBodyPatterns.Added) > 0 ||
		len(diff.AllowedIPs.Removed) > 0 {
		hasHardening = true
	}

	if len(diff.AllowedASNs.Added) > 0 || base.ASNDB != candidate.ASNDB {
		hasRelaxing = true
	}
	if len(diff.AllowedASNs.Removed) > 0 {
		hasHardening = true
	}
	if hasRelaxing {
		diff.Impact = DiffImpactRelaxed
	} else if hasHardening {
		diff.Impact = DiffImpactHardened
	} else {
		diff.Impact = DiffImpactNeutral
	}

	return diff
}

func diffStringSlices(oldList, newList []string) SliceDiff {
	oldMap := make(map[string]bool)
	for _, s := range oldList {
		oldMap[strings.TrimSpace(s)] = true
	}

	newMap := make(map[string]bool)
	for _, s := range newList {
		newMap[strings.TrimSpace(s)] = true
	}

	var added []string
	seenAdded := make(map[string]bool)
	for _, s := range newList {
		sTrimmed := strings.TrimSpace(s)
		if sTrimmed != "" && !oldMap[sTrimmed] && !seenAdded[sTrimmed] {
			seenAdded[sTrimmed] = true
			added = append(added, sTrimmed)
		}
	}

	var removed []string
	seenRemoved := make(map[string]bool)
	for _, s := range oldList {
		sTrimmed := strings.TrimSpace(s)
		if sTrimmed != "" && !newMap[sTrimmed] && !seenRemoved[sTrimmed] {
			seenRemoved[sTrimmed] = true
			removed = append(removed, sTrimmed)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	return SliceDiff{
		Added:   added,
		Removed: removed,
	}
}
