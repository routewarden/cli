package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Severity represents the severity level of an audit finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

// AuditIssue represents a single rule or configuration flaw detected by the linter.
type AuditIssue struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	Pattern     string   `json:"pattern,omitempty"`
	Field       string   `json:"field,omitempty"`
	Remediation string   `json:"remediation"`
}

// AuditReport holds the complete evaluation result of a configuration audit.
type AuditReport struct {
	ConfigFile    string            `json:"configFile,omitempty"`
	TotalIssues   int               `json:"totalIssues"`
	CriticalCount int               `json:"criticalCount"`
	WarningCount  int               `json:"warningCount"`
	InfoCount     int               `json:"infoCount"`
	SecurityScore int               `json:"securityScore"`
	Passed        bool              `json:"passed"`
	Issues        []AuditIssue      `json:"issues"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// AuditConfig performs deep static analysis and linting on a RouteWarden configuration.
func AuditConfig(cfg *Config, filename string) *AuditReport {
	report := &AuditReport{
		ConfigFile: filename,
		Issues:     make([]AuditIssue, 0),
		Metadata:   make(map[string]string),
	}

	if cfg == nil {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A000",
			Severity:    SeverityCritical,
			Title:       "Nil Configuration",
			Message:     "Configuration object is nil or could not be loaded.",
			Remediation: "Provide a valid RouteWarden JSON policy file.",
		})
		report.finalize(false)
		return report
	}

	// ── Rule RW-A001: Overall Enabled Check ──────────────────────────────────
	if !cfg.Enabled {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A001",
			Severity:    SeverityCritical,
			Title:       "Protection Globally Disabled",
			Message:     "The 'enabled' toggle is set to false. RouteWarden will not inspect any traffic.",
			Field:       "enabled",
			Remediation: "Set 'enabled: true' in your configuration.",
		})
	}

	// ── Rule RW-A002: Default Pattern Coverage Check ────────────────────────
	if !cfg.EnableDefaultPatterns && len(cfg.BlockPatterns) == 0 {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A002",
			Severity:    SeverityCritical,
			Title:       "Zero Block Patterns Configured",
			Message:     "Default block patterns are disabled and no custom block patterns are defined. All paths will be allowed.",
			Field:       "enableDefaultPatterns",
			Remediation: "Enable default patterns with 'enableDefaultPatterns: true' or define custom rules in 'blockPatterns'.",
		})
	}

	// ── Rule RW-A003: Overly Broad Wildcard Pattern Check ───────────────────
	allBlockPatterns := append([]string{}, cfg.BlockPatterns...)
	for _, p := range allBlockPatterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == ".*" || trimmed == "^.*$" || trimmed == "*" || trimmed == "^.+$" || trimmed == ".+" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A003",
				Severity:    SeverityCritical,
				Title:       "Universal Wildcard Block Pattern",
				Message:     fmt.Sprintf("Pattern %q matches every incoming path, causing denial of service on all traffic.", p),
				Pattern:     p,
				Field:       "blockPatterns",
				Remediation: "Target specific sensitive paths (e.g. '(?i)\\.env' or '/admin/.*') instead of universal wildcards.",
			})
		}
	}

	for _, p := range cfg.AllowPatterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == ".*" || trimmed == "^.*$" || trimmed == "*" || trimmed == "^.+$" || trimmed == ".+" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A004",
				Severity:    SeverityCritical,
				Title:       "Universal Wildcard Allow Pattern",
				Message:     fmt.Sprintf("Allow pattern %q matches every incoming path, which bypasses all security block rules.", p),
				Pattern:     p,
				Field:       "allowPatterns",
				Remediation: "Restrict allow patterns to precise safe routes (e.g. '/api/v1/health' or '(?i)^/public/').",
			})
		}
	}

	// ── Rule RW-A005: Unescaped Dots in File Extensions ────────────────────
	unescapedDotRegex := regexp.MustCompile(`(^|[^\\])\.(env|git|sql|bak|yml|yaml|json|conf|ini|log|key|pem|crt|tar|gz|zip|sh|bash)($|[^a-zA-Z0-9_-])`)
	for _, p := range cfg.BlockPatterns {
		if unescapedDotRegex.MatchString(p) && !strings.Contains(p, `\.`) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A005",
				Severity:    SeverityWarning,
				Title:       "Unescaped Dot in File Extension",
				Message:     fmt.Sprintf("Pattern %q contains an unescaped dot before a file extension. In regex, '.' matches any single character.", p),
				Pattern:     p,
				Field:       "blockPatterns",
				Remediation: fmt.Sprintf("Escape the dot with a backslash: e.g. %q", strings.ReplaceAll(p, ".", `\.`)),
			})
		}
	}

	// ── Rule RW-A006: ReDoS Catastrophic Backtracking Risks ────────────────
	nestedQuantifiers := regexp.MustCompile(`(\([^\)]*[\*\+\?][^\)]*\)[\*\+\?]|\.\*[\*\+]|\.\+[\*\+])`)
	allPatternsToCheck := append(append([]string{}, cfg.BlockPatterns...), cfg.AllowPatterns...)
	allPatternsToCheck = append(allPatternsToCheck, cfg.CheckBodyPatterns...)
	for _, p := range allPatternsToCheck {
		if nestedQuantifiers.MatchString(p) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A006",
				Severity:    SeverityCritical,
				Title:       "Potential ReDoS Vulnerability (Catastrophic Backtracking)",
				Message:     fmt.Sprintf("Pattern %q contains nested quantifiers that can cause exponential execution time on long input paths.", p),
				Pattern:     p,
				Field:       "patterns",
				Remediation: "Simplify quantifier nesting or avoid nested repeated groups like '(.*)*' or '(a+)+'.",
			})
		}
	}

	// ── Rule RW-A007: Duplicate / Redundant Patterns ────────────────────────
	seenBlock := make(map[string]bool)
	for _, p := range cfg.BlockPatterns {
		normalized := strings.TrimSpace(p)
		if seenBlock[normalized] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A007",
				Severity:    SeverityInfo,
				Title:       "Duplicate Block Pattern",
				Message:     fmt.Sprintf("Pattern %q is defined multiple times in blockPatterns.", p),
				Pattern:     p,
				Field:       "blockPatterns",
				Remediation: "Remove duplicate entries to optimize regex compilation and memory.",
			})
		}
		seenBlock[normalized] = true
	}

	seenAllow := make(map[string]bool)
	for _, p := range cfg.AllowPatterns {
		normalized := strings.TrimSpace(p)
		if seenAllow[normalized] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A008",
				Severity:    SeverityInfo,
				Title:       "Duplicate Allow Pattern",
				Message:     fmt.Sprintf("Pattern %q is defined multiple times in allowPatterns.", p),
				Pattern:     p,
				Field:       "allowPatterns",
				Remediation: "Remove duplicate allow entries to optimize regex matching.",
			})
		}
		seenAllow[normalized] = true
	}

	seenBody := make(map[string]bool)
	for _, p := range cfg.CheckBodyPatterns {
		normalized := strings.TrimSpace(p)
		if seenBody[normalized] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A008",
				Severity:    SeverityInfo,
				Title:       "Duplicate Body Pattern",
				Message:     fmt.Sprintf("Pattern %q is defined multiple times in checkBodyPatterns.", p),
				Pattern:     p,
				Field:       "checkBodyPatterns",
				Remediation: "Remove duplicate body entries to optimize regex inspection.",
			})
		}
		seenBody[normalized] = true
	}

	// ── Rule RW-A015: Invalid Regular Expression Syntax ─────────────────────
	checkRegexSyntax := func(patterns []string, field string) {
		for _, p := range patterns {
			trimmed := strings.TrimSpace(p)
			if trimmed == "" {
				continue
			}
			if _, err := regexp.Compile(trimmed); err != nil {
				report.Issues = append(report.Issues, AuditIssue{
					Code:        "RW-A015",
					Severity:    SeverityCritical,
					Title:       "Invalid Regular Expression Syntax",
					Message:     fmt.Sprintf("Pattern %q cannot be compiled: %v", p, err),
					Pattern:     p,
					Field:       field,
					Remediation: "Fix the syntax error in the regular expression so it compiles cleanly.",
				})
			}
		}
	}
	checkRegexSyntax(cfg.BlockPatterns, "blockPatterns")
	checkRegexSyntax(cfg.AllowPatterns, "allowPatterns")
	checkRegexSyntax(cfg.CheckBodyPatterns, "checkBodyPatterns")

	// ── Rule RW-A009: Invalid IP / CIDR Notations ───────────────────────────
	for _, ipStr := range cfg.AllowedIPs {
		ipTrimmed := strings.TrimSpace(ipStr)
		if ipTrimmed == "" {
			continue
		}
		if !isValidIPOrCIDR(ipTrimmed) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A009",
				Severity:    SeverityCritical,
				Title:       "Malformed Allowed IP / CIDR",
				Message:     fmt.Sprintf("%q is neither a valid IPv4/IPv6 address nor a valid CIDR subnet.", ipStr),
				Pattern:     ipStr,
				Field:       "allowedIps",
				Remediation: "Provide valid IP notations like '192.168.1.100' or CIDR blocks like '10.0.0.0/8'.",
			})
		}
	}

	for _, ipStr := range cfg.TrustedProxies {
		ipTrimmed := strings.TrimSpace(ipStr)
		if ipTrimmed == "" {
			continue
		}
		if !isValidIPOrCIDR(ipTrimmed) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A010",
				Severity:    SeverityCritical,
				Title:       "Malformed Trusted Proxy IP / CIDR",
				Message:     fmt.Sprintf("%q in trustedProxies is neither a valid IP address nor a valid CIDR subnet.", ipStr),
				Pattern:     ipStr,
				Field:       "trustedProxies",
				Remediation: "Provide valid trusted proxy IPs or CIDRs (e.g. '127.0.0.1', '10.0.0.0/8', '172.16.0.0/12').",
			})
		}
	}

	// ── Rule RW-A011: Status Code Validation ────────────────────────────────
	if cfg.StatusCode != 0 && (cfg.StatusCode < 100 || cfg.StatusCode > 599) {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A011",
			Severity:    SeverityCritical,
			Title:       "Invalid HTTP Status Code",
			Message:     fmt.Sprintf("HTTP statusCode %d is outside the valid range 100-599.", cfg.StatusCode),
			Field:       "statusCode",
			Remediation: "Use standard client error codes such as 403 (Forbidden), 404 (Not Found), or 429 (Too Many Requests).",
		})
	}
	if cfg.Response != nil && cfg.Response.StatusCode != 0 && (cfg.Response.StatusCode < 100 || cfg.Response.StatusCode > 599) {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A011",
			Severity:    SeverityCritical,
			Title:       "Invalid HTTP Status Code in Response Config",
			Message:     fmt.Sprintf("HTTP response.statusCode %d is outside the valid range 100-599.", cfg.Response.StatusCode),
			Field:       "response.statusCode",
			Remediation: "Use standard client error codes such as 403 (Forbidden), 404 (Not Found), or 429 (Too Many Requests).",
		})
	}

	// ── Rule RW-A012: Insecure Response Mode Check ──────────────────────────
	validModes := map[string]bool{
		"text":                 true,
		"json":                 true,
		"html":                 true,
		"captcha":              true,
		"redirect":             true,
		"silentdrop":           true,
		"silent_drop":          true,
		"drop":                 true,
		"gzipbomb":             true,
		"gzip_bomb":            true,
		"bomb":                 true,
		"tarpit":               true,
		"fakesuccess":          true,
		"fake_success":         true,
		"decoy":                true,
		"ratelimit":            true,
		"ratelimitchallenge":   true,
		"rate_limit_challenge": true,
		"backoff":              true,
		"proxy":                true,
		"mirror":               true,
		"infinitestream":       true,
		"infinite_stream":      true,
		"garbagestream":        true,
		"xml":                  true,
		"custom":               true,
		"default":              true,
	}
	modeToCheck := cfg.Mode
	if modeToCheck == "" && cfg.Response != nil && cfg.Response.Mode != "" {
		modeToCheck = cfg.Response.Mode
	}
	if modeToCheck != "" && !validModes[strings.ToLower(modeToCheck)] {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A012",
			Severity:    SeverityWarning,
			Title:       "Unrecognized Response Mode",
			Message:     fmt.Sprintf("Mode %q is not a recognized RouteWarden response mode.", modeToCheck),
			Field:       "mode",
			Remediation: "Use one of: 'text', 'json', 'html', 'captcha', 'redirect', 'silentDrop', 'gzipBomb', 'tarpit', 'fakeSuccess', 'rateLimitChallenge', 'proxy', 'infiniteStream', or 'xml'.",
		})
	}

	// ── Rule RW-A013: Monitored Forwarding Headers without Trusted Proxies ──
	hasForwardingHeaders := false
	for _, h := range cfg.CheckHeaders {
		lower := strings.ToLower(h)
		if lower == "x-forwarded-for" || lower == "x-real-ip" || lower == "x-forwarded-uri" {
			hasForwardingHeaders = true
			break
		}
	}
	if hasForwardingHeaders && len(cfg.TrustedProxies) == 0 {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A013",
			Severity:    SeverityWarning,
			Title:       "Header Spoofing Risk without Trusted Proxies",
			Message:     "Forwarding headers (e.g. X-Forwarded-For, X-Real-IP) are inspected but 'trustedProxies' is empty, allowing attackers to spoof headers.",
			Field:       "trustedProxies",
			Remediation: "Define upstream reverse proxy or load balancer CIDRs in 'trustedProxies' to restrict header trust.",
		})
	}

	// ── Rule RW-A014: Default Allow Patterns Disabled Notice ────────────────
	if !cfg.EnableDefaultAllowPatterns {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A014",
			Severity:    SeverityInfo,
			Title:       "Default Allow Patterns Disabled",
			Message:     "Default allow patterns are disabled. Legitimate Let's Encrypt ACME challenges (/.well-known/acme-challenge/*) might be blocked if sensitive file patterns overlap.",
			Field:       "enableDefaultAllowPatterns",
			Remediation: "Keep 'enableDefaultAllowPatterns: true' unless explicitly required by security policy.",
		})
	}

	report.finalize(false)
	return report
}

func isValidIPOrCIDR(v string) bool {
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	if ip := net.ParseIP(v); ip != nil {
		return true
	}
	return false
}

func (r *AuditReport) finalize(strict bool) {
	r.TotalIssues = len(r.Issues)
	r.CriticalCount = 0
	r.WarningCount = 0
	r.InfoCount = 0

	for _, issue := range r.Issues {
		switch issue.Severity {
		case SeverityCritical:
			r.CriticalCount++
		case SeverityWarning:
			r.WarningCount++
		case SeverityInfo:
			r.InfoCount++
		}
	}

	// Calculate 0-100 score
	score := 100 - (r.CriticalCount * 30) - (r.WarningCount * 10) - (r.InfoCount * 2)
	if score < 0 {
		score = 0
	}
	r.SecurityScore = score

	if strict {
		r.Passed = (r.CriticalCount == 0 && r.WarningCount == 0)
	} else {
		r.Passed = (r.CriticalCount == 0)
	}
}

// ToSARIF converts the audit report into the standard OASIS SARIF v2.1.0 JSON format for GitHub Code Scanning.
func (r *AuditReport) ToSARIF() ([]byte, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
		Help             sarifMessage `json:"help"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	rulesMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(r.Issues))

	uri := r.ConfigFile
	if uri == "" {
		uri = "routewarden.json"
	}

	for _, issue := range r.Issues {
		level := "note"
		switch issue.Severity {
		case SeverityCritical:
			level = "error"
		case SeverityWarning:
			level = "warning"
		case SeverityInfo:
			level = "note"
		}

		if _, exists := rulesMap[issue.Code]; !exists {
			rulesMap[issue.Code] = sarifRule{
				ID:               issue.Code,
				Name:             strings.ReplaceAll(issue.Title, " ", ""),
				ShortDescription: sarifMessage{Text: issue.Title},
				Help:             sarifMessage{Text: issue.Remediation},
			}
		}

		res := sarifResult{
			RuleID:  issue.Code,
			Level:   level,
			Message: sarifMessage{Text: issue.Message},
		}

		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		res.Locations = []sarifLocation{loc}

		results = append(results, res)
	}

	rules := make([]sarifRule, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "RouteWarden Security Linter",
						Version:        "5.4.0", // tool version
						InformationURI: "https://routewarden.github.io",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}
