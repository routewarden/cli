package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	isUniversalWildcard := func(p string) bool {
		trimmed := strings.TrimSpace(p)
		clean := strings.TrimPrefix(trimmed, "(?i)")
		clean = strings.TrimPrefix(clean, "(?-i)")
		clean = strings.TrimSpace(clean)
		return clean == ".*" || clean == "^.*$" || clean == "*" || clean == "^.+$" || clean == ".+" ||
			clean == "^.*" || clean == ".*$" || clean == "^/.*$" || clean == "^/.*" || clean == "/.*"
	}

	allBlockPatterns := append([]string{}, cfg.BlockPatterns...)
	for _, p := range allBlockPatterns {
		if isUniversalWildcard(p) {
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
		if isUniversalWildcard(p) {
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
		if unescapedDotRegex.MatchString(p) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A005",
				Severity:    SeverityWarning,
				Title:       "Unescaped Dot in File Extension",
				Message:     fmt.Sprintf("Pattern %q contains an unescaped dot before a file extension. In regex, '.' matches any single character.", p),
				Pattern:     p,
				Field:       "blockPatterns",
				Remediation: fmt.Sprintf("Escape the dot with a backslash: e.g. %q", unescapedDotRegex.ReplaceAllString(p, `${1}\.${2}${3}`)),
			})
		}
	}

	// ── Rule RW-A006: ReDoS Catastrophic Backtracking Risks ────────────────
	nestedQuantifiers := regexp.MustCompile(`(\([^\)]*[\*\+\?][^\)]*\)[\*\+\?]|\.\*[\*\+]|\.\+[\*\+])`)
	allPatternsToCheck := append(append([]string{}, cfg.BlockPatterns...), cfg.AllowPatterns...)
	allPatternsToCheck = append(allPatternsToCheck, cfg.CheckBodyPatterns...)
	allPatternsToCheck = append(allPatternsToCheck, cfg.BlockUserAgents...)
	allPatternsToCheck = append(allPatternsToCheck, cfg.AllowUserAgents...)
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
				Code:        "RW-A021",
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

	seenBlockUA := make(map[string]bool)
	for _, p := range cfg.BlockUserAgents {
		normalized := strings.TrimSpace(p)
		if seenBlockUA[normalized] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A007",
				Severity:    SeverityInfo,
				Title:       "Duplicate Block User-Agent Pattern",
				Message:     fmt.Sprintf("Pattern %q is defined multiple times in blockUserAgents.", p),
				Pattern:     p,
				Field:       "blockUserAgents",
				Remediation: "Remove duplicate entries to optimize User-Agent inspection.",
			})
		}
		seenBlockUA[normalized] = true
	}

	seenAllowUA := make(map[string]bool)
	for _, p := range cfg.AllowUserAgents {
		normalized := strings.TrimSpace(p)
		if seenAllowUA[normalized] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A008",
				Severity:    SeverityInfo,
				Title:       "Duplicate Allow User-Agent Pattern",
				Message:     fmt.Sprintf("Pattern %q is defined multiple times in allowUserAgents.", p),
				Pattern:     p,
				Field:       "allowUserAgents",
				Remediation: "Remove duplicate allow entries to optimize User-Agent matching.",
			})
		}
		seenAllowUA[normalized] = true
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
	checkRegexSyntax(cfg.BlockUserAgents, "blockUserAgents")
	checkRegexSyntax(cfg.AllowUserAgents, "allowUserAgents")

	// ── Rule RW-A016: AI Bot Profile Validation ─────────────────────────────
	if cfg.AIBotProfile != "" {
		p := strings.ToLower(cfg.AIBotProfile)
		if p != "train_only" && p != "search_only" && p != "agents_only" && p != "all" && p != "aggressive" && p != "custom" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A016",
				Severity:    SeverityWarning,
				Title:       "Unrecognized AI Bot Profile",
				Message:     fmt.Sprintf("AI bot profile %q is not recognized.", cfg.AIBotProfile),
				Field:       "aiBotProfile",
				Remediation: "Use one of: 'train_only' (default), 'search_only', 'agents_only', 'all', 'aggressive', or 'custom'.",
			})
		}
	}

	// ── Rule RW-A017: Bot Defense Level Validation ──────────────────────────
	if cfg.BotDefenseLevel != "" {
		lvl := strings.ToLower(strings.TrimSpace(cfg.BotDefenseLevel))
		validLevels := map[string]bool{
			"off": true, "light": true, "relaxed": true,
			"standard": true, "moderate": true,
			"strict": true, "aggressive": true, "paranoia": true,
		}
		if !validLevels[lvl] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A017",
				Severity:    SeverityWarning,
				Title:       "Unrecognized Bot Defense Level",
				Message:     fmt.Sprintf("Bot defense level %q is not recognized.", cfg.BotDefenseLevel),
				Field:       "botDefenseLevel",
				Remediation: "Use one of: 'off', 'light' (relaxed), 'standard' (moderate), 'strict', or 'aggressive' (paranoia).",
			})
		}
	}

	// ── Rule RW-A009: Invalid IP / CIDR Notations ───────────────────────────
	for _, ipStr := range cfg.AllowedIPs {
		ipTrimmed := strings.TrimSpace(ipStr)
		if ipTrimmed == "" {
			continue
		}
		if ipTrimmed == "0.0.0.0/0" || ipTrimmed == "::/0" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A022",
				Severity:    SeverityCritical,
				Title:       "Universal Allowlist CIDR (Bypasses All Defense)",
				Message:     fmt.Sprintf("%q in allowedIps unconditionally bypasses all RouteWarden inspection and security rules for all clients worldwide.", ipStr),
				Pattern:     ipStr,
				Field:       "allowedIps",
				Remediation: "Remove '0.0.0.0/0' or '::/0'. Whitelist only specific administrative IPs or internal subnets.",
			})
		} else if !isValidIPOrCIDR(ipTrimmed) {
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
		if ipTrimmed == "0.0.0.0/0" || ipTrimmed == "::/0" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A023",
				Severity:    SeverityCritical,
				Title:       "Universal Trusted Proxy CIDR (Header Spoofing Risk)",
				Message:     fmt.Sprintf("%q in trustedProxies trusts forwarding headers (X-Forwarded-For, X-Real-IP) from every client on the internet, enabling arbitrary IP spoofing.", ipStr),
				Pattern:     ipStr,
				Field:       "trustedProxies",
				Remediation: "Define explicit upstream reverse proxy or load balancer CIDRs in 'trustedProxies' instead of universal 0.0.0.0/0 or ::/0.",
			})
		} else if !isValidIPOrCIDR(ipTrimmed) {
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
		"aipoison":             true,
		"ai_poison":            true,
		"poison":               true,
		"markovtarpit":         true,
		"markov_tarpit":        true,
		"markov":               true,
		"tokenbleed":           true,
		"custom":               true,
		"default":              true,
	}
	checkMode := func(m, fieldName string) {
		if m != "" && !validModes[strings.ToLower(strings.TrimSpace(m))] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A012",
				Severity:    SeverityWarning,
				Title:       "Unrecognized Response Mode",
				Message:     fmt.Sprintf("Mode %q is not a recognized RouteWarden response mode.", m),
				Field:       fieldName,
				Remediation: "Use one of: 'text', 'json', 'html', 'captcha', 'redirect', 'silentDrop', 'gzipBomb', 'tarpit', 'fakeSuccess', 'rateLimitChallenge', 'proxy', 'infiniteStream', 'xml', 'aiPoison', or 'markovTarpit'.",
			})
		}
	}
	if cfg.Mode != "" {
		checkMode(cfg.Mode, "mode")
	}
	if cfg.Response != nil && cfg.Response.Mode != "" {
		checkMode(cfg.Response.Mode, "response.mode")
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

	// ── Rule RW-A018: Missing ASN Database Check ────────────────────────────
	if (len(cfg.AllowedASNs) > 0 || len(cfg.BlockedASNs) > 0) && strings.TrimSpace(cfg.ASNDB) == "" {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A018",
			Severity:    SeverityCritical,
			Title:       "Missing ASN Database File",
			Message:     "ASN allowlisting or blocking is configured, but 'asnDB' is empty. RouteWarden requires an offline JSON routing database to resolve client IPs to ASNs.",
			Field:       "asnDB",
			Remediation: "Specify the path to your offline ASN routing snapshot in 'asnDB' (e.g. '/etc/routewarden/asn.json').",
		})
	}

	// ── Rule RW-A019: ASN Identifier Syntax Validation ──────────────────────
	checkASNs := func(asns []string, field string) {
		for _, rawASN := range asns {
			trimmed := strings.TrimSpace(rawASN)
			if trimmed == "" {
				continue
			}
			if _, err := parseASN(trimmed); err != nil {
				report.Issues = append(report.Issues, AuditIssue{
					Code:        "RW-A019",
					Severity:    SeverityCritical,
					Title:       "Malformed ASN Identifier",
					Message:     fmt.Sprintf("ASN %q in %s is invalid: %v", rawASN, field, err),
					Pattern:     rawASN,
					Field:       field,
					Remediation: "Provide valid ASN format like 'AS13335' or numeric '13335' (1..4294967295).",
				})
			}
		}
	}
	checkASNs(cfg.AllowedASNs, "allowedASNs")
	checkASNs(cfg.BlockedASNs, "blockedASNs")

	// ── Rule RW-A020: Trap Ban Duration Validation ──────────────────────────
	if cfg.TrapBanDuration != "" && !isValidBanDuration(cfg.TrapBanDuration) {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A020",
			Severity:    SeverityWarning,
			Title:       "Invalid Honeypot Trap Ban Duration",
			Message:     fmt.Sprintf("trapBanDuration %q cannot be parsed as a time duration or integer seconds.", cfg.TrapBanDuration),
			Pattern:     cfg.TrapBanDuration,
			Field:       "trapBanDuration",
			Remediation: "Use standard duration strings such as '24h', '1h', '30m', or positive integer seconds (e.g. '86400').",
		})
	}

	// ── Rule RW-A024: Case-Sensitive Block Pattern Advisory ──────────────────
	for _, p := range cfg.BlockPatterns {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if !strings.Contains(trimmed, "(?i)") && !strings.Contains(trimmed, "(?i:") {
			hasLetters := false
			for _, r := range trimmed {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
					hasLetters = true
					break
				}
			}
			if hasLetters {
				report.Issues = append(report.Issues, AuditIssue{
					Code:        "RW-A024",
					Severity:    SeverityInfo,
					Title:       "Case-Sensitive Block Pattern",
					Message:     fmt.Sprintf("Pattern %q lacks '(?i)' flag. On case-insensitive file systems (Windows, macOS) or frameworks, requests with alternative casing (e.g. /ADMIN) may bypass inspection.", p),
					Pattern:     p,
					Field:       "blockPatterns",
					Remediation: fmt.Sprintf("Prefix the pattern with '(?i)' for case-insensitive matching: '(?i)%s'", trimmed),
				})
			}
		}
	}

	// ── Rule RW-A025: HTTP Methods Validation ───────────────────────────────
	standardMethods := map[string]bool{
		"GET": true, "HEAD": true, "POST": true, "PUT": true,
		"DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true, "PATCH": true,
	}
	for _, m := range cfg.Methods {
		trimmed := strings.TrimSpace(m)
		if trimmed == "" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A025",
				Severity:    SeverityWarning,
				Title:       "Empty HTTP Method in Inspected Methods",
				Message:     "An empty string was found in the 'methods' configuration list.",
				Field:       "methods",
				Remediation: "Remove the empty entry or specify standard HTTP methods like 'GET', 'POST', 'PUT'.",
			})
			continue
		}
		upper := strings.ToUpper(trimmed)
		if upper != trimmed {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A025",
				Severity:    SeverityWarning,
				Title:       "Lowercase or Mixed-Case HTTP Method",
				Message:     fmt.Sprintf("HTTP method %q should be uppercase (%q). RFC 9110 specifies HTTP methods are case-sensitive uppercase tokens.", m, upper),
				Pattern:     m,
				Field:       "methods",
				Remediation: fmt.Sprintf("Use uppercase %q in 'methods'.", upper),
			})
		} else if !standardMethods[upper] {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A025",
				Severity:    SeverityWarning,
				Title:       "Unrecognized Non-Standard HTTP Method",
				Message:     fmt.Sprintf("Method %q is not a standard HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT).", m),
				Pattern:     m,
				Field:       "methods",
				Remediation: "Verify the method name or replace with standard HTTP methods.",
			})
		}
	}

	// ── Rule RW-A026: Body Inspection Configured Without Mutation Methods ───
	if (cfg.CheckBody || len(cfg.CheckBodyPatterns) > 0) && len(cfg.Methods) > 0 {
		hasMutationMethod := false
		for _, m := range cfg.Methods {
			upper := strings.ToUpper(strings.TrimSpace(m))
			if upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE" {
				hasMutationMethod = true
				break
			}
		}
		if !hasMutationMethod {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A026",
				Severity:    SeverityWarning,
				Title:       "Body Inspection Configured Without Mutation Methods",
				Message:     "Body inspection is enabled ('checkBody' or 'checkBodyPatterns'), but 'methods' contains only read-only methods (e.g. GET/HEAD/OPTIONS). Incoming POST, PUT, or PATCH request bodies will bypass inspection.",
				Field:       "methods",
				Remediation: "Add 'POST', 'PUT', and 'PATCH' to 'methods' so mutating requests with payloads are inspected.",
			})
		}
	}

	// ── Rule RW-A027: Malformed Monitored Header Name ───────────────────────
	headerTokenRegex := regexp.MustCompile(`^[a-zA-Z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)
	for _, h := range cfg.CheckHeaders {
		trimmed := strings.TrimSpace(h)
		if trimmed == "" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A027",
				Severity:    SeverityWarning,
				Title:       "Empty Header Name in checkHeaders",
				Message:     "An empty string was found in 'checkHeaders'.",
				Field:       "checkHeaders",
				Remediation: "Remove the empty entry from 'checkHeaders'.",
			})
		} else if strings.Contains(trimmed, ":") {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A027",
				Severity:    SeverityCritical,
				Title:       "Header Name Contains Colon",
				Message:     fmt.Sprintf("Header name %q in 'checkHeaders' contains a colon (:). Only the header field name should be specified, not its value.", h),
				Pattern:     h,
				Field:       "checkHeaders",
				Remediation: fmt.Sprintf("Use %q instead of %q.", strings.TrimSpace(strings.Split(trimmed, ":")[0]), h),
			})
		} else if !headerTokenRegex.MatchString(trimmed) {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A027",
				Severity:    SeverityWarning,
				Title:       "Invalid HTTP Header Token Syntax",
				Message:     fmt.Sprintf("Header name %q in 'checkHeaders' contains characters not permitted in RFC 9110 HTTP field names.", h),
				Pattern:     h,
				Field:       "checkHeaders",
				Remediation: "Use standard HTTP header names (e.g. 'X-Forwarded-Prefix', 'X-Original-URL').",
			})
		}
	}

	// ── Rule RW-A028: Body Inspection Buffer Limit ──────────────────────────
	if cfg.CheckBodyMaxBytes < 0 {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A028",
			Severity:    SeverityCritical,
			Title:       "Negative Body Inspection Buffer Limit",
			Message:     fmt.Sprintf("checkBodyMaxBytes (%d) cannot be negative.", cfg.CheckBodyMaxBytes),
			Field:       "checkBodyMaxBytes",
			Remediation: "Set 'checkBodyMaxBytes' to a positive byte size, e.g. 65536 (64KB).",
		})
	} else if cfg.CheckBodyMaxBytes > 10*1024*1024 { // >10 MB
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A028",
			Severity:    SeverityWarning,
			Title:       "Excessive Body Inspection Buffer Limit (DoS Risk)",
			Message:     fmt.Sprintf("checkBodyMaxBytes (%d bytes) exceeds 10MB. Buffering large request bodies in memory per concurrent request risks memory exhaustion / denial of service.", cfg.CheckBodyMaxBytes),
			Field:       "checkBodyMaxBytes",
			Remediation: "Limit 'checkBodyMaxBytes' to reasonable sizes (e.g. 65536 for 64KB or 1048576 for 1MB).",
		})
	}

	// ── Rule RW-A029: Honeypot Trap Path Configuration ──────────────────────
	for _, trap := range cfg.HoneypotTrapPaths {
		trimmed := strings.TrimSpace(trap)
		if trimmed == "" {
			report.Issues = append(report.Issues, AuditIssue{
				Code:        "RW-A029",
				Severity:    SeverityWarning,
				Title:       "Empty Honeypot Trap Path",
				Message:     "An empty honeypot trap path was configured. Empty trap paths are ignored.",
				Pattern:     trap,
				Field:       "honeypotTrapPaths",
				Remediation: "Remove empty honeypot trap path entries or specify a dedicated hidden URI such as '/hidden-spider-trap'.",
			})
		} else {
			clean := trimmed
			if !strings.HasPrefix(clean, "/") {
				clean = "/" + clean
			}
			base := strings.TrimRight(clean, "/")
			if base == "" {
				report.Issues = append(report.Issues, AuditIssue{
					Code:        "RW-A029",
					Severity:    SeverityCritical,
					Title:       "Dangerous Root Honeypot Trap Path",
					Message:     fmt.Sprintf("honeypotTrapPath %q resolves to the root path ('/'). This will cause legitimate root requests to be blocked and clients to be banned.", trap),
					Pattern:     trap,
					Field:       "honeypotTrapPaths",
					Remediation: "Do not set honeypot trap path to '/'. Use an obscure path that is only linked via hidden crawler traps (e.g. '/trap/spider').",
				})
			}
		}
	}

	// ── Rule RW-A030: Search Engine Verification Advisory ───────────────────
	if cfg.BlockAIBots && !cfg.VerifySearchEngineBots {
		report.Issues = append(report.Issues, AuditIssue{
			Code:        "RW-A030",
			Severity:    SeverityInfo,
			Title:       "Missing Search Engine FCrDNS Verification",
			Message:     "AI bot defense is active ('blockAIBots: true') but search engine bot verification ('verifySearchEngineBots') is disabled. Search engine crawlers (Googlebot, Bingbot, Yandex, etc.) may be blocked or spoofed.",
			Field:       "verifySearchEngineBots",
			Remediation: "Enable 'verifySearchEngineBots: true' to perform reverse DNS (FCrDNS) verification for legitimate search engine crawlers while blocking impostors.",
		})
	}

	report.finalize(false)
	return report
}

func isValidBanDuration(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" {
		return true
	}
	if dur, err := time.ParseDuration(d); err == nil && dur > 0 {
		return true
	}
	if secs, err := strconv.ParseInt(d, 10, 64); err == nil && secs > 0 {
		return true
	}
	return false
}

func isValidIPOrCIDR(v string) bool {
	v = strings.TrimSpace(v)
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = host
	}
	v = strings.Trim(v, "[]")
	if idx := strings.IndexByte(v, '%'); idx != -1 {
		v = v[:idx]
	}
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
						Version:        "5.5.0", // tool version
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
