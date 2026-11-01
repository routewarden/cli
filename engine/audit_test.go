package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditConfig_CleanConfig(t *testing.T) {
	cfg := CreateConfig()
	cfg.BlockPatterns = []string{`(?i)\.env`, `(?i)\.git`}
	cfg.AllowPatterns = []string{`(?i)^/api/v1/health`}
	cfg.AllowedIPs = []string{"127.0.0.1", "10.0.0.0/8"}
	cfg.TrustedProxies = []string{"172.16.0.0/12"}

	report := AuditConfig(cfg, "routewarden.json")
	if !report.Passed {
		t.Errorf("expected clean config to pass audit, got failures: %+v", report.Issues)
	}
	if report.CriticalCount != 0 {
		t.Errorf("expected 0 critical issues, got %d", report.CriticalCount)
	}
	if report.SecurityScore < 80 {
		t.Errorf("expected security score >= 80, got %d", report.SecurityScore)
	}

	sarifBytes, err := report.ToSARIF()
	if err != nil {
		t.Fatalf("ToSARIF failed: %v", err)
	}
	if len(sarifBytes) == 0 {
		t.Fatal("empty SARIF output")
	}
}

func TestAuditConfig_DetectFlaws(t *testing.T) {
	cfg := CreateConfig()
	cfg.Enabled = false // RW-A001
	cfg.EnableDefaultPatterns = false
	cfg.BlockPatterns = []string{
		".*",           // RW-A003: universal block
		"/secret/.env", // RW-A005: unescaped dot
		"((a+)+)+",     // RW-A006: ReDoS
		".*",           // RW-A007: duplicate
		"(?i)[a-z",     // RW-A015: unclosed bracket regex syntax error
	}
	cfg.AllowPatterns = []string{
		".*", // RW-A004: universal allow
		".*", // RW-A008: duplicate allow
	}
	cfg.CheckBodyPatterns = []string{
		"((b+)+)+", // RW-A006: ReDoS in body pattern
		"dupBody",
		"dupBody", // RW-A008: duplicate body pattern
	}
	cfg.BlockUserAgents = []string{
		"(?i)[a-z", // RW-A015: unclosed bracket regex in blockUserAgents
	}
	cfg.AIBotProfile = "unsupported_profile"            // RW-A016: invalid profile
	cfg.BotDefenseLevel = "unsupported_level"           // RW-A017: invalid bot defense level
	cfg.AllowedASNs = []string{"AS13335", "AS_INVALID"} // RW-A018: missing asnDB, RW-A019: malformed ASN
	cfg.TrapBanDuration = "invalid_duration"            // RW-A020: invalid ban duration
	cfg.AllowedIPs = []string{"999.999.999.999"}        // RW-A009: malformed IP
	cfg.StatusCode = 999                                // RW-A011: invalid status code
	cfg.Mode = "invalidMode"                            // RW-A012: invalid mode

	report := AuditConfig(cfg, "malformed.json")
	if report.Passed {
		t.Error("expected malformed config to fail audit, but passed")
	}
	if report.CriticalCount == 0 {
		t.Error("expected critical issues to be detected")
	}

	foundCodes := make(map[string]bool)
	for _, issue := range report.Issues {
		foundCodes[issue.Code] = true
	}

	expectedCodes := []string{"RW-A001", "RW-A003", "RW-A004", "RW-A005", "RW-A006", "RW-A007", "RW-A008", "RW-A009", "RW-A011", "RW-A012", "RW-A015", "RW-A016", "RW-A017", "RW-A018", "RW-A019", "RW-A020", "RW-A021"}
	for _, code := range expectedCodes {
		if !foundCodes[code] {
			t.Errorf("expected audit issue %s to be flagged", code)
		}
	}
}

func TestAuditConfig_NilHandling(t *testing.T) {
	report := AuditConfig(nil, "")
	if report.Passed {
		t.Error("expected nil config to fail audit")
	}
	if report.CriticalCount != 1 || report.Issues[0].Code != "RW-A000" {
		t.Errorf("expected RW-A000 for nil config, got %+v", report.Issues)
	}
}

func TestAuditConfig_SARIFSerialization(t *testing.T) {
	cfg := CreateConfig()
	cfg.BlockPatterns = []string{".env"} // unescaped dot
	report := AuditConfig(cfg, "test.json")

	sarifBytes, err := report.ToSARIF()
	if err != nil {
		t.Fatalf("ToSARIF error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(sarifBytes, &parsed); err != nil {
		t.Fatalf("SARIF JSON parse error: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}
}

func TestAuditConfig_ResponseModeFieldValidation(t *testing.T) {
	cfg := CreateConfig()
	cfg.Mode = "valid_json" // will be invalid
	cfg.Response = &ResponseConfig{
		Mode: "nested_invalid_mode",
	}

	report := AuditConfig(cfg, "config.json")
	var flaggedFields []string
	for _, issue := range report.Issues {
		if issue.Code == "RW-A012" {
			flaggedFields = append(flaggedFields, issue.Field)
		}
	}

	if len(flaggedFields) != 2 {
		t.Fatalf("expected 2 RW-A012 issues for top-level and response.mode, got %d: %v", len(flaggedFields), flaggedFields)
	}
	if flaggedFields[0] != "mode" || flaggedFields[1] != "response.mode" {
		t.Errorf("expected fields [mode, response.mode], got %v", flaggedFields)
	}

	// Verify valid modes pass without RW-A012
	cfgClean := CreateConfig()
	cfgClean.Mode = "aiPoison"
	cfgClean.Response = &ResponseConfig{
		Mode: "markovTarpit",
	}
	cleanReport := AuditConfig(cfgClean, "clean.json")
	for _, issue := range cleanReport.Issues {
		if issue.Code == "RW-A012" {
			t.Errorf("unexpected RW-A012 issue for valid modes: %v", issue)
		}
	}
}

func TestAuditConfig_WildcardsAndUnescapedDots(t *testing.T) {
	// 1. (?i).* and ^/.*$ universal wildcards
	cfgWild := CreateConfig()
	cfgWild.BlockPatterns = []string{"(?i).*", "^/.*$"}
	cfgWild.AllowPatterns = []string{"(?i)^.*$", "/.*"}
	repWild := AuditConfig(cfgWild, "wildcards.json")

	rwa003Count := 0
	rwa004Count := 0
	for _, issue := range repWild.Issues {
		if issue.Code == "RW-A003" {
			rwa003Count++
		}
		if issue.Code == "RW-A004" {
			rwa004Count++
		}
	}
	if rwa003Count != 2 {
		t.Errorf("expected 2 RW-A003 issues for (?i).* and ^/.*$, got %d", rwa003Count)
	}
	if rwa004Count != 2 {
		t.Errorf("expected 2 RW-A004 issues for (?i)^.*$ and /.*, got %d", rwa004Count)
	}

	// 2. Pattern with both escaped and unescaped dots
	cfgDots := CreateConfig()
	cfgDots.BlockPatterns = []string{`(?i)\.env|config.json`}
	repDots := AuditConfig(cfgDots, "dots.json")
	hasRwa005 := false
	for _, issue := range repDots.Issues {
		if issue.Code == "RW-A005" {
			hasRwa005 = true
			break
		}
	}
	if !hasRwa005 {
		t.Errorf("expected RW-A005 to flag config.json even when pattern contains escaped \\.env")
	}
}

func TestAuditConfig_UniversalCIDRs(t *testing.T) {
	cfg := CreateConfig()
	cfg.AllowedIPs = []string{"0.0.0.0/0", "::/0", "192.168.1.50:8080"}
	cfg.TrustedProxies = []string{"0.0.0.0/0", "10.0.0.1:443"}

	rep := AuditConfig(cfg, "universal_cidrs.json")

	hasRwa022V4 := false
	hasRwa022V6 := false
	hasRwa023 := false
	hasRwa009 := false
	hasRwa010 := false

	for _, issue := range rep.Issues {
		if issue.Code == "RW-A022" && issue.Pattern == "0.0.0.0/0" {
			hasRwa022V4 = true
		}
		if issue.Code == "RW-A022" && issue.Pattern == "::/0" {
			hasRwa022V6 = true
		}
		if issue.Code == "RW-A023" && issue.Pattern == "0.0.0.0/0" {
			hasRwa023 = true
		}
		if issue.Code == "RW-A009" {
			hasRwa009 = true
		}
		if issue.Code == "RW-A010" {
			hasRwa010 = true
		}
	}

	if !hasRwa022V4 || !hasRwa022V6 {
		t.Errorf("expected RW-A022 for 0.0.0.0/0 and ::/0, got v4=%v v6=%v", hasRwa022V4, hasRwa022V6)
	}
	if !hasRwa023 {
		t.Errorf("expected RW-A023 for 0.0.0.0/0 in trustedProxies")
	}
	if hasRwa009 {
		t.Errorf("did not expect RW-A009 error for 192.168.1.50:8080 (port should be stripped cleanly)")
	}
	if hasRwa010 {
		t.Errorf("did not expect RW-A010 error for 10.0.0.1:443 (port should be stripped cleanly)")
	}
}

func TestAuditConfig_UserAgentAudit(t *testing.T) {
	cfg := CreateConfig()
	cfg.BlockUserAgents = []string{`(?i)(badbot+)+`, `badbot1`, `badbot1`}
	cfg.AllowUserAgents = []string{`goodbot1`, `goodbot1`}

	rep := AuditConfig(cfg, "ua_audit.json")

	hasReDoS := false
	hasDupBlockUA := false
	hasDupAllowUA := false

	for _, issue := range rep.Issues {
		if issue.Code == "RW-A006" && strings.Contains(issue.Pattern, "badbot") {
			hasReDoS = true
		}
		if issue.Code == "RW-A007" && issue.Field == "blockUserAgents" {
			hasDupBlockUA = true
		}
		if issue.Code == "RW-A008" && issue.Field == "allowUserAgents" {
			hasDupAllowUA = true
		}
	}

	if !hasReDoS {
		t.Errorf("expected RW-A006 ReDoS alert for blockUserAgents nested quantifier")
	}
	if !hasDupBlockUA {
		t.Errorf("expected RW-A007 duplicate alert for blockUserAgents")
	}
	if !hasDupAllowUA {
		t.Errorf("expected RW-A008 duplicate alert for allowUserAgents")
	}
}

func TestAuditConfig_CaseSensitiveBlockPattern(t *testing.T) {
	cfg := CreateConfig()
	cfg.BlockPatterns = []string{`^/admin/.*`, `(?i)^/secret/.*`}

	rep := AuditConfig(cfg, "case_audit.json")

	hasRwa024 := false
	for _, issue := range rep.Issues {
		if issue.Code == "RW-A024" && issue.Pattern == `^/admin/.*` {
			hasRwa024 = true
		}
		if issue.Code == "RW-A024" && issue.Pattern == `(?i)^/secret/.*` {
			t.Errorf("did not expect RW-A024 for pattern with (?i)")
		}
	}

	if !hasRwa024 {
		t.Errorf("expected RW-A024 case-sensitive warning for ^/admin/.*")
	}
}

func TestAuditConfig_HTTPMethodsValidation(t *testing.T) {
	cfg := CreateConfig()
	cfg.Methods = []string{"get", "CUSTOM_VERB", ""}

	rep := AuditConfig(cfg, "methods_audit.json")

	hasLower := false
	hasCustom := false
	hasEmpty := false

	for _, issue := range rep.Issues {
		if issue.Code == "RW-A025" {
			if strings.Contains(issue.Title, "Lowercase") {
				hasLower = true
			}
			if strings.Contains(issue.Title, "Unrecognized") {
				hasCustom = true
			}
			if strings.Contains(issue.Title, "Empty") {
				hasEmpty = true
			}
		}
	}

	if !hasLower {
		t.Errorf("expected RW-A025 lowercase method warning for 'get'")
	}
	if !hasCustom {
		t.Errorf("expected RW-A025 unrecognized method warning for 'CUSTOM_VERB'")
	}
	if !hasEmpty {
		t.Errorf("expected RW-A025 empty method warning")
	}
}

func TestAuditConfig_BodyInspectionWithoutMutationMethods(t *testing.T) {
	cfg := CreateConfig()
	cfg.CheckBody = true
	cfg.Methods = []string{"GET", "HEAD"}

	rep := AuditConfig(cfg, "body_methods_audit.json")

	hasRwa026 := false
	for _, issue := range rep.Issues {
		if issue.Code == "RW-A026" {
			hasRwa026 = true
			break
		}
	}

	if !hasRwa026 {
		t.Errorf("expected RW-A026 warning when checkBody is true but methods contains only read-only verbs")
	}
}

func TestAuditConfig_CheckHeadersValidation(t *testing.T) {
	cfg := CreateConfig()
	cfg.CheckHeaders = []string{"X-Header: value", "Invalid Header Name", ""}

	rep := AuditConfig(cfg, "headers_audit.json")

	hasColon := false
	hasInvalidToken := false
	hasEmpty := false

	for _, issue := range rep.Issues {
		if issue.Code == "RW-A027" {
			if strings.Contains(issue.Title, "Colon") {
				hasColon = true
			}
			if strings.Contains(issue.Title, "Token") {
				hasInvalidToken = true
			}
			if strings.Contains(issue.Title, "Empty") {
				hasEmpty = true
			}
		}
	}

	if !hasColon {
		t.Errorf("expected RW-A027 critical error for header with colon")
	}
	if !hasInvalidToken {
		t.Errorf("expected RW-A027 warning for header with space")
	}
	if !hasEmpty {
		t.Errorf("expected RW-A027 warning for empty header name")
	}
}

func TestAuditConfig_CheckBodyMaxBytesValidation(t *testing.T) {
	cfgNegative := CreateConfig()
	cfgNegative.CheckBodyMaxBytes = -50
	repNeg := AuditConfig(cfgNegative, "neg_bytes.json")

	hasNeg := false
	for _, issue := range repNeg.Issues {
		if issue.Code == "RW-A028" && issue.Severity == SeverityCritical {
			hasNeg = true
			break
		}
	}
	if !hasNeg {
		t.Errorf("expected RW-A028 critical issue for negative checkBodyMaxBytes")
	}

	cfgExcessive := CreateConfig()
	cfgExcessive.CheckBodyMaxBytes = 50 * 1024 * 1024 // 50MB
	repExcessive := AuditConfig(cfgExcessive, "excessive_bytes.json")

	hasExcessive := false
	for _, issue := range repExcessive.Issues {
		if issue.Code == "RW-A028" && issue.Severity == SeverityWarning {
			hasExcessive = true
			break
		}
	}
	if !hasExcessive {
		t.Errorf("expected RW-A028 warning for excessive checkBodyMaxBytes (>10MB)")
	}
}

func TestAuditConfig_HoneypotTrapPathValidation(t *testing.T) {
	cfg := CreateConfig()
	cfg.HoneypotTrapPaths = []string{"", "   ", "/", "///", "/valid-trap"}
	rep := AuditConfig(cfg, "honeypot_audit.json")

	hasEmptyWarning := false
	hasRootCritical := false

	for _, issue := range rep.Issues {
		if issue.Code == "RW-A029" {
			if issue.Severity == SeverityWarning && issue.Title == "Empty Honeypot Trap Path" {
				hasEmptyWarning = true
			}
			if issue.Severity == SeverityCritical && issue.Title == "Dangerous Root Honeypot Trap Path" {
				hasRootCritical = true
			}
		}
	}

	if !hasEmptyWarning {
		t.Errorf("expected RW-A029 warning for empty honeypot trap path")
	}
	if !hasRootCritical {
		t.Errorf("expected RW-A029 critical issue for root honeypot trap path ('/')")
	}
}
