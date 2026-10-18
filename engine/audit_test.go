package engine

import (
	"encoding/json"
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
	}
	cfg.AllowPatterns = []string{
		".*", // RW-A004: universal allow
	}
	cfg.AllowedIPs = []string{"999.999.999.999"} // RW-A009: malformed IP
	cfg.StatusCode = 999                         // RW-A011: invalid status code
	cfg.Mode = "invalidMode"                     // RW-A012: invalid mode

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

	expectedCodes := []string{"RW-A001", "RW-A003", "RW-A004", "RW-A005", "RW-A006", "RW-A007", "RW-A009", "RW-A011", "RW-A012"}
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
