package observability

import (
	"strings"
	"testing"
)

func TestToCombinedLog(t *testing.T) {
	// JSON log event
	jsonLine := `{"time":"2026-10-17T12:00:00Z","client_ip":"198.51.100.42","method":"POST","path":"/login?user=\"admin\"","verdict":"BLOCK","rule":"sqli-detect","status_code":403}`
	combined := toCombinedLog(jsonLine)
	if combined == "" {
		t.Fatalf("expected non-empty combined log line, got empty string")
	}

	// Verify IP
	if !strings.HasPrefix(combined, "198.51.100.42 ") {
		t.Errorf("expected IP 198.51.100.42, got %s", combined)
	}
	// Verify method and sanitized path
	if !strings.Contains(combined, `"POST /login?user=%22admin%22 HTTP/1.1"`) {
		t.Errorf("expected escaped quotes in path, got %s", combined)
	}
	// Verify status
	if !strings.Contains(combined, " 403 0 ") {
		t.Errorf("expected status code 403, got %s", combined)
	}
	// Verify structured threat verdict in user-agent
	if !strings.Contains(combined, `"[BLOCK: sqli-detect]"`) {
		t.Errorf("expected [BLOCK: sqli-detect] in user-agent, got %s", combined)
	}

	// Test TARPIT verdict
	tarpitLine := `{"time":"2026-10-17T12:00:01Z","client_ip":"198.51.100.43","method":"GET","path":"/api/scan","verdict":"TARPIT","rule":"slow-bot"}`
	tarpitCombined := toCombinedLog(tarpitLine)
	if !strings.Contains(tarpitCombined, `"[TARPIT: slow-bot]"`) || !strings.Contains(tarpitCombined, " 429 0 ") {
		t.Errorf("expected [TARPIT: slow-bot] with 429 status, got %s", tarpitCombined)
	}

	// Test clean ALLOW verdict
	cleanLine := `{"time":"2026-10-17T12:00:02Z","client_ip":"198.51.100.44","method":"GET","path":"/home","verdict":"ALLOW"}`
	cleanCombined := toCombinedLog(cleanLine)
	if !strings.Contains(cleanCombined, `"RouteWarden/1.5 (Clean)"`) || !strings.Contains(cleanCombined, " 200 0 ") {
		t.Errorf("expected clean allow format, got %s", cleanCombined)
	}

	// Arbitrary debug text should be dropped
	debugLine := "[DEBUG] connecting to redis on 127.0.0.1:6379"
	if res := toCombinedLog(debugLine); res != "" {
		t.Errorf("expected debug line to be dropped, got %s", res)
	}
}
