package engine

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPoW_CountLeadingZeroBits(t *testing.T) {
	tests := []struct {
		data     []byte
		expected int
	}{
		{[]byte{0x00, 0x00}, 16},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x40}, 9},
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x80}, 0},
		{[]byte{0x40}, 1},
		{[]byte{0x20}, 2},
		{[]byte{0x10}, 3},
		{[]byte{0x08}, 4},
		{[]byte{0x04}, 5},
		{[]byte{0x02}, 6},
		{[]byte{0x01}, 7},
		{[]byte{0x00}, 8},
		{[]byte{}, 0},
	}

	for _, tc := range tests {
		actual := CountLeadingZeroBits(tc.data)
		if actual != tc.expected {
			t.Errorf("CountLeadingZeroBits(%x): expected %d, got %d", tc.data, tc.expected, actual)
		}
	}
}

func TestPoW_NormalizePoWIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"fe80::1%eth0", "fe80::1"},
	}

	for _, tc := range tests {
		actual := NormalizePoWIP(tc.input)
		if actual != tc.expected {
			t.Errorf("NormalizePoWIP(%q): expected %q, got %q", tc.input, tc.expected, actual)
		}
	}
}

func TestPoW_ChallengeGenerationAndStatelessVerification(t *testing.T) {
	clientIP := "203.0.113.42"
	secret := "test-pow-secret-key-12345"
	difficulty := 10 // Quick for test execution (~1,024 iterations)
	now := time.Now()

	challenge, err := GeneratePoWChallenge(clientIP, secret, difficulty, now)
	if err != nil {
		t.Fatalf("GeneratePoWChallenge failed: %v", err)
	}

	parts := strings.Split(challenge, ".")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts in challenge, got %d (%s)", len(parts), challenge)
	}

	// 1. Solve challenge
	nonce := SolvePoW(challenge, difficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	// 2. Verify valid solution
	valid, reason := VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(10*time.Second))
	if !valid {
		t.Fatalf("expected solution to verify successfully, failed with: %s", reason)
	}

	// 3. Reject if client IP is spoofed / solved by another IP
	valid, reason = VerifyPoWSolution("198.51.100.99", secret, solution, 300, now.Add(10*time.Second))
	if valid || reason != "invalid_pow_signature" {
		t.Errorf("expected rejection for IP mismatch, got valid=%v, reason=%s", valid, reason)
	}

	// 4. Reject if secret is wrong
	valid, reason = VerifyPoWSolution(clientIP, "wrong-secret", solution, 300, now.Add(10*time.Second))
	if valid || reason != "invalid_pow_signature" {
		t.Errorf("expected rejection for wrong secret, got valid=%v, reason=%s", valid, reason)
	}

	// 5. Reject if expired
	valid, reason = VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(305*time.Second))
	if valid || reason != "expired_pow" {
		t.Errorf("expected rejection for expired solution, got valid=%v, reason=%s", valid, reason)
	}

	// 6. Reject if nonce is invalid (insufficient work)
	badSolution := fmt.Sprintf("%s.%d", challenge, nonce+1)
	valid, _ = VerifyPoWSolution(clientIP, secret, badSolution, 300, now.Add(10*time.Second))
	if valid {
		t.Errorf("expected rejection for bad nonce")
	}

	// 7. Reject malformed solution formats
	for _, malformed := range []string{"", "abc", "1.2.3", "1.2.3.4", "1.2.3.4.notanumber"} {
		valid, _ := VerifyPoWSolution(clientIP, secret, malformed, 300, now)
		if valid {
			t.Errorf("expected rejection for malformed solution %q", malformed)
		}
	}
}

func TestPoW_GeneratePoWHTML(t *testing.T) {
	html := GeneratePoWHTML("12345.16.abcd.ef01", 16, 300)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML doctype")
	}
	if !strings.Contains(html, "12345.16.abcd.ef01") {
		t.Errorf("expected HTML to contain challenge token")
	}
	if !strings.Contains(html, "__rw_pow") {
		t.Errorf("expected HTML to contain __rw_pow cookie injection")
	}
	if !strings.Contains(html, "crypto.subtle") {
		t.Errorf("expected HTML to use Web Crypto API")
	}
}

func TestPoW_EngineEvaluationBypass(t *testing.T) {
	cfg := &Config{
		Enabled:           true,
		BlockUserAgents:   []string{"^BadBot.*"},
		BlockPatterns:     []string{"^/admin.*"},
		HoneypotTrapPaths: []string{"/honeypot"},
		Response: &ResponseConfig{
			Mode:              "powChallenge",
			PoWDifficulty:     10, // Fast for unit testing
			PoWSecret:         "unit-test-pow-secret",
			PoWTimeoutSeconds: 300,
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	clientIP := "198.51.100.5"

	// 1. Request with blocked UA -> blocked with user_agent_blocked
	headersBlocked := map[string]string{
		"User-Agent": "BadBot/1.0",
	}
	resBlocked := engine.EvaluateWithBody(http.MethodGet, "/index.html", "", headersBlocked, clientIP, "")
	if resBlocked.Allowed || resBlocked.Reason != "user_agent_blocked" {
		t.Fatalf("expected BadBot to be blocked, got allowed=%v, reason=%s", resBlocked.Allowed, resBlocked.Reason)
	}

	// 2. Solve challenge for clientIP
	challenge, err := GeneratePoWChallenge(clientIP, cfg.Response.PoWSecret, cfg.Response.PoWDifficulty, time.Now())
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	nonce := SolvePoW(challenge, cfg.Response.PoWDifficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	// 3. Request with BadBot + valid __rw_pow cookie -> ALLOWED (pow_verified)
	headersCookie := map[string]string{
		"User-Agent": "BadBot/1.0",
		"Cookie":     fmt.Sprintf("session=xyz; __rw_pow=%s; theme=dark", solution),
	}
	resCookie := engine.EvaluateWithBody(http.MethodGet, "/index.html", "", headersCookie, clientIP, "")
	if !resCookie.Allowed || !resCookie.PoWVerified || resCookie.Reason != "pow_verified" {
		t.Fatalf("expected request with valid PoW cookie to be allowed, got allowed=%v, powVerified=%v, reason=%s",
			resCookie.Allowed, resCookie.PoWVerified, resCookie.Reason)
	}

	// 4. Request with BadBot + valid X-RW-PoW header -> ALLOWED (pow_verified)
	headersHeader := map[string]string{
		"User-Agent": "BadBot/1.0",
		"X-RW-PoW":   solution,
	}
	resHeader := engine.EvaluateWithBody(http.MethodGet, "/index.html", "", headersHeader, clientIP, "")
	if !resHeader.Allowed || !resHeader.PoWVerified || resHeader.Reason != "pow_verified" {
		t.Fatalf("expected request with valid X-RW-PoW header to be allowed, got allowed=%v, powVerified=%v, reason=%s",
			resHeader.Allowed, resHeader.PoWVerified, resHeader.Reason)
	}

	// 5. Protected path /admin/settings with BadBot + valid PoW -> ALLOWED (pow_verified)
	resAdmin := engine.EvaluateWithBody(http.MethodGet, "/admin/settings", "", headersCookie, clientIP, "")
	if !resAdmin.Allowed || !resAdmin.PoWVerified || resAdmin.Reason != "pow_verified" {
		t.Fatalf("expected protected path with valid PoW to be allowed, got allowed=%v, reason=%s", resAdmin.Allowed, resAdmin.Reason)
	}

	// 6. Hard IP ban MUST NOT be bypassed by PoW
	engine.BanTable.Ban(clientIP, 1*time.Hour)
	resBanned := engine.EvaluateWithBody(http.MethodGet, "/index.html", "", headersCookie, clientIP, "")
	if resBanned.Allowed || resBanned.Reason != "ip_banned" {
		t.Fatalf("expected banned IP to remain blocked despite valid PoW, got allowed=%v, reason=%s", resBanned.Allowed, resBanned.Reason)
	}

	// 7. Honeypot spider trap MUST NOT be bypassed by PoW
	freshIP := "198.51.100.88"
	freshChallenge, _ := GeneratePoWChallenge(freshIP, cfg.Response.PoWSecret, cfg.Response.PoWDifficulty, time.Now())
	freshNonce := SolvePoW(freshChallenge, cfg.Response.PoWDifficulty)
	freshSolution := fmt.Sprintf("%s.%d", freshChallenge, freshNonce)

	cfgHoneypot := &Config{
		Enabled:           true,
		HoneypotTrapPaths: []string{"/secret_trap/"},
		Response:          cfg.Response,
	}
	engineHoneypot, _ := NewEngine(cfgHoneypot)

	headersTrap := map[string]string{
		"User-Agent": "BadBot/1.0",
		"Cookie":     fmt.Sprintf("__rw_pow=%s", freshSolution),
	}
	resTrap := engineHoneypot.EvaluateWithBody(http.MethodGet, "/secret_trap/crawl", "", headersTrap, freshIP, "")
	if resTrap.Allowed || resTrap.Reason != "honeypot_trap_triggered" {
		t.Fatalf("expected honeypot trap to trigger and block despite valid PoW, got allowed=%v, reason=%s", resTrap.Allowed, resTrap.Reason)
	}
	if !engineHoneypot.BanTable.IsBanned(freshIP) {
		t.Fatalf("expected freshIP to be banned in BanTable after hitting honeypot trap")
	}
}

func TestPoW_AuditAndDiff(t *testing.T) {
	// Audit rule RW-A033
	cfgLow := &Config{
		Enabled: true,
		Response: &ResponseConfig{
			Mode:          "powChallenge",
			PoWDifficulty: 4, // Too low (<8)
		},
	}
	reportLow := AuditConfig(cfgLow, "low.json")
	hasLowIssue := false
	for _, iss := range reportLow.Issues {
		if iss.Code == "RW-A033" {
			hasLowIssue = true
			break
		}
	}
	if !hasLowIssue {
		t.Errorf("expected RW-A033 for powDifficulty=4")
	}

	cfgHigh := &Config{
		Enabled: true,
		Response: &ResponseConfig{
			Mode:          "powChallenge",
			PoWDifficulty: 30, // Too high (>24)
		},
	}
	reportHigh := AuditConfig(cfgHigh, "high.json")
	hasHighIssue := false
	for _, iss := range reportHigh.Issues {
		if iss.Code == "RW-A033" {
			hasHighIssue = true
			break
		}
	}
	if !hasHighIssue {
		t.Errorf("expected RW-A033 for powDifficulty=30")
	}

	// Valid difficulty
	cfgValid := &Config{
		Enabled: true,
		Response: &ResponseConfig{
			Mode:          "powChallenge",
			PoWDifficulty: 16,
		},
	}
	reportValid := AuditConfig(cfgValid, "valid.json")
	for _, iss := range reportValid.Issues {
		if iss.Code == "RW-A033" || iss.Code == "RW-A012" {
			t.Errorf("unexpected issue %s for valid PoW config", iss.Code)
		}
	}

	// Diffing
	diff := DiffConfigs(cfgLow, cfgValid, "low.json", "valid.json")
	if _, ok := diff.Properties["response.powDifficulty"]; !ok {
		t.Errorf("expected diff to capture response.powDifficulty")
	}

	// Generators
	yaml := cfgValid.GenerateTraefikYAML()
	if !strings.Contains(yaml, "mode: powChallenge") || !strings.Contains(yaml, "powDifficulty: 16") {
		t.Errorf("expected Traefik YAML to contain powChallenge and powDifficulty: %s", yaml)
	}
	caddy := cfgValid.GenerateCaddyfile()
	if !strings.Contains(caddy, "mode powChallenge") || !strings.Contains(caddy, "pow_difficulty 16") {
		t.Errorf("expected Caddyfile to contain powChallenge and pow_difficulty: %s", caddy)
	}
	lua := cfgValid.GenerateNginxLua()
	if !strings.Contains(lua, `mode = "powChallenge"`) || !strings.Contains(lua, `pow_difficulty = 16`) {
		t.Errorf("expected Nginx Lua to contain powChallenge and pow_difficulty: %s", lua)
	}
}
