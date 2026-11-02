package engine

import (
	"strings"
	"testing"
	"time"
)

func TestRobotsHoneypot_TokenGeneration(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	token1 := GetRobotsHoneypotToken("secret123", fixedTime)
	token2 := GetRobotsHoneypotToken("secret123", fixedTime)
	if token1 != token2 {
		t.Fatalf("expected deterministic token, got %q vs %q", token1, token2)
	}

	if len(token1) != 12 {
		t.Fatalf("expected 12-char token, got %q (len %d)", token1, len(token1))
	}

	// Different secret should yield different token
	tokenDiffSecret := GetRobotsHoneypotToken("other-secret", fixedTime)
	if token1 == tokenDiffSecret {
		t.Fatalf("expected different token for different secret, got %q", tokenDiffSecret)
	}

	// Default secret should work when secret is empty
	tokenDefault := GetRobotsHoneypotToken("", fixedTime)
	if tokenDefault == "" {
		t.Fatal("expected non-empty token for default secret")
	}

	// Different day should yield different token
	nextDay := fixedTime.Add(24 * time.Hour)
	tokenNextDay := GetRobotsHoneypotToken("secret123", nextDay)
	if token1 == tokenNextDay {
		t.Fatalf("expected different token for next day, got %q", tokenNextDay)
	}
}

func TestRobotsHoneypot_ActiveTraps(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	activeTrap, validPrefixes := GetActiveRobotsHoneypotTraps("mysecret", fixedTime)

	if !strings.HasPrefix(activeTrap, "/_rw_trap_") || !strings.HasSuffix(activeTrap, "/") {
		t.Fatalf("unexpected activeTrap format: %q", activeTrap)
	}

	if len(validPrefixes) != 2 {
		t.Fatalf("expected 2 active prefixes (today and yesterday), got %d", len(validPrefixes))
	}

	todayToken := GetRobotsHoneypotToken("mysecret", fixedTime)
	yesterdayToken := GetRobotsHoneypotToken("mysecret", fixedTime.Add(-24*time.Hour))

	expectedTodayPrefix := "/_rw_trap_" + todayToken
	expectedYesterdayPrefix := "/_rw_trap_" + yesterdayToken

	if validPrefixes[0] != expectedTodayPrefix || validPrefixes[1] != expectedYesterdayPrefix {
		t.Fatalf("unexpected validPrefixes: %v (expected %s and %s)", validPrefixes, expectedTodayPrefix, expectedYesterdayPrefix)
	}
}

func TestRobotsHoneypot_IsRobotsTxtPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/robots.txt", true},
		{"/robots.txt/", true},
		{"/ROBOTS.TXT", true},
		{" /robots.txt ", true},
		{"/robots.txt.bak", false},
		{"/robots.txt?query=1", false},
		{"/api/robots.txt", false},
		{"/", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsRobotsTxtPath(tt.path); got != tt.want {
			t.Errorf("IsRobotsTxtPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRobotsHoneypot_InjectRobotsTxtTrap(t *testing.T) {
	activeTrap := "/_rw_trap_f8a3e9c1/"

	// Case 1: Empty upstream body
	injectedEmpty := string(InjectRobotsTxtTrap(nil, activeTrap))
	if !strings.Contains(injectedEmpty, "User-agent: *\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("unexpected empty injection: %q", injectedEmpty)
	}

	// Case 2: Existing upstream body without trailing newline
	origBody := "User-agent: Googlebot\nDisallow: /admin"
	injected := string(InjectRobotsTxtTrap([]byte(origBody), activeTrap))
	if !strings.HasPrefix(injected, origBody) {
		t.Fatalf("original body was not preserved: %q", injected)
	}
	if !strings.Contains(injected, "\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("missing injected disallow: %q", injected)
	}
}

func TestRobotsHoneypot_EngineIntegration(t *testing.T) {
	cfg := CreateConfig()
	cfg.EnableRobotsTxtHoneypot = true
	cfg.RobotsTxtHoneypotSecret = "integration-secret"
	cfg.TrapBanDuration = "1h"

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if engine.BanTable == nil {
		t.Fatal("expected BanTable to be initialized when EnableRobotsTxtHoneypot is true")
	}

	now := time.Now()
	activeTrap, validPrefixes := GetActiveRobotsHoneypotTraps(cfg.RobotsTxtHoneypotSecret, now)

	// 1. Request to /robots.txt -> Allowed and InjectedRobotsTxt populated
	resRobots := engine.EvaluateWithClientIP("GET", "/robots.txt", "", nil, "203.0.113.10")
	if !resRobots.Allowed {
		t.Fatalf("expected /robots.txt to be allowed, got blocked: %s", resRobots.Reason)
	}
	if !strings.Contains(resRobots.InjectedRobotsTxt, activeTrap) {
		t.Fatalf("expected InjectedRobotsTxt to contain %q, got %q", activeTrap, resRobots.InjectedRobotsTxt)
	}

	// 2. Request to today's dynamic trap path -> Blocked with honeypot_trap_triggered and IP banned
	todayTrapURI := validPrefixes[0] + "/deep/scraper-target.html"
	clientIP := "198.51.100.55"
	resTrap := engine.EvaluateWithClientIP("GET", todayTrapURI, "", nil, clientIP)
	if resTrap.Allowed || !resTrap.Blocked {
		t.Fatalf("expected trap request to be blocked, got allowed=%v", resTrap.Allowed)
	}
	if resTrap.Reason != "honeypot_trap_triggered" {
		t.Fatalf("expected reason honeypot_trap_triggered, got %q", resTrap.Reason)
	}

	// 3. Subsequent request from the banned IP to a normal route -> Blocked with ip_banned
	resBanned := engine.EvaluateWithClientIP("GET", "/index.html", "", nil, clientIP)
	if resBanned.Allowed || !resBanned.Blocked {
		t.Fatal("expected banned client IP to be blocked on subsequent request")
	}
	if resBanned.Reason != "ip_banned" {
		t.Fatalf("expected reason ip_banned, got %q", resBanned.Reason)
	}

	// 4. Request from a different IP to yesterday's rollover trap prefix -> Also blocked and banned
	yesterdayTrapURI := validPrefixes[1] + "/"
	otherIP := "198.51.100.66"
	resYesterday := engine.EvaluateWithClientIP("GET", yesterdayTrapURI, "", nil, otherIP)
	if resYesterday.Allowed || !resYesterday.Blocked {
		t.Fatalf("expected yesterday's trap to be blocked, got allowed=%v", resYesterday.Allowed)
	}
	if resYesterday.Reason != "honeypot_trap_triggered" {
		t.Fatalf("expected reason honeypot_trap_triggered, got %q", resYesterday.Reason)
	}

	// 5. Clean request from third unbanned IP -> Allowed
	resClean := engine.EvaluateWithClientIP("GET", "/index.html", "", nil, "198.51.100.77")
	if !resClean.Allowed {
		t.Fatalf("expected clean request to be allowed, got blocked: %s", resClean.Reason)
	}
}
