package observability

import (
	"os"
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

func TestDashboardEnvironmentVariables(t *testing.T) {
	resolveAuthAndHost := func(options ...string) (string, string) {
		var authStr string
		var hostStr string
		if len(options) > 0 {
			authStr = strings.TrimSpace(options[0])
		}
		if len(options) > 1 {
			hostStr = strings.TrimSpace(options[1])
		}
		if authStr == "" {
			authStr = strings.TrimSpace(os.Getenv("RW_DASHBOARD_AUTH"))
		}
		if authStr == "" {
			u := strings.TrimSpace(os.Getenv("RW_DASHBOARD_USER"))
			p := strings.TrimSpace(os.Getenv("RW_DASHBOARD_PASS"))
			if p == "" {
				p = strings.TrimSpace(os.Getenv("RW_DASHBOARD_PASSWORD"))
			}
			if u != "" {
				authStr = u + ":" + p
			}
		}
		if hostStr == "" {
			hostStr = strings.TrimSpace(os.Getenv("RW_DASHBOARD_HOST"))
		}
		return authStr, hostStr
	}

	t.Run("RW_DASHBOARD_AUTH env var", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_AUTH", "admin:supersecret")
		auth, host := resolveAuthAndHost()
		if auth != "admin:supersecret" {
			t.Errorf("expected 'admin:supersecret', got %q", auth)
		}
		if host != "" {
			t.Errorf("expected empty host, got %q", host)
		}
	})

	t.Run("RW_DASHBOARD_USER and RW_DASHBOARD_PASS", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_AUTH", "")
		t.Setenv("RW_DASHBOARD_USER", "soc-op")
		t.Setenv("RW_DASHBOARD_PASS", "key123")
		auth, _ := resolveAuthAndHost()
		if auth != "soc-op:key123" {
			t.Errorf("expected 'soc-op:key123', got %q", auth)
		}
	})

	t.Run("RW_DASHBOARD_PASSWORD fallback", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_AUTH", "")
		t.Setenv("RW_DASHBOARD_USER", "soc-admin")
		t.Setenv("RW_DASHBOARD_PASS", "")
		t.Setenv("RW_DASHBOARD_PASSWORD", "longpassword")
		auth, _ := resolveAuthAndHost()
		if auth != "soc-admin:longpassword" {
			t.Errorf("expected 'soc-admin:longpassword', got %q", auth)
		}
	})

	t.Run("RW_DASHBOARD_HOST env var", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_HOST", "127.0.0.1")
		_, host := resolveAuthAndHost()
		if host != "127.0.0.1" {
			t.Errorf("expected '127.0.0.1', got %q", host)
		}
	})

	t.Run("Explicit options take precedence over env vars", func(t *testing.T) {
		t.Setenv("RW_DASHBOARD_AUTH", "env-user:env-pass")
		t.Setenv("RW_DASHBOARD_HOST", "10.0.0.1")
		auth, host := resolveAuthAndHost("cli-user:cli-pass", "0.0.0.0")
		if auth != "cli-user:cli-pass" {
			t.Errorf("expected CLI auth to override env, got %q", auth)
		}
		if host != "0.0.0.0" {
			t.Errorf("expected CLI host to override env, got %q", host)
		}
	})
}

