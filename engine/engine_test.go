package engine_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestEngine_EvaluatePaths(t *testing.T) {
	cfg := engine.CreateConfig()
	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		query      string
		headers    map[string]string
		wantBlock  bool
		wantBypass bool
		wantAllow  bool
	}{
		{
			name:      "Block .env",
			method:    "GET",
			path:      "/.env",
			wantBlock: true,
		},
		{
			name:      "Block server.key",
			method:    "GET",
			path:      "/server.key",
			wantBlock: true,
		},
		{
			name:      "Block cert.pem",
			method:    "GET",
			path:      "/cert.pem",
			wantBlock: true,
		},
		{
			name:      "Block Dockerfile",
			method:    "GET",
			path:      "/Dockerfile",
			wantBlock: true,
		},
		{
			name:      "Block double-encoded traversal",
			method:    "GET",
			path:      "/static/%252e%252e/.env",
			wantBlock: true,
		},
		{
			name:      "Allow robots.txt override",
			method:    "GET",
			path:      "/robots.txt",
			wantAllow: true,
		},
		{
			name:       "Bypass POST when method filter is default GET",
			method:     "POST",
			path:       "/.env",
			wantBypass: true,
		},
		{
			name:      "Normal public path passes",
			method:    "GET",
			path:      "/public/index.html",
			wantAllow: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := eng.Evaluate(tc.method, tc.path, tc.query, tc.headers)
			if tc.wantBlock && !res.Blocked {
				t.Errorf("expected request to be blocked, got %+v", res)
			}
			if tc.wantBypass && !res.Bypassed {
				t.Errorf("expected request to be bypassed, got %+v", res)
			}
			if tc.wantAllow && (res.Blocked || res.Bypassed) {
				t.Errorf("expected request to pass, got %+v", res)
			}
		})
	}
}

func TestEngine_HeaderInspection(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.CheckHeaders = []string{"X-Forwarded-Uri"}
	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Clean header
	cleanRes := eng.Evaluate("GET", "/dashboard", "", map[string]string{
		"X-Forwarded-Uri": "/dashboard",
	})
	if cleanRes.Blocked {
		t.Errorf("expected clean header to pass, got blocked: %+v", cleanRes)
	}

	// Smuggled path in header
	smuggledRes := eng.Evaluate("GET", "/dashboard", "", map[string]string{
		"X-Forwarded-Uri": "/.env",
	})
	if !smuggledRes.Blocked {
		t.Errorf("expected smuggled header to be blocked, got %+v", smuggledRes)
	}
	if smuggledRes.Reason != "header_blocked" {
		t.Errorf("expected reason header_blocked, got %s", smuggledRes.Reason)
	}
}

func TestEngine_NewEngineEdgeCases(t *testing.T) {
	t.Run("Nil config uses default configuration", func(t *testing.T) {
		eng, err := engine.NewEngine(nil)
		if err != nil {
			t.Fatalf("expected nil config to succeed, got %v", err)
		}
		if eng == nil || eng.Config == nil {
			t.Fatal("expected non-nil engine and config")
		}
		res := eng.Evaluate("GET", "/.env", "", nil)
		if !res.Blocked {
			t.Fatalf("expected default engine to block /.env")
		}
	})

	t.Run("Invalid CIDR returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.AllowedIPs = []string{"999.999.999.999/24"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on invalid CIDR, got nil")
		}
	})

	t.Run("Invalid single IP returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.AllowedIPs = []string{"not-an-ip"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on invalid IP, got nil")
		}
	})

	t.Run("Invalid allow regex returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.AllowPatterns = []string{"[open-unclosed-regex"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on invalid allow regex, got nil")
		}
	})

	t.Run("Invalid top-level statusCode returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.StatusCode = 999
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on invalid status code, got nil")
		}
	})

	t.Run("Invalid response.mode returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{Mode: "unsupported_mode"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on invalid response mode, got nil")
		}
	})

	t.Run("Redirect mode without redirectUrl returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{Mode: "redirect"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error when redirectUrl is empty, got nil")
		}
	})

	t.Run("Proxy mode with invalid proxyUrl returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{Mode: "proxy", ProxyURL: "://bad-url"}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error when proxyUrl is invalid, got nil")
		}
	})

	t.Run("Invalid captcha provider returns error", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{
			Mode: "captcha",
			Captcha: &engine.CaptchaConfig{
				Provider: "unsupported_provider",
			},
		}
		_, err := engine.NewEngine(cfg)
		if err == nil {
			t.Fatal("expected error on unsupported captcha provider, got nil")
		}
	})

	t.Run("Top-level mode alias is normalized into Response.Mode", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Mode = "json"
		cfg.Response = nil
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatalf("expected NewEngine to succeed with top-level mode, got: %v", err)
		}
		if eng.Config.Response.Mode != "json" {
			t.Fatalf("expected Response.Mode to be 'json', got %q", eng.Config.Response.Mode)
		}
	})

	t.Run("All valid response.mode options compile and validate", func(t *testing.T) {
		validModes := []struct {
			mode        string
			redirectURL string
			proxyURL    string
			captcha     *engine.CaptchaConfig
		}{
			{mode: "text"},
			{mode: "json"},
			{mode: "html"},
			{mode: "captcha", captcha: &engine.CaptchaConfig{Provider: "turnstile"}},
			{mode: "redirect", redirectURL: "https://example.com/blocked"},
			{mode: "silentDrop"},
			{mode: "drop"},
			{mode: "gzipBomb"},
			{mode: "tarpit"},
			{mode: "fakeSuccess"},
			{mode: "rateLimit"},
			{mode: "rateLimitChallenge"},
			{mode: "proxy", proxyURL: "http://127.0.0.1:8080/honeypot"},
			{mode: "infiniteStream"},
			{mode: "garbagestream"},
			{mode: "xml"},
			{mode: "aiPoison"},
			{mode: "markovTarpit"},
		}

		for _, vm := range validModes {
			cfg := engine.CreateConfig()
			cfg.Response = &engine.ResponseConfig{
				Mode:        vm.mode,
				RedirectURL: vm.redirectURL,
				ProxyURL:    vm.proxyURL,
				Captcha:     vm.captcha,
			}
			eng, err := engine.NewEngine(cfg)
			if err != nil {
				t.Errorf("expected mode %q to be valid, got error: %v", vm.mode, err)
			}
			resolvedMode, _, _ := eng.Config.ResolveResponse()
			if resolvedMode != vm.mode {
				t.Errorf("expected resolvedMode %q, got %q", vm.mode, resolvedMode)
			}
		}
	})

	t.Run("ResolveResponse defaults status codes per mode", func(t *testing.T) {
		tests := []struct {
			mode           string
			topCode        int
			respCode       int
			expectedStatus int
		}{
			{mode: "gzipBomb", expectedStatus: 200},
			{mode: "bomb", expectedStatus: 200},
			{mode: "fakeSuccess", expectedStatus: 200},
			{mode: "decoy", expectedStatus: 200},
			{mode: "aiPoison", expectedStatus: 200},
			{mode: "poison", expectedStatus: 200},
			{mode: "markovTarpit", expectedStatus: 200},
			{mode: "rateLimitChallenge", expectedStatus: 429},
			{mode: "rateLimit", expectedStatus: 429},
			{mode: "backoff", expectedStatus: 429},
			{mode: "redirect", expectedStatus: 302},
			{mode: "text", expectedStatus: 403},
			{mode: "json", expectedStatus: 403},
			{mode: "html", expectedStatus: 403},
			{mode: "xml", expectedStatus: 403},
			// Explicit overrides
			{mode: "gzipBomb", respCode: 403, expectedStatus: 403},
			{mode: "gzipBomb", respCode: 418, expectedStatus: 418},
			{mode: "gzipBomb", topCode: 418, expectedStatus: 418},
		}

		for _, tc := range tests {
			cfg := engine.CreateConfig()
			if tc.topCode != 0 {
				cfg.StatusCode = tc.topCode
			}
			cfg.Response = &engine.ResponseConfig{
				Mode:       tc.mode,
				StatusCode: tc.respCode,
			}
			_, status, _ := cfg.ResolveResponse()
			if status != tc.expectedStatus {
				t.Errorf("mode %s (respCode=%d, topCode=%d): expected status %d, got %d",
					tc.mode, tc.respCode, tc.topCode, tc.expectedStatus, status)
			}
		}
	})
}

func TestEngine_EvaluateEdgeCases(t *testing.T) {
	t.Run("Disabled engine bypasses all checks", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Enabled = false
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res := eng.Evaluate("GET", "/.env", "", nil)
		if !res.Bypassed || res.Blocked {
			t.Fatalf("expected bypassed when enabled=false, got %+v", res)
		}
		if res.Reason != "middleware_disabled" {
			t.Fatalf("expected reason middleware_disabled, got %s", res.Reason)
		}
	})

	t.Run("Empty method defaults to GET", func(t *testing.T) {
		cfg := engine.CreateConfig()
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res := eng.Evaluate("", "/.env", "", nil)
		if !res.Blocked {
			t.Fatalf("expected empty method to default to GET and block /.env, got %+v", res)
		}
	})

	t.Run("Query inspection with checkQuery enabled", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.CheckQuery = true
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res := eng.Evaluate("GET", "/search", "target=../../.env", nil)
		if !res.Blocked {
			t.Fatalf("expected query string to be blocked, got %+v", res)
		}
		if res.Reason != "query_blocked" {
			t.Fatalf("expected reason query_blocked, got %s", res.Reason)
		}
	})
}

func TestEngine_ExtractCandidatePaths(t *testing.T) {
	tests := []struct {
		name       string
		rawPath    string
		pathStr    string
		requestURI string
		wantPaths  []string
	}{
		{
			name:       "Matrix parameters separated with semicolon",
			rawPath:    "",
			pathStr:    "/users;/admin",
			requestURI: "/users;/admin",
			wantPaths:  []string{"/users;/admin", "/users/admin"},
		},
		{
			name:       "Backslash paths converted to slash",
			rawPath:    "",
			pathStr:    `\admin\secrets`,
			requestURI: `\admin\secrets`,
			wantPaths:  []string{"/admin/secrets"},
		},
		{
			name:       "Null byte stripping",
			rawPath:    "",
			pathStr:    "/admin\x00/page",
			requestURI: "/admin\x00/page",
			wantPaths:  []string{"/admin/page"},
		},
		{
			name:       "NTFS Alternate Data Stream (::$DATA)",
			rawPath:    "",
			pathStr:    "/wp-config.php::$DATA",
			requestURI: "/wp-config.php::$DATA",
			wantPaths:  []string{"/wp-config.php"},
		},
		{
			name:       "Trailing dot on sensitive file extension",
			rawPath:    "",
			pathStr:    "/settings.py.",
			requestURI: "/settings.py.",
			wantPaths:  []string{"/settings.py"},
		},
		{
			name:       "Trailing dot on path segment",
			rawPath:    "",
			pathStr:    "/sub./.env",
			requestURI: "/sub./.env",
			wantPaths:  []string{"/sub/.env"},
		},
		{
			name:       "Absolute URI in requestURI",
			rawPath:    "",
			pathStr:    "/wp-config.php",
			requestURI: "http://example.com/wp-config.php",
			wantPaths:  []string{"/wp-config.php"},
		},
		{
			name:       "Absolute URI with Windows backslash",
			rawPath:    "",
			pathStr:    `http://example.com\.env`,
			requestURI: `http://example.com\.env`,
			wantPaths:  []string{"/.env"},
		},
		{
			name:       "Multi-layer encoded rawPath",
			rawPath:    "/%252e%252e/.env",
			pathStr:    "/public/test",
			requestURI: "/public/test",
			wantPaths:  []string{"/.env"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.ExtractCandidatePaths(tc.rawPath, tc.pathStr, tc.requestURI)
			for _, want := range tc.wantPaths {
				found := false
				for _, p := range got {
					if p == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("candidate paths missing %q, got: %v", want, got)
				}
			}
		})
	}
}

// TestPathNormalizer_EdgeCases covers edge cases P-1 through P-5 in CLI engine.
func TestPathNormalizer_EdgeCases(t *testing.T) {
	// P-1: Repeated percent signs (%%%%2eenv) – should not panic; result must be well-formed
	t.Run("P-1 repeated percent signs", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "/%%%%2eenv", "")
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for %%%%2eenv path")
		}
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("candidate %q does not start with '/'", c)
			}
		}
	})

	// P-2: Exact "/" path
	t.Run("P-2 exact root path", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "/", "")
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for '/'")
		}
		found := false
		for _, c := range candidates {
			if c == "/" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected '/' to be in candidates, got: %v", candidates)
		}
	})

	// P-3: Very long path (>16 KB) must not panic or OOM
	t.Run("P-3 very long path", func(t *testing.T) {
		longPath := "/" + string(make([]byte, 16*1024+1))
		for i := range longPath[1:] {
			longPath = longPath[:i+1] + "a" + longPath[i+2:]
		}
		candidates := engine.ExtractCandidatePaths("", longPath, "")
		if len(candidates) == 0 {
			t.Fatal("expected at least one candidate for very long path")
		}
	})

	// P-4: Unicode NFD path – normalizer must not panic; result must be well-formed
	t.Run("P-4 unicode NFC/NFD path", func(t *testing.T) {
		nfdPath := "/caf\u00e9/menu"
		candidates := engine.ExtractCandidatePaths("", nfdPath, "")
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("unicode candidate %q does not start with '/'", c)
			}
		}
	})

	// P-5: Path with embedded fragment (#anchor) – fragment must not pollute path candidates
	t.Run("P-5 embedded fragment", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "/api/v1#admin", "/api/v1#admin")
		foundBase := false
		for _, c := range candidates {
			if len(c) > 0 && c[0] != '/' {
				t.Errorf("fragment candidate %q does not start with '/'", c)
			}
			if c == "/api/v1" {
				foundBase = true
			}
		}
		if !foundBase {
			t.Errorf("expected candidates to contain stripped base path '/api/v1', got %v", candidates)
		}
	})

	// P-6: Malformed percent-encoding (%zz or trailing %) with multi-layer traversal
	t.Run("P-6 lenient multi-layer percent decoding", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "/%252e%252e/.env%zz", "/%252e%252e/.env%zz")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env%zz" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env%%zz', got %v", candidates)
		}

		cfg := engine.CreateConfig()
		cfg.BlockPatterns = []string{`(?i)(^|/)\.env($|[/?#])`}
		cfg.CheckQuery = true
		cfg.CheckBody = true
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatalf("failed to create engine: %v", err)
		}

		// Blocked via path
		res := eng.Evaluate("GET", "/%252e%252e/.env%zz", "", nil)
		if !res.Blocked {
			t.Errorf("expected /%%252e%%252e/.env%%zz to be blocked, got allowed")
		}

		// Blocked via query string with malformed percent-encoding
		resQuery := eng.Evaluate("GET", "/search", "target=/%252e%252e/.env%zz", nil)
		if !resQuery.Blocked {
			t.Errorf("expected query with /%%252e%%252e/.env%%zz to be blocked, got allowed")
		}

		// Blocked via body with malformed percent-encoding
		resBody := eng.EvaluateWithBody("POST", "/submit", "", nil, "127.0.0.1", "field=/%252e%252e/.env%zz")
		if !resBody.Blocked {
			t.Errorf("expected body with /%%252e%%252e/.env%%zz to be blocked, got allowed")
		}
	})

	// P-7: Quadruple percent-encoded traversal (/%2525252e%2525252e/.env)
	t.Run("P-7 quadruple percent-encoded traversal", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "/%2525252e%2525252e/.env", "/%2525252e%2525252e/.env")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env' after 4 unescaping passes, got %v", candidates)
		}
	})

	// P-8: Absolute URI with multi-layer percent-encoded traversal and backslashes
	t.Run("P-8 absolute URI with multi-layer traversal", func(t *testing.T) {
		candidates := engine.ExtractCandidatePaths("", "http://example.com/%252e%252e/.env", "http://example.com/%252e%252e/.env")
		foundEnv := false
		for _, c := range candidates {
			if c == "/.env" {
				foundEnv = true
				break
			}
		}
		if !foundEnv {
			t.Errorf("expected candidates to contain '/.env' from absolute URI, got %v", candidates)
		}

		// Verify evaluation blocks absolute URI targeting sensitive file
		cfg := engine.CreateConfig()
		cfg.EnableDefaultPatterns = true
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatalf("failed to create engine: %v", err)
		}
		res := eng.Evaluate("GET", "http://example.com/%252e%252e/.env", "", nil)
		if !res.Blocked {
			t.Errorf("expected absolute URI http://example.com/%%252e%%252e/.env to be blocked, got allowed")
		}

		// Also check absolute URI with backslash
		resBackslash := eng.Evaluate("GET", "http://example.com\\admin\\.env", "", nil)
		if !resBackslash.Blocked {
			t.Errorf("expected absolute URI http://example.com\\admin\\.env to be blocked, got allowed")
		}
	})
}

func TestEngine_CheckDockerInstalled(t *testing.T) {
	// CheckDockerInstalled should return an error or nil without panicking
	err := engine.CheckDockerInstalled()
	if err != nil {
		t.Logf("CheckDockerInstalled returned error (expected in environments without Docker or daemon running): %v", err)
	} else {
		t.Logf("Docker is installed and running")
	}
}

func TestEngine_GenerateSandboxConfig(t *testing.T) {
	cfg := engine.CreateConfig()
	for _, target := range []string{"traefik", "caddy", "nginx"} {
		conf, err := engine.GenerateSandboxConfig(target, cfg)
		if err != nil {
			t.Fatalf("[%s] unexpected error generating sandbox config: %v", target, err)
		}
		if len(conf) == 0 {
			t.Fatalf("[%s] generated sandbox config is empty", target)
		}
	}
	_, err := engine.GenerateSandboxConfig("unsupported", cfg)
	if err == nil {
		t.Fatalf("expected error for unsupported target")
	}
}

func TestEngine_GenerateTCPWardenYAML(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.AllowedIPs = []string{"192.168.1.0/24", "10.0.0.1"}

	out, err := cfg.Generate("tcp-warden")
	if err != nil {
		t.Fatalf("unexpected error generating tcp-warden config: %v", err)
	}

	if !strings.Contains(out, "services:") {
		t.Errorf("expected generated tcp-warden config to contain 'services:'")
	}
	if !strings.Contains(out, "192.168.1.0/24") {
		t.Errorf("expected generated tcp-warden config to contain allowed IP")
	}
	if !strings.Contains(out, "ssh:") || !strings.Contains(out, "smtp:") {
		t.Errorf("expected starter services in tcp-warden config")
	}
}

func TestEngine_TrustedProxies(t *testing.T) {
	// 1. Invalid CIDR in TrustedProxies
	cfgBadCIDR := engine.CreateConfig()
	cfgBadCIDR.TrustedProxies = []string{"999.999.999.999/24"}
	if _, err := engine.NewEngine(cfgBadCIDR); err == nil {
		t.Errorf("expected error for invalid trustedProxies CIDR")
	}

	// 2. Invalid IP in TrustedProxies
	cfgBadIP := engine.CreateConfig()
	cfgBadIP.TrustedProxies = []string{"not-an-ip"}
	if _, err := engine.NewEngine(cfgBadIP); err == nil {
		t.Errorf("expected error for invalid trustedProxies IP")
	}

	// 3. Evaluation with TrustedProxies
	cfg := engine.CreateConfig()
	cfg.AllowedIPs = []string{"192.168.1.50"}
	cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.1.1"}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Untrusted peer with spoofed XFF: must be blocked
	resUntrusted := eng.EvaluateWithClientIP("GET", "/.env", "", map[string]string{
		"X-Forwarded-For": "192.168.1.50",
	}, "198.51.100.20")
	if !resUntrusted.Blocked {
		t.Errorf("untrusted peer with spoofed XFF should be blocked, got: %+v", resUntrusted)
	}

	// Trusted proxy peer with valid forwarded IP: must be allowed
	resTrusted := eng.EvaluateWithClientIP("GET", "/.env", "", map[string]string{
		"X-Forwarded-For": "192.168.1.50",
	}, "10.0.1.1")
	if !resTrusted.Allowed || resTrusted.Reason != "ip_whitelisted" {
		t.Errorf("trusted proxy with forwarded whitelisted IP should be allowed, got: %+v", resTrusted)
	}

	// Trusted proxy peer with non-whitelisted forwarded IP: must be blocked
	resTrustedBlocked := eng.EvaluateWithClientIP("GET", "/.env", "", map[string]string{
		"X-Forwarded-For": "203.0.113.5",
	}, "10.0.1.1")
	if !resTrustedBlocked.Blocked {
		t.Errorf("trusted proxy with forwarded non-whitelisted IP should be blocked, got: %+v", resTrustedBlocked)
	}
}

func TestEngine_UnsafeRedirectAndProxyURLs(t *testing.T) {
	unsafeRedirects := []string{
		"//attacker.com/phish",
		"javascript:alert(1)",
		"ftp://example.com/evil",
		"data:text/html,<html>",
	}
	for _, u := range unsafeRedirects {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{
			Mode:        "redirect",
			RedirectURL: u,
		}
		if _, err := engine.NewEngine(cfg); err == nil {
			t.Errorf("expected error for unsafe redirectUrl %q, got nil", u)
		}
	}

	unsafeProxies := []string{
		"javascript:alert(1)",
		"ftp://internal.repo",
		"data:text/plain,hello",
	}
	for _, p := range unsafeProxies {
		cfg := engine.CreateConfig()
		cfg.Response = &engine.ResponseConfig{
			Mode:     "proxy",
			ProxyURL: p,
		}
		if _, err := engine.NewEngine(cfg); err == nil {
			t.Errorf("expected error for unsafe proxyUrl %q, got nil", p)
		}
	}
}

func TestEngine_GenerateWithTrustedProxies(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.AllowedIPs = []string{"192.168.1.50"}
	cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.1"}

	// Traefik YAML
	yamlOut, err := cfg.Generate("traefik-yaml")
	if err != nil {
		t.Fatalf("traefik-yaml generate failed: %v", err)
	}
	if !strings.Contains(yamlOut, "trustedProxies:") || !strings.Contains(yamlOut, "10.0.0.0/8") {
		t.Errorf("traefik-yaml missing trustedProxies: %s", yamlOut)
	}

	// Traefik TOML
	tomlOut, err := cfg.Generate("traefik-toml")
	if err != nil {
		t.Fatalf("traefik-toml generate failed: %v", err)
	}
	if !strings.Contains(tomlOut, "trustedProxies = [") || !strings.Contains(tomlOut, "10.0.0.0/8") {
		t.Errorf("traefik-toml missing trustedProxies: %s", tomlOut)
	}

	// Traefik Labels
	labelsOut, err := cfg.Generate("traefik-labels")
	if err != nil {
		t.Fatalf("traefik-labels generate failed: %v", err)
	}
	if !strings.Contains(labelsOut, "trustedProxies=") || !strings.Contains(labelsOut, "10.0.0.0/8") {
		t.Errorf("traefik-labels missing trustedProxies: %s", labelsOut)
	}

	// Caddyfile
	caddyOut, err := cfg.Generate("caddy")
	if err != nil {
		t.Fatalf("caddy generate failed: %v", err)
	}
	if !strings.Contains(caddyOut, "trusted_proxies 10.0.0.0/8") {
		t.Errorf("caddy missing trusted_proxies: %s", caddyOut)
	}

	// NGINX
	nginxOut, err := cfg.Generate("nginx")
	if err != nil {
		t.Fatalf("nginx generate failed: %v", err)
	}
	if !strings.Contains(nginxOut, "trusted_proxies = {") || !strings.Contains(nginxOut, "10.0.0.0/8") {
		t.Errorf("nginx missing trusted_proxies: %s", nginxOut)
	}
}

func TestEngine_CheckBody(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.Methods = []string{"POST"}
	cfg.CheckBody = true
	cfg.CheckBodyPatterns = []string{"(?i)grant_type=password"}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	// 1. Should block grant_type=password
	res1 := eng.EvaluateWithBody("POST", "/identity/connect/token", "", nil, "127.0.0.1", "grant_type=password&username=admin")
	if !res1.Blocked {
		t.Errorf("expected request body to be blocked")
	}
	if res1.Reason != "body_blocked" {
		t.Errorf("expected reason 'body_blocked', got %q", res1.Reason)
	}

	// 2. Should allow grant_type=send_access
	res2 := eng.EvaluateWithBody("POST", "/identity/connect/token", "", nil, "127.0.0.1", "grant_type=send_access")
	if res2.Blocked {
		t.Errorf("expected send_access request body to be allowed")
	}

	// 3. Fallback to BlockPatterns when CheckBodyPatterns is empty
	cfgFallback := engine.CreateConfig()
	cfgFallback.Methods = []string{"POST"}
	cfgFallback.CheckBody = true
	cfgFallback.BlockPatterns = []string{"(?i)sql_injection"}

	engFallback, err := engine.NewEngine(cfgFallback)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	res3 := engFallback.EvaluateWithBody("POST", "/api/submit", "", nil, "127.0.0.1", "payload=sql_injection")
	if !res3.Blocked {
		t.Errorf("expected request to be blocked by fallback BlockPatterns")
	}

	// 4. URL percent-encoded body payload check
	res4 := engFallback.EvaluateWithBody("POST", "/api/submit", "", nil, "127.0.0.1", "payload=sql%5Finjection")
	if !res4.Blocked {
		t.Errorf("expected URL-encoded request body to be detected and blocked")
	}

	// 5. Form parameter unpacking with end-anchored pattern
	cfgForm := engine.CreateConfig()
	cfgForm.Methods = []string{"POST"}
	cfgForm.CheckBody = true
	cfgForm.BlockPatterns = []string{`(?i)\.key$`}

	engForm, err := engine.NewEngine(cfgForm)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	// In raw form string "other=1&cert=server.key&final=ok", raw body ends in "ok", not ".key"
	res5 := engForm.EvaluateWithBody("POST", "/upload", "", nil, "127.0.0.1", "other=1&cert=server.key&final=ok")
	if !res5.Blocked {
		t.Errorf("expected form parameter server.key to be extracted and blocked by end-anchored pattern")
	}

	// 6. JSON payload unpacking with end-anchored pattern
	res6 := engForm.EvaluateWithBody("POST", "/upload", "", nil, "127.0.0.1", `{"config": {"private_key": "id_rsa.key"}, "status": "active"}`)
	if !res6.Blocked {
		t.Errorf("expected JSON string id_rsa.key to be extracted and blocked by end-anchored pattern")
	}
}

func TestEngine_GenerateWithCheckBody(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.CheckBody = true
	cfg.CheckBodyMaxBytes = 32768
	cfg.CheckBodyPatterns = []string{"(?i)grant_type=password"}

	// Traefik YAML
	yamlOut, err := cfg.Generate("traefik-yaml")
	if err != nil {
		t.Fatalf("traefik-yaml generate failed: %v", err)
	}
	if !strings.Contains(yamlOut, "checkBody: true") || !strings.Contains(yamlOut, "checkBodyMaxBytes: 32768") || !strings.Contains(yamlOut, "(?i)grant_type=password") {
		t.Errorf("traefik-yaml missing checkBody configurations: %s", yamlOut)
	}

	// Traefik TOML
	tomlOut, err := cfg.Generate("traefik-toml")
	if err != nil {
		t.Fatalf("traefik-toml generate failed: %v", err)
	}
	if !strings.Contains(tomlOut, "checkBody = true") || !strings.Contains(tomlOut, "checkBodyMaxBytes = 32768") || !strings.Contains(tomlOut, "(?i)grant_type=password") {
		t.Errorf("traefik-toml missing checkBody configurations: %s", tomlOut)
	}

	// Traefik Labels
	labelsOut, err := cfg.Generate("traefik-labels")
	if err != nil {
		t.Fatalf("traefik-labels generate failed: %v", err)
	}
	if !strings.Contains(labelsOut, "checkBody=true") || !strings.Contains(labelsOut, "checkBodyMaxBytes=32768") || !strings.Contains(labelsOut, "(?i)grant_type=password") {
		t.Errorf("traefik-labels missing checkBody configurations: %s", labelsOut)
	}

	// Caddyfile
	caddyOut, err := cfg.Generate("caddy")
	if err != nil {
		t.Fatalf("caddy generate failed: %v", err)
	}
	if !strings.Contains(caddyOut, "check_body") || !strings.Contains(caddyOut, "check_body_max_bytes 32768") || !strings.Contains(caddyOut, "check_body_patterns \"(?i)grant_type=password\"") {
		t.Errorf("caddy missing check_body configurations: %s", caddyOut)
	}

	// NGINX
	nginxOut, err := cfg.Generate("nginx")
	if err != nil {
		t.Fatalf("nginx generate failed: %v", err)
	}
	if !strings.Contains(nginxOut, "check_body = true") || !strings.Contains(nginxOut, "check_body_max_bytes = 32768") || !strings.Contains(nginxOut, "check_body_patterns = {") {
		t.Errorf("nginx missing check_body configurations: %s", nginxOut)
	}
}

func TestEngine_IPv4MappedIPv6Evaluation(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.AllowedIPs = []string{"192.168.1.0/24", "10.0.0.1"}
	cfg.TrustedProxies = []string{"172.16.0.0/12"}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// 1. Direct peer with IPv4-mapped IPv6 matching allowed CIDR
	res := eng.EvaluateWithClientIP("GET", "/.env", "", nil, "::ffff:192.168.1.55")
	if !res.Allowed || res.Reason != "ip_whitelisted" {
		t.Errorf("expected ::ffff:192.168.1.55 to be whitelisted via 192.168.1.0/24, got allowed=%v reason=%q", res.Allowed, res.Reason)
	}

	// 2. Direct peer with bracketed IPv6
	resBracket := eng.EvaluateWithClientIP("GET", "/.env", "", nil, "[::ffff:10.0.0.1]")
	if !resBracket.Allowed || resBracket.Reason != "ip_whitelisted" {
		t.Errorf("expected [::ffff:10.0.0.1] to be whitelisted, got allowed=%v reason=%q", resBracket.Allowed, resBracket.Reason)
	}

	// 3. Trusted proxy with IPv4-mapped IPv6 in XFF
	headers := map[string]string{
		"X-Forwarded-For": "::ffff:192.168.1.99",
	}
	resProxy := eng.EvaluateWithClientIP("GET", "/.env", "", headers, "172.16.5.10")
	if !resProxy.Allowed || resProxy.Reason != "ip_whitelisted" {
		t.Errorf("expected forwarded IPv4-mapped IP from trusted proxy to be whitelisted, got allowed=%v reason=%q", resProxy.Allowed, resProxy.Reason)
	}
}

func TestGenerate_SecurityBoundaries(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.Response = &engine.ResponseConfig{
		Mode:        "custom",
		StatusCode:  403,
		ContentType: "text/html; charset=utf-8",
		RedirectURL: "https://example.com/login?param=1&foo=bar",
		ProxyURL:    "http://127.0.0.1:8080/honeypot",
		Headers: map[string]string{
			"Server":               "RouteWarden Firewall v2.0",
			"X-Injected\r\nHeader": "evil-value\r\nInjected: 1",
		},
	}

	// 1. Caddyfile generator must quote strings with spaces and sanitize CRLF
	caddy := cfg.GenerateCaddyfile()
	if !strings.Contains(caddy, `content_type "text/html; charset=utf-8"`) {
		t.Errorf("expected quoted content_type in Caddyfile, got:\n%s", caddy)
	}
	if !strings.Contains(caddy, `header Server "RouteWarden Firewall v2.0"`) {
		t.Errorf("expected quoted header value with spaces in Caddyfile, got:\n%s", caddy)
	}
	if strings.Contains(caddy, "X-Injected\r\n") || strings.Contains(caddy, "X-Injected\n") {
		t.Errorf("expected header key with CRLF to be sanitized in Caddyfile, got:\n%s", caddy)
	}
	if !strings.Contains(caddy, `header X-InjectedHeader "evil-value\r\nInjected: 1"`) {
		t.Errorf("expected sanitized header key and escaped value in Caddyfile, got:\n%s", caddy)
	}

	// 2. Traefik YAML generator must sanitize header keys
	traefik := cfg.GenerateTraefikYAML()
	if strings.Contains(traefik, "X-Injected\r\n") || strings.Contains(traefik, "X-Injected\n") {
		t.Errorf("expected header key with CRLF to be sanitized in Traefik YAML, got:\n%s", traefik)
	}
	if !strings.Contains(traefik, `X-InjectedHeader: "evil-value\r\nInjected: 1"`) {
		t.Errorf("expected sanitized header key and escaped value in Traefik YAML, got:\n%s", traefik)
	}

	// 3. Traefik TOML generator must sanitize header keys
	toml := cfg.GenerateTraefikTOML()
	if strings.Contains(toml, "X-Injected\r\n") || strings.Contains(toml, "X-Injected\n") {
		t.Errorf("expected header key with CRLF to be sanitized in Traefik TOML, got:\n%s", toml)
	}
	if strings.Contains(toml, "\revil-value") || strings.Contains(toml, "\nevil-value") {
		t.Errorf("expected header value with CRLF to be sanitized in Traefik TOML, got:\n%s", toml)
	}

	// 4. Traefik Labels generator must sanitize header keys
	labels := cfg.GenerateTraefikLabels()
	if strings.Contains(labels, "X-Injected\r\n") || strings.Contains(labels, "X-Injected\n") {
		t.Errorf("expected header key with CRLF to be sanitized in Traefik Labels, got:\n%s", labels)
	}

	// 5. Nginx Lua generator must sanitize header keys
	nginx := cfg.GenerateNginxLua()
	if strings.Contains(nginx, "X-Injected\r\n") || strings.Contains(nginx, "X-Injected\n") {
		t.Errorf("expected header key with CRLF to be sanitized in Nginx Lua, got:\n%s", nginx)
	}
}

func TestEngine_AllowAndBlockPatterns_Comprehensive(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.EnableDefaultAllowPatterns = true
	cfg.BlockPatterns = []string{
		`(?i)^/admin/.*$`,
		`(?i)\.(key|pem|conf|secret)$`,
		`(?i)^/internal/debug$`,
	}
	cfg.AllowPatterns = []string{
		`(?i)^/admin/public/health$`,
		`(?i)^/admin/assets/.*$`,
		`(?i)^/public/sample\.conf$`,
		`(?i)^/\.well-known/acme-challenge/.*$`,
	}
	cfg.AllowedIPs = []string{"192.168.100.50"}
	cfg.CheckQuery = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	tests := []struct {
		name          string
		method        string
		path          string
		query         string
		clientIP      string
		expectBlocked bool
		expectReason  string
	}{
		// BlockPatterns matches
		{
			name:          "Block pattern: /admin/dashboard blocked",
			method:        "GET",
			path:          "/admin/dashboard",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		{
			name:          "Block pattern: case insensitive /ADMIN/Settings blocked",
			method:        "GET",
			path:          "/ADMIN/Settings",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		{
			name:          "Block pattern: file extension /certs/server.key blocked",
			method:        "GET",
			path:          "/certs/server.key",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		{
			name:          "Block pattern: file extension /config/app.conf blocked",
			method:        "GET",
			path:          "/config/app.conf",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		{
			name:          "Block pattern: exact endpoint /internal/debug blocked",
			method:        "GET",
			path:          "/internal/debug",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		// AllowPatterns overriding BlockPatterns
		{
			name:          "Allow pattern override: /admin/public/health passes",
			method:        "GET",
			path:          "/admin/public/health",
			expectBlocked: false,
		},
		{
			name:          "Allow pattern override: /admin/assets/app.js passes",
			method:        "GET",
			path:          "/admin/assets/app.js",
			expectBlocked: false,
		},
		{
			name:          "Allow pattern override: /public/sample.conf passes despite .conf extension",
			method:        "GET",
			path:          "/public/sample.conf",
			expectBlocked: false,
		},
		{
			name:          "Allow pattern override on default block: /.well-known/acme-challenge/abc-token passes",
			method:        "GET",
			path:          "/.well-known/acme-challenge/abc-token",
			expectBlocked: false,
		},
		// Default block pattern still active
		{
			name:          "Default block pattern: /.env blocked",
			method:        "GET",
			path:          "/.env",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		// Non-matching clean routes
		{
			name:          "Clean route: /api/v1/products passes",
			method:        "GET",
			path:          "/api/v1/products",
			expectBlocked: false,
		},
		{
			name:          "Clean route: /internal/debug/public passes (not exact /internal/debug)",
			method:        "GET",
			path:          "/internal/debug/public",
			expectBlocked: false,
		},
		// IP Whitelist bypass for blocked paths
		{
			name:          "IP Whitelist bypass: /admin/dashboard allowed from whitelisted IP",
			method:        "GET",
			path:          "/admin/dashboard",
			clientIP:      "192.168.100.50",
			expectBlocked: false,
			expectReason:  "ip_whitelisted",
		},
		{
			name:          "Non-whitelisted IP blocked on /admin/dashboard",
			method:        "GET",
			path:          "/admin/dashboard",
			clientIP:      "10.0.0.1",
			expectBlocked: true,
			expectReason:  "path_blocked",
		},
		// CheckQuery inspection with BlockPatterns
		{
			name:          "Query string matching BlockPatterns is blocked",
			method:        "GET",
			path:          "/search",
			query:         "redirect=/admin/dashboard",
			expectBlocked: true,
		},
		{
			name:          "Query string not matching BlockPatterns passes",
			method:        "GET",
			path:          "/search",
			query:         "q=normal-search-term",
			expectBlocked: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := eng.EvaluateWithClientIP(tc.method, tc.path, tc.query, nil, tc.clientIP)
			if res.Blocked != tc.expectBlocked {
				t.Errorf("[%s] expected Blocked=%v, got %v (reason=%q)", tc.name, tc.expectBlocked, res.Blocked, res.Reason)
			}
			if tc.expectReason != "" && res.Reason != tc.expectReason {
				t.Errorf("[%s] expected reason %q, got %q", tc.name, tc.expectReason, res.Reason)
			}
		})
	}
}

func TestEngine_CleanIP_Comprehensive(t *testing.T) {
	cfg := engine.CreateConfig()
	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	tests := []struct {
		input      string
		remoteAddr string
		headers    map[string]string
		expectIP   string
	}{
		{
			remoteAddr: "192.0.2.1:8080",
			expectIP:   "192.0.2.1",
		},
		{
			remoteAddr: "[2001:db8::1]:443",
			expectIP:   "2001:db8::1",
		},
		{
			remoteAddr: "10.0.0.1",
			expectIP:   "10.0.0.1",
		},
		{
			remoteAddr: "fe80::1%eth0:1234",
			expectIP:   "fe80::1",
		},
		{
			remoteAddr: "",
			expectIP:   "",
		},
	}

	for _, tc := range tests {
		got := eng.ExtractClientIP(tc.headers, tc.remoteAddr)
		if got != tc.expectIP {
			t.Errorf("ExtractClientIP(remote=%q): expected %q, got %q", tc.remoteAddr, tc.expectIP, got)
		}
	}
}

func TestEngine_ExtractClientIP_TrustedProxiesChains(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.TrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.1.1"}
	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	// 1. Untrusted remoteAddr ignores X-Forwarded-For
	untrustedHeaders := map[string]string{"X-Forwarded-For": "203.0.113.50"}
	if ip := eng.ExtractClientIP(untrustedHeaders, "198.51.100.1:12345"); ip != "198.51.100.1" {
		t.Errorf("expected untrusted remoteAddr to be returned directly, got %q", ip)
	}

	// 2. Trusted proxy with X-Forwarded-For chain: client -> proxy1 -> proxy2 -> routewarden
	proxyChainHeaders := map[string]string{
		"X-Forwarded-For": "203.0.113.99, 10.0.0.2, 172.16.1.5",
	}
	if ip := eng.ExtractClientIP(proxyChainHeaders, "10.0.0.1:443"); ip != "203.0.113.99" {
		t.Errorf("expected client IP 203.0.113.99 from proxy chain, got %q", ip)
	}

	// 3. Trusted proxy with X-Real-IP when X-Forwarded-For is missing
	realIPHeaders := map[string]string{"X-Real-IP": "198.51.100.200"}
	if ip := eng.ExtractClientIP(realIPHeaders, "192.168.1.1:5000"); ip != "198.51.100.200" {
		t.Errorf("expected X-Real-IP 198.51.100.200, got %q", ip)
	}

	// 4. Trusted proxy with spaces and multiple commas
	spacedHeaders := map[string]string{
		"X-Forwarded-For": "  198.51.100.77  , 10.0.0.5  ",
	}
	if ip := eng.ExtractClientIP(spacedHeaders, "10.0.0.1:443"); ip != "198.51.100.77" {
		t.Errorf("expected client IP 198.51.100.77 with spaced header, got %q", ip)
	}
}

func TestEngine_GenerateTraefikTOML_AllResponseModes(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.Enabled = true
	cfg.EnableDefaultPatterns = true
	cfg.EnableDefaultAllowPatterns = true
	cfg.CheckQuery = true
	cfg.CheckBody = true
	cfg.CheckBodyMaxBytes = 32768
	cfg.CheckBodyPatterns = []string{`(?i)select.*from`}
	cfg.CheckHeaders = []string{"X-Forwarded-Host"}
	cfg.Methods = []string{"GET", "POST"}
	cfg.BlockPatterns = []string{`(?i)^/admin`}
	cfg.AllowPatterns = []string{`(?i)^/public`}
	cfg.AllowedIPs = []string{"10.0.0.0/8"}
	cfg.TrustedProxies = []string{"172.16.0.0/12"}
	cfg.Response = &engine.ResponseConfig{
		Mode:                     "tarpit",
		StatusCode:               429,
		ContentType:              "text/plain",
		Body:                     "slow down",
		RedirectURL:              "https://sinkhole.example.com",
		ProxyURL:                 "http://honeypot:8080",
		GzipBombMB:               15,
		RetryAfterSeconds:        60,
		TarpitDelayMs:            1500,
		TarpitMaxDurationSeconds: 10,
		StreamSizeMB:             5,
		Headers: map[string]string{
			"X-Firewall":  "RouteWarden",
			"Retry-After": "60",
		},
		Captcha: &engine.CaptchaConfig{
			Provider: "turnstile",
			SiteKey:  "0x4AAAAAA",
			Title:    "Bot Check",
			Template: "custom-template.html",
		},
	}

	toml := cfg.GenerateTraefikTOML()

	expectedSnippets := []string{
		"[http.middlewares.routewarden.plugin.routewarden]",
		"enabled = true",
		"enableDefaultPatterns = true",
		"enableDefaultAllowPatterns = true",
		"checkQuery = true",
		"checkBody = true",
		"checkBodyMaxBytes = 32768",
		"mode = \"tarpit\"",
		"statusCode = 429",
		"contentType = \"text/plain\"",
		"body = \"slow down\"",
		"redirectUrl = \"https://sinkhole.example.com\"",
		"proxyUrl = \"http://honeypot:8080\"",
		"gzipBombMB = 15",
		"retryAfterSeconds = 60",
		"tarpitDelayMs = 1500",
		"tarpitMaxDurationSeconds = 10",
		"streamSizeMB = 5",
		"[http.middlewares.routewarden.plugin.routewarden.response.captcha]",
		"provider = \"turnstile\"",
		"siteKey = \"0x4AAAAAA\"",
		"title = \"Bot Check\"",
		"template = \"custom-template.html\"",
		"[http.middlewares.routewarden.plugin.routewarden.response.headers]",
		"X-Firewall = \"RouteWarden\"",
	}

	for _, s := range expectedSnippets {
		if !strings.Contains(toml, s) {
			t.Errorf("missing expected snippet %q in generated TOML:\n%s", s, toml)
		}
	}
}

func TestEngine_Generate_AllTargetsAndError(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.BlockPatterns = []string{`(?i)^/admin`}
	cfg.Response = &engine.ResponseConfig{
		Mode:       "captcha",
		StatusCode: 403,
		Captcha: &engine.CaptchaConfig{
			Provider: "hcaptcha",
			SiteKey:  "my-site-key",
			Title:    "Please Verify",
		},
	}

	validTargets := []string{
		"traefik-yaml",
		"traefik-toml",
		"traefik-labels",
		"caddy",
		"nginx",
		"tcp-warden",
	}

	for _, target := range validTargets {
		out, err := cfg.Generate(target)
		if err != nil {
			t.Errorf("Generate(%q) unexpected error: %v", target, err)
		}
		if len(out) == 0 {
			t.Errorf("Generate(%q) produced empty output", target)
		}
	}

	// Unknown target error
	_, err := cfg.Generate("unknown-target")
	if err == nil {
		t.Fatalf("expected error for unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported target") {
		t.Errorf("expected 'unsupported target' in error, got: %v", err)
	}
}

func TestEngine_ExtractCandidatePaths_EvasionMatrix(t *testing.T) {
	testCases := []struct {
		name          string
		rawPath       string
		expectMatched string
	}{
		{
			name:          "Multiple consecutive slashes",
			rawPath:       "//////admin///////.env",
			expectMatched: "/admin/.env",
		},
		{
			name:          "Mixed backslashes and slashes",
			rawPath:       "/api\\v1\\.env",
			expectMatched: "/api/v1/.env",
		},
		{
			name:          "Matrix parameters stripping",
			rawPath:       "/api;session=xyz/admin;role=admin/.env",
			expectMatched: "/api/admin/.env",
		},
		{
			name:          "Triple percent-encoded dots and slashes",
			rawPath:       "%25252e%25252e%25252f%25252e%252565%25256e%252576",
			expectMatched: "/.env",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			candidates := engine.ExtractCandidatePaths(tc.rawPath, tc.rawPath, tc.rawPath)
			found := false
			for _, c := range candidates {
				if strings.Contains(c, tc.expectMatched) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("[%s] expected candidate containing %q, got: %v", tc.name, tc.expectMatched, candidates)
			}
		})
	}
}

func TestEngine_EvaluateWithBody_BoundaryLimits(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.Methods = []string{"GET", "POST"}
	cfg.CheckBody = true
	cfg.CheckBodyMaxBytes = 20
	cfg.CheckBodyPatterns = []string{`(?i)drop\s+table`}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	// 1. Body within maxBytes matching pattern is blocked
	res1 := eng.EvaluateWithBody("POST", "/api/query", "", nil, "", "DROP TABLE users;")
	if !res1.Blocked {
		t.Errorf("expected DROP TABLE body to be blocked, got allowed")
	}

	// 2. Malicious keyword pushed past CheckBodyMaxBytes (20 bytes)
	// First 20 bytes is "safe safe safe safe " (20 bytes). The "DROP TABLE" occurs at byte 21.
	padding := "safe safe safe safe DROP TABLE users;"
	res2 := eng.EvaluateWithBody("POST", "/api/query", "", nil, "", padding)
	if res2.Blocked {
		t.Errorf("expected payload beyond maxBytes to be truncated and allowed, got blocked")
	}

	// 3. Clean body passes inspection
	res3 := eng.EvaluateWithBody("POST", "/api/query", "", nil, "", `{"name":"alice"}`)
	if res3.Blocked {
		t.Errorf("expected clean JSON body to pass, got blocked")
	}
}

func TestEngine_ConfigFile_LoadAndOverride(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "base_routewarden.json")
	baseContent := `{
		"blockPatterns": ["(?i)^/admin(/.*)?$"],
		"allowedIps": ["10.0.0.1"],
		"methods": ["GET"],
		"response": {
			"mode": "json",
			"statusCode": 403
		}
	}`
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 1. Load with configFile (camelCase) and override response mode & methods
	cfg := engine.CreateConfig()
	cfg.ConfigFile = basePath
	cfg.Methods = []string{"GET", "POST"}
	cfg.Response = &engine.ResponseConfig{
		Mode:       "text",
		StatusCode: 404,
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("unexpected NewEngine error: %v", err)
	}

	// Preserved block patterns from base file
	eval1 := eng.EvaluateWithClientIP("POST", "/admin/secrets", "", nil, "192.168.1.1")
	if !eval1.Blocked {
		t.Errorf("expected /admin/secrets to be blocked based on base configFile patterns")
	}

	// Preserved IP allowlist from base file
	eval2 := eng.EvaluateWithClientIP("POST", "/admin/secrets", "", nil, "10.0.0.1")
	if eval2.Blocked || eval2.Reason != "ip_whitelisted" {
		t.Errorf("expected 10.0.0.1 to be whitelisted from base configFile, got: blocked=%v reason=%s", eval2.Blocked, eval2.Reason)
	}

	// 2. Load with config_file (snake_case alias)
	cfgSnake := engine.CreateConfig()
	cfgSnake.ConfigFileSnake = basePath
	engSnake, err := engine.NewEngine(cfgSnake)
	if err != nil {
		t.Fatalf("unexpected NewEngine error with config_file alias: %v", err)
	}
	evalSnake := engSnake.EvaluateWithClientIP("GET", "/admin/settings", "", nil, "192.168.1.1")
	if !evalSnake.Blocked {
		t.Errorf("expected /admin/settings to be blocked using config_file alias")
	}
	if engSnake.Config.Response.Mode != "json" {
		t.Errorf("expected base response.mode 'json' to be preserved, got: %s", engSnake.Config.Response.Mode)
	}
}

func TestConfig_SnakeCaseUnmarshal(t *testing.T) {
	rawJSON := `{
		"config_file": "/path/to/base.json",
		"enabled": true,
		"enable_default_patterns": false,
		"enable_default_allow_patterns": false,
		"block_patterns": ["(?i)^/secret/.*$"],
		"allow_patterns": ["(?i)^/secret/public$"],
		"allowed_ips": ["192.168.1.50"],
		"trusted_proxies": ["10.0.0.1"],
		"status_code": 404,
		"custom_response_text": "Custom blocked text",
		"check_query": true,
		"check_headers": ["X-Forwarded-Uri"],
		"check_body": true,
		"check_body_max_bytes": 32768,
		"check_body_patterns": ["(?i)grant_type=password"],
		"security_log": false,
		"response": {
			"mode": "redirect",
			"status_code": 307,
			"redirect_url": "https://example.com/blocked",
			"proxy_url": "http://127.0.0.1:8080",
			"gzip_bomb_mb": 20,
			"retry_after_seconds": 600,
			"tarpit_delay_ms": 2000,
			"tarpit_max_duration_seconds": 120,
			"stream_size_mb": 50,
			"captcha": {
				"provider": "hcaptcha",
				"site_key": "0xABC123DEF456"
			}
		}
	}`

	var cfg engine.Config
	if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if cfg.ConfigFile != "/path/to/base.json" {
		t.Errorf("expected config_file parsed into ConfigFile, got: %s", cfg.ConfigFile)
	}
	if !cfg.Enabled {
		t.Errorf("expected enabled == true")
	}
	if cfg.EnableDefaultPatterns {
		t.Errorf("expected enable_default_patterns == false")
	}
	if cfg.EnableDefaultAllowPatterns {
		t.Errorf("expected enable_default_allow_patterns == false")
	}
	if len(cfg.BlockPatterns) != 1 || cfg.BlockPatterns[0] != "(?i)^/secret/.*$" {
		t.Errorf("unexpected blockPatterns: %v", cfg.BlockPatterns)
	}
	if len(cfg.AllowPatterns) != 1 || cfg.AllowPatterns[0] != "(?i)^/secret/public$" {
		t.Errorf("unexpected allowPatterns: %v", cfg.AllowPatterns)
	}
	if len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0] != "192.168.1.50" {
		t.Errorf("unexpected allowedIps: %v", cfg.AllowedIPs)
	}
	if len(cfg.TrustedProxies) != 1 || cfg.TrustedProxies[0] != "10.0.0.1" {
		t.Errorf("unexpected trustedProxies: %v", cfg.TrustedProxies)
	}
	if cfg.StatusCode != 404 {
		t.Errorf("expected status_code 404, got %d", cfg.StatusCode)
	}
	if cfg.CustomResponseText != "Custom blocked text" {
		t.Errorf("expected custom_response_text, got: %s", cfg.CustomResponseText)
	}
	if !cfg.CheckQuery {
		t.Errorf("expected check_query == true")
	}
	if len(cfg.CheckHeaders) != 1 || cfg.CheckHeaders[0] != "X-Forwarded-Uri" {
		t.Errorf("unexpected checkHeaders: %v", cfg.CheckHeaders)
	}
	if !cfg.CheckBody {
		t.Errorf("expected check_body == true")
	}
	if cfg.CheckBodyMaxBytes != 32768 {
		t.Errorf("expected check_body_max_bytes 32768, got %d", cfg.CheckBodyMaxBytes)
	}
	if len(cfg.CheckBodyPatterns) != 1 || cfg.CheckBodyPatterns[0] != "(?i)grant_type=password" {
		t.Errorf("unexpected checkBodyPatterns: %v", cfg.CheckBodyPatterns)
	}
	if cfg.SecurityLog {
		t.Errorf("expected security_log == false")
	}
	if cfg.Response == nil {
		t.Fatalf("expected non-nil response")
	}
	if cfg.Response.Mode != "redirect" {
		t.Errorf("expected response.mode 'redirect', got: %s", cfg.Response.Mode)
	}
	if cfg.Response.StatusCode != 307 {
		t.Errorf("expected response.status_code 307, got: %d", cfg.Response.StatusCode)
	}
	if cfg.Response.RedirectURL != "https://example.com/blocked" {
		t.Errorf("expected redirect_url, got: %s", cfg.Response.RedirectURL)
	}
	if cfg.Response.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("expected proxy_url, got: %s", cfg.Response.ProxyURL)
	}
	if cfg.Response.GzipBombMB != 20 {
		t.Errorf("expected gzip_bomb_mb 20, got: %v", cfg.Response.GzipBombMB)
	}
	if cfg.Response.RetryAfterSeconds != 600 {
		t.Errorf("expected retry_after_seconds 600, got: %d", cfg.Response.RetryAfterSeconds)
	}
	if cfg.Response.TarpitDelayMs != 2000 {
		t.Errorf("expected tarpit_delay_ms 2000, got: %d", cfg.Response.TarpitDelayMs)
	}
	if cfg.Response.TarpitMaxDurationSeconds != 120 {
		t.Errorf("expected tarpit_max_duration_seconds 120, got: %d", cfg.Response.TarpitMaxDurationSeconds)
	}
	if cfg.Response.StreamSizeMB != 50 {
		t.Errorf("expected stream_size_mb 50, got: %d", cfg.Response.StreamSizeMB)
	}
	if cfg.Response.Captcha == nil || cfg.Response.Captcha.SiteKey != "0xABC123DEF456" {
		t.Errorf("expected captcha.site_key parsed, got: %+v", cfg.Response.Captcha)
	}
}

func TestEngine_ConfigFile_ErrorHandling(t *testing.T) {
	// 1. Missing file error
	cfgMissing := engine.CreateConfig()
	cfgMissing.ConfigFile = "/path/to/definitely/nonexistent/routewarden.json"
	_, err := engine.NewEngine(cfgMissing)
	if err == nil {
		t.Fatalf("expected error for missing configFile, got nil")
	}
	if !strings.Contains(err.Error(), "cannot read configFile") {
		t.Errorf("expected 'cannot read configFile' in error, got: %v", err)
	}

	// 2. Malformed JSON file error
	tmpDir := t.TempDir()
	malformedPath := filepath.Join(tmpDir, "malformed.json")
	if err := os.WriteFile(malformedPath, []byte(`{ broken json`), 0644); err != nil {
		t.Fatal(err)
	}
	cfgMalformed := engine.CreateConfig()
	cfgMalformed.ConfigFile = malformedPath
	_, err2 := engine.NewEngine(cfgMalformed)
	if err2 == nil {
		t.Fatalf("expected error for malformed configFile, got nil")
	}
	if !strings.Contains(err2.Error(), "cannot parse configFile") {
		t.Errorf("expected 'cannot parse configFile' in error, got: %v", err2)
	}
}

func TestEngine_ConfigFile_Generators(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.ConfigFile = "/etc/routewarden/shared.json"

	// Traefik YAML
	yamlOut := cfg.GenerateTraefikYAML()
	if !strings.Contains(yamlOut, "configFile: /etc/routewarden/shared.json") {
		t.Errorf("expected configFile in Traefik YAML, got:\n%s", yamlOut)
	}

	// Traefik TOML
	tomlOut := cfg.GenerateTraefikTOML()
	if !strings.Contains(tomlOut, `configFile = "/etc/routewarden/shared.json"`) {
		t.Errorf("expected configFile in Traefik TOML, got:\n%s", tomlOut)
	}

	// Traefik Labels
	labelsOut := cfg.GenerateTraefikLabels()
	if !strings.Contains(labelsOut, "traefik.http.middlewares.warden.plugin.routewarden.configFile=/etc/routewarden/shared.json") {
		t.Errorf("expected configFile in Traefik Labels, got:\n%s", labelsOut)
	}

	// Caddyfile
	caddyOut := cfg.GenerateCaddyfile()
	if !strings.Contains(caddyOut, "config_file /etc/routewarden/shared.json") {
		t.Errorf("expected config_file in Caddyfile, got:\n%s", caddyOut)
	}

	// Nginx Lua
	nginxOut := cfg.GenerateNginxLua()
	if !strings.Contains(nginxOut, `config_file = "/etc/routewarden/shared.json"`) {
		t.Errorf("expected config_file in Nginx Lua, got:\n%s", nginxOut)
	}
}

func TestGzipBombMB_FloatingValues(t *testing.T) {
	// 1. JSON unmarshaling with float number
	rawJSON := []byte(`{
		"response": {
			"mode": "gzipBomb",
			"gzipBombMB": 0.5
		}
	}`)
	var cfg engine.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		t.Fatalf("failed to unmarshal JSON with float gzipBombMB: %v", err)
	}
	if cfg.Response == nil || cfg.Response.GzipBombMB != 0.5 {
		t.Fatalf("expected gzipBombMB 0.5, got: %v", cfg.Response.GzipBombMB)
	}

	// 2. JSON unmarshaling with snake_case and string float
	rawJSONSnake := []byte(`{
		"response": {
			"mode": "gzipBomb",
			"gzip_bomb_mb": "1.75"
		}
	}`)
	var cfgSnake engine.Config
	if err := json.Unmarshal(rawJSONSnake, &cfgSnake); err != nil {
		t.Fatalf("failed to unmarshal JSON with string float gzip_bomb_mb: %v", err)
	}
	if cfgSnake.Response == nil || cfgSnake.Response.GzipBombMB != 1.75 {
		t.Fatalf("expected gzip_bomb_mb 1.75, got: %v", cfgSnake.Response.GzipBombMB)
	}

	// 3. Export config to all formats with float 0.5
	cfgFloat := &engine.Config{
		Enabled: true,
		Response: &engine.ResponseConfig{
			Mode:       "gzipBomb",
			GzipBombMB: 0.5,
		},
	}

	// Traefik Dynamic YAML
	traefikYAML := cfgFloat.GenerateTraefikYAML()
	if !strings.Contains(traefikYAML, "gzipBombMB: 0.5") {
		t.Errorf("expected 'gzipBombMB: 0.5' in Traefik YAML, got:\n%s", traefikYAML)
	}

	// Traefik TOML
	traefikTOML := cfgFloat.GenerateTraefikTOML()
	if !strings.Contains(traefikTOML, "gzipBombMB = 0.5") {
		t.Errorf("expected 'gzipBombMB = 0.5' in Traefik TOML, got:\n%s", traefikTOML)
	}

	// Traefik Labels
	traefikLabels := cfgFloat.GenerateTraefikLabels()
	if !strings.Contains(traefikLabels, "response.gzipBombMB=0.5") {
		t.Errorf("expected 'response.gzipBombMB=0.5' in Traefik Labels, got:\n%s", traefikLabels)
	}

	// Caddyfile
	caddyfile := cfgFloat.GenerateCaddyfile()
	if !strings.Contains(caddyfile, "gzip_bomb_mb 0.5") {
		t.Errorf("expected 'gzip_bomb_mb 0.5' in Caddyfile, got:\n%s", caddyfile)
	}

	// Nginx Lua
	nginxLua := cfgFloat.GenerateNginxLua()
	if !strings.Contains(nginxLua, "gzip_bomb_mb = 0.5,") {
		t.Errorf("expected 'gzip_bomb_mb = 0.5,' in Nginx Lua, got:\n%s", nginxLua)
	}
}

func TestEngine_MatrixParam_NoAllowlistBypass(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.EnableDefaultAllowPatterns = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	attackPaths := []string{
		"/.env;robots.txt",
		"/.env;sitemap.xml",
		"/backup.sql;robots.txt",
		"/.git/config;robots.txt",
	}

	for _, attack := range attackPaths {
		res := eng.Evaluate("GET", attack, "", nil)
		if res.Blocked == false {
			t.Errorf("expected path %q to be blocked, but was not blocked (allowed: %v, reason: %s)",
				attack, res.Allowed, res.Reason)
		}
	}
}

func TestEngine_URIFragmentAnchorBypassPrevented(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	attackPaths := []string{
		"/server-status#admin",
		"/server-status#section",
		"/server.key#frag",
		"/.env#local",
		"/phpinfo.php#info",
	}

	for _, attack := range attackPaths {
		res := eng.Evaluate("GET", attack, "", nil)
		if res.Blocked == false {
			t.Errorf("expected path %q with fragment to be blocked, got blocked=%v, reason=%s",
				attack, res.Blocked, res.Reason)
		}
	}
}

func TestEngine_WildcardMethods(t *testing.T) {
	cfgStar := engine.CreateConfig()
	cfgStar.Methods = []string{"*"}
	cfgStar.EnableDefaultPatterns = true

	engStar, err := engine.NewEngine(cfgStar)
	if err != nil {
		t.Fatalf("failed to create engine with *: %v", err)
	}
	resStarPOST := engStar.Evaluate("POST", "/.env", "", nil)
	if !resStarPOST.Blocked {
		t.Errorf("expected POST /.env to be blocked with wildcard *, got bypassed: %v", resStarPOST.Bypassed)
	}
	resStarDELETE := engStar.Evaluate("DELETE", "/.env", "", nil)
	if !resStarDELETE.Blocked {
		t.Errorf("expected DELETE /.env to be blocked with wildcard *, got bypassed: %v", resStarDELETE.Bypassed)
	}

	cfgAll := engine.CreateConfig()
	cfgAll.Methods = []string{"ALL"}
	cfgAll.EnableDefaultPatterns = true

	engAll, err := engine.NewEngine(cfgAll)
	if err != nil {
		t.Fatalf("failed to create engine with ALL: %v", err)
	}
	resAllPOST := engAll.Evaluate("POST", "/.env", "", nil)
	if !resAllPOST.Blocked {
		t.Errorf("expected POST /.env to be blocked with wildcard ALL, got bypassed: %v", resAllPOST.Bypassed)
	}
}

func TestEngine_CheckBody_AutoExpandsMethods(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.CheckBody = true
	cfg.CheckBodyPatterns = []string{"(?i)password_leak"}
	cfg.EnableDefaultPatterns = false

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	res := eng.EvaluateWithBody("POST", "/api/login", "", nil, "", "user=admin&token=password_leak_123")
	if !res.Blocked {
		t.Errorf("expected POST with body violation to be blocked when methods is omitted, got: blocked=%v, bypassed=%v, reason=%s",
			res.Blocked, res.Bypassed, res.Reason)
	}
}

func TestEngine_CheckQuery_Keys(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.CheckQuery = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Sensitive endpoint in query key
	res := eng.Evaluate("GET", "/", ".env=1", nil)
	if !res.Blocked {
		t.Errorf("expected query key .env to be blocked, got blocked=%v, reason=%s", res.Blocked, res.Reason)
	}

	// Sensitive endpoint in query key with slash
	res2 := eng.Evaluate("GET", "/", "/server-status=true", nil)
	if !res2.Blocked {
		t.Errorf("expected query key /server-status to be blocked, got blocked=%v, reason=%s", res2.Blocked, res2.Reason)
	}
}

func TestEngine_CheckHeaders_MultiValue(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.CheckHeaders = []string{"X-Rewrite-URL", "X-Custom-Path"}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	headers := map[string]string{
		"X-Custom-Path": "/safe/path, /.env",
	}
	res := eng.Evaluate("GET", "/index.html", "", headers)
	if !res.Blocked {
		t.Errorf("expected comma-separated header containing /.env to be blocked, got blocked=%v, reason=%s", res.Blocked, res.Reason)
	}
}

func TestEngine_CheckQuery_MalformedPercentEncoding(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.CheckQuery = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	res := eng.Evaluate("GET", "/search", "target=/.env&broken=%zz", nil)
	if !res.Blocked {
		t.Errorf("expected query with target=/.env&broken=%%zz to be blocked, got blocked=%v, reason=%s", res.Blocked, res.Reason)
	}
}

func TestEngine_BracketedIPv6CIDR_AllowedIPs(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = true
	cfg.AllowedIPs = []string{"[2001:db8::]/32", "[2001:db9::cafe]"}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine with bracketed IPv6 CIDR: %v", err)
	}

	headers := map[string]string{}
	// Allowed via bracketed CIDR
	res1 := eng.EvaluateWithClientIP("GET", "/.env", "", headers, "2001:db8::1")
	if res1.Blocked {
		t.Errorf("expected 2001:db8::1 to be allowed by [2001:db8::]/32, got blocked=%v", res1.Blocked)
	}

	// Allowed via bracketed exact IP
	res2 := eng.EvaluateWithClientIP("GET", "/.env", "", headers, "2001:db9::cafe")
	if res2.Blocked {
		t.Errorf("expected 2001:db9::cafe to be allowed by [2001:db9::cafe], got blocked=%v", res2.Blocked)
	}

	// Not allowed -> should block sensitive file /.env
	res3 := eng.EvaluateWithClientIP("GET", "/.env", "", headers, "2001:dba::1")
	if !res3.Blocked {
		t.Errorf("expected 2001:dba::1 accessing /.env to be blocked")
	}
}

func TestEngine_AIBotsAndHoneypotSpiderTrap(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.EnableDefaultPatterns = false
	cfg.BlockAIBots = true
	cfg.AIBotProfile = "train_only"
	cfg.BlockUserAgents = []string{`(?i)CustomScraperBot`}
	cfg.AllowUserAgents = []string{`(?i)PartnerBot`}
	cfg.HoneypotTrapPaths = []string{"/secret-spider-trap", "/crawler-trap/"}
	cfg.TrapBanDuration = "1h"

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	clientIP := "198.51.100.22"

	// 1. Legitimate request passes
	res1 := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientIP)
	if res1.Blocked {
		t.Errorf("expected legitimate request to pass, got blocked: %s", res1.Reason)
	}

	// 2. GPTBot blocked under train_only profile
	resGPT := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"}, "203.0.113.1")
	if !resGPT.Blocked || resGPT.Reason != "ai_bot_blocked" {
		t.Errorf("expected GPTBot to be blocked with ai_bot_blocked, got blocked=%v, reason=%s", resGPT.Blocked, resGPT.Reason)
	}

	// 3. Allowed User-Agent bypasses AI bot block
	resAllowed := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": "PartnerBot GPTBot/1.0"}, "203.0.113.2")
	if resAllowed.Blocked {
		t.Errorf("expected PartnerBot to bypass bot blocking, got blocked: %s", resAllowed.Reason)
	}

	// 4. Custom blocked User-Agent
	resCustom := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": "CustomScraperBot/2.0"}, "203.0.113.3")
	if !resCustom.Blocked || resCustom.Reason != "user_agent_blocked" {
		t.Errorf("expected CustomScraperBot to be blocked with user_agent_blocked, got blocked=%v, reason=%s", resCustom.Blocked, resCustom.Reason)
	}

	// 5. Honeypot Spider Trap triggers ban
	resTrap := eng.EvaluateWithClientIP("GET", "/secret-spider-trap", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientIP)
	if !resTrap.Blocked || resTrap.Reason != "honeypot_trap_triggered" {
		t.Fatalf("expected trap to be blocked with honeypot_trap_triggered, got blocked=%v, reason=%s", resTrap.Blocked, resTrap.Reason)
	}

	// 6. Subsequent request from same IP is blocked via ban table
	resBanned := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientIP)
	if !resBanned.Blocked || resBanned.Reason != "ip_banned" {
		t.Errorf("expected banned client to be blocked with ip_banned, got blocked=%v, reason=%s", resBanned.Blocked, resBanned.Reason)
	}

	// 7. Subpath of trap without trailing slash (/secret-spider-trap/deep/link) triggers trap
	clientSub := "198.51.100.88"
	resSubTrap := eng.EvaluateWithClientIP("GET", "/secret-spider-trap/deep/link", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientSub)
	if !resSubTrap.Blocked || resSubTrap.Reason != "honeypot_trap_triggered" {
		t.Fatalf("expected subpath trap to be blocked with honeypot_trap_triggered, got blocked=%v, reason=%s", resSubTrap.Blocked, resSubTrap.Reason)
	}

	// 8. Legitimate request to prefix-collision path (/secret-spider-trapdoor) must NOT trigger trap
	clientPrefixSafe := "198.51.100.89"
	resPrefixSafe := eng.EvaluateWithClientIP("GET", "/secret-spider-trapdoor", "", map[string]string{"User-Agent": "Mozilla/5.0"}, clientPrefixSafe)
	if resPrefixSafe.Blocked {
		t.Errorf("expected prefix-collision path /secret-spider-trapdoor to pass, got blocked: %s", resPrefixSafe.Reason)
	}

	// 9. Honeypot trap configured WITHOUT leading slash (e.g. "no-slash-trap")
	cfgNoSlash := engine.CreateConfig()
	cfgNoSlash.EnableDefaultPatterns = false
	cfgNoSlash.HoneypotTrapPaths = []string{"no-slash-trap"}
	cfgNoSlash.TrapBanDuration = "1h"
	engNoSlash, err := engine.NewEngine(cfgNoSlash)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	resNoSlash := engNoSlash.EvaluateWithClientIP("GET", "/no-slash-trap", "", nil, "198.51.100.91")
	if !resNoSlash.Blocked || resNoSlash.Reason != "honeypot_trap_triggered" {
		t.Errorf("expected trap path without leading slash to trigger, got blocked=%v, reason=%s", resNoSlash.Blocked, resNoSlash.Reason)
	}

	// 10. Case-insensitive matching: uppercase/mixed-case requests must trigger trap
	resCase1 := eng.EvaluateWithClientIP("GET", "/SECRET-SPIDER-TRAP", "", map[string]string{"User-Agent": "Mozilla/5.0"}, "198.51.100.92")
	if !resCase1.Blocked || resCase1.Reason != "honeypot_trap_triggered" {
		t.Errorf("expected /SECRET-SPIDER-TRAP to trigger honeypot trap case-insensitively, got blocked=%v, reason=%s", resCase1.Blocked, resCase1.Reason)
	}
	resCase2 := eng.EvaluateWithClientIP("GET", "/Crawler-Trap/Deep/Link", "", map[string]string{"User-Agent": "Mozilla/5.0"}, "198.51.100.93")
	if !resCase2.Blocked || resCase2.Reason != "honeypot_trap_triggered" {
		t.Errorf("expected /Crawler-Trap/Deep/Link to trigger honeypot trap case-insensitively, got blocked=%v, reason=%s", resCase2.Blocked, resCase2.Reason)
	}

	// 11. Root honeypot trap path safeguard: "/" must be ignored and not block root
	cfgRoot := engine.CreateConfig()
	cfgRoot.EnableDefaultPatterns = false
	cfgRoot.HoneypotTrapPaths = []string{"/", "   "}
	cfgRoot.TrapBanDuration = "1h"
	engRoot, err := engine.NewEngine(cfgRoot)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	resRoot := engRoot.EvaluateWithClientIP("GET", "/", "", nil, "198.51.100.94")
	if resRoot.Blocked {
		t.Errorf("expected root request to NOT be blocked when honeypotTrapPaths contains '/', got blocked=%v, reason=%s", resRoot.Blocked, resRoot.Reason)
	}
}

func TestEngine_VerifySearchEngineBots(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.BlockAIBots = true
	cfg.VerifySearchEngineBots = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	eng.SetFCrDNSLookupFuncs(
		func(ctx context.Context, addr string) ([]string, error) {
			if addr == "66.249.66.1" {
				return []string{"crawl-66-249-66-1.googlebot.com."}, nil
			}
			return []string{"attacker.com."}, nil
		},
		func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "crawl-66-249-66-1.googlebot.com." || host == "crawl-66-249-66-1.googlebot.com" {
				return []net.IP{net.ParseIP("66.249.66.1")}, nil
			}
			return []net.IP{net.ParseIP("198.51.100.2")}, nil
		},
	)

	googleUA := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	// 1. Spoofed Googlebot
	resSpoofed := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": googleUA}, "198.51.100.2")
	if !resSpoofed.Blocked || resSpoofed.Reason != "search_engine_spoofed" {
		t.Errorf("expected spoofed Googlebot to be blocked with search_engine_spoofed, got blocked=%v, reason=%s", resSpoofed.Blocked, resSpoofed.Reason)
	}

	// 2. Legitimate Googlebot
	resLegit := eng.EvaluateWithClientIP("GET", "/home", "", map[string]string{"User-Agent": googleUA}, "66.249.66.1")
	if resLegit.Blocked {
		t.Errorf("expected genuine Googlebot to be allowed, got blocked=%v, reason=%s", resLegit.Blocked, resLegit.Reason)
	}

	// 3. Generators include verifySearchEngineBots
	yamlOut := cfg.GenerateTraefikYAML()
	if !strings.Contains(yamlOut, "verifySearchEngineBots: true") {
		t.Errorf("expected Traefik YAML to contain verifySearchEngineBots: true, got:\n%s", yamlOut)
	}
	caddyOut := cfg.GenerateCaddyfile()
	if !strings.Contains(caddyOut, "verify_search_engine_bots true") {
		t.Errorf("expected Caddyfile to contain verify_search_engine_bots true, got:\n%s", caddyOut)
	}
	nginxOut := cfg.GenerateNginxLua()
	if !strings.Contains(nginxOut, "verify_search_engine_bots = true") {
		t.Errorf("expected Nginx Lua to contain verify_search_engine_bots = true, got:\n%s", nginxOut)
	}
}

func TestEngine_BrowserImpersonationAndScriptClients(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.DetectBrowserImpersonation = true
	cfg.BlockScriptClients = true

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

	// 1. Spoofed Chrome (missing Accept-Language)
	resSpoofed := eng.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent":      chromeUA,
		"Accept-Encoding": "gzip, deflate, br",
	})
	if !resSpoofed.Blocked || resSpoofed.Reason != "browser_spoofed" || resSpoofed.MatchedPattern != "missing_accept_language" {
		t.Errorf("expected missing_accept_language browser_spoofed, got blocked=%v, reason=%s, pattern=%s", resSpoofed.Blocked, resSpoofed.Reason, resSpoofed.MatchedPattern)
	}

	// 2. Legitimate Chrome with companion headers
	resLegit := eng.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent":         chromeUA,
		"Accept-Language":    "en-US,en;q=0.9",
		"Accept-Encoding":    "gzip, deflate, br",
		"Sec-CH-UA":          `"Chromium";v="128", "Google Chrome";v="128"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"Sec-Fetch-Site":     "none",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-Dest":     "document",
	})
	if resLegit.Blocked {
		t.Errorf("expected genuine Chrome to be allowed, got blocked=%v, reason=%s", resLegit.Blocked, resLegit.Reason)
	}

	// 3. Script client (python-requests)
	resScript := eng.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "python-requests/2.31.0",
	})
	if !resScript.Blocked || resScript.Reason != "script_client_blocked" {
		t.Errorf("expected python-requests to be blocked with script_client_blocked, got blocked=%v, reason=%s", resScript.Blocked, resScript.Reason)
	}

	// 4. Script client via headless header
	resHeadless := eng.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent":         chromeUA,
		"Accept-Language":    "en-US,en;q=0.9",
		"Accept-Encoding":    "gzip, deflate, br",
		"Sec-CH-UA":          `"Chromium";v="128", "Google Chrome";v="128"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"Sec-Fetch-Site":     "none",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-Dest":     "document",
		"X-Playwright":       "true",
	})
	if !resHeadless.Blocked || resHeadless.Reason != "script_client_blocked" || resHeadless.MatchedPattern != "playwright_headless" {
		t.Errorf("expected playwright to be blocked with script_client_blocked, got blocked=%v, reason=%s, pattern=%s", resHeadless.Blocked, resHeadless.Reason, resHeadless.MatchedPattern)
	}

	// 4b. Script client via headless header with EMPTY User-Agent
	resEmptyUAHeadless := eng.Evaluate("GET", "/index.html", "", map[string]string{
		"X-Playwright": "true",
	})
	if !resEmptyUAHeadless.Blocked || resEmptyUAHeadless.Reason != "script_client_blocked" || resEmptyUAHeadless.MatchedPattern != "playwright_headless" {
		t.Errorf("expected empty UA with X-Playwright to be blocked, got blocked=%v, reason=%s", resEmptyUAHeadless.Blocked, resEmptyUAHeadless.Reason)
	}

	// 4c. Custom BlockUserAgents with ^$ regex matching empty User-Agent
	cfgEmptyUA := engine.CreateConfig()
	cfgEmptyUA.BlockUserAgents = []string{"^$"}
	engEmptyUA, err := engine.NewEngine(cfgEmptyUA)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	resEmptyBlocked := engEmptyUA.Evaluate("GET", "/index.html", "", map[string]string{})
	if !resEmptyBlocked.Blocked || resEmptyBlocked.Reason != "user_agent_blocked" {
		t.Errorf("expected empty UA to be blocked by ^$ pattern, got blocked=%v, reason=%s", resEmptyBlocked.Blocked, resEmptyBlocked.Reason)
	}

	// 5. Check generators
	yamlOut := cfg.GenerateTraefikYAML()
	if !strings.Contains(yamlOut, "detectBrowserImpersonation: true") || !strings.Contains(yamlOut, "blockScriptClients: true") {
		t.Errorf("expected Traefik YAML to contain new fields, got:\n%s", yamlOut)
	}
	tomlOut := cfg.GenerateTraefikTOML()
	if !strings.Contains(tomlOut, "detectBrowserImpersonation = true") || !strings.Contains(tomlOut, "blockScriptClients = true") {
		t.Errorf("expected Traefik TOML to contain new fields, got:\n%s", tomlOut)
	}
	labelsOut := cfg.GenerateTraefikLabels()
	if !strings.Contains(labelsOut, "detectBrowserImpersonation=true") || !strings.Contains(labelsOut, "blockScriptClients=true") {
		t.Errorf("expected Traefik labels to contain new fields, got:\n%s", labelsOut)
	}
	caddyOut := cfg.GenerateCaddyfile()
	if !strings.Contains(caddyOut, "detect_browser_impersonation true") || !strings.Contains(caddyOut, "block_script_clients true") {
		t.Errorf("expected Caddyfile to contain new fields, got:\n%s", caddyOut)
	}
	nginxOut := cfg.GenerateNginxLua()
	if !strings.Contains(nginxOut, "detect_browser_impersonation = true") || !strings.Contains(nginxOut, "block_script_clients = true") {
		t.Errorf("expected Nginx Lua to contain new fields, got:\n%s", nginxOut)
	}
}

func TestEngine_BotDefenseLevelPresets(t *testing.T) {
	// 1. Standard Level
	cfgStandard := engine.CreateConfig()
	cfgStandard.BotDefenseLevel = "standard"
	engStandard, err := engine.NewEngine(cfgStandard)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// GPTBot blocked
	resGPT := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	})
	if !resGPT.Blocked || resGPT.Reason != "ai_bot_blocked" {
		t.Errorf("expected GPTBot to be blocked under standard level, got blocked=%v, reason=%s", resGPT.Blocked, resGPT.Reason)
	}

	// python-requests blocked
	resPy := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "python-requests/2.31.0",
	})
	if !resPy.Blocked || resPy.Reason != "script_client_blocked" {
		t.Errorf("expected python-requests to be blocked under standard level, got blocked=%v, reason=%s", resPy.Blocked, resPy.Reason)
	}

	// Spoofed Chrome (missing Accept-Language) blocked
	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
	resSpoofed := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": chromeUA,
	})
	if !resSpoofed.Blocked || resSpoofed.Reason != "browser_spoofed" {
		t.Errorf("expected spoofed Chrome to be blocked under standard level, got blocked=%v, reason=%s", resSpoofed.Blocked, resSpoofed.Reason)
	}

	// Search bot (PerplexityBot) allowed under standard (train_only default)
	resPerp := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
	})
	if resPerp.Blocked {
		t.Errorf("expected PerplexityBot to pass under standard level, got blocked=%v, reason=%s", resPerp.Blocked, resPerp.Reason)
	}

	// 2. Strict Level -> blocks search bot (PerplexityBot)
	cfgStrict := engine.CreateConfig()
	cfgStrict.BotDefenseLevel = "strict"
	engStrict, err := engine.NewEngine(cfgStrict)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	resPerpStrict := engStrict.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
	})
	if !resPerpStrict.Blocked || resPerpStrict.Reason != "ai_bot_blocked" {
		t.Errorf("expected PerplexityBot to be blocked under strict level, got blocked=%v, reason=%s", resPerpStrict.Blocked, resPerpStrict.Reason)
	}

	// 3. Light Level -> allows spoofed Chrome (browser impersonation off), blocks python-requests
	cfgLight := engine.CreateConfig()
	cfgLight.BotDefenseLevel = "light"
	engLight, err := engine.NewEngine(cfgLight)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	resSpoofedLight := engLight.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": chromeUA,
	})
	if resSpoofedLight.Blocked {
		t.Errorf("expected spoofed Chrome to pass under light level, got blocked=%v, reason=%s", resSpoofedLight.Blocked, resSpoofedLight.Reason)
	}
	resPyLight := engLight.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "python-requests/2.31.0",
	})
	if !resPyLight.Blocked || resPyLight.Reason != "script_client_blocked" {
		t.Errorf("expected python-requests to be blocked under light level, got blocked=%v, reason=%s", resPyLight.Blocked, resPyLight.Reason)
	}

	// 4. JSON Config File with override
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "routewarden.json")
	overrideJSON := `{
		"botDefenseLevel": "standard",
		"detectBrowserImpersonation": false
	}`
	if err := os.WriteFile(confPath, []byte(overrideJSON), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfgOverride := engine.CreateConfig()
	cfgOverride.ConfigFile = confPath
	engOverride, err := engine.NewEngine(cfgOverride)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	// Spoofed Chrome should pass because detectBrowserImpersonation is overridden to false
	resSpoofedOverride := engOverride.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": chromeUA,
	})
	if resSpoofedOverride.Blocked {
		t.Errorf("expected spoofed Chrome to pass with explicit override, got blocked=%v, reason=%s", resSpoofedOverride.Blocked, resSpoofedOverride.Reason)
	}
	// GPTBot still blocked because standard level enabled blockAIBots
	resGPTOverride := engOverride.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	})
	if !resGPTOverride.Blocked || resGPTOverride.Reason != "ai_bot_blocked" {
		t.Errorf("expected GPTBot to be blocked under standard level in file, got blocked=%v, reason=%s", resGPTOverride.Blocked, resGPTOverride.Reason)
	}

	// 4b. Direct JSON Unmarshal without ConfigFile, verifying explicit override is preserved in NewEngine
	var cfgDirect engine.Config
	if err := json.Unmarshal([]byte(overrideJSON), &cfgDirect); err != nil {
		t.Fatalf("failed to unmarshal direct JSON: %v", err)
	}
	engDirect, err := engine.NewEngine(&cfgDirect)
	if err != nil {
		t.Fatalf("failed to create direct engine: %v", err)
	}
	resSpoofedDirect := engDirect.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": chromeUA,
	})
	if resSpoofedDirect.Blocked {
		t.Errorf("expected spoofed Chrome to pass with direct json unmarshal override, got blocked=%v, reason=%s", resSpoofedDirect.Blocked, resSpoofedDirect.Reason)
	}
	resGPTDirect := engDirect.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
	})
	if !resGPTDirect.Blocked || resGPTDirect.Reason != "ai_bot_blocked" {
		t.Errorf("expected GPTBot to be blocked under direct json unmarshal, got blocked=%v, reason=%s", resGPTDirect.Blocked, resGPTDirect.Reason)
	}

	// 4c. Bug audit tests: Amazonbot and Anthropic UA matching
	resAmazon := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
	})
	if !resAmazon.Blocked || resAmazon.Reason != "ai_bot_blocked" {
		t.Errorf("expected Amazonbot to be blocked under standard level, got blocked=%v, reason=%s", resAmazon.Blocked, resAmazon.Reason)
	}
	resAnthropic := engStandard.Evaluate("GET", "/index.html", "", map[string]string{
		"User-Agent": "Anthropic/1.0",
	})
	if !resAnthropic.Blocked || resAnthropic.Reason != "ai_bot_blocked" {
		t.Errorf("expected Anthropic/1.0 to be blocked under standard level, got blocked=%v, reason=%s", resAnthropic.Blocked, resAnthropic.Reason)
	}

	// 5. Generator tests
	yamlOut := cfgStandard.GenerateTraefikYAML()
	if !strings.Contains(yamlOut, `botDefenseLevel: "standard"`) {
		t.Errorf("expected Traefik YAML to contain botDefenseLevel, got:\n%s", yamlOut)
	}
	tomlOut := cfgStandard.GenerateTraefikTOML()
	if !strings.Contains(tomlOut, `botDefenseLevel = "standard"`) {
		t.Errorf("expected Traefik TOML to contain botDefenseLevel, got:\n%s", tomlOut)
	}
	labelsOut := cfgStandard.GenerateTraefikLabels()
	if !strings.Contains(labelsOut, `botDefenseLevel=standard`) {
		t.Errorf("expected Traefik labels to contain botDefenseLevel, got:\n%s", labelsOut)
	}
	caddyOut := cfgStandard.GenerateCaddyfile()
	if !strings.Contains(caddyOut, "bot_defense_level standard") {
		t.Errorf("expected Caddyfile to contain bot_defense_level, got:\n%s", caddyOut)
	}
	nginxOut := cfgStandard.GenerateNginxLua()
	if !strings.Contains(nginxOut, `bot_defense_level = "standard"`) {
		t.Errorf("expected Nginx Lua to contain bot_defense_level, got:\n%s", nginxOut)
	}

	// 5b. Generator tests with explicit false overrides
	cfgExplicitFalse := engine.CreateConfig()
	overrideFalseJSON := `{
		"botDefenseLevel": "standard",
		"detectBrowserImpersonation": false
	}`
	if err := json.Unmarshal([]byte(overrideFalseJSON), cfgExplicitFalse); err != nil {
		t.Fatalf("failed to unmarshal explicit false json: %v", err)
	}

	yamlFalse := cfgExplicitFalse.GenerateTraefikYAML()
	if !strings.Contains(yamlFalse, "detectBrowserImpersonation: false") {
		t.Errorf("expected Traefik YAML to serialize detectBrowserImpersonation: false, got:\n%s", yamlFalse)
	}

	tomlFalse := cfgExplicitFalse.GenerateTraefikTOML()
	if !strings.Contains(tomlFalse, "detectBrowserImpersonation = false") {
		t.Errorf("expected Traefik TOML to serialize detectBrowserImpersonation = false, got:\n%s", tomlFalse)
	}

	labelsFalse := cfgExplicitFalse.GenerateTraefikLabels()
	if !strings.Contains(labelsFalse, "detectBrowserImpersonation=false") {
		t.Errorf("expected Traefik Labels to serialize detectBrowserImpersonation=false, got:\n%s", labelsFalse)
	}

	caddyFalse := cfgExplicitFalse.GenerateCaddyfile()
	if !strings.Contains(caddyFalse, "detect_browser_impersonation false") {
		t.Errorf("expected Caddyfile to serialize detect_browser_impersonation false, got:\n%s", caddyFalse)
	}

	nginxFalse := cfgExplicitFalse.GenerateNginxLua()
	if !strings.Contains(nginxFalse, "detect_browser_impersonation = false") {
		t.Errorf("expected Nginx Lua to serialize detect_browser_impersonation = false, got:\n%s", nginxFalse)
	}
}

func TestEngine_TrailingSlashMatching(t *testing.T) {
	cfg := &engine.Config{
		Enabled:               true,
		EnableDefaultPatterns: false,
		BlockPatterns:         []string{`(?i)^/admin/$`},
	}
	e, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to compile engine: %v", err)
	}

	// 1. Request with trailing slash
	resWithSlash := e.Evaluate("GET", "/admin/", "", nil)
	if !resWithSlash.Blocked {
		t.Fatalf("expected /admin/ to be blocked by ^/admin/$")
	}

	// 2. Request without trailing slash
	resNoSlash := e.Evaluate("GET", "/admin", "", nil)
	if !resNoSlash.Blocked {
		t.Fatalf("expected /admin to be blocked by ^/admin/$ (candidate trailing slash)")
	}

	// 3. Subpath should not match exact ^/admin/$
	resSubpath := e.Evaluate("GET", "/admin/users", "", nil)
	if resSubpath.Blocked {
		t.Fatalf("expected /admin/users NOT to be blocked by ^/admin/$")
	}
}

func TestEngine_CheckHeaders_WhitespaceAndQuotes(t *testing.T) {
	cfg := &engine.Config{
		Enabled:               true,
		EnableDefaultPatterns: true,
		CheckHeaders:          []string{"X-Forwarded-Prefix", "X-Rewrite-URL"},
	}
	e, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to compile engine: %v", err)
	}

	cases := []struct {
		name    string
		headers map[string]string
		blocked bool
	}{
		{
			name:    "Header with whitespace",
			headers: map[string]string{"X-Forwarded-Prefix": "  /.env  "},
			blocked: true,
		},
		{
			name:    "Header wrapped in double quotes",
			headers: map[string]string{"X-Forwarded-Prefix": `"/wp-config.php"`},
			blocked: true,
		},
		{
			name:    "Header wrapped in single quotes",
			headers: map[string]string{"X-Rewrite-URL": `'/.env'`},
			blocked: true,
		},
		{
			name:    "Comma-separated header with quotes and spaces",
			headers: map[string]string{"X-Forwarded-Prefix": `" /safe ", " /.env "`},
			blocked: true,
		},
		{
			name:    "Safe header",
			headers: map[string]string{"X-Forwarded-Prefix": `"/dashboard"`},
			blocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Evaluate("GET", "/api/data", "", tc.headers)
			if res.Blocked != tc.blocked {
				t.Fatalf("expected blocked=%v, got=%v (reason=%s)", tc.blocked, res.Blocked, res.Reason)
			}
		})
	}
}

func TestEngine_EncodedDelimitersAndWhitespaceEvasion(t *testing.T) {
	cfg := &engine.Config{
		Enabled:               true,
		EnableDefaultPatterns: true,
	}
	e, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to compile engine: %v", err)
	}

	cases := []struct {
		name    string
		path    string
		blocked bool
	}{
		{
			name:    "Encoded question mark in sensitive extension (?param)",
			path:    "/backup.sql%3fparam=value",
			blocked: true,
		},
		{
			name:    "Encoded fragment in sensitive file (#section)",
			path:    "/database.sql%23section",
			blocked: true,
		},
		{
			name:    "Encoded query and fragment combined (%3f and %23)",
			path:    "/server.key%3ffoo%23bar",
			blocked: true,
		},
		{
			name:    "Encoded carriage return (%0d)",
			path:    "/.env%0d",
			blocked: true,
		},
		{
			name:    "Encoded newline (%0a)",
			path:    "/.env%0a",
			blocked: true,
		},
		{
			name:    "Encoded horizontal tab (%09)",
			path:    "/.env%09",
			blocked: true,
		},
		{
			name:    "Clean harmless request",
			path:    "/index.html",
			blocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Evaluate("GET", tc.path, "", nil)
			if res.Blocked != tc.blocked {
				t.Fatalf("expected blocked=%v, got=%v (reason=%s, candidates=%v)", tc.blocked, res.Blocked, res.Reason, res.CandidatePaths)
			}
		})
	}
}






