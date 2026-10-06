package engine_test

import (
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
			"Server":                 "RouteWarden Firewall v2.0",
			"X-Injected\r\nHeader":  "evil-value\r\nInjected: 1",
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




