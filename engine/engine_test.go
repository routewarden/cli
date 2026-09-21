package engine_test

import (
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

	t.Run("Top-level action alias is normalized into Response.Mode", func(t *testing.T) {
		cfg := engine.CreateConfig()
		cfg.Action = "silentDrop"
		cfg.Response = nil
		eng, err := engine.NewEngine(cfg)
		if err != nil {
			t.Fatalf("expected NewEngine to succeed with top-level action, got: %v", err)
		}
		if eng.Config.Response.Mode != "silentDrop" {
			t.Fatalf("expected Response.Mode to be 'silentDrop', got %q", eng.Config.Response.Mode)
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
