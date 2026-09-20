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
