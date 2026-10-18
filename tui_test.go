package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestTUI_Helpers(t *testing.T) {
	captureStdout := func(fn func()) string {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		fn()

		_ = w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		return buf.String()
	}

	t.Run("printTUIBanner", func(t *testing.T) {
		cfg := engine.CreateConfig()
		out := captureStdout(func() {
			printTUIBanner("test-config.json", cfg)
		})
		if !strings.Contains(out, "RouteWarden Interactive Security Simulator") {
			t.Errorf("missing simulator header in: %s", out)
		}
		if !strings.Contains(out, "test-config.json") {
			t.Errorf("missing config name in: %s", out)
		}
	})

	t.Run("printTUIHelp", func(t *testing.T) {
		out := captureStdout(func() {
			printTUIHelp()
		})
		if !strings.Contains(out, ":method <METHOD>") || !strings.Contains(out, ":ip <address>") {
			t.Errorf("missing command explanations in: %s", out)
		}
	})

	t.Run("printTUIStatus", func(t *testing.T) {
		cfg := engine.CreateConfig()
		headers := map[string]string{
			"X-Forwarded-For": "203.0.113.1",
			"User-Agent":      "SecurityScanner",
		}
		out := captureStdout(func() {
			printTUIStatus("prod.json", "POST", "192.168.1.1", "foo=bar", "payload", headers, cfg)
		})
		if !strings.Contains(out, "prod.json") || !strings.Contains(out, "POST") || !strings.Contains(out, "192.168.1.1") {
			t.Errorf("missing environment details in: %s", out)
		}
		if !strings.Contains(out, "X-Forwarded-For: 203.0.113.1") {
			t.Errorf("missing header in: %s", out)
		}
	})

	t.Run("renderEvaluationResult blocked", func(t *testing.T) {
		res := &engine.EvaluationResult{
			Blocked:        true,
			Reason:         "Matched sensitive file extension",
			MatchedPattern: "*.env",
			MatchedTarget:  "path",
			CandidatePaths: []string{"/.env", "%2e%2e/.env"},
		}
		out := captureStdout(func() {
			renderEvaluationResult("/.env", "GET", "127.0.0.1", "", "", 403, res)
		})
		if !strings.Contains(out, "🛑 BLOCKED (HTTP Status 403)") {
			t.Errorf("missing BLOCKED banner in: %s", out)
		}
		if !strings.Contains(out, "Matched sensitive file extension") {
			t.Errorf("missing reason in: %s", out)
		}
		if !strings.Contains(out, "Candidate Paths Extracted (2)") {
			t.Errorf("missing candidate paths count in: %s", out)
		}
	})

	t.Run("renderEvaluationResult allowed", func(t *testing.T) {
		res := &engine.EvaluationResult{
			Blocked: false,
			Reason:  "Path clean, no threat rules matched",
		}
		out := captureStdout(func() {
			renderEvaluationResult("/api/health", "GET", "127.0.0.1", "", "", 403, res)
		})
		if !strings.Contains(out, "✅ ALLOWED (Request permitted to backend)") {
			t.Errorf("missing ALLOWED banner in: %s", out)
		}
	})
}
