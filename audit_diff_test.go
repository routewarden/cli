package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestPrintAuditTextReport(t *testing.T) {
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

	t.Run("zero issues report", func(t *testing.T) {
		report := &engine.AuditReport{
			ConfigFile:    "routewarden.json",
			SecurityScore: 100,
			TotalIssues:   0,
			Issues:        []engine.AuditIssue{},
		}

		out := captureStdout(func() {
			printAuditTextReport(report, false)
		})

		if !strings.Contains(out, "No issues found") {
			t.Errorf("expected 'No issues found', got: %s", out)
		}
		if !strings.Contains(out, "100/100 (EXCELLENT)") {
			t.Errorf("expected 100/100 (EXCELLENT), got: %s", out)
		}
	})

	t.Run("critical issues report", func(t *testing.T) {
		report := &engine.AuditReport{
			ConfigFile:    "vulnerable.json",
			SecurityScore: 30,
			TotalIssues:   1,
			CriticalCount: 1,
			Issues: []engine.AuditIssue{
				{
					Severity:    engine.SeverityCritical,
					Code:        "RW-SEC-001",
					Title:       "ReDoS Vulnerability Detected",
					Message:     "Pattern contains catastrophic backtracking expression",
					Pattern:     "^(a+)+$",
					Field:       "customBlockList[0]",
					Remediation: "Replace with non-backtracking regular expression",
				},
			},
		}

		out := captureStdout(func() {
			printAuditTextReport(report, false)
		})

		if !strings.Contains(out, "🛑 CRITICAL") {
			t.Errorf("expected CRITICAL badge, got: %s", out)
		}
		if !strings.Contains(out, "RW-SEC-001") || !strings.Contains(out, "^(a+)+$") {
			t.Errorf("expected issue code and pattern in output: %s", out)
		}
		if !strings.Contains(out, "Result: ❌ FAILED") {
			t.Errorf("expected Result: FAILED, got: %s", out)
		}
	})

	t.Run("warning issues with strict mode", func(t *testing.T) {
		report := &engine.AuditReport{
			ConfigFile:    "loose.json",
			SecurityScore: 80,
			TotalIssues:   1,
			WarningCount:  1,
			Issues: []engine.AuditIssue{
				{
					Severity:    engine.SeverityWarning,
					Code:        "RW-WARN-002",
					Title:       "Broad Wildcard Pattern",
					Message:     "Pattern may block legitimate requests",
					Pattern:     "*",
					Field:       "customBlockList[0]",
					Remediation: "Narrow pattern scope",
				},
			},
		}

		// Non-strict: should PASS
		outNonStrict := captureStdout(func() {
			printAuditTextReport(report, false)
		})
		if !strings.Contains(outNonStrict, "Result: ✅ PASSED") {
			t.Errorf("expected non-strict warning to pass, got: %s", outNonStrict)
		}

		// Strict: should FAIL
		outStrict := captureStdout(func() {
			printAuditTextReport(report, true)
		})
		if !strings.Contains(outStrict, "Result: ❌ FAILED (Strict mode enabled") {
			t.Errorf("expected strict warning to fail, got: %s", outStrict)
		}
	})
}

func TestPrintDiffTextReport(t *testing.T) {
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

	t.Run("identical configurations", func(t *testing.T) {
		diff := &engine.PolicyDiff{
			BaseFile:       "base.json",
			CandidateFile:  "candidate.json",
			HasDifferences: false,
		}

		out := captureStdout(func() {
			printDiffTextReport(diff)
		})

		if !strings.Contains(out, "No differences found") {
			t.Errorf("expected 'No differences found', got: %s", out)
		}
	})

	t.Run("relaxed posture diff", func(t *testing.T) {
		diff := &engine.PolicyDiff{
			BaseFile:       "prod.json",
			CandidateFile:  "stage.json",
			HasDifferences: true,
			Impact:         engine.DiffImpactRelaxed,
			ImpactReasons:  []string{"Default block rules were removed: *.env"},
			BlockPatterns: engine.SliceDiff{
				Removed: []string{"*.env", "*.git"},
				Added:   []string{"*.log"},
			},
			AllowPatterns: engine.SliceDiff{
				Added: []string{"/api/public/*"},
			},
			AllowedIPs: engine.SliceDiff{
				Removed: []string{"192.168.1.0/24"},
				Added:   []string{"10.0.0.0/8"},
			},
			TrustedProxies: engine.SliceDiff{
				Added: []string{"172.16.0.1"},
			},
			Properties: map[string]engine.ScalarDiff{
				"statusCode": {Old: 403, New: 404},
			},
		}

		out := captureStdout(func() {
			printDiffTextReport(diff)
		})

		if !strings.Contains(out, "SECURITY POSTURE IMPACT: RELAXED") {
			t.Errorf("expected RELAXED impact banner, got: %s", out)
		}
		if !strings.Contains(out, "- *.env (removed)") || !strings.Contains(out, "+ *.log (added)") {
			t.Errorf("expected block pattern changes in output: %s", out)
		}
		if !strings.Contains(out, "+ /api/public/* (added)") {
			t.Errorf("expected allow pattern changes in output: %s", out)
		}
		if !strings.Contains(out, "~ statusCode: 403 ➔ 404") {
			t.Errorf("expected property diff in output: %s", out)
		}
	})

	t.Run("hardened posture diff", func(t *testing.T) {
		diff := &engine.PolicyDiff{
			BaseFile:       "old.json",
			CandidateFile:  "new.json",
			HasDifferences: true,
			Impact:         engine.DiffImpactHardened,
			ImpactReasons:  []string{"Added 15 sensitive directory defense rules"},
			BlockPatterns: engine.SliceDiff{
				Added: []string{"/.aws/*", "/.kube/*"},
			},
		}

		out := captureStdout(func() {
			printDiffTextReport(diff)
		})

		if !strings.Contains(out, "SECURITY POSTURE IMPACT: HARDENED") {
			t.Errorf("expected HARDENED impact banner, got: %s", out)
		}
		if !strings.Contains(out, "+ /.aws/* (added)") {
			t.Errorf("expected /.aws/* in output: %s", out)
		}
	})
}
