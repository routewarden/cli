package main_test

import (
	"os"
	"strings"
	"testing"
)

func TestCLI_ManCommand(t *testing.T) {
	stdout, _, code := runCLI(t, "man")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, ".TH RWARDEN 1") {
		t.Errorf("expected roff title .TH RWARDEN 1, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "test") || !strings.Contains(stdout, "audit") || !strings.Contains(stdout, "diff") {
		t.Errorf("manpage missing core commands")
	}

	// Test output to temp file
	tmp, err := os.CreateTemp("", "rwarden-man-*.1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	_, _, code = runCLI(t, "man", "-o", tmp.Name())
	if code != 0 {
		t.Fatalf("expected exit code 0 for man -o, got %d", code)
	}
	content, err := os.ReadFile(tmp.Name())
	if err != nil || !strings.Contains(string(content), ".TH RWARDEN 1") {
		t.Errorf("expected file %s to contain man content", tmp.Name())
	}
}

func TestCLI_CompletionCommand(t *testing.T) {
	shells := []string{"bash", "zsh", "fish", "powershell"}
	for _, sh := range shells {
		stdout, _, code := runCLI(t, "completion", sh)
		if code != 0 {
			t.Fatalf("expected exit code 0 for completion %s, got %d", sh, code)
		}
		if len(stdout) < 100 {
			t.Errorf("expected substantial completion output for %s", sh)
		}
	}

	// Unsupported shell
	_, stderr, code := runCLI(t, "completion", "unknown_shell")
	if code == 0 || !strings.Contains(stderr, "Unsupported shell") {
		t.Errorf("expected error for unknown shell, got code %d, stderr: %s", code, stderr)
	}
}

func TestCLI_AuditCommand(t *testing.T) {
	// 1. Audit clean sample
	stdout, _, code := runCLI(t, "audit", "samples/json/routewarden.json")
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean sample, got %d, out:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "Security Score:") {
		t.Errorf("expected security score in output, got:\n%s", stdout)
	}

	// 2. Audit with JSON format
	stdout, _, code = runCLI(t, "audit", "samples/json/routewarden.json", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit code 0 for json format, got %d", code)
	}
	if !strings.Contains(stdout, `"securityScore"`) {
		t.Errorf("expected json with securityScore, got:\n%s", stdout)
	}

	// 3. Audit with SARIF format
	stdout, _, code = runCLI(t, "audit", "samples/json/routewarden.json", "--format", "sarif")
	if code != 0 {
		t.Fatalf("expected exit code 0 for sarif format, got %d", code)
	}
	if !strings.Contains(stdout, `"version": "2.1.0"`) {
		t.Errorf("expected sarif output, got:\n%s", stdout)
	}

	// 4. Audit invalid config via temp file
	tmp, err := os.CreateTemp("", "bad-rw-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(`{"enabled": false, "blockPatterns": [".*"]}`)
	tmp.Close()

	stdout, _, code = runCLI(t, "audit", tmp.Name())
	if code == 0 {
		t.Errorf("expected non-zero exit code for critical security flaws, got %d", code)
	}
	if !strings.Contains(stdout, "RW-A001") || !strings.Contains(stdout, "RW-A003") {
		t.Errorf("expected RW-A001 and RW-A003 flags in output, got:\n%s", stdout)
	}
}

func TestCLI_DiffCommand(t *testing.T) {
	// 1. Identical configs
	stdout, _, code := runCLI(t, "diff", "samples/json/routewarden.json", "samples/json/routewarden.json")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout, "No differences found") {
		t.Errorf("expected no differences message, got:\n%s", stdout)
	}

	// 2. Modified candidate
	tmpBase, _ := os.CreateTemp("", "base-*.json")
	defer os.Remove(tmpBase.Name())
	_, _ = tmpBase.WriteString(`{"blockPatterns": ["(?i)\\.env", "(?i)\\.git"]}`)
	tmpBase.Close()

	tmpCandidate, _ := os.CreateTemp("", "cand-*.json")
	defer os.Remove(tmpCandidate.Name())
	_, _ = tmpCandidate.WriteString(`{"blockPatterns": ["(?i)\\.env"]}`)
	tmpCandidate.Close()

	stdout, _, code = runCLI(t, "diff", tmpBase.Name(), tmpCandidate.Name())
	if code != 0 {
		t.Fatalf("expected exit code 0 when --exit-code not set, got %d", code)
	}
	if !strings.Contains(stdout, "RELAXED") || !strings.Contains(stdout, "(?i)\\.git (removed)") {
		t.Errorf("expected RELAXED and removed .git pattern, got:\n%s", stdout)
	}

	// Test with --exit-code
	_, _, code = runCLI(t, "diff", tmpBase.Name(), tmpCandidate.Name(), "--exit-code")
	if code != 2 {
		t.Errorf("expected exit code 2 for relaxed posture with --exit-code, got %d", code)
	}
}

func TestCLI_MonitorCommand_WithFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-monitor-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	_, _ = tmp.WriteString(`{"time":"2026-10-17T11:15:02Z", "client_ip":"1.2.3.4", "verdict":"BLOCK", "path":"/.env", "matched_pattern":"(?i)\\.env"}
{"time":"2026-10-17T11:15:03Z", "client_ip":"10.0.0.1", "verdict":"ALLOW", "path":"/api/health"}
`)
	tmp.Close()

	stdout, _, code := runCLI(t, "monitor", "-f", tmp.Name(), "--verdict", "BLOCK")
	if code != 0 {
		t.Fatalf("monitor failed with code %d", code)
	}
	if !strings.Contains(stdout, "1.2.3.4") || !strings.Contains(stdout, "/.env") {
		t.Errorf("expected filtered BLOCK event in output, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "10.0.0.1") {
		t.Errorf("expected ALLOW event to be filtered out, but was present")
	}
}

func TestCLI_TUICommand_InteractiveExit(t *testing.T) {
	stdout, _, code := runCLIWithStdin(t, "exit\n", "tui")
	if code != 0 {
		t.Fatalf("tui failed with code %d", code)
	}
	if !strings.Contains(stdout, "RouteWarden Interactive Security Simulator") {
		t.Errorf("expected TUI banner, got:\n%s", stdout)
	}
}
