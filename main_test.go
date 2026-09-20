package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Compile temporary binary for CLI blackbox testing
	tmpDir, err := os.MkdirTemp("", "rwarden-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	bin := filepath.Join(tmpDir, "rwarden")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if err := cmd.Run(); err != nil {
		panic("failed to build rwarden for testing: " + err.Error())
	}

	binaryPath = bin
	os.Exit(m.Run())
}

func TestCLI_Version(t *testing.T) {
	out, err := exec.Command(binaryPath, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if !strings.Contains(string(out), "rwarden version") {
		t.Errorf("expected version output, got: %s", string(out))
	}
}

func TestCLI_Schema(t *testing.T) {
	out, err := exec.Command(binaryPath, "schema").CombinedOutput()
	if err != nil {
		t.Fatalf("schema command failed: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(out, &schema); err != nil {
		t.Fatalf("schema output is not valid JSON: %v\nOutput: %s", err, string(out))
	}

	if schema["title"] != "RouteWarden Configuration" {
		t.Errorf("expected title 'RouteWarden Configuration', got %v", schema["title"])
	}
}

func TestCLI_TestCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{
			name:       "Block .env path",
			args:       []string{"test", "--path", "/.env"},
			wantOutput: "Result: 🛑 BLOCKED",
		},
		{
			name:       "Allow safe path",
			args:       []string{"test", "--path", "/public/index.html"},
			wantOutput: "Result: ✅ ALLOWED",
		},
		{
			name:       "Allow robots.txt override",
			args:       []string{"test", "--path", "/robots.txt"},
			wantOutput: "Allowlist Override",
		},
		{
			name:       "Bypass POST on default GET",
			args:       []string{"test", "--method", "POST", "--path", "/.env"},
			wantOutput: "Result: ⏭️ BYPASSED",
		},
		{
			name:       "Header smuggling detection",
			args:       []string{"test", "--path", "/dashboard", "--header", "X-Forwarded-Uri:/.env"},
			wantOutput: "Result: 🛑 BLOCKED",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(binaryPath, tc.args...).CombinedOutput()
			if err != nil {
				t.Fatalf("command failed with %v: %s", err, string(out))
			}
			if !strings.Contains(string(out), tc.wantOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tc.wantOutput, string(out))
			}
		})
	}
}

func TestCLI_ValidateCommand(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Valid configuration
	validConfig := filepath.Join(tmpDir, "valid.json")
	validContent := `{
		"enabled": true,
		"enableDefaultPatterns": true,
		"methods": ["GET", "POST"],
		"blockPatterns": ["^/secret/.*"],
		"response": {
			"mode": "json",
			"statusCode": 403
		}
	}`
	if err := os.WriteFile(validConfig, []byte(validContent), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(binaryPath, "validate", "--config", validConfig).CombinedOutput()
	if err != nil {
		t.Fatalf("expected valid config to succeed, got %v: %s", err, string(out))
	}
	if !strings.Contains(string(out), "is VALID") {
		t.Errorf("expected 'is VALID', got:\n%s", string(out))
	}

	// 2. Invalid regex pattern
	invalidConfig := filepath.Join(tmpDir, "invalid.json")
	invalidContent := `{
		"enabled": true,
		"blockPatterns": ["[invalid-regex-("]
	}`
	if err := os.WriteFile(invalidConfig, []byte(invalidContent), 0644); err != nil {
		t.Fatal(err)
	}

	out, err = exec.Command(binaryPath, "validate", "--config", invalidConfig).CombinedOutput()
	if err == nil {
		t.Errorf("expected invalid config to fail, but exited successfully: %s", string(out))
	}
	// 3. Stdin validation
	cmd := exec.Command(binaryPath, "validate", "--config", "-")
	cmd.Stdin = strings.NewReader(validContent)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected stdin valid config to succeed, got %v: %s", err, string(out))
	}
	if !strings.Contains(string(out), "is VALID") {
		t.Errorf("expected 'is VALID', got:\n%s", string(out))
	}
}
