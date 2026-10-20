package main_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditAndDiff_IntegrationCLI(t *testing.T) {
	tmpDir := t.TempDir()

	baseConfig := `{
		"enabled": true,
		"enableDefaultPatterns": true,
		"blockPatterns": [
			"(?i)^/admin/secret.*$",
			"(?i)^/internal/metrics.*$"
		],
		"allowedIps": ["127.0.0.1"]
	}`

	candidateConfigRelaxed := `{
		"enabled": true,
		"enableDefaultPatterns": true,
		"blockPatterns": [
			"(?i)^/admin/secret.*$"
		],
		"allowedIps": ["127.0.0.1", "0.0.0.0/0"]
	}`

	basePath := filepath.Join(tmpDir, "base.json")
	candidatePath := filepath.Join(tmpDir, "candidate.json")

	if err := os.WriteFile(basePath, []byte(baseConfig), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidatePath, []byte(candidateConfigRelaxed), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("audit with JSON format", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "audit", basePath, "--format", "json")
		if code != 0 {
			t.Fatalf("expected audit exit 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"securityScore":`) || !strings.Contains(stdout, `"configFile":`) {
			t.Errorf("expected valid JSON audit output: %s", stdout)
		}
	})

	t.Run("audit with SARIF format", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "audit", basePath, "--format", "sarif")
		if code != 0 {
			t.Fatalf("expected audit exit 0 for SARIF, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"$schema"`) || !strings.Contains(stdout, `"runs"`) {
			t.Errorf("expected SARIF structure in output: %s", stdout)
		}
	})

	t.Run("diff with exit-code relaxed posture returns 2", func(t *testing.T) {
		_, _, code := runCLI(t, "diff", basePath, candidatePath, "--exit-code")
		if code != 2 {
			t.Fatalf("expected exit code 2 for relaxed security posture, got %d", code)
		}
	})

	t.Run("diff with format JSON", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "diff", basePath, candidatePath, "--format", "json")
		if code != 0 {
			t.Fatalf("expected exit code 0 without --exit-code flag, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"hasDifferences": true`) {
			t.Errorf("expected hasDifferences: true in JSON diff: %s", stdout)
		}
	})

	t.Run("diff identical files with exit-code returns 0", func(t *testing.T) {
		_, _, code := runCLI(t, "diff", basePath, basePath, "--exit-code")
		if code != 0 {
			t.Fatalf("expected exit code 0 for identical files with --exit-code, got %d", code)
		}
	})

	t.Run("diff insufficient arguments returns error", func(t *testing.T) {
		_, stderr, code := runCLI(t, "diff", basePath)
		if code == 0 || !strings.Contains(stderr, "requires two configuration files") {
			t.Errorf("expected error for insufficient diff arguments, got code %d, stderr: %s", code, stderr)
		}
	})

	t.Run("diff non-existent file returns error", func(t *testing.T) {
		_, stderr, code := runCLI(t, "diff", basePath, filepath.Join(tmpDir, "missing.json"))
		if code == 0 || !strings.Contains(stderr, "Error reading candidate file") {
			t.Errorf("expected error for missing diff file, got code %d, stderr: %s", code, stderr)
		}
	})

	t.Run("audit with snake_case JSON passes", func(t *testing.T) {
		snakeConfig := `{
			"enable_default_patterns": true,
			"block_patterns": ["(?i)^/admin/secret.*$"],
			"allowed_ips": ["10.0.0.1"],
			"check_query": true
		}`
		snakePath := filepath.Join(tmpDir, "snake.json")
		if err := os.WriteFile(snakePath, []byte(snakeConfig), 0644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := runCLI(t, "audit", snakePath, "--format", "json")
		if code != 0 {
			t.Fatalf("expected audit exit 0 for snake_case config, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"criticalCount": 0`) {
			t.Errorf("expected 0 critical issues for valid snake_case config: %s", stdout)
		}
	})

	t.Run("audit from stdin with '-'", func(t *testing.T) {
		inputJSON := `{"enableDefaultPatterns": true, "blockPatterns": ["(?i)^/admin"]}`
		stdout, stderr, code := runCLIWithStdin(t, inputJSON, "audit", "-")
		if code != 0 {
			t.Fatalf("expected audit exit 0 for stdin, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "stdin") {
			t.Errorf("expected output to mention stdin, got: %s", stdout)
		}
	})

	t.Run("audit all valid response modes under strict mode", func(t *testing.T) {
		modes := []string{"captcha", "gzipbomb", "redirect", "fakesuccess", "ratelimit", "proxy", "xml", "infinitestream"}
		for _, m := range modes {
			cfgJSON := `{"enableDefaultPatterns": true, "blockPatterns": ["(?i)^/admin"], "mode": "` + m + `"}`
			cfgPath := filepath.Join(tmpDir, "mode_"+m+".json")
			if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code := runCLI(t, "audit", cfgPath, "--strict")
			if code != 0 {
				t.Fatalf("expected mode %q to pass strict audit, got code %d. stdout: %s, stderr: %s", m, code, stdout, stderr)
			}
			if strings.Contains(stdout, "RW-A012") {
				t.Errorf("expected mode %q not to trigger RW-A012 warning: %s", m, stdout)
			}
		}
	})

	t.Run("diff with stdin '-'", func(t *testing.T) {
		stdout, stderr, code := runCLIWithStdin(t, baseConfig, "diff", "-", candidatePath, "--format", "json")
		if code != 0 {
			t.Fatalf("expected diff with stdin to succeed, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, `"hasDifferences": true`) {
			t.Errorf("expected diff from stdin to report differences: %s", stdout)
		}
	})
}
