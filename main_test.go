package main_test

import (
	"encoding/json"
	"fmt"
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

func runCLI(t *testing.T, args ...string) (string, string, int) {
	return runCLIWithStdin(t, "", args...)
}

func runCLIWithStdin(t *testing.T, stdin string, args ...string) (string, string, int) {
	cmd := exec.Command(binaryPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to execute %s %v: %v", binaryPath, args, err)
		}
	}
	return stdout.String(), stderr.String(), exitCode
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
		stdin      string
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
		{
			name: "Custom response statusCode and mode from config",
			args: []string{
				"test",
				"--config", "-",
				"--path", "/.env",
			},
			stdin: `{
				"enabled": true,
				"enableDefaultPatterns": true,
				"methods": ["GET", "POST"],
				"response": {
					"mode": "rateLimitChallenge",
					"statusCode": 429,
					"retryAfterSeconds": 300
				}
			}`,
			wantOutput: "Result: 🛑 BLOCKED (HTTP Status 429, Mode: rateLimitChallenge)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out string
			var err string
			var code int
			if tc.stdin != "" {
				out, err, code = runCLIWithStdin(t, tc.stdin, tc.args...)
			} else {
				out, err, code = runCLI(t, tc.args...)
			}
			combined := out + err
			if code != 0 {
				t.Fatalf("command failed with exit code %d: %s", code, combined)
			}
			if !strings.Contains(combined, tc.wantOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tc.wantOutput, combined)
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

func TestCLI_GenerateCommand(t *testing.T) {
	// Base config used across most sub-tests
	baseConfig := `{
		"enabled": true,
		"enableDefaultPatterns": true,
		"pathPatterns": ["(?i)^/admin(/.*)?$"],
		"allowPatterns": ["(?i)^/admin/public(/.*)?$"],
		"allowedIps": ["192.168.1.1", "10.0.0.0/8"],
		"methods": ["GET", "POST"],
		"checkQuery": true,
		"response": {
			"mode": "json",
			"statusCode": 403,
			"body": "{\"error\":\"Forbidden\"}"
		}
	}`

	t.Run("traefik-labels via stdin", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik-labels", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		if !strings.Contains(strOut, "traefik.http.middlewares.warden.plugin.routewarden.enabled=true") {
			t.Errorf("missing warden middleware label:\n%s", strOut)
		}
		if !strings.Contains(strOut, "pathPatterns=(?i)^/admin(/.*)?$") {
			t.Errorf("missing pathPatterns in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowPatterns=(?i)^/admin/public(/.*)?$") {
			t.Errorf("missing allowPatterns in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowedIps=192.168.1.1,10.0.0.0/8") {
			t.Errorf("missing allowedIps in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "methods=GET,POST") {
			t.Errorf("missing methods in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "checkQuery=true") {
			t.Errorf("missing checkQuery in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "response.mode=json") {
			t.Errorf("missing response.mode in traefik-labels output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "response.statusCode=403") {
			t.Errorf("missing response.statusCode in traefik-labels output:\n%s", strOut)
		}
		// Body with quotes should be escaped
		if !strings.Contains(strOut, "response.body=") {
			t.Errorf("missing response.body in traefik-labels output:\n%s", strOut)
		}
	})

	t.Run("traefik YAML via stdin", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		// Must be valid YAML structure
		if !strings.Contains(strOut, "http:") {
			t.Errorf("missing 'http:' section in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "middlewares:") {
			t.Errorf("missing 'middlewares:' section in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "plugin:") {
			t.Errorf("missing 'plugin:' section in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "enabled: true") {
			t.Errorf("missing 'enabled: true' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "enableDefaultPatterns: true") {
			t.Errorf("missing 'enableDefaultPatterns: true' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "pathPatterns:") {
			t.Errorf("missing 'pathPatterns:' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowPatterns:") {
			t.Errorf("missing 'allowPatterns:' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowedIps:") {
			t.Errorf("missing 'allowedIps:' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "methods:") {
			t.Errorf("missing 'methods:' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "checkQuery: true") {
			t.Errorf("missing 'checkQuery: true' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "mode: json") {
			t.Errorf("missing 'mode: json' in traefik YAML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "statusCode: 403") {
			t.Errorf("missing 'statusCode: 403' in traefik YAML:\n%s", strOut)
		}
	})

	t.Run("caddy via stdin", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "caddy", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		if !strings.Contains(strOut, "routewarden {") {
			t.Errorf("missing 'routewarden {' block in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "block_pattern") {
			t.Errorf("missing 'block_pattern' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allow_pattern") {
			t.Errorf("missing 'allow_pattern' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowed_ip 192.168.1.1") {
			t.Errorf("missing 'allowed_ip' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "methods GET POST") {
			t.Errorf("missing 'methods GET POST' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "check_query") {
			t.Errorf("missing 'check_query' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "response {") {
			t.Errorf("missing 'response {' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "mode json") {
			t.Errorf("missing 'mode json' in Caddyfile:\n%s", strOut)
		}
		if !strings.Contains(strOut, "status 403") {
			t.Errorf("missing 'status 403' in Caddyfile:\n%s", strOut)
		}
	})

	t.Run("nginx lua via stdin", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "nginx", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		if !strings.Contains(strOut, "local routewarden_config") {
			t.Errorf("missing 'local routewarden_config' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "enabled = true") {
			t.Errorf("missing 'enabled = true' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "block_patterns") {
			t.Errorf("missing 'block_patterns' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allow_patterns") {
			t.Errorf("missing 'allow_patterns' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "allowed_ips") {
			t.Errorf("missing 'allowed_ips' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "methods") {
			t.Errorf("missing 'methods' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "check_query = true") {
			t.Errorf("missing 'check_query = true' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "mode = \"json\"") {
			t.Errorf("missing 'mode = \"json\"' in Nginx Lua output:\n%s", strOut)
		}
		if !strings.Contains(strOut, "status_code = 403") {
			t.Errorf("missing 'status_code = 403' in Nginx Lua output:\n%s", strOut)
		}
	})

	t.Run("generate from file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "rw.json")
		if err := os.WriteFile(cfgFile, []byte(baseConfig), 0644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(binaryPath, "generate", "--target", "traefik-labels", "--config", cfgFile).CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate from file to succeed, got %v: %s", err, string(out))
		}
		if !strings.Contains(string(out), "traefik.http.middlewares.warden.plugin.routewarden.enabled=true") {
			t.Errorf("missing middleware label from file-based config:\n%s", string(out))
		}
	})

	t.Run("traefik-toml via stdin", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik-toml", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate traefik-toml to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		if !strings.Contains(strOut, "[http.middlewares.routewarden.plugin.routewarden]") {
			t.Errorf("missing TOML section header:\n%s", strOut)
		}
		if !strings.Contains(strOut, "enabled = true") {
			t.Errorf("missing 'enabled = true' in TOML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "pathPatterns = [") {
			t.Errorf("missing 'pathPatterns = [' in TOML:\n%s", strOut)
		}
		if !strings.Contains(strOut, "[http.middlewares.routewarden.plugin.routewarden.response]") {
			t.Errorf("missing TOML response section:\n%s", strOut)
		}
	})

	t.Run("traefik-yaml via explicit target", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik-yaml", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate traefik-yaml to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		if !strings.Contains(strOut, "http:") || !strings.Contains(strOut, "middlewares:") {
			t.Errorf("missing expected YAML structure in traefik-yaml:\n%s", strOut)
		}
	})

	t.Run("invalid target fails", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "nginx-invalid", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("expected non-zero exit for invalid target, but it succeeded:\n%s", string(out))
		}
		if !strings.Contains(string(out), "unsupported target") {
			t.Errorf("expected 'unsupported target' in error output, got:\n%s", string(out))
		}
	})

	t.Run("missing --target flag fails", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--config", "-")
		cmd.Stdin = strings.NewReader(baseConfig)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("expected non-zero exit when --target is missing:\n%s", string(out))
		}
		if !strings.Contains(string(out), "--target") {
			t.Errorf("expected error mentioning '--target', got:\n%s", string(out))
		}
	})

	t.Run("malformed JSON config fails", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik", "--config", "-")
		cmd.Stdin = strings.NewReader(`{ "enabled": true, BROKEN`)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("expected non-zero exit for malformed JSON:\n%s", string(out))
		}
	})

	t.Run("nonexistent config file fails", func(t *testing.T) {
		out, err := exec.Command(binaryPath, "generate", "--target", "traefik", "--config", "/nonexistent/path/config.json").CombinedOutput()
		if err == nil {
			t.Errorf("expected non-zero exit for nonexistent config file:\n%s", string(out))
		}
	})

	t.Run("minimal config (defaults only)", func(t *testing.T) {
		minimalConfig := `{"enabled": true}`
		for _, target := range []string{"traefik", "traefik-labels", "caddy", "nginx"} {
			target := target
			t.Run(target, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "generate", "--target", target, "--config", "-")
				cmd.Stdin = strings.NewReader(minimalConfig)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("[%s] expected generate with minimal config to succeed, got %v: %s", target, err, string(out))
				}
				if len(out) == 0 {
					t.Errorf("[%s] expected non-empty output for minimal config", target)
				}
			})
		}
	})

	t.Run("disabled config generates enabled=false", func(t *testing.T) {
		disabledConfig := `{"enabled": false, "enableDefaultPatterns": false}`
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik", "--config", "-")
		cmd.Stdin = strings.NewReader(disabledConfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed for disabled config, got %v: %s", err, string(out))
		}
		if !strings.Contains(string(out), "enabled: false") {
			t.Errorf("expected 'enabled: false' in output, got:\n%s", string(out))
		}
		if !strings.Contains(string(out), "enableDefaultPatterns: false") {
			t.Errorf("expected 'enableDefaultPatterns: false' in output, got:\n%s", string(out))
		}
	})

	t.Run("YAML single-quote escaping for patterns with apostrophes", func(t *testing.T) {
		// Single quotes in patterns must be doubled in YAML single-quoted scalars
		configWithQuote := `{
			"enabled": true,
			"pathPatterns": ["(?i)^/it's-admin(/.*)?$"]
		}`
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik", "--config", "-")
		cmd.Stdin = strings.NewReader(configWithQuote)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		// The YAML encoder should double the single quote
		if !strings.Contains(string(out), "''") {
			t.Errorf("expected doubled single-quote in YAML output, got:\n%s", string(out))
		}
	})

	t.Run("traefik-labels body with embedded quotes is escaped", func(t *testing.T) {
		cfgWithQuotes := `{
			"enabled": true,
			"response": {
				"mode": "json",
				"statusCode": 403,
				"body": "{\"error\":\"access denied\"}"
			}
		}`
		cmd := exec.Command(binaryPath, "generate", "--target", "traefik-labels", "--config", "-")
		cmd.Stdin = strings.NewReader(cfgWithQuotes)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected generate to succeed, got %v: %s", err, string(out))
		}
		strOut := string(out)
		// Embedded double-quotes must be backslash-escaped so the label value is shell-safe
		if !strings.Contains(strOut, `response.body=`) {
			t.Errorf("missing response.body label in output:\n%s", strOut)
		}
		if strings.Contains(strOut, `body={"error"`) {
			t.Errorf("double-quotes in body label were not escaped:\n%s", strOut)
		}
	})

	t.Run("multiple pathPatterns and allowPatterns all appear", func(t *testing.T) {
		multiPatternConfig := `{
			"enabled": true,
			"pathPatterns": ["^/secret/.*$", "^/private/.*$"],
			"allowPatterns": ["^/public/.*$", "^/assets/.*$"]
		}`
		for _, target := range []string{"traefik", "traefik-labels", "caddy", "nginx"} {
			target := target
			t.Run(target, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "generate", "--target", target, "--config", "-")
				cmd.Stdin = strings.NewReader(multiPatternConfig)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("[%s] expected generate to succeed, got %v: %s", target, err, string(out))
				}
				strOut := string(out)
				if !strings.Contains(strOut, "/secret/") {
					t.Errorf("[%s] missing /secret/ pattern in output:\n%s", target, strOut)
				}
				if !strings.Contains(strOut, "/private/") {
					t.Errorf("[%s] missing /private/ pattern in output:\n%s", target, strOut)
				}
				if !strings.Contains(strOut, "/public/") {
					t.Errorf("[%s] missing /public/ allow pattern in output:\n%s", target, strOut)
				}
				if !strings.Contains(strOut, "/assets/") {
					t.Errorf("[%s] missing /assets/ allow pattern in output:\n%s", target, strOut)
				}
			})
		}
	})

	t.Run("blockPatterns field also appears in output", func(t *testing.T) {
		// blockPatterns and pathPatterns are merged in all targets
		blockConfig := `{
			"enabled": true,
			"blockPatterns": ["^/legacy-secret/.*$"]
		}`
		for _, target := range []string{"traefik", "traefik-labels", "caddy", "nginx"} {
			target := target
			t.Run(target, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "generate", "--target", target, "--config", "-")
				cmd.Stdin = strings.NewReader(blockConfig)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("[%s] expected generate to succeed, got %v: %s", target, err, string(out))
				}
				if !strings.Contains(string(out), "/legacy-secret/") {
					t.Errorf("[%s] missing blockPatterns content in output:\n%s", target, string(out))
				}
			})
		}
	})

	t.Run("CIDR and single IP in allowedIps", func(t *testing.T) {
		ipConfig := `{
			"enabled": true,
			"allowedIps": ["10.0.0.1", "172.16.0.0/12", "::1"]
		}`
		for _, target := range []string{"traefik", "traefik-labels", "caddy", "nginx"} {
			target := target
			t.Run(target, func(t *testing.T) {
				cmd := exec.Command(binaryPath, "generate", "--target", target, "--config", "-")
				cmd.Stdin = strings.NewReader(ipConfig)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("[%s] expected generate to succeed, got %v: %s", target, err, string(out))
				}
				strOut := string(out)
				if !strings.Contains(strOut, "10.0.0.1") {
					t.Errorf("[%s] missing single IP in output:\n%s", target, strOut)
				}
				if !strings.Contains(strOut, "172.16.0.0/12") {
					t.Errorf("[%s] missing CIDR in output:\n%s", target, strOut)
				}
				if !strings.Contains(strOut, "::1") {
					t.Errorf("[%s] missing IPv6 loopback in output:\n%s", target, strOut)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// CLI UX / routing tests
// ---------------------------------------------------------------------------

func TestCLI_HelpAndUsage(t *testing.T) {
	for _, flagName := range []string{"help", "--help", "-h"} {
		t.Run(flagName, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, flagName)
			if code != 0 {
				t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
			}
			if !strings.Contains(stdout, "Usage:") || !strings.Contains(stdout, "rwarden <command>") {
				t.Fatalf("expected usage output, got: %s", stdout)
			}
		})
	}

	t.Run("No args prints usage and exits non-zero", func(t *testing.T) {
		stdout, stderr, code := runCLI(t)
		if code == 0 {
			t.Fatalf("expected non-zero exit for no args, got 0")
		}
		if !strings.Contains(stdout, "Usage:") && !strings.Contains(stderr, "Usage:") {
			t.Fatalf("expected usage output on no args, stdout: %s, stderr: %s", stdout, stderr)
		}
	})

	t.Run("Unknown command prints error and exits non-zero", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "foobar")
		if code == 0 {
			t.Fatalf("expected non-zero exit for unknown command, got 0")
		}
		if !strings.Contains(stderr, "Unknown command: foobar") {
			t.Fatalf("expected 'Unknown command: foobar' in stderr, got: %s", stderr)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Fatalf("expected usage in stdout, got: %s", stdout)
		}
	})
}

func TestCLI_VersionAliases(t *testing.T) {
	for _, alias := range []string{"version", "--version", "-v"} {
		t.Run(alias, func(t *testing.T) {
			stdout, _, code := runCLI(t, alias)
			if code != 0 {
				t.Fatalf("expected code 0, got %d", code)
			}
			if !strings.Contains(stdout, "rwarden version") {
				t.Fatalf("expected version info, got: %s", stdout)
			}
		})
	}
}

func TestCLI_TestCommandEdgeCases(t *testing.T) {
	t.Run("Missing --path flag errors and exits non-zero", func(t *testing.T) {
		_, stderr, code := runCLI(t, "test")
		if code == 0 {
			t.Fatalf("expected non-zero exit, got 0")
		}
		if !strings.Contains(stderr, "Error: --path <url-path> is required") {
			t.Fatalf("expected path required error, got: %s", stderr)
		}
	})

	t.Run("Query string inspection blocks malicious query param", func(t *testing.T) {
		stdout, _, code := runCLI(t, "test", "--path", "/search", "--query", "file=../../.env")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Fatalf("expected blocked result for malicious query, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "query_blocked") {
			t.Fatalf("expected reason query_blocked, got:\n%s", stdout)
		}
	})

	t.Run("Disabling check-query allows malicious query", func(t *testing.T) {
		stdout, _, code := runCLI(t, "test", "--path", "/search", "--query", "file=../../.env", "--check-query=false")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "Result: ✅ ALLOWED") {
			t.Fatalf("expected allowed result when check-query=false, got:\n%s", stdout)
		}
	})

	t.Run("Header flag without colon does not panic", func(t *testing.T) {
		stdout, _, code := runCLI(t, "test", "--path", "/index.html", "--header", "MalformedHeaderNoColon")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "Result: ✅ ALLOWED") {
			t.Fatalf("expected allowed result, got:\n%s", stdout)
		}
	})

	t.Run("Case-insensitive HTTP method", func(t *testing.T) {
		stdout, _, code := runCLI(t, "test", "--path", "/.env", "--method", "get")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "GET /.env") {
			t.Fatalf("expected uppercased GET in output, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Fatalf("expected blocked result, got:\n%s", stdout)
		}
	})

	t.Run("Client IP whitelisting via --ip", func(t *testing.T) {
		cfgJSON := `{
			"allowedIps": ["10.0.0.1", "192.168.0.0/16"]
		}`
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "routewarden.json")
		if err := os.WriteFile(cfgFile, []byte(cfgJSON), 0644); err != nil {
			t.Fatal(err)
		}

		// Blocked without IP
		stdout, _, code := runCLI(t, "test", "--config", cfgFile, "--path", "/.env")
		if code != 0 || !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Fatalf("expected blocked without matching IP, got:\n%s", stdout)
		}

		// Allowed with single whitelisted IP
		stdout, _, code = runCLI(t, "test", "--config", cfgFile, "--path", "/.env", "--ip", "10.0.0.1")
		if code != 0 || !strings.Contains(stdout, "Result: ✅ ALLOWED") || !strings.Contains(stdout, "Whitelisted client IP") {
			t.Fatalf("expected allowed with whitelisted IP, got:\n%s", stdout)
		}

		// Allowed with CIDR range IP
		stdout, _, code = runCLI(t, "test", "--config", cfgFile, "--path", "/.env", "--ip", "192.168.5.50")
		if code != 0 || !strings.Contains(stdout, "Result: ✅ ALLOWED") || !strings.Contains(stdout, "Whitelisted client IP") {
			t.Fatalf("expected allowed with CIDR matching IP, got:\n%s", stdout)
		}
	})
}

func TestCLI_ValidateCommandEdgeCases(t *testing.T) {
	t.Run("Missing --config flag on terminal exits non-zero", func(t *testing.T) {
		_, stderr, code := runCLI(t, "validate")
		if code == 0 {
			t.Fatalf("expected non-zero exit, got 0")
		}
		if !strings.Contains(stderr, "Error: --config <filepath> or stdin is required") {
			t.Fatalf("expected error message, got: %s", stderr)
		}
	})

	t.Run("Nonexistent file fails", func(t *testing.T) {
		_, stderr, code := runCLI(t, "validate", "--config", "/nonexistent/path/routewarden.json")
		if code == 0 {
			t.Fatalf("expected non-zero exit, got 0")
		}
		if !strings.Contains(stderr, "Error reading config file") {
			t.Fatalf("expected reading error, got: %s", stderr)
		}
	})

	t.Run("Valid full config shows detailed breakdown", func(t *testing.T) {
		cfgJSON := `{
			"enabled": true,
			"methods": ["GET", "POST"],
			"blockPatterns": ["^/admin.*"],
			"allowPatterns": ["^/admin/login$"],
			"checkHeaders": ["X-Forwarded-Uri"]
		}`
		stdout, stderr, code := runCLIWithStdin(t, cfgJSON, "validate")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "VALID") {
			t.Fatalf("expected VALID in output, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Custom block patterns: 1") {
			t.Fatalf("expected 'Custom block patterns: 1', got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Custom allow patterns: 1") {
			t.Fatalf("expected 'Custom allow patterns: 1', got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Monitored headers: [X-Forwarded-Uri]") {
			t.Fatalf("expected monitored headers, got:\n%s", stdout)
		}
	})

	t.Run("Invalid regex pattern fails validation", func(t *testing.T) {
		invalidJSON := `{"blockPatterns": ["([a-z"]}`
		_, stderr, code := runCLIWithStdin(t, invalidJSON, "validate")
		if code == 0 {
			t.Fatalf("expected non-zero exit on invalid regex, got 0")
		}
		if !strings.Contains(stderr, "Validation FAILED") {
			t.Fatalf("expected 'Validation FAILED', got: %s", stderr)
		}
	})
}

func TestCLI_SandboxCommand(t *testing.T) {
	t.Run("sandbox --help", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "sandbox", "--help")
		if code != 0 {
			t.Fatalf("expected code 0 for sandbox --help, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Usage of sandbox:") && !strings.Contains(stderr, "Usage of sandbox:") {
			t.Fatalf("expected 'Usage of sandbox:', got stdout: %s, stderr: %s", stdout, stderr)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "-target") {
			t.Errorf("missing '-target' in help output:\n%s", combined)
		}
		if !strings.Contains(combined, "-print-config") {
			t.Errorf("missing '-print-config' in help output:\n%s", combined)
		}
		if !strings.Contains(combined, "-plugin-version") {
			t.Errorf("missing '-plugin-version' in help output:\n%s", combined)
		}
		if !strings.Contains(combined, "-plugin-path") {
			t.Errorf("missing '-plugin-path' in help output:\n%s", combined)
		}
	})

	t.Run("missing --target flag errors", func(t *testing.T) {
		_, stderr, code := runCLI(t, "sandbox")
		if code == 0 {
			t.Fatalf("expected non-zero exit when --target is missing, got 0")
		}
		if !strings.Contains(stderr, "--target <traefik|caddy|nginx> is required") {
			t.Fatalf("expected missing target error, got: %s", stderr)
		}
	})

	t.Run("unsupported target errors", func(t *testing.T) {
		_, stderr, code := runCLI(t, "sandbox", "--target", "envoy")
		if code == 0 {
			t.Fatalf("expected non-zero exit for unsupported target, got 0")
		}
		if !strings.Contains(stderr, "unsupported target \"envoy\"") {
			t.Fatalf("expected unsupported target error, got: %s", stderr)
		}
	})

	cfgJSON := `{
		"enabled": true,
		"methods": ["GET", "POST"],
		"response": {
			"mode": "rateLimitChallenge",
			"statusCode": 429
		}
	}`

	for _, target := range []string{"traefik", "caddy", "nginx"} {
		target := target
		t.Run(fmt.Sprintf("dry-run with --print-config for %s", target), func(t *testing.T) {
			stdout, stderr, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", target, "--dry-run", "--print-config")
			if code != 0 {
				t.Fatalf("[%s] expected code 0, got %d. stderr: %s", target, code, stderr)
			}
			if !strings.Contains(stdout, fmt.Sprintf("[%s Configuration Generated by RouteWarden]", strings.ToUpper(target))) {
				t.Errorf("[%s] missing config header in output:\n%s", target, stdout)
			}
			if !strings.Contains(stdout, "rateLimitChallenge") {
				t.Errorf("[%s] missing 'rateLimitChallenge' in printed config:\n%s", target, stdout)
			}
			if !strings.Contains(stdout, "[Dry Run] Docker command for "+target) {
				t.Errorf("[%s] missing dry-run message in output:\n%s", target, stdout)
			}
			if !strings.Contains(stdout, "docker run --rm") {
				t.Errorf("[%s] missing docker run command in output:\n%s", target, stdout)
			}
		})
	}

	t.Run("dry-run with custom port and image override", func(t *testing.T) {
		stdout, _, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "caddy", "--port", "9090", "--image", "my-custom-caddy:latest", "--dry-run")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "-p 9090:8080") {
			t.Errorf("expected port mapping 9090:8080, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "my-custom-caddy:latest") {
			t.Errorf("expected custom image override, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with --plugin-version for traefik", func(t *testing.T) {
		stdout, _, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "traefik", "--plugin-version", "v1.2.0", "--dry-run")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "--experimental.plugins.routewarden.version=v1.2.0") {
			t.Errorf("expected experimental plugin version in traefik command, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with --plugin-path for traefik", func(t *testing.T) {
		stdout, _, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "traefik", "--plugin-path", "/tmp/traefik-warden", "--dry-run")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "/plugins-local/src/github.com/routewarden/traefik-warden:ro") {
			t.Errorf("expected local plugin volume mount for traefik, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "--experimental.localplugins.routewarden.modulename=github.com/routewarden/traefik-warden") {
			t.Errorf("expected localplugins flag in traefik command, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with --plugin-version for caddy", func(t *testing.T) {
		stdout, _, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "caddy", "--plugin-version", "v1.0.5", "--dry-run")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "ghcr.io/routewarden/caddy-warden:v1.0.5") {
			t.Errorf("expected caddy plugin image override with version, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with --plugin-version and --plugin-path for nginx", func(t *testing.T) {
		stdout, _, code := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "nginx", "--plugin-version", "v1.1.0", "--dry-run")
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
		if !strings.Contains(stdout, "ghcr.io/routewarden/nginx-warden:v1.1.0") {
			t.Errorf("expected nginx plugin image override with version, got:\n%s", stdout)
		}

		stdoutPath, _, codePath := runCLIWithStdin(t, cfgJSON, "sandbox", "--target", "nginx", "--plugin-path", "/tmp/nginx-warden", "--dry-run")
		if codePath != 0 {
			t.Fatalf("expected code 0, got %d", codePath)
		}
		if !strings.Contains(stdoutPath, ":/usr/local/openresty/site/lualib/resty/routewarden:ro") {
			t.Errorf("expected local lua volume mount for nginx, got:\n%s", stdoutPath)
		}
	})

	t.Run("dry-run with traefik.toml and auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		tomlPath := filepath.Join(tmpDir, "traefik.toml")
		tomlContent := `[http.middlewares.shield.plugin.routewarden]
  enabled = true
  pathPatterns = ["(?i)^/admin.*$"]
`
		if err := os.WriteFile(tomlPath, []byte(tomlContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", tomlPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "--providers.file.filename=/etc/traefik/dynamic.toml") {
			t.Errorf("expected dynamic.toml provider filename in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, ":/etc/traefik:ro") {
			t.Errorf("expected dynamic.toml volume mount in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, "TRAEFIK Configuration Generated by RouteWarden") {
			t.Errorf("expected auto-detected TRAEFIK header in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with traefik.yaml and auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		yamlPath := filepath.Join(tmpDir, "traefik.yaml")
		yamlContent := `http:
  middlewares:
    shield:
      plugin:
        routewarden:
          enabled: true
`
		if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", yamlPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "--providers.file.filename=/etc/traefik/dynamic.yml") {
			t.Errorf("expected dynamic.yml provider in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, "TRAEFIK Configuration Generated by RouteWarden") {
			t.Errorf("expected auto-detected TRAEFIK header in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with docker-compose.yaml labels auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		composePath := filepath.Join(tmpDir, "docker-compose.yaml")
		composeContent := `services:
  app:
    image: nginx
    labels:
      - "traefik.enable=true"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.enabled=true"
      - "traefik.http.middlewares.my-shield.plugin.routewarden.response.statusCode=401"
`
		if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", composePath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "my-shield:") {
			t.Errorf("expected converted my-shield middleware in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, "statusCode: 401") {
			t.Errorf("expected statusCode 401 in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with inline --labels flag", func(t *testing.T) {
		labels := "traefik.http.middlewares.inline-warden.plugin.routewarden.enabled=true,traefik.http.middlewares.inline-warden.plugin.routewarden.response.statusCode=429"
		stdout, stderr, code := runCLI(t, "sandbox", "--labels", labels, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "inline-warden:") {
			t.Errorf("expected converted inline-warden middleware in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, "statusCode: 429") {
			t.Errorf("expected statusCode 429 in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with Caddyfile and auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		caddyPath := filepath.Join(tmpDir, "Caddyfile")
		caddyContent := `:8080 {
    routewarden {
        methods GET
    }
    respond "OK" 200
}
`
		if err := os.WriteFile(caddyPath, []byte(caddyContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", caddyPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "CADDY Configuration Generated by RouteWarden") {
			t.Errorf("expected CADDY header in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, ":/etc/caddy/Caddyfile:ro") {
			t.Errorf("expected Caddyfile mount in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with nginx.conf and auto-detection", func(t *testing.T) {
		tmpDir := t.TempDir()
		nginxPath := filepath.Join(tmpDir, "nginx.conf")
		nginxContent := `worker_processes 1;
events { worker_connections 1024; }
http {
    server {
        listen 8080;
        location / {
            access_by_lua_block {
                require("resty.routewarden")
            }
        }
    }
}
`
		if err := os.WriteFile(nginxPath, []byte(nginxContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", nginxPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "NGINX Configuration Generated by RouteWarden") {
			t.Errorf("expected NGINX header in output:\n%s", stdout)
		}
		if !strings.Contains(stdout, ":/usr/local/openresty/nginx/conf/nginx.conf:ro") {
			t.Errorf("expected nginx.conf mount in output:\n%s", stdout)
		}
	})

	t.Run("dry-run with complete traefik yaml containing backend service url", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "traefik.yaml")
		cfgContent := "http:\n" +
			"  routers:\n" +
			"    prod-app:\n" +
			"      rule: \"Host(`app.internal`)\"\n" +
			"      entryPoints:\n" +
			"        - websecure\n" +
			"      middlewares:\n" +
			"        - routewarden\n" +
			"      service: backend-service\n" +
			"  services:\n" +
			"    backend-service:\n" +
			"      loadBalancer:\n" +
			"        servers:\n" +
			"          - url: \"http://10.0.1.20:8080\"\n"
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", cfgPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "service: ping@internal") {
			t.Errorf("expected router service to be ping@internal, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "- web") {
			t.Errorf("expected web entrypoint to be injected, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Host(`app.internal`) || Host(`127.0.0.1`) || Host(`localhost`)") {
			t.Errorf("expected Host rule loopback expansion, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with complete caddyfile containing reverse_proxy to external service", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "Caddyfile")
		cfgContent := `app.internal.domain {
    routewarden {
        deny_paths /.env
    }
    reverse_proxy http://app-upstream:8080
}
`
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", cfgPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, ":8080, app.internal.domain {") {
			t.Errorf("expected :8080 port injection in Caddyfile, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "order routewarden first") {
			t.Errorf("expected order routewarden first in Caddyfile, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "auto_https off") {
			t.Errorf("expected auto_https off in Caddyfile, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "respond \"OK: Upstream Passed (RouteWarden Sandbox)\" 200") {
			t.Errorf("expected reverse_proxy replacement with mock responder, got:\n%s", stdout)
		}
	})

	t.Run("dry-run with complete nginx.conf containing upstream hostnames and proxy_pass", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "nginx.conf")
		cfgContent := `user nginx;
worker_processes 1;
events { worker_connections 1024; }
http {
    upstream backend_pool {
        server backend1.company.local:8080;
    }
    server {
        listen 80;
        listen 443 ssl;
        ssl_certificate /etc/ssl/cert.pem;
        location / {
            access_by_lua_block {
                require("resty.routewarden")
            }
            proxy_pass http://backend_pool;
        }
    }
}
`
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
			t.Fatal(err)
		}

		stdout, stderr, code := runCLI(t, "sandbox", "--config", cfgPath, "--dry-run", "--print-config")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "# user directive disabled in sandbox;") {
			t.Errorf("expected user directive to be commented out, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "server 127.0.0.1:8080 down;") {
			t.Errorf("expected upstream server hostname to be neutralized, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "content_by_lua_block { ngx.header[\"Content-Type\"] = \"text/plain\"; ngx.say(\"OK: Upstream Passed (RouteWarden Sandbox)\") }") {
			t.Errorf("expected proxy_pass to be replaced with mock content block, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "# ssl_certificate disabled in sandbox;") {
			t.Errorf("expected ssl_certificate to be commented out, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "listen 8080;") {
			t.Errorf("expected listen 8080; in server block, got:\n%s", stdout)
		}
	})

	t.Run("dry-run against sample directory files", func(t *testing.T) {
		sampleTests := []struct {
			path       string
			target     string
			wantHeader string
			wantMount  string
		}{
			{
				path:       "samples/traefik/dynamic.yml",
				wantHeader: "TRAEFIK Configuration Generated by RouteWarden",
				wantMount:  ":/etc/traefik:ro",
			},
			{
				path:       "samples/traefik/dynamic.toml",
				wantHeader: "TRAEFIK Configuration Generated by RouteWarden",
				wantMount:  ":/etc/traefik:ro",
			},
			{
				path:       "samples/traefik/docker-compose.yaml",
				wantHeader: "TRAEFIK Configuration Generated by RouteWarden",
				wantMount:  ":/etc/traefik:ro",
			},
			{
				path:       "samples/caddy/Caddyfile",
				wantHeader: "CADDY Configuration Generated by RouteWarden",
				wantMount:  "Caddyfile:/etc/caddy/Caddyfile:ro",
			},
			{
				path:       "samples/nginx/nginx.conf",
				wantHeader: "NGINX Configuration Generated by RouteWarden",
				wantMount:  "nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro",
			},
			{
				path:       "samples/json/routewarden.json",
				target:     "traefik",
				wantHeader: "TRAEFIK Configuration Generated by RouteWarden",
				wantMount:  ":/etc/traefik:ro",
			},
		}

		for _, st := range sampleTests {
			st := st
			t.Run(st.path, func(t *testing.T) {
				args := []string{"sandbox", "--config", st.path, "--dry-run", "--print-config"}
				if st.target != "" {
					args = append(args, "--target", st.target)
				}
				stdout, stderr, code := runCLI(t, args...)
				if code != 0 {
					t.Fatalf("[%s] expected code 0, got %d. stderr: %s", st.path, code, stderr)
				}
				if !strings.Contains(stdout, st.wantHeader) {
					t.Errorf("[%s] missing expected header %q in output:\n%s", st.path, st.wantHeader, stdout)
				}
				if !strings.Contains(stdout, st.wantMount) {
					t.Errorf("[%s] missing expected volume mount %q in output:\n%s", st.path, st.wantMount, stdout)
				}
			})
		}
	})
}

func TestCLI_CleanupCommand(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not accessible in test sandbox; skipping cleanup execution")
	}
	stdout, stderr, code := runCLI(t, "cleanup")
	if code != 0 {
		t.Fatalf("expected code 0 from cleanup, got %d. stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Cleaning up RouteWarden sandbox containers") {
		t.Errorf("missing expected cleanup banner, got: %s", stdout)
	}

	// Test alias: sandbox cleanup
	stdout, stderr, code = runCLI(t, "sandbox", "cleanup")
	if code != 0 {
		t.Fatalf("expected code 0 from sandbox cleanup, got %d. stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Cleaning up RouteWarden sandbox containers") {
		t.Errorf("missing expected banner from sandbox cleanup, got: %s", stdout)
	}
}

func TestCLI_PositionalAndFlagAliases(t *testing.T) {
	sampleJSON := filepath.Join("samples", "json", "routewarden.json")
	sampleCaddy := filepath.Join("samples", "caddy", "Caddyfile")

	t.Run("test command positional path", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "test", "/.env")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Errorf("expected blocked result for positional /.env, got:\n%s", stdout)
		}
	})

	t.Run("test command -X and -m method aliases", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "test", "-X", "POST", "/.env")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Testing: POST /.env") {
			t.Errorf("missing POST method in output:\n%s", stdout)
		}

		stdout, stderr, code = runCLI(t, "test", "-m", "DELETE", "/.env")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Testing: DELETE /.env") {
			t.Errorf("missing DELETE method in output:\n%s", stdout)
		}
	})

	t.Run("test command -H repeatable header flag", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "test", "-H", "X-Forwarded-Uri: /.env", "/api/public")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Errorf("expected blocked result for -H header injection, got:\n%s", stdout)
		}
	})

	t.Run("test command -q query flag", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "test", "-q", "file=../../.env", "/search")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "Result: 🛑 BLOCKED") {
			t.Errorf("expected blocked result for -q query inspection, got:\n%s", stdout)
		}
	})

	t.Run("validate command positional config and -c alias", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "validate", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "is VALID") {
			t.Errorf("expected valid output for positional config, got:\n%s", stdout)
		}

		stdout, stderr, code = runCLI(t, "validate", "-c", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "is VALID") {
			t.Errorf("expected valid output for -c config, got:\n%s", stdout)
		}
	})

	t.Run("generate command positional target and config", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "generate", "caddy", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "routewarden {") {
			t.Errorf("expected caddy output from positional generate, got:\n%s", stdout)
		}
	})

	t.Run("generate command target aliases: yaml, toml, compose", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "generate", "yaml", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "middlewares:") {
			t.Errorf("expected yaml output from generate yaml, got:\n%s", stdout)
		}

		stdout, stderr, code = runCLI(t, "generate", "toml", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "[http.middlewares.routewarden.plugin.routewarden]") {
			t.Errorf("expected toml output from generate toml, got:\n%s", stdout)
		}

		stdout, stderr, code = runCLI(t, "generate", "compose", sampleJSON)
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "traefik.http.middlewares.warden") {
			t.Errorf("expected compose output from generate compose, got:\n%s", stdout)
		}
	})

	t.Run("sandbox command positional target and config with -n dry-run alias", func(t *testing.T) {
		stdout, stderr, code := runCLI(t, "sandbox", "caddy", sampleCaddy, "-n")
		if code != 0 {
			t.Fatalf("expected code 0, got %d. stderr: %s", code, stderr)
		}
		if !strings.Contains(stdout, "[Dry Run] Docker command for caddy:") {
			t.Errorf("expected dry run output from sandbox caddy, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "docker run --rm") {
			t.Errorf("missing docker run in dry run output:\n%s", stdout)
		}
	})
}

