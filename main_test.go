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
