package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTCPWarden_PrintUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "TCP Warden") {
		t.Errorf("expected header in tcp-warden printUsage, got: %s", output)
	}
	if !strings.Contains(output, "run") || !strings.Contains(output, "validate") || !strings.Contains(output, "plugins") {
		t.Errorf("expected commands in usage, got: %s", output)
	}
}

func TestTCPWarden_ResolveConfigPath(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Explicit path
	explicit := filepath.Join(tmpDir, "my-conf.yaml")
	if got := resolveConfigPath(explicit); got != explicit {
		t.Errorf("expected %q, got %q", explicit, got)
	}

	// 2. ROUTEWARDEN_CONFIG env var
	t.Setenv("ROUTEWARDEN_CONFIG", filepath.Join(tmpDir, "env-conf.yaml"))
	if got := resolveConfigPath(""); got != filepath.Join(tmpDir, "env-conf.yaml") {
		t.Errorf("expected env path, got %q", got)
	}
	t.Setenv("ROUTEWARDEN_CONFIG", "")

	// 3. Local tcp-warden.yml file detection
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err == nil {
		defer func() { _ = os.Chdir(origWd) }()
		_ = os.WriteFile("tcp-warden.yml", []byte("services:\n"), 0644)
		if got := resolveConfigPath(""); got != "tcp-warden.yml" {
			t.Errorf("expected tcp-warden.yml, got %q", got)
		}
	}
}

func TestTCPWarden_EnsureConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "sub", "tcp-warden.yaml")

	// Ensure creates default template
	if err := ensureConfigFile(targetPath); err != nil {
		t.Fatalf("ensureConfigFile failed: %v", err)
	}

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		t.Errorf("expected %s to exist", targetPath)
	}

	// Calling again should not error or overwrite
	if err := ensureConfigFile(targetPath); err != nil {
		t.Fatalf("ensureConfigFile secondary call failed: %v", err)
	}
}
