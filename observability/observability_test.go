package observability_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/cli/observability"
)

func TestExportObservabilityAssets(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "routewarden-observability-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	requiredFiles := []string{
		"docker-compose.yml",
		"goaccess.conf",
		"README.md",
	}

	for _, rel := range requiredFiles {
		full := filepath.Join(tempDir, rel)
		info, err := os.Stat(full)
		if err != nil {
			t.Errorf("expected exported file %s does not exist: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("exported file %s is empty", rel)
		}
	}

	// Verify docker-compose.yml references GoAccess image
	composeData, err := os.ReadFile(filepath.Join(tempDir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("failed to read exported docker-compose.yml: %v", err)
	}
	composeStr := string(composeData)
	if !strings.Contains(composeStr, "allinurl/goaccess") {
		t.Errorf("expected allinurl/goaccess image in docker-compose.yml, got:\n%s", composeStr)
	}
	if !strings.Contains(composeStr, "monitor:") {
		t.Errorf("expected monitor service in docker-compose.yml, got:\n%s", composeStr)
	}
	if !strings.Contains(composeStr, "ghcr.io/routewarden/cli") {
		t.Errorf("expected ghcr.io/routewarden/cli image in docker-compose.yml, got:\n%s", composeStr)
	}
	if !strings.Contains(composeStr, "profiles:") || !strings.Contains(composeStr, "monitor") {
		t.Errorf("expected monitor profile in docker-compose.yml, got:\n%s", composeStr)
	}

	// Verify goaccess.conf contains expected configuration directives
	confData, err := os.ReadFile(filepath.Join(tempDir, "goaccess.conf"))
	if err != nil {
		t.Fatalf("failed to read exported goaccess.conf: %v", err)
	}
	confStr := string(confData)
	if !strings.Contains(confStr, "real-time-html true") {
		t.Errorf("expected real-time-html true in goaccess.conf")
	}
	if !strings.Contains(confStr, "log-format COMBINED") {
		t.Errorf("expected log-format COMBINED in goaccess.conf")
	}
	if !strings.Contains(confStr, "RouteWarden — Threat & Security Intelligence") {
		t.Errorf("expected title in goaccess.conf")
	}
}

func TestObservabilityManager_Helpers(t *testing.T) {
	// 1. DefaultDir returns non-empty path
	defaultDir := observability.DefaultDir()
	if defaultDir == "" {
		t.Errorf("expected non-empty DefaultDir")
	}
	if !strings.Contains(defaultDir, ".routewarden") {
		t.Errorf("expected DefaultDir to contain .routewarden, got: %s", defaultDir)
	}

	// 2. EnsureStackPrepared creates directory and files on first call, no-ops on second call
	tempDir, err := os.MkdirTemp("", "routewarden-ensure-stack-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := observability.EnsureStackPrepared(tempDir); err != nil {
		t.Fatalf("EnsureStackPrepared failed on initial call: %v", err)
	}

	composePath := filepath.Join(tempDir, "docker-compose.yml")
	stat1, err := os.Stat(composePath)
	if err != nil {
		t.Fatalf("expected docker-compose.yml to exist: %v", err)
	}

	// Second call should return nil immediately because file exists
	if err := observability.EnsureStackPrepared(tempDir); err != nil {
		t.Fatalf("EnsureStackPrepared failed on second call: %v", err)
	}
	stat2, err := os.Stat(composePath)
	if err != nil || stat1.ModTime() != stat2.ModTime() {
		t.Errorf("EnsureStackPrepared should not have re-exported on second call")
	}

	// 3. Export can overwrite existing files without error
	if err := observability.Export(tempDir); err != nil {
		t.Fatalf("Export failed on overwrite: %v", err)
	}
}
