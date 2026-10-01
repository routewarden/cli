package observability_test

import (
	"os"
	"path/filepath"
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
		"config.alloy",
		"loki-config.yaml",
		"grafana/provisioning/datasources/datasources.yaml",
		"grafana/provisioning/dashboards/dashboards.yaml",
		"grafana/dashboards/routewarden-overview.json",
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
}
