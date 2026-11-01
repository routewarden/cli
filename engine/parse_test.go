package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfig_JSON(t *testing.T) {
	jsonContent := []byte(`{
		"enabled": true,
		"blockPatterns": ["(?i)\\.env"],
		"methods": ["GET", "POST"]
	}`)

	cfg, err := ParseConfig(jsonContent)
	if err != nil {
		t.Fatalf("unexpected error parsing JSON: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true")
	}
	if len(cfg.BlockPatterns) != 1 || cfg.BlockPatterns[0] != `(?i)\.env` {
		t.Errorf("unexpected block patterns: %v", cfg.BlockPatterns)
	}
	if len(cfg.Methods) != 2 {
		t.Errorf("unexpected methods: %v", cfg.Methods)
	}
}

func TestParseConfig_YAML(t *testing.T) {
	yamlContent := []byte(`
enabled: true
enableDefaultPatterns: true
blockPatterns:
  - '(?i)\.env'
  - '(?i)\.git'
methods:
  - GET
checkQuery: true
response:
  mode: json
  statusCode: 403
`)

	cfg, err := ParseConfig(yamlContent)
	if err != nil {
		t.Fatalf("unexpected error parsing YAML: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true")
	}
	if !cfg.EnableDefaultPatterns {
		t.Error("expected enableDefaultPatterns=true")
	}
	if len(cfg.BlockPatterns) != 2 {
		t.Errorf("expected 2 block patterns, got %d", len(cfg.BlockPatterns))
	}
	if !cfg.CheckQuery {
		t.Error("expected checkQuery=true")
	}
	if cfg.Response == nil || cfg.Response.Mode != "json" || cfg.Response.StatusCode != 403 {
		t.Errorf("unexpected response config: %+v", cfg.Response)
	}
}

func TestParseConfig_TraefikDynamicYAML(t *testing.T) {
	samplePath := filepath.Join("..", "samples", "traefik", "dynamic.yml")
	content, err := os.ReadFile(samplePath)
	if err != nil {
		t.Skipf("sample file not found at %s: %v", samplePath, err)
		return
	}

	cfg, err := ParseConfig(content)
	if err != nil {
		t.Fatalf("failed to parse Traefik dynamic YAML sample: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true from Traefik dynamic middleware")
	}
	if len(cfg.BlockPatterns) < 2 {
		t.Errorf("expected at least 2 block patterns from Traefik sample, got %d", len(cfg.BlockPatterns))
	}
	if cfg.Response == nil || cfg.Response.Mode != "json" {
		t.Errorf("expected json response mode from Traefik sample, got %+v", cfg.Response)
	}
}

func TestParseConfig_WrappedJSON(t *testing.T) {
	wrappedJSON := []byte(`{
		"routewarden": {
			"enabled": true,
			"blockPatterns": ["(?i)^/admin"],
			"methods": ["GET", "POST"]
		}
	}`)

	cfg, err := ParseConfig(wrappedJSON)
	if err != nil {
		t.Fatalf("unexpected error parsing wrapped JSON: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true from wrapped JSON")
	}
	if len(cfg.BlockPatterns) != 1 || cfg.BlockPatterns[0] != "(?i)^/admin" {
		t.Errorf("unexpected block patterns: %v", cfg.BlockPatterns)
	}
	if len(cfg.Methods) != 2 {
		t.Errorf("unexpected methods: %v", cfg.Methods)
	}
}

func TestParseConfig_WrappedYAML_Helm(t *testing.T) {
	helmYAML := []byte(`
routewarden:
  enabled: true
  enableDefaultPatterns: true
  blockPatterns:
    - '(?i)\.env'
  checkQuery: true
`)

	cfg, err := ParseConfig(helmYAML)
	if err != nil {
		t.Fatalf("unexpected error parsing Helm YAML: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true from Helm YAML")
	}
	if !cfg.EnableDefaultPatterns {
		t.Error("expected enableDefaultPatterns=true from Helm YAML")
	}
	if len(cfg.BlockPatterns) != 1 || cfg.BlockPatterns[0] != `(?i)\.env` {
		t.Errorf("unexpected block patterns: %v", cfg.BlockPatterns)
	}
	if !cfg.CheckQuery {
		t.Error("expected checkQuery=true from Helm YAML")
	}
}

func TestParseConfig_TraefikMiddlewaresRoot(t *testing.T) {
	traefikMiddlewaresYAML := []byte(`
middlewares:
  sec-filter:
    plugin:
      routewarden:
        enabled: true
        blockPatterns:
          - '(?i)^/api/private'
`)

	cfg, err := ParseConfig(traefikMiddlewaresYAML)
	if err != nil {
		t.Fatalf("unexpected error parsing Traefik middlewares root YAML: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled=true from Traefik middlewares YAML")
	}
	if len(cfg.BlockPatterns) != 1 || cfg.BlockPatterns[0] != `(?i)^/api/private` {
		t.Errorf("unexpected block patterns: %v", cfg.BlockPatterns)
	}
}

func TestParseConfig_EmptyAndInvalid(t *testing.T) {
	cfgEmpty, err := ParseConfig([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error on empty bytes: %v", err)
	}
	if cfgEmpty == nil {
		t.Fatal("expected non-nil default config on empty bytes")
	}

	_, errInvalid := ParseConfig([]byte("invalid::: {{ yaml"))
	if errInvalid == nil {
		t.Error("expected error on malformed YAML/JSON")
	}
}

