package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentConfig_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sub", "agent.json")

	cfg := &AgentConfig{
		DashboardURL:    "http://198.51.100.10:7890",
		AgentToken:      "rw_sec_test_token_12345",
		AgentID:         "agent_abcdef1234",
		AgentName:       "node-us-west",
		ServerPublicKey: "rw_pk_test_public_key_67890",
		RegisteredAt:    "2026-10-18T12:00:00Z",
	}

	// 1. Save config
	if err := saveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("saveAgentConfig failed: %v", err)
	}

	// 2. Load config
	loaded, err := loadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadAgentConfig failed: %v", err)
	}

	if !reflect.DeepEqual(cfg, loaded) {
		t.Errorf("loaded config does not match saved config:\nwanted: %+v\ngot:    %+v", cfg, loaded)
	}

	// 3. Load non-existent file
	_, err = loadAgentConfig(filepath.Join(tmpDir, "nonexistent.json"))
	if err == nil {
		t.Errorf("expected error loading non-existent config, got nil")
	}
}

func TestDefaultAgentConfigPath(t *testing.T) {
	path := defaultAgentConfigPath()
	if path == "" {
		t.Fatalf("expected non-empty defaultAgentConfigPath")
	}
	if filepath.Base(path) != "agent.json" {
		t.Errorf("expected base name agent.json, got: %s", filepath.Base(path))
	}
}
