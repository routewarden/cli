package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRegisterAgent_Validation(t *testing.T) {
	// Empty URL
	_, err := RegisterAgent("", "rw_sec_test", "", nil)
	if err == nil {
		t.Error("expected error when dashboard URL is empty")
	}

	// Empty key
	_, err = RegisterAgent("http://localhost:7890", "", "", nil)
	if err == nil {
		t.Error("expected error when agent key is empty")
	}
}

func TestRegisterAgent_Failures(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-reg-fail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	cfgFile := filepath.Join(tempDir, "agent.json")

	// 1. Connection / Network failure
	clientNetworkErr := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		}),
	}
	_, err = RegisterAgent("http://localhost:7890", "rw_sec_test", cfgFile, clientNetworkErr)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("expected connection error, got %v", err)
	}

	// 2. Server returns HTTP 401 Unauthorized with JSON error
	client401 := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusUnauthorized)
			rec.Header().Set("Content-Type", "application/json")
			_, _ = rec.WriteString(`{"error":"invalid API key"}`)
			return rec.Result(), nil
		}),
	}
	_, err = RegisterAgent("http://localhost:7890", "rw_sec_test", cfgFile, client401)
	if err == nil || !strings.Contains(err.Error(), "invalid API key") {
		t.Errorf("expected 401 invalid API key error, got %v", err)
	}

	// 3. Server returns HTTP 500 Internal Server Error
	client500 := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusInternalServerError)
			_, _ = rec.WriteString("Database connection failure")
			return rec.Result(), nil
		}),
	}
	_, err = RegisterAgent("http://localhost:7890", "rw_sec_test", cfgFile, client500)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected HTTP 500 error, got %v", err)
	}

	// 4. Server returns HTTP 200 but malformed JSON body
	clientMalformed := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`not-valid-json`)
			return rec.Result(), nil
		}),
	}
	_, err = RegisterAgent("http://localhost:7890", "rw_sec_test", cfgFile, clientMalformed)
	if err == nil || !strings.Contains(err.Error(), "invalid response") {
		t.Errorf("expected JSON unmarshal error, got %v", err)
	}
}

func TestRegisterAgent_ConfigPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-reg-cfg-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	subDir := filepath.Join(tempDir, "nested", ".routewarden")
	cfgPath := filepath.Join(subDir, "agent.json")

	// Mock server returning successful registration
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if !strings.HasSuffix(req.URL.Path, "/api/v1/register") {
				return nil, fmt.Errorf("unexpected path: %s", req.URL.Path)
			}
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.WriteString(`{
				"status": "registered",
				"agent_id": "agent_abc123",
				"agent_name": "worker-edge-1",
				"public_key": "pub_key_base64_sample"
			}`)
			return rec.Result(), nil
		}),
	}

	cfg, err := RegisterAgent("http://localhost:9095/", "rw_sec_test_token", cfgPath, client)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	if cfg.AgentID != "agent_abc123" || cfg.AgentName != "worker-edge-1" {
		t.Errorf("unexpected agent config: %+v", cfg)
	}
	if cfg.DashboardURL != "http://localhost:9095" {
		t.Errorf("expected trimmed trailing slash in URL, got %s", cfg.DashboardURL)
	}

	// Verify file permissions 0600
	fileInfo, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat agent.json: %v", err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Errorf("expected agent.json permissions 0600, got %o", fileInfo.Mode().Perm())
	}

	// Verify loadAgentConfig
	loaded, err := loadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadAgentConfig failed: %v", err)
	}
	if loaded.ServerPublicKey != "pub_key_base64_sample" {
		t.Errorf("mismatched loaded public key: %s", loaded.ServerPublicKey)
	}
}
