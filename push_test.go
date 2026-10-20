package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/cli/crypto"
	"github.com/routewarden/cli/observability"
)

type mockTransport struct {
	handler http.Handler
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func TestEndToEnd_RegistrationAndEncryptedPush(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	serverDir := filepath.Join(tempDir, "server")
	clientDir := filepath.Join(tempDir, "client")
	_ = os.MkdirAll(serverDir, 0700)
	_ = os.MkdirAll(clientDir, 0700)

	// 1. Initialize Server Keypair and create an agent key
	serverPriv, serverPub, err := observability.EnsureServerKeypair(serverDir)
	if err != nil {
		t.Fatalf("failed to initialize server keypair: %v", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	rawToken, agentKey, err := observability.CreateAgentKey("edge-prod-test", serverDir)
	if err != nil {
		t.Fatalf("failed to create agent key: %v", err)
	}

	// 2. Setup mock RouteWarden dashboard handler
	var ingestedEvents []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+rawToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/v1/register":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "registered",
				"agent_id":   agentKey.ID,
				"agent_name": agentKey.Name,
				"public_key": serverPubStr,
			})

		case "/api/v1/heartbeat":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

		case "/api/v1/events":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Decrypt payload
			var encPayload crypto.EncryptedPayload
			if err := json.Unmarshal(body, &encPayload); err != nil {
				t.Errorf("failed to unmarshal encrypted payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			plaintext, err := crypto.Decrypt(serverPriv, &encPayload)
			if err != nil {
				t.Errorf("failed to decrypt payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			var payload pushPayload
			if err := json.Unmarshal(plaintext, &payload); err != nil {
				t.Errorf("failed to unmarshal decrypted json: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ingestedEvents = append(ingestedEvents, payload.Events...)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "accepted",
				"ingested": len(payload.Events),
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	// 3. Test Agent Registration via in-memory mock client
	clientConfigFile := filepath.Join(clientDir, "agent.json")
	cfg, err := RegisterAgent("http://routewarden.internal:7890", rawToken, clientConfigFile, mockClient)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Verify agent.json was created with server public key
	loadedCfg, err := loadAgentConfig(clientConfigFile)
	if err != nil {
		t.Fatalf("failed to load saved agent config: %v", err)
	}
	if loadedCfg.AgentName != "edge-prod-test" || loadedCfg.ServerPublicKey != serverPubStr {
		t.Fatalf("agent config mismatch: %+v", loadedCfg)
	}
	if cfg.AgentID != agentKey.ID {
		t.Errorf("expected agent ID %s, got %s", agentKey.ID, cfg.AgentID)
	}

	// 4. Test Client Encrypted Push
	sampleEvents := []string{
		`{"time":"2026-10-18T11:40:00Z","client_ip":"192.0.2.1","method":"GET","path":"/.env","verdict":"BLOCK","rule":"dotenv"}`,
		`{"time":"2026-10-18T11:40:01Z","client_ip":"198.51.100.2","method":"POST","path":"/login","verdict":"ALLOW"}`,
	}

	payloadObj := pushPayload{
		AgentID:  cfg.AgentID,
		Hostname: "test-host",
		Events:   sampleEvents,
	}
	payloadBytes, _ := json.Marshal(payloadObj)

	recipientPub, err := crypto.DecodePublicKey(cfg.ServerPublicKey)
	if err != nil {
		t.Fatalf("failed to decode server public key: %v", err)
	}

	encrypted, err := crypto.Encrypt(recipientPub, payloadBytes)
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}

	bodyToSend, _ := json.Marshal(encrypted)
	req, _ := http.NewRequest(http.MethodPost, "http://routewarden.internal:7890/api/v1/events", bytes.NewReader(bodyToSend))
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := mockClient.Do(req)
	if err != nil {
		t.Fatalf("push request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status 202 Accepted, got %d", resp.StatusCode)
	}

	if len(ingestedEvents) != 2 {
		t.Fatalf("expected 2 ingested events on server, got %d", len(ingestedEvents))
	}
	if ingestedEvents[0] != sampleEvents[0] {
		t.Errorf("event mismatch.\nExpected: %s\nGot:      %s", sampleEvents[0], ingestedEvents[0])
	}
}

func TestSendBatchWithRetry_ManualDirectEvents(t *testing.T) {
	var receivedPayload pushPayload
	var receivedAuth string
	var receivedContentType string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	client := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	manualEvents := []string{
		`{"client_ip":"198.51.100.1","path":"/.env","verdict":"BLOCK","rule":"sensitive_files"}`,
		`{"client_ip":"198.51.100.2","path":"/login.php","verdict":"BLOCK","rule":"admin_paths"}`,
	}

	err := sendBatchWithRetry(
		context.Background(),
		client,
		"http://routewarden.internal:7890/api/v1/events",
		"rw_sec_manualtoken123",
		"manual-agent-01",
		"edge-worker-node",
		nil,
		manualEvents,
	)
	if err != nil {
		t.Fatalf("sendBatchWithRetry failed: %v", err)
	}

	if receivedAuth != "Bearer rw_sec_manualtoken123" {
		t.Errorf("expected Bearer rw_sec_manualtoken123, got: %s", receivedAuth)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected application/json, got: %s", receivedContentType)
	}
	if receivedPayload.AgentID != "manual-agent-01" {
		t.Errorf("expected agent ID manual-agent-01, got: %s", receivedPayload.AgentID)
	}
	if receivedPayload.Hostname != "edge-worker-node" {
		t.Errorf("expected hostname edge-worker-node, got: %s", receivedPayload.Hostname)
	}
	if len(receivedPayload.Events) != 2 || receivedPayload.Events[0] != manualEvents[0] {
		t.Errorf("expected payload events to match manual events, got: %+v", receivedPayload.Events)
	}
}

func TestSendBatchWithRetry_ManualEventsEncrypted(t *testing.T) {
	serverPriv, serverPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var decryptedEvents []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var encPayload crypto.EncryptedPayload
		if err := json.NewDecoder(r.Body).Decode(&encPayload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plaintext, err := crypto.Decrypt(serverPriv, &encPayload)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload pushPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		decryptedEvents = payload.Events
		w.WriteHeader(http.StatusAccepted)
	})

	client := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	manualEvents := []string{
		`{"client_ip":"203.0.113.50","path":"/backup.sql","verdict":"BLOCK"}`,
	}

	err = sendBatchWithRetry(
		context.Background(),
		client,
		"http://routewarden.internal:7890/api/v1/events",
		"rw_sec_encryptedtoken",
		"agent-enc",
		"secure-host",
		serverPub,
		manualEvents,
	)
	if err != nil {
		t.Fatalf("sendBatchWithRetry failed: %v", err)
	}

	if len(decryptedEvents) != 1 || decryptedEvents[0] != manualEvents[0] {
		t.Fatalf("expected decrypted event %s, got: %v", manualEvents[0], decryptedEvents)
	}
}

func TestIsRouteWardenLog_FilterValidation(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "Structured RouteWarden security JSON",
			line:     `{"time":"2026-10-18T11:40:00Z","client_ip":"192.0.2.1","method":"GET","path":"/.env","verdict":"BLOCK","rule":"dotenv"}`,
			expected: true,
		},
		{
			name:     "RouteWarden security event with verdict only",
			line:     `{"client_ip":"198.51.100.1","path":"/admin","verdict":"ALLOW"}`,
			expected: true,
		},
		{
			name:     "Standard Apache/NGINX combined access log",
			line:     `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /.env HTTP/1.1" 403 0 "-" "[BLOCK: BlockDotEnv]"`,
			expected: true,
		},
		{
			name:     "Traefik JSON access log format",
			line:     `{"ClientHost":"198.51.100.5","RequestPath":"/api/v1/status","RequestMethod":"GET","DownstreamStatus":200}`,
			expected: true,
		},
		{
			name:     "Layer 4 UDP / tcp-warden security log",
			line:     `{"timestamp":"2026-10-01T15:30:00Z","plugin":"tcp-warden","client_ip":"198.51.100.22","action":"blocked"}`,
			expected: true,
		},
		{
			name:     "Docker timestamp prefix with valid RouteWarden JSON",
			line:     `2026-10-20T14:00:01.123456789Z {"time":"2026-10-20T14:00:01Z","client_ip":"198.51.100.1","path":"/","verdict":"BLOCK"}`,
			expected: true,
		},
		{
			name:     "Docker timestamp prefix with Combined log",
			line:     `2026-10-20T14:00:01.123456789Z 198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET / HTTP/1.1" 200 12 "-" "-"`,
			expected: true,
		},
		{
			name:     "Generic Docker container startup info log (should be filtered out)",
			line:     `time="2026-10-20T14:00:00Z" level=info msg="Configuration loaded from flags."`,
			expected: false,
		},
		{
			name:     "NGINX notice banner (should be filtered out)",
			line:     `2026/10/20 14:00:00 [notice] 1#1: using the "epoll" event method`,
			expected: false,
		},
		{
			name:     "Application debug message (should be filtered out)",
			line:     `[DEBUG] (resolver) querying 1.1.1.1 for domain test.internal`,
			expected: false,
		},
		{
			name:     "Arbitrary JSON without RouteWarden fields (should be filtered out)",
			line:     `{"level":"info","msg":"heartbeat OK","timestamp":"2026-10-20T14:00:00Z"}`,
			expected: false,
		},
		{
			name:     "Application error trace (should be filtered out)",
			line:     `panic: runtime error: invalid memory address or nil pointer dereference`,
			expected: false,
		},
		{
			name:     "Empty line (should be filtered out)",
			line:     `   `,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cleanLine, ok := filterRouteWardenLog(tc.line, false)
			if ok != tc.expected {
				t.Errorf("filterRouteWardenLog(..., false) for %q got ok=%v, expected %v", tc.line, ok, tc.expected)
			}
			if ok && strings.HasPrefix(tc.line, "2026-10-20T14:00:01.123456789Z ") {
				if strings.HasPrefix(cleanLine, "2026-10-20T14:00:01.123456789Z ") {
					t.Errorf("expected docker timestamp prefix stripped, got: %s", cleanLine)
				}
			}
		})
	}
}

func TestFilterRouteWardenLog_AllLogsBypass(t *testing.T) {
	rawLine := `[DEBUG] (resolver) querying 1.1.1.1 for domain test.internal`
	clean, ok := filterRouteWardenLog(rawLine, true)
	if !ok || clean != rawLine {
		t.Errorf("expected line to pass when allLogs=true, got ok=%v clean=%q", ok, clean)
	}

	cleanDefault, okDefault := filterRouteWardenLog(rawLine, false)
	if okDefault || cleanDefault != "" {
		t.Errorf("expected line to be filtered when allLogs=false, got ok=%v clean=%q", okDefault, cleanDefault)
	}
}
