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
			name:     "Traefik JSON access log format 200 OK (filtered by default)",
			line:     `{"ClientHost":"198.51.100.5","RequestPath":"/api/v1/status","RequestMethod":"GET","DownstreamStatus":200}`,
			expected: false,
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
			name:     "Docker timestamp prefix with Combined log 200 OK (filtered by default)",
			line:     `2026-10-20T14:00:01.123456789Z 198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET / HTTP/1.1" 200 12 "-" "-"`,
			expected: false,
		},
		{
			name:     "Combined log with 403 Forbidden (security event)",
			line:     `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /secret HTTP/1.1" 403 12 "-" "-"`,
			expected: true,
		},
		{
			name:     "Combined log with 429 Too Many Requests (security event)",
			line:     `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /api HTTP/1.1" 429 12 "-" "-"`,
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

func TestFilterRouteWardenLog_FilterOptions(t *testing.T) {
	caddy404 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/not-found","method":"GET"},"status":404}`
	caddy500 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/server-error","method":"GET"},"status":500}`
	caddy200 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/ok","method":"GET"},"status":200}`
	caddy403 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/forbidden","method":"GET"},"status":403}`

	// 1. Default: only 403 passes (security event)
	if _, ok := filterRouteWardenLogOpts(caddy200, FilterOptions{}); ok {
		t.Error("expected caddy 200 to be filtered by default")
	}
	if _, ok := filterRouteWardenLogOpts(caddy404, FilterOptions{}); ok {
		t.Error("expected caddy 404 to be filtered by default")
	}
	if _, ok := filterRouteWardenLogOpts(caddy403, FilterOptions{}); !ok {
		t.Error("expected caddy 403 to pass by default")
	}

	// 2. IncludeFailed: 404, 500, 403 pass, 200 fails
	if _, ok := filterRouteWardenLogOpts(caddy404, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected caddy 404 to pass with IncludeFailed")
	}
	if _, ok := filterRouteWardenLogOpts(caddy500, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected caddy 500 to pass with IncludeFailed")
	}
	if _, ok := filterRouteWardenLogOpts(caddy200, FilterOptions{IncludeFailed: true}); ok {
		t.Error("expected caddy 200 to be filtered even with IncludeFailed")
	}

	// 3. AllTraffic: 200 passes
	if _, ok := filterRouteWardenLogOpts(caddy200, FilterOptions{AllTraffic: true}); !ok {
		t.Error("expected caddy 200 to pass with AllTraffic")
	}
}

func TestMultiProxy_ComprehensiveStatusMatrix(t *testing.T) {
	type testCase struct {
		name              string
		proxy             string
		status            int
		line              string
		passDefault       bool
		passIncludeFailed bool
		passAllTraffic    bool
	}

	testCases := []testCase{
		// Caddy JSON format
		{
			name:              "Caddy 101 Switching Protocols",
			proxy:             "caddy",
			status:            101,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/ws","method":"GET"},"status":101}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 200 OK",
			proxy:             "caddy",
			status:            200,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/home","method":"GET"},"status":200}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 201 Created",
			proxy:             "caddy",
			status:            201,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/api/users","method":"POST"},"status":201}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 204 No Content",
			proxy:             "caddy",
			status:            204,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/api/heartbeat","method":"POST"},"status":204}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 301 Moved Permanently",
			proxy:             "caddy",
			status:            301,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/old-url","method":"GET"},"status":301}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 302 Found",
			proxy:             "caddy",
			status:            302,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/login","method":"GET"},"status":302}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 304 Not Modified",
			proxy:             "caddy",
			status:            304,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/static/app.css","method":"GET"},"status":304}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 400 Bad Request",
			proxy:             "caddy",
			status:            400,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/api/query","method":"GET"},"status":400}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 401 Unauthorized",
			proxy:             "caddy",
			status:            401,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/admin","method":"GET"},"status":401}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 403 Forbidden (Security Event)",
			proxy:             "caddy",
			status:            403,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/.env","method":"GET"},"status":403}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 404 Not Found",
			proxy:             "caddy",
			status:            404,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/missing","method":"GET"},"status":404}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 405 Method Not Allowed",
			proxy:             "caddy",
			status:            405,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/static","method":"DELETE"},"status":405}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 422 Unprocessable Entity",
			proxy:             "caddy",
			status:            422,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/api/validate","method":"POST"},"status":422}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 429 Too Many Requests (Security Event)",
			proxy:             "caddy",
			status:            429,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/api/limit","method":"POST"},"status":429}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 500 Internal Server Error",
			proxy:             "caddy",
			status:            500,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/crash","method":"GET"},"status":500}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 502 Bad Gateway",
			proxy:             "caddy",
			status:            502,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/upstream-down","method":"GET"},"status":502}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 503 Service Unavailable",
			proxy:             "caddy",
			status:            503,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/maint","method":"GET"},"status":503}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Caddy 504 Gateway Timeout",
			proxy:             "caddy",
			status:            504,
			line:              `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/slow-api","method":"GET"},"status":504}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},

		// Traefik JSON format
		{
			name:              "Traefik JSON 200 OK",
			proxy:             "traefik",
			status:            200,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/metrics","RequestMethod":"GET","DownstreamStatus":200}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Traefik JSON 403 Forbidden (Security Event)",
			proxy:             "traefik",
			status:            403,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/.git/config","RequestMethod":"GET","DownstreamStatus":403}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Traefik JSON 404 Not Found",
			proxy:             "traefik",
			status:            404,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/not-found","RequestMethod":"GET","DownstreamStatus":404}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Traefik JSON 429 Too Many Requests (Security Event)",
			proxy:             "traefik",
			status:            429,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/rate-limited","RequestMethod":"POST","DownstreamStatus":429}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Traefik JSON 500 Server Error",
			proxy:             "traefik",
			status:            500,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/broken-endpoint","RequestMethod":"POST","DownstreamStatus":500}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Traefik JSON 502 Bad Gateway",
			proxy:             "traefik",
			status:            502,
			line:              `{"ClientHost":"198.51.100.5","RequestPath":"/api/v2","RequestMethod":"GET","DownstreamStatus":502}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},

		// NGINX JSON format
		{
			name:              "NGINX JSON 200 OK",
			proxy:             "nginx",
			status:            200,
			line:              `{"remote_addr":"198.51.100.44","status":200,"request_uri":"/index.html","method":"GET"}`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "NGINX JSON 403 Forbidden (Security Event)",
			proxy:             "nginx",
			status:            403,
			line:              `{"remote_addr":"198.51.100.44","status":403,"request_uri":"/wp-config.php","method":"GET"}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "NGINX JSON 404 Not Found",
			proxy:             "nginx",
			status:            404,
			line:              `{"remote_addr":"198.51.100.44","status":404,"request_uri":"/missing.js","method":"GET"}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "NGINX JSON 429 Too Many Requests (Security Event)",
			proxy:             "nginx",
			status:            429,
			line:              `{"remote_addr":"198.51.100.44","status":429,"request_uri":"/login","method":"POST"}`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "NGINX JSON 500 Internal Error",
			proxy:             "nginx",
			status:            500,
			line:              `{"remote_addr":"198.51.100.44","status":500,"request_uri":"/crash","method":"GET"}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "NGINX JSON 503 Service Unavailable",
			proxy:             "nginx",
			status:            503,
			line:              `{"remote_addr":"198.51.100.44","status":503,"request_uri":"/status","method":"GET"}`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},

		// Combined Log format (NGINX / Apache / Traefik / Caddy common log)
		{
			name:              "Combined Log 200 OK",
			proxy:             "combined",
			status:            200,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /app.js HTTP/1.1" 200 4500 "-" "Mozilla/5.0"`,
			passDefault:       false,
			passIncludeFailed: false,
			passAllTraffic:    true,
		},
		{
			name:              "Combined Log 403 Forbidden (Security Event)",
			proxy:             "combined",
			status:            403,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /.aws/credentials HTTP/1.1" 403 0 "-" "curl/7.88.1"`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Combined Log 429 Too Many Requests (Security Event)",
			proxy:             "combined",
			status:            429,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "POST /api/v1/auth HTTP/1.1" 429 12 "-" "Python-requests"`,
			passDefault:       true,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Combined Log 404 Not Found",
			proxy:             "combined",
			status:            404,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /unknown-path HTTP/1.1" 404 150 "-" "-"`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Combined Log 500 Server Error",
			proxy:             "combined",
			status:            500,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /fail HTTP/1.1" 500 0 "-" "-"`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
		{
			name:              "Combined Log 502 Bad Gateway",
			proxy:             "combined",
			status:            502,
			line:              `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /api HTTP/1.1" 502 0 "-" "-"`,
			passDefault:       false,
			passIncludeFailed: true,
			passAllTraffic:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mode 1: Default
			_, okDef := filterRouteWardenLogOpts(tc.line, FilterOptions{})
			if okDef != tc.passDefault {
				t.Errorf("[%s] Default mode: got ok=%v, expected=%v for line: %s", tc.name, okDef, tc.passDefault, tc.line)
			}

			// Mode 2: IncludeFailed
			_, okFail := filterRouteWardenLogOpts(tc.line, FilterOptions{IncludeFailed: true})
			if okFail != tc.passIncludeFailed {
				t.Errorf("[%s] IncludeFailed mode: got ok=%v, expected=%v for line: %s", tc.name, okFail, tc.passIncludeFailed, tc.line)
			}

			// Mode 3: AllTraffic
			_, okAll := filterRouteWardenLogOpts(tc.line, FilterOptions{AllTraffic: true})
			if okAll != tc.passAllTraffic {
				t.Errorf("[%s] AllTraffic mode: got ok=%v, expected=%v for line: %s", tc.name, okAll, tc.passAllTraffic, tc.line)
			}

			// Mode 4: AllLogs (always true)
			_, okAllLogs := filterRouteWardenLogOpts(tc.line, FilterOptions{AllLogs: true})
			if !okAllLogs {
				t.Errorf("[%s] AllLogs mode: expected true, got false", tc.name)
			}
		})
	}
}

func TestExplicitSecurityTagsOverrideAllModes(t *testing.T) {
	securityLines := []struct {
		name string
		line string
	}{
		{"Bracket TARPIT tag", `198.51.100.2 - - [21/Oct/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 200 0 "-" "[TARPIT: SlowDown]"`},
		{"Bracket HONEYPOT tag", `198.51.100.2 - - [21/Oct/2026:12:00:00 +0000] "GET /fake.sql HTTP/1.1" 200 0 "-" "[HONEYPOT: DecoyTable]"`},
		{"Bracket RULE tag", `198.51.100.2 - - [21/Oct/2026:12:00:00 +0000] "GET /api HTTP/1.1" 200 0 "-" "[RULE: SQLInjectionDetected]"`},
		{"Bracket BLOCK tag", `198.51.100.2 - - [21/Oct/2026:12:00:00 +0000] "GET /admin HTTP/1.1" 200 0 "-" "[BLOCK: AdminOnly]"`},
		{"Bracket ALLOW tag", `198.51.100.2 - - [21/Oct/2026:12:00:00 +0000] "GET /health HTTP/1.1" 200 0 "-" "[ALLOW: WhitelistedIP]"`},
		{"JSON verdict BLOCK", `{"client_ip":"198.51.100.3","path":"/.env","verdict":"BLOCK","rule":"DotEnv"}`},
		{"JSON verdict TARPIT", `{"client_ip":"198.51.100.3","path":"/crawl","verdict":"TARPIT","action":"tarpit"}`},
		{"JSON verdict HONEYPOT", `{"client_ip":"198.51.100.3","path":"/decoy","verdict":"HONEYPOT","rule":"trap"}`},
		{"JSON plugin signal", `{"client_ip":"198.51.100.3","path":"/query","plugin":"caddy-warden","rule":"rfi"}`},
		{"JSON gateway signal", `{"client_ip":"198.51.100.3","path":"/auth","gateway":"traefik-warden","rule":"auth_bypass"}`},
	}

	for _, item := range securityLines {
		t.Run(item.name, func(t *testing.T) {
			clean, ok := filterRouteWardenLogOpts(item.line, FilterOptions{})
			if !ok || clean == "" {
				t.Fatalf("expected security event to pass by default, got ok=%v: %s", ok, item.line)
			}
		})
	}
}

func TestNonHTTPAndCorruptLogs(t *testing.T) {
	nonHTTP := []struct {
		name string
		line string
	}{
		{"Empty string", ""},
		{"Whitespace only", "    \t \r\n"},
		{"Corrupt JSON starting with brace", `{"client_ip": "1.2.3.4", incomplete`},
		{"Non-access JSON system event", `{"level":"info","msg":"Listening on :80","service":"web"}`},
		{"Plain application debug text", `[DEBUG] (cache) hit key=session:1234 duration=12ms`},
		{"Systemd syslog line", `Oct 21 12:00:00 node01 systemd[1]: Started Network Time Service.`},
		{"Panic stack trace", `goroutine 1 [running]: main.main() /app/main.go:42`},
		{"Combined log with non-integer status", `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET / HTTP/1.1" ABC 123`},
	}

	for _, item := range nonHTTP {
		t.Run(item.name, func(t *testing.T) {
			if _, ok := filterRouteWardenLogOpts(item.line, FilterOptions{}); ok {
				t.Errorf("[%s] expected false in Default mode, got true", item.name)
			}
			if _, ok := filterRouteWardenLogOpts(item.line, FilterOptions{IncludeFailed: true}); ok {
				t.Errorf("[%s] expected false in IncludeFailed mode, got true", item.name)
			}
			if _, ok := filterRouteWardenLogOpts(item.line, FilterOptions{AllTraffic: true}); ok {
				t.Errorf("[%s] expected false in AllTraffic mode, got true", item.name)
			}

			clean, okAll := filterRouteWardenLogOpts(item.line, FilterOptions{AllLogs: true})
			trimmed := strings.TrimSpace(item.line)
			if trimmed == "" {
				if okAll {
					t.Errorf("[%s] expected false even in AllLogs for empty string", item.name)
				}
			} else {
				if !okAll || clean != item.line {
					t.Errorf("[%s] expected true in AllLogs mode, got ok=%v", item.name, okAll)
				}
			}
		})
	}
}

func TestStringStatusCodesAndFlexibleParsing(t *testing.T) {
	nginxString404 := `{"remote_addr":"198.51.100.1","request_uri":"/missing","method":"GET","status":"404"}`
	nginxString500 := `{"remote_addr":"198.51.100.1","request_uri":"/crash","method":"GET","status":"500"}`
	nginxString403 := `{"remote_addr":"198.51.100.1","request_uri":"/forbidden","method":"GET","status":"403"}`
	nginxString200 := `{"remote_addr":"198.51.100.1","request_uri":"/ok","method":"GET","status":"200"}`

	// 1. Default mode: string "403" is recognized as security event and passes, while "200" and "404" are filtered
	if _, ok := filterRouteWardenLogOpts(nginxString403, FilterOptions{}); !ok {
		t.Error("expected quoted status \"403\" to pass in default mode")
	}
	if _, ok := filterRouteWardenLogOpts(nginxString200, FilterOptions{}); ok {
		t.Error("expected quoted status \"200\" to be filtered by default")
	}
	if _, ok := filterRouteWardenLogOpts(nginxString404, FilterOptions{}); ok {
		t.Error("expected quoted status \"404\" to be filtered by default")
	}

	// 2. IncludeFailed mode: string "404" and "500" pass, "200" is filtered
	if _, ok := filterRouteWardenLogOpts(nginxString404, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected quoted status \"404\" to pass with IncludeFailed")
	}
	if _, ok := filterRouteWardenLogOpts(nginxString500, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected quoted status \"500\" to pass with IncludeFailed")
	}
	if _, ok := filterRouteWardenLogOpts(nginxString200, FilterOptions{IncludeFailed: true}); ok {
		t.Error("expected quoted status \"200\" to be filtered with IncludeFailed")
	}

	// 3. AllTraffic mode: string "200" passes
	if _, ok := filterRouteWardenLogOpts(nginxString200, FilterOptions{AllTraffic: true}); !ok {
		t.Error("expected quoted status \"200\" to pass with AllTraffic")
	}
}
