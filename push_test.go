package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
