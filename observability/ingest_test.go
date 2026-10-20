package observability

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/cli/crypto"
)

func setupTestDashboard(t *testing.T) (string, string, string, *os.File, http.Handler, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "rw-ingest-test-*")
	if err != nil {
		t.Fatal(err)
	}

	serverPriv, serverPub, err := EnsureServerKeypair(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to init server keypair: %v", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	agentMu.Lock()
	agents = make(map[string]*RemoteAgentInfo)
	agentMu.Unlock()

	rawToken, _, err := CreateAgentKey("edge-eu-node-1", tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create agent key: %v", err)
	}

	logFilePath := filepath.Join(tempDir, "access.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create test log file: %v", err)
	}

	handler := NewDashboardHandler(tempDir, serverPriv, serverPubStr, logFile, nil, "")

	cleanup := func() {
		_ = logFile.Close()
		_ = os.RemoveAll(tempDir)
	}

	return tempDir, rawToken, serverPubStr, logFile, handler, cleanup
}

func TestIngest_GetPubKey(t *testing.T) {
	_, _, serverPubStr, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pubkey", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var res map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}

	if res["public_key"] != serverPubStr {
		t.Errorf("expected public_key %q, got %q", serverPubStr, res["public_key"])
	}
	if res["version"] != Version {
		t.Errorf("expected version %s, got %s", Version, res["version"])
	}
}

func TestIngest_Register(t *testing.T) {
	tempDir, rawToken, serverPubStr, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	// 1. Method Not Allowed (GET)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/register", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rec.Code)
	}

	// 2. Unauthorized (Missing token)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rec.Code)
	}

	// 3. Unauthorized (Invalid token)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.Header.Set("Authorization", "Bearer rw_sec_invalidtoken123")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for invalid token, got %d", rec.Code)
	}

	// 4. Successful registration via Authorization Bearer
	req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.RemoteAddr = "192.0.2.10:45678"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var regRes map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &regRes); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if regRes["status"] != "registered" {
		t.Errorf("expected status registered, got %v", regRes["status"])
	}
	if regRes["agent_name"] != "edge-eu-node-1" {
		t.Errorf("expected agent_name edge-eu-node-1, got %v", regRes["agent_name"])
	}
	if regRes["public_key"] != serverPubStr {
		t.Errorf("expected server public key %s, got %v", serverPubStr, regRes["public_key"])
	}

	// 5. Successful registration via X-API-Key header
	req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.Header.Set("X-API-Key", rawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK with X-API-Key, got %d", rec.Code)
	}

	// 6. Registration with revoked token fails
	_ = RevokeAgentKey("edge-eu-node-1", tempDir)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for revoked token, got %d", rec.Code)
	}
}

func TestIngest_Heartbeat(t *testing.T) {
	_, rawToken, _, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	// 1. Method Not Allowed
	req := httptest.NewRequest(http.MethodGet, "/api/v1/heartbeat", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}

	// 2. Unauthorized
	req = httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	// 3. Valid Heartbeat with hostname
	hbBody := `{"hostname":"worker-frankfurt-01"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewBufferString(hbBody))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] != "ok" {
		t.Errorf("expected status ok, got %s", res["status"])
	}
}

func TestIngest_Events_EncryptedAndPlain(t *testing.T) {
	_, rawToken, serverPubStr, logFile, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	serverPub, err := crypto.DecodePublicKey(serverPubStr)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}

	// 1. Unauthorized
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// 2. Malformed encrypted payload (invalid base64 / corrupted ciphertext)
	badPayload := `{"ciphertext":"not-valid-base64!!!","nonce":"AAAA","ephemeral_pub":"AAAA"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(badPayload))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on decryption failure, got %d", rec.Code)
	}

	// 3. Valid Encrypted Batch of events
	eventLines := []string{
		`{"time":"2026-10-18T12:00:00Z","client_ip":"198.51.100.42","method":"GET","path":"/api/users","status":200}`,
		`{"time":"2026-10-18T12:00:01Z","client_ip":"198.51.100.99","method":"POST","path":"/wp-admin.php","verdict":"BLOCK","rule":"traversal"}`,
	}
	type pushObj struct {
		AgentID  string   `json:"agent_id"`
		Hostname string   `json:"hostname"`
		Events   []string `json:"events"`
	}
	plainBytes, _ := json.Marshal(pushObj{
		AgentID:  "edge-eu-node-1",
		Hostname: "node-1.edge",
		Events:   eventLines,
	})

	encrypted, err := crypto.Encrypt(serverPub, plainBytes)
	if err != nil {
		t.Fatalf("crypto.Encrypt failed: %v", err)
	}
	encBytes, _ := json.Marshal(encrypted)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(encBytes))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.42:54321"
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var acceptedRes map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &acceptedRes)
	if acceptedRes["status"] != "accepted" {
		t.Errorf("expected status accepted, got %v", acceptedRes["status"])
	}
	if int(acceptedRes["ingested"].(float64)) != 2 {
		t.Errorf("expected 2 ingested events, got %v", acceptedRes["ingested"])
	}

	// 4. Verify log file contains converted combined log entries
	logBytes, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("failed to read access log: %v", err)
	}
	logContent := string(logBytes)
	if !strings.Contains(logContent, "198.51.100.42") || !strings.Contains(logContent, "/api/users") {
		t.Errorf("expected log entry in combined format, got: %s", logContent)
	}
	if !strings.Contains(logContent, "198.51.100.99") || !strings.Contains(logContent, "/wp-admin.php") {
		t.Errorf("expected second log entry in combined format, got: %s", logContent)
	}

	// 5. Plain JSON string list ingestion (backward compatibility)
	plainList := `["192.168.1.50 - - [18/Oct/2026:12:00:02 +0000] \"GET /index.html HTTP/1.1\" 200 1024"]`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(plainList))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted for plain JSON list, got %d", rec.Code)
	}
}

func TestIngest_SourcesAPI_AndAgentAging(t *testing.T) {
	_, rawToken, _, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	// Register an agent first
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("X-Forwarded-For", "198.51.100.77")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registration failed: %d", rec.Code)
	}

	// Fetch /api/sources
	req = httptest.NewRequest(http.MethodGet, "/api/sources", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/sources, got %d", rec.Code)
	}

	var sourceInfo SourceInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &sourceInfo); err != nil {
		t.Fatalf("failed to parse /api/sources response: %v", err)
	}

	found := false
	for _, a := range sourceInfo.Agents {
		if a.Name == "edge-eu-node-1" {
			found = true
			if a.Status != "online" {
				t.Errorf("expected agent status online, got %s", a.Status)
			}
			if a.RemoteIP != "198.51.100.77" {
				t.Errorf("expected RemoteIP 198.51.100.77, got %s", a.RemoteIP)
			}
		}
	}
	if !found {
		t.Error("registered agent not found in /api/sources response")
	}

	// Test Agent Status Aging logic directly
	agentMu.Lock()
	testAgent := &RemoteAgentInfo{
		ID:        "aging-test-agent",
		Name:      "aging-test",
		Status:    "online",
		FirstSeen: time.Now().UTC().Format(time.RFC3339),
	}
	agents["aging-test-agent"] = testAgent
	agentMu.Unlock()

	// Within 60s -> online
	testAgent.LastSeen = time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339)
	active := getActiveAgents()
	for _, a := range active {
		if a.ID == "aging-test-agent" && a.Status != "online" {
			t.Errorf("expected online for <60s, got %s", a.Status)
		}
	}

	// Between 60s and 5m -> idle
	testAgent.LastSeen = time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	active = getActiveAgents()
	for _, a := range active {
		if a.ID == "aging-test-agent" && a.Status != "idle" {
			t.Errorf("expected idle for 2m, got %s", a.Status)
		}
	}

	// Over 5m -> offline
	testAgent.LastSeen = time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	active = getActiveAgents()
	for _, a := range active {
		if a.ID == "aging-test-agent" && a.Status != "offline" {
			t.Errorf("expected offline for 10m, got %s", a.Status)
		}
	}
}

func TestIngest_Logging_RegisterAndEvents(t *testing.T) {
	_, rawToken, serverPubStr, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	// 1. Capture registration logging
	var regStdout, regStderr string
	{
		oldOut := os.Stdout
		oldErr := os.Stderr
		rOut, wOut, _ := os.Pipe()
		rErr, wErr, _ := os.Pipe()
		os.Stdout = wOut
		os.Stderr = wErr

		req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
		req.Header.Set("Authorization", "Bearer "+rawToken)
		req.RemoteAddr = "198.51.100.88:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		_ = wOut.Close()
		_ = wErr.Close()
		os.Stdout = oldOut
		os.Stderr = oldErr

		var outBuf, errBuf bytes.Buffer
		_, _ = io.Copy(&outBuf, rOut)
		_, _ = io.Copy(&errBuf, rErr)
		regStdout = outBuf.String()
		regStderr = errBuf.String()
	}

	if !strings.Contains(regStdout, "🤝 [Register] Registered agent 'edge-eu-node-1'") {
		t.Errorf("expected registration confirmation log, got stdout:\n%s\nstderr:\n%s", regStdout, regStderr)
	}

	// 2. Capture plain event ingest logging
	var evStdout string
	{
		oldOut := os.Stdout
		rOut, wOut, _ := os.Pipe()
		os.Stdout = wOut

		payload := `{"hostname":"edge-node-x","events":["{\"client_ip\":\"203.0.113.1\",\"path\":\"/test\"}"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(payload))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		req.RemoteAddr = "198.51.100.88:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		_ = wOut.Close()
		os.Stdout = oldOut

		var outBuf bytes.Buffer
		_, _ = io.Copy(&outBuf, rOut)
		evStdout = outBuf.String()
	}

	if !strings.Contains(evStdout, "📥 Ingested batch of 1 event(s) from agent 'edge-eu-node-1'") {
		t.Errorf("expected event ingest log in stdout, got:\n%s", evStdout)
	}

	// 3. Capture encrypted event ingest logging
	serverPub, err := crypto.DecodePublicKey(serverPubStr)
	if err != nil {
		t.Fatal(err)
	}
	plainBytes := []byte(`{"hostname":"edge-enc-node","events":["{\"client_ip\":\"203.0.113.2\",\"path\":\"/enc\"}"]}`)
	encrypted, err := crypto.Encrypt(serverPub, plainBytes)
	if err != nil {
		t.Fatal(err)
	}
	encBytes, _ := json.Marshal(encrypted)

	var encStdout string
	{
		oldOut := os.Stdout
		rOut, wOut, _ := os.Pipe()
		os.Stdout = wOut

		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(encBytes))
		req.Header.Set("Authorization", "Bearer "+rawToken)
		req.RemoteAddr = "198.51.100.88:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		_ = wOut.Close()
		os.Stdout = oldOut

		var outBuf bytes.Buffer
		_, _ = io.Copy(&outBuf, rOut)
		encStdout = outBuf.String()
	}

	if !strings.Contains(encStdout, "🔒 Ingested batch of 1 event(s) (encrypted) from agent 'edge-eu-node-1'") {
		t.Errorf("expected encrypted event ingest log, got:\n%s", encStdout)
	}
}

func TestIngest_Logging_VerbosePreviews(t *testing.T) {
	_, rawToken, _, _, handler, cleanup := setupTestDashboard(t)
	defer cleanup()

	SetVerboseLogging(true)
	defer SetVerboseLogging(false)

	oldOut := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	payload := `{"hostname":"verbose-node","events":["{\"client_ip\":\"203.0.113.99\",\"path\":\"/admin-panel\"}"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.RemoteAddr = "198.51.100.99:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	_ = wOut.Close()
	os.Stdout = oldOut

	var outBuf bytes.Buffer
	_, _ = io.Copy(&outBuf, rOut)
	stdout := outBuf.String()

	if !strings.Contains(stdout, "📥 Ingested batch of 1 event(s)") {
		t.Errorf("expected ingest batch line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "↳ [edge-eu-node-1]") || !strings.Contains(stdout, "/admin-panel") {
		t.Errorf("expected verbose event preview in stdout, got:\n%s", stdout)
	}
}
