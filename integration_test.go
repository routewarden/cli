package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/routewarden/cli/crypto"
	"github.com/routewarden/cli/observability"
)

// setupIntegrationCluster spins up a central dashboard ingestion handler backed by a temp directory.
func setupIntegrationCluster(t *testing.T) (string, string, *os.File, http.Handler, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "rw-cluster-test-*")
	if err != nil {
		t.Fatal(err)
	}

	serverPriv, serverPub, err := observability.EnsureServerKeypair(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to init server keypair: %v", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	logFilePath := filepath.Join(tempDir, "access.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("failed to create access log file: %v", err)
	}

	handler := observability.NewDashboardHandler(tempDir, serverPriv, serverPubStr, logFile, nil, "")

	cleanup := func() {
		_ = logFile.Close()
		_ = os.RemoveAll(tempDir)
	}

	return tempDir, serverPubStr, logFile, handler, cleanup
}

func TestIntegration_MultiAgent_ConcurrentStreaming(t *testing.T) {
	clusterDir, _, logFile, handler, cleanup := setupIntegrationCluster(t)
	defer cleanup()

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	const agentCount = 5
	const batchesPerAgent = 10
	const eventsPerBatch = 20
	const totalExpectedEvents = agentCount * batchesPerAgent * eventsPerBatch

	agentNames := []string{
		"edge-us-east-1",
		"edge-us-west-2",
		"edge-eu-central-1",
		"edge-ap-southeast-1",
		"edge-sa-east-1",
	}

	type agentSession struct {
		name       string
		token      string
		cfg        *AgentConfig
		configFile string
	}

	sessions := make([]*agentSession, agentCount)

	// 1. Enroll all agents via Keystore and RegisterAgent
	for i := 0; i < agentCount; i++ {
		name := agentNames[i]
		rawToken, _, err := observability.CreateAgentKey(name, clusterDir)
		if err != nil {
			t.Fatalf("failed to create agent key for %s: %v", name, err)
		}

		cfgPath := filepath.Join(clusterDir, fmt.Sprintf("agent_%d.json", i))
		cfg, err := RegisterAgent("http://routewarden.internal:7890", rawToken, cfgPath, mockClient)
		if err != nil {
			t.Fatalf("failed to register agent %s: %v", name, err)
		}

		sessions[i] = &agentSession{
			name:       name,
			token:      rawToken,
			cfg:        cfg,
			configFile: cfgPath,
		}
	}

	// 2. Stream concurrently across goroutines
	var wg sync.WaitGroup
	errChan := make(chan error, agentCount*batchesPerAgent)

	for i := 0; i < agentCount; i++ {
		sess := sessions[i]
		wg.Add(1)

		go func(s *agentSession, agentIndex int) {
			defer wg.Done()

			recipientPub, err := crypto.DecodePublicKey(s.cfg.ServerPublicKey)
			if err != nil {
				errChan <- fmt.Errorf("agent %s: decode pubkey: %w", s.name, err)
				return
			}

			// Fire heartbeat first
			hbReq, _ := http.NewRequest(http.MethodPost, "http://routewarden.internal:7890/api/v1/heartbeat", bytes.NewBufferString(fmt.Sprintf(`{"hostname":"host-%s"}`, s.name)))
			hbReq.Header.Set("Authorization", "Bearer "+s.token)
			hbReq.Header.Set("Content-Type", "application/json")
			hbReq.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", 10+agentIndex))
			hbResp, err := mockClient.Do(hbReq)
			if err != nil || hbResp.StatusCode != http.StatusOK {
				errChan <- fmt.Errorf("agent %s heartbeat failed: %v", s.name, err)
				return
			}
			_ = hbResp.Body.Close()

			// Stream encrypted batches
			for b := 0; b < batchesPerAgent; b++ {
				var batch []string
				for e := 0; e < eventsPerBatch; e++ {
					ev := fmt.Sprintf(`{"time":"2026-10-18T12:00:00Z","client_ip":"198.51.100.%d","method":"GET","path":"/api/%s/resource_%d","status":200}`,
						10+agentIndex, s.name, b*eventsPerBatch+e)
					batch = append(batch, ev)
				}

				err := sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", s.token, s.cfg.AgentID, s.name+".internal", recipientPub, batch)
				if err != nil {
					errChan <- fmt.Errorf("agent %s batch %d failed: %w", s.name, b, err)
					return
				}
			}
		}(sess, i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatalf("concurrent streaming error: %v", err)
	}

	// 3. Verify total log lines on disk
	logBytes, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("failed to read access.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	if len(lines) != totalExpectedEvents {
		t.Fatalf("expected exactly %d ingested events, got %d", totalExpectedEvents, len(lines))
	}

	// 4. Verify /api/sources reports all 5 agents with online status & exact counts
	req := httptest.NewRequest(http.MethodGet, "/api/sources", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/sources, got %d", rec.Code)
	}

	var sourceInfo observability.SourceInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &sourceInfo); err != nil {
		t.Fatalf("failed to parse /api/sources: %v", err)
	}

	if len(sourceInfo.Agents) != agentCount {
		t.Fatalf("expected %d active agents, got %d", agentCount, len(sourceInfo.Agents))
	}

	for _, a := range sourceInfo.Agents {
		if a.Status != "online" {
			t.Errorf("agent %s has status %s, expected online", a.Name, a.Status)
		}
		if a.EventCount != int64(batchesPerAgent*eventsPerBatch) {
			t.Errorf("agent %s has event count %d, expected %d", a.Name, a.EventCount, batchesPerAgent*eventsPerBatch)
		}
	}
}

func TestIntegration_AgentRevocation_MidFlight(t *testing.T) {
	clusterDir, _, _, handler, cleanup := setupIntegrationCluster(t)
	defer cleanup()

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	// 1. Enroll Agent Alpha and Agent Beta
	rawAlpha, keyAlpha, err := observability.CreateAgentKey("agent-alpha", clusterDir)
	if err != nil {
		t.Fatal(err)
	}
	cfgAlpha, err := RegisterAgent("http://routewarden.internal:7890", rawAlpha, filepath.Join(clusterDir, "alpha.json"), mockClient)
	if err != nil {
		t.Fatal(err)
	}

	rawBeta, _, err := observability.CreateAgentKey("agent-beta", clusterDir)
	if err != nil {
		t.Fatal(err)
	}
	cfgBeta, err := RegisterAgent("http://routewarden.internal:7890", rawBeta, filepath.Join(clusterDir, "beta.json"), mockClient)
	if err != nil {
		t.Fatal(err)
	}

	pubAlpha, _ := crypto.DecodePublicKey(cfgAlpha.ServerPublicKey)
	pubBeta, _ := crypto.DecodePublicKey(cfgBeta.ServerPublicKey)

	// 2. Both agents stream initial batches successfully
	batch := []string{`{"time":"2026-10-18T12:00:00Z","client_ip":"1.1.1.1","method":"GET","path":"/test","status":200}`}
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawAlpha, cfgAlpha.AgentID, "alpha", pubAlpha, batch)
	if err != nil {
		t.Fatalf("initial alpha push failed: %v", err)
	}
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawBeta, cfgBeta.AgentID, "beta", pubBeta, batch)
	if err != nil {
		t.Fatalf("initial beta push failed: %v", err)
	}

	// 3. Admin revokes Agent Alpha mid-flight
	if err := observability.RevokeAgentKey(keyAlpha.ID, clusterDir); err != nil {
		t.Fatalf("RevokeAgentKey failed: %v", err)
	}

	// 4. Agent Alpha's next push MUST fail with 401 Unauthorized
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawAlpha, cfgAlpha.AgentID, "alpha", pubAlpha, batch)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 error after revocation of alpha, got: %v", err)
	}

	// 5. Agent Alpha's heartbeat MUST also fail with 401
	hbReq, _ := http.NewRequest(http.MethodPost, "http://routewarden.internal:7890/api/v1/heartbeat", bytes.NewBufferString(`{"hostname":"alpha"}`))
	hbReq.Header.Set("Authorization", "Bearer "+rawAlpha)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := mockClient.Do(hbReq)
	if err != nil || hbResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on heartbeat for revoked alpha, got code: %d", hbResp.StatusCode)
	}
	_ = hbResp.Body.Close()

	// 6. Agent Beta MUST continue streaming without interruption
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawBeta, cfgBeta.AgentID, "beta", pubBeta, batch)
	if err != nil {
		t.Fatalf("beta push should have succeeded after alpha revocation: %v", err)
	}

	// 7. Enrolling a new Agent Gamma succeeds normally
	rawGamma, _, err := observability.CreateAgentKey("agent-gamma", clusterDir)
	if err != nil {
		t.Fatal(err)
	}
	cfgGamma, err := RegisterAgent("http://routewarden.internal:7890", rawGamma, filepath.Join(clusterDir, "gamma.json"), mockClient)
	if err != nil {
		t.Fatalf("registration of gamma failed: %v", err)
	}
	pubGamma, _ := crypto.DecodePublicKey(cfgGamma.ServerPublicKey)
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawGamma, cfgGamma.AgentID, "gamma", pubGamma, batch)
	if err != nil {
		t.Fatalf("gamma push failed: %v", err)
	}
}

func TestIntegration_MultiFormat_LogNormalizationPipeline(t *testing.T) {
	clusterDir, _, logFile, handler, cleanup := setupIntegrationCluster(t)
	defer cleanup()

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	rawToken, _, err := observability.CreateAgentKey("parser-test-agent", clusterDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := RegisterAgent("http://routewarden.internal:7890", rawToken, filepath.Join(clusterDir, "agent.json"), mockClient)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := crypto.DecodePublicKey(cfg.ServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Mix of realistic diverse log formats
	diverseEvents := []string{
		// 1. Raw NCSA Combined log format string
		`192.0.2.1 - frank [18/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0"`,
		// 2. RouteWarden Security BLOCK event
		`{"time":"2026-10-18T12:00:01Z","client_ip":"198.51.100.25","method":"GET","path":"/.env","verdict":"BLOCK","rule":"traversal"}`,
		// 3. RouteWarden Security TARPIT event (status mapped to 429)
		`{"time":"2026-10-18T12:00:02Z","client_ip":"203.0.113.88","method":"POST","path":"/xmlrpc.php","verdict":"TARPIT","rule":"bruteforce"}`,
		// 4. Traefik JSON access log format
		`{"ClientHost":"192.168.1.100","RequestMethod":"POST","RequestPath":"/api/login","DownstreamStatus":200,"time":"2026-10-18T12:00:03Z"}`,
		// 5. Path with quotes and special characters
		`{"time":"2026-10-18T12:00:04Z","client_ip":"10.0.0.5","method":"GET","path":"/search?q=\"test\"","verdict":"ALLOW"}`,
	}

	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawToken, cfg.AgentID, "host-parser", serverPub, diverseEvents)
	if err != nil {
		t.Fatalf("sendBatchWithRetry failed: %v", err)
	}

	// Read normalized log file
	logBytes, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read access.log: %v", err)
	}
	content := string(logBytes)
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 normalized log lines, got %d:\n%s", len(lines), content)
	}

	// Verify Line 1 (Raw Combined passed through)
	if !strings.Contains(lines[0], "192.0.2.1") || !strings.Contains(lines[0], "/index.html") {
		t.Errorf("line 1 mismatch: %s", lines[0])
	}

	// Verify Line 2 (BLOCK verdict translated to HTTP 403)
	if !strings.Contains(lines[1], "198.51.100.25") || !strings.Contains(lines[1], "403") || !strings.Contains(lines[1], "traversal") {
		t.Errorf("line 2 expected status 403 and rule traversal: %s", lines[1])
	}

	// Verify Line 3 (TARPIT verdict translated to HTTP 429)
	if !strings.Contains(lines[2], "203.0.113.88") || !strings.Contains(lines[2], "429") || !strings.Contains(lines[2], "bruteforce") {
		t.Errorf("line 3 expected status 429: %s", lines[2])
	}

	// Verify Line 4 (Traefik JSON translated)
	if !strings.Contains(lines[3], "192.168.1.100") || !strings.Contains(lines[3], "/api/login") || !strings.Contains(lines[3], "200") {
		t.Errorf("line 4 Traefik translation mismatch: %s", lines[3])
	}

	// Verify Line 5 (Path quotes escaped to %22)
	if !strings.Contains(lines[4], "%22test%22") {
		t.Errorf("line 5 path quotes should be sanitized to %%22: %s", lines[4])
	}
}

func TestIntegration_CLI_KeysManagement(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-cli-keys-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Capture stdout
	captureStdout := func(fn func()) string {
		orig := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		fn()

		_ = w.Close()
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		os.Stdout = orig
		return buf.String()
	}

	// 1. `rwarden keys create node-alpha`
	out := captureStdout(func() {
		handleKeys([]string{"create", "--dir", tempDir, "node-alpha"})
	})
	if !strings.Contains(out, "Agent Key Created Successfully") || !strings.Contains(out, "node-alpha") {
		t.Fatalf("unexpected create output: %s", out)
	}

	// 2. `rwarden keys list`
	listOut := captureStdout(func() {
		handleKeys([]string{"list", "--dir", tempDir})
	})
	if !strings.Contains(listOut, "node-alpha") || !strings.Contains(listOut, "ACTIVE") {
		t.Fatalf("unexpected list output: %s", listOut)
	}

	// 3. `rwarden keys revoke node-alpha`
	revokeOut := captureStdout(func() {
		handleKeys([]string{"revoke", "--dir", tempDir, "node-alpha"})
	})
	if !strings.Contains(revokeOut, "has been revoked") {
		t.Fatalf("unexpected revoke output: %s", revokeOut)
	}

	// 4. `rwarden keys list` after revoke
	listOutAfter := captureStdout(func() {
		handleKeys([]string{"list", "--dir", tempDir})
	})
	if !strings.Contains(listOutAfter, "REVOKED") {
		t.Fatalf("expected REVOKED status in list output: %s", listOutAfter)
	}
}

func TestIntegration_ZeroSocket_FullHandshakeAndPushLifecycle(t *testing.T) {
	clusterDir, _, logFile, handler, cleanup := setupIntegrationCluster(t)
	defer cleanup()

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	// 1. Verify GET /api/v1/pubkey returns public key
	pubReq := httptest.NewRequest(http.MethodGet, "http://routewarden.internal:7890/api/v1/pubkey", nil)
	pubRec := httptest.NewRecorder()
	handler.ServeHTTP(pubRec, pubReq)
	if pubRec.Code != http.StatusOK {
		t.Fatalf("pubkey endpoint failed: %d", pubRec.Code)
	}
	var pubResp struct {
		PublicKey string `json:"public_key"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(pubRec.Body.Bytes(), &pubResp); err != nil {
		t.Fatalf("parse pubkey response: %v", err)
	}
	if pubResp.PublicKey == "" || pubResp.Version != observability.Version {
		t.Fatalf("unexpected pubkey response: %+v", pubResp)
	}

	// 2. Create agent credentials in keystore
	rawToken, keyInfo, err := observability.CreateAgentKey("prod-gateway-fra", clusterDir)
	if err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	// 3. Register client via RegisterAgent
	clientCfgPath := filepath.Join(clusterDir, "client_agent.json")
	cfg, err := RegisterAgent("http://routewarden.internal:7890", rawToken, clientCfgPath, mockClient)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	if cfg.AgentID != keyInfo.ID || cfg.AgentName != "prod-gateway-fra" {
		t.Errorf("mismatched agent config: %+v", cfg)
	}
	if cfg.ServerPublicKey != pubResp.PublicKey {
		t.Errorf("mismatched server public key in config")
	}

	// 4. Stream 3 batches of encrypted events
	recipientPub, err := crypto.DecodePublicKey(cfg.ServerPublicKey)
	if err != nil {
		t.Fatalf("decode server public key: %v", err)
	}

	batches := [][]string{
		{
			`{"time":"2026-10-18T12:00:10Z","client_ip":"198.51.100.1","method":"GET","path":"/","status":200}`,
			`{"time":"2026-10-18T12:00:11Z","client_ip":"198.51.100.2","method":"POST","path":"/login","status":200}`,
		},
		{
			`{"time":"2026-10-18T12:00:12Z","client_ip":"203.0.113.50","method":"GET","path":"/etc/passwd","verdict":"BLOCK","rule":"traversal"}`,
		},
		{
			`{"time":"2026-10-18T12:00:13Z","client_ip":"198.51.100.3","method":"GET","path":"/assets/app.js","status":304}`,
			`{"time":"2026-10-18T12:00:14Z","client_ip":"198.51.100.4","method":"GET","path":"/favicon.ico","status":200}`,
		},
	}

	totalEventsExpected := 0
	for i, b := range batches {
		totalEventsExpected += len(b)
		err := sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawToken, cfg.AgentID, "fra-host-01", recipientPub, b)
		if err != nil {
			t.Fatalf("batch %d send failed: %v", i, err)
		}
	}

	// 5. Send Heartbeat
	hbReq, _ := http.NewRequest(http.MethodPost, "http://routewarden.internal:7890/api/v1/heartbeat", bytes.NewBufferString(`{"hostname":"fra-host-01"}`))
	hbReq.Header.Set("Authorization", "Bearer "+rawToken)
	hbReq.Header.Set("Content-Type", "application/json")
	hbResp, err := mockClient.Do(hbReq)
	if err != nil || hbResp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat failed: %v", err)
	}
	_ = hbResp.Body.Close()

	// 6. Verify server access log contains all 5 entries
	logBytes, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	if len(lines) != totalEventsExpected {
		t.Fatalf("expected %d lines in log file, got %d:\n%s", totalEventsExpected, len(lines), string(logBytes))
	}

	// 7. Verify /api/sources returns the active agent with 5 ingested events
	srcReq := httptest.NewRequest(http.MethodGet, "http://routewarden.internal:7890/api/sources", nil)
	srcRec := httptest.NewRecorder()
	handler.ServeHTTP(srcRec, srcReq)
	if srcRec.Code != http.StatusOK {
		t.Fatalf("/api/sources failed: %d", srcRec.Code)
	}
	var srcInfo observability.SourceInfo
	if err := json.Unmarshal(srcRec.Body.Bytes(), &srcInfo); err != nil {
		t.Fatalf("parse sources: %v", err)
	}
	found := false
	for _, a := range srcInfo.Agents {
		if a.Name == "prod-gateway-fra" {
			found = true
			if a.EventCount != int64(totalEventsExpected) {
				t.Errorf("expected %d events, got %d", totalEventsExpected, a.EventCount)
			}
			if a.Status != "online" {
				t.Errorf("expected online status, got %s", a.Status)
			}
		}
	}
	if !found {
		t.Errorf("agent prod-gateway-fra not found in /api/sources")
	}
}

func TestIntegration_MultiSource_FileAndDockerConcurrentStreaming(t *testing.T) {
	clusterDir, serverPubStr, logFile, handler, cleanup := setupIntegrationCluster(t)
	defer cleanup()

	mockClient := &http.Client{
		Transport: &mockTransport{handler: handler},
	}

	// 1. Create agent key and register
	rawToken, keyMeta, err := observability.CreateAgentKey("multi-source-node", clusterDir)
	if err != nil {
		t.Fatalf("failed to create agent key: %v", err)
	}
	recipientPub, _ := crypto.DecodePublicKey(serverPubStr)

	// 2. Create 2 distinct log files on disk (simulating Nginx and Traefik)
	tmpDir := t.TempDir()
	nginxLogPath := filepath.Join(tmpDir, "nginx_access.log")
	traefikLogPath := filepath.Join(tmpDir, "traefik_access.log")

	nginxLines := []string{
		`192.168.1.10 - - [18/Oct/2026:12:00:00 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "curl/8.0"`,
		`192.168.1.11 - - [18/Oct/2026:12:00:01 +0000] "POST /api/v1/login HTTP/1.1" 200 512 "-" "Mozilla/5.0"`,
	}
	traefikLines := []string{
		`{"ClientHost":"10.0.0.5","RequestMethod":"GET","RequestPath":"/healthz","DownstreamStatus":200,"Duration":1500000}`,
		`{"ClientHost":"10.0.0.6","RequestMethod":"GET","RequestPath":"/metrics","DownstreamStatus":200,"Duration":2500000}`,
	}
	dockerLines := []string{
		`172.17.0.2 - - [18/Oct/2026:12:00:02 +0000] "GET /status HTTP/1.1" 200 64 "-" "DockerApp"`,
	}

	_ = os.WriteFile(nginxLogPath, []byte(strings.Join(nginxLines, "\n")+"\n"), 0600)
	_ = os.WriteFile(traefikLogPath, []byte(strings.Join(traefikLines, "\n")+"\n"), 0600)

	// 3. Resolve files using resolveFileList and verify multi-file glob resolution
	filesToMonitor := resolveFileList([]string{filepath.Join(tmpDir, "*_access.log")}, nil)
	if len(filesToMonitor) != 2 {
		t.Fatalf("expected 2 files resolved from glob, got %d: %v", len(filesToMonitor), filesToMonitor)
	}

	// 4. Setup shared ring buffer channel
	eventChan := make(chan string, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Concurrently tail both files
	for _, f := range filesToMonitor {
		go tailFileToChan(ctx, f, "10", eventChan)
	}

	// Concurrently inject Docker events into the same ring buffer
	go func() {
		for _, dl := range dockerLines {
			select {
			case <-ctx.Done():
				return
			case eventChan <- dl:
			}
		}
	}()

	// 5. Read all 5 events from shared eventChan with timeout
	var collected []string
	expectedTotal := len(nginxLines) + len(traefikLines) + len(dockerLines)
	deadline := time.After(1500 * time.Millisecond)

collectLoop:
	for len(collected) < expectedTotal {
		select {
		case line := <-eventChan:
			collected = append(collected, line)
		case <-deadline:
			break collectLoop
		}
	}

	if len(collected) < expectedTotal {
		t.Fatalf("expected %d total collected events, got %d: %v", expectedTotal, len(collected), collected)
	}

	// 6. Encrypt batch and push to server
	err = sendBatchWithRetry(context.Background(), mockClient, "http://routewarden.internal:7890/api/v1/events", rawToken, keyMeta.ID, "multi-node-host", recipientPub, collected)
	if err != nil {
		t.Fatalf("failed to push multi-source batch: %v", err)
	}

	// 7. Verify all entries are present in server central log
	logBytes, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read central log: %v", err)
	}
	serverLogLines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	if len(serverLogLines) != expectedTotal {
		t.Fatalf("expected %d entries in central log, got %d:\n%s", expectedTotal, len(serverLogLines), string(logBytes))
	}
}
