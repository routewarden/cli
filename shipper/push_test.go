package shipper

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/routewarden/cli/crypto"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestShipper_SendBatchWithRetry_EmptyBatch(t *testing.T) {
	called := false
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
	}

	err := SendBatchWithRetry(context.Background(), client, "http://example.com/api/v1/events", "token", "agent1", "host1", nil, nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}
	if called {
		t.Error("expected no HTTP call for empty batch")
	}
}

func TestShipper_SendBatchWithRetry_ManualDirectEvents(t *testing.T) {
	var receivedPayload pushPayload
	var receivedAuth string
	var receivedContentType string

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			receivedAuth = req.Header.Get("Authorization")
			receivedContentType = req.Header.Get("Content-Type")

			rec := httptest.NewRecorder()
			if err := json.NewDecoder(req.Body).Decode(&receivedPayload); err != nil {
				rec.WriteHeader(http.StatusBadRequest)
				return rec.Result(), nil
			}
			rec.WriteHeader(http.StatusAccepted)
			return rec.Result(), nil
		}),
	}

	manualEvents := []string{
		`{"client_ip":"198.51.100.1","path":"/.env","verdict":"BLOCK"}`,
		`{"client_ip":"198.51.100.2","path":"/server.key","verdict":"BLOCK"}`,
	}

	err := SendBatchWithRetry(
		context.Background(),
		client,
		"http://localhost:7890/api/v1/events",
		"rw_sec_shipper_token",
		"shipper-agent-01",
		"node-alpha",
		nil,
		manualEvents,
	)
	if err != nil {
		t.Fatalf("SendBatchWithRetry failed: %v", err)
	}

	if receivedAuth != "Bearer rw_sec_shipper_token" {
		t.Errorf("expected Bearer rw_sec_shipper_token, got: %s", receivedAuth)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected application/json, got: %s", receivedContentType)
	}
	if receivedPayload.AgentID != "shipper-agent-01" {
		t.Errorf("expected agent ID shipper-agent-01, got: %s", receivedPayload.AgentID)
	}
	if receivedPayload.Hostname != "node-alpha" {
		t.Errorf("expected hostname node-alpha, got: %s", receivedPayload.Hostname)
	}
	if len(receivedPayload.Events) != 2 || receivedPayload.Events[0] != manualEvents[0] {
		t.Errorf("expected events to match manualEvents, got: %v", receivedPayload.Events)
	}
}

func TestShipper_SendBatchWithRetry_Encrypted(t *testing.T) {
	serverPriv, serverPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var decryptedEvents []string
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			var encPayload crypto.EncryptedPayload
			if err := json.NewDecoder(req.Body).Decode(&encPayload); err != nil {
				rec.WriteHeader(http.StatusBadRequest)
				return rec.Result(), nil
			}
			plaintext, err := crypto.Decrypt(serverPriv, &encPayload)
			if err != nil {
				rec.WriteHeader(http.StatusBadRequest)
				return rec.Result(), nil
			}
			var payload pushPayload
			if err := json.Unmarshal(plaintext, &payload); err != nil {
				rec.WriteHeader(http.StatusBadRequest)
				return rec.Result(), nil
			}
			decryptedEvents = payload.Events
			rec.WriteHeader(http.StatusAccepted)
			return rec.Result(), nil
		}),
	}

	manualEvents := []string{
		`{"client_ip":"198.51.100.99","path":"/admin.php","verdict":"BLOCK"}`,
	}

	err = SendBatchWithRetry(
		context.Background(),
		client,
		"http://localhost:7890/api/v1/events",
		"token",
		"agent-enc",
		"enc-host",
		serverPub,
		manualEvents,
	)
	if err != nil {
		t.Fatalf("SendBatchWithRetry failed: %v", err)
	}

	if len(decryptedEvents) != 1 || decryptedEvents[0] != manualEvents[0] {
		t.Errorf("decrypted events mismatch: %v", decryptedEvents)
	}
}

func TestShipper_SendBatchWithRetry_RetryRecovery(t *testing.T) {
	var attempts int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count := atomic.AddInt32(&attempts, 1)
			rec := httptest.NewRecorder()
			if count == 1 {
				rec.WriteHeader(http.StatusBadGateway)
			} else {
				rec.WriteHeader(http.StatusAccepted)
			}
			return rec.Result(), nil
		}),
	}

	err := SendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "tok", "id", "host", nil, []string{"ev1"})
	if err != nil {
		t.Fatalf("expected recovery on retry, got: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestShipper_SendBatchWithRetry_ContextCancelled(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusServiceUnavailable)
			return rec.Result(), nil
		}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	batch := []string{"event 1"}
	err := SendBatchWithRetry(ctx, client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestShipper_SendBatchWithRetry_ExhaustionError(t *testing.T) {
	var attempts int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusInternalServerError)
			return rec.Result(), nil
		}),
	}

	batch := []string{"event 1"}
	err := SendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Error("expected error after retry exhaustion, got nil")
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestShipper_SendBatchWithRetry_ClientError401(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusUnauthorized)
			return rec.Result(), nil
		}),
	}

	batch := []string{"event 1"}
	err := SendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Fatal("expected error for 401 Unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error message, got: %v", err)
	}
}

func TestShipper_ResolveFileList(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "access_1.log")
	f2 := filepath.Join(tmpDir, "access_2.log")
	_ = os.WriteFile(f1, []byte("log1"), 0644)
	_ = os.WriteFile(f2, []byte("log2"), 0644)

	t.Run("direct paths and glob", func(t *testing.T) {
		res := ResolveFileList([]string{f1, tmpDir + "/*.log"}, nil)
		if len(res) != 2 {
			t.Fatalf("expected 2 resolved files, got %d: %v", len(res), res)
		}
	})

	t.Run("stdin dash resolution", func(t *testing.T) {
		res := ResolveFileList([]string{"-"}, nil)
		if len(res) != 1 || res[0] != "-" {
			t.Errorf("expected ['-'], got %v", res)
		}
		resPos := ResolveFileList(nil, []string{"-"})
		if len(resPos) != 1 || resPos[0] != "-" {
			t.Errorf("expected ['-'], got %v", resPos)
		}
	})
}

func TestShipper_ResolveContainerList(t *testing.T) {
	res := ResolveContainerList([]string{"c1", "c2,c3", "c1"})
	if len(res) != 3 {
		t.Fatalf("expected 3 unique containers, got %d: %v", len(res), res)
	}
	if res[0] != "c1" || res[1] != "c2" || res[2] != "c3" {
		t.Errorf("unexpected containers: %v", res)
	}
}

func TestShipper_StringSliceFlag(t *testing.T) {
	var s StringSlice
	if s.String() != "" {
		t.Errorf("expected empty string, got: %s", s.String())
	}
	if err := s.Set("val1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("val2"); err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0] != "val1" || s[1] != "val2" {
		t.Errorf("unexpected slice: %v", s)
	}
	if s.String() != "val1, val2" {
		t.Errorf("unexpected string: %s", s.String())
	}
}

func TestShipper_ParseFlagsLenient(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var events StringSlice
	fs.Var(&events, "event", "event flag")
	fs.Var(&events, "e", "alias")
	stdinMode := fs.Bool("stdin", false, "stdin mode")

	args := []string{"positional_file.log", "-e", "event_one", "--event", "event_two", "--stdin", "another_file.log"}
	err := ParseFlagsLenient(fs, args)
	if err != nil {
		t.Fatalf("ParseFlagsLenient failed: %v", err)
	}

	if !*stdinMode {
		t.Error("expected --stdin to be true")
	}
	if len(events) != 2 || events[0] != "event_one" || events[1] != "event_two" {
		t.Errorf("unexpected events: %v", events)
	}
	if len(fs.Args()) != 2 || fs.Args()[0] != "positional_file.log" || fs.Args()[1] != "another_file.log" {
		t.Errorf("unexpected positional args: %v", fs.Args())
	}
}

func TestShipper_ParseFlagsLenient_Verbose(t *testing.T) {
	fs := flag.NewFlagSet("test_verbose", flag.ContinueOnError)
	verbose := fs.Bool("verbose", false, "verbose mode")
	fs.BoolVar(verbose, "v", false, "alias")

	args := []string{"-v", "app.log"}
	if err := ParseFlagsLenient(fs, args); err != nil {
		t.Fatalf("ParseFlagsLenient failed: %v", err)
	}
	if !*verbose {
		t.Error("expected verbose to be true with -v")
	}

	fs2 := flag.NewFlagSet("test_verbose2", flag.ContinueOnError)
	verbose2 := fs2.Bool("verbose", false, "verbose mode")
	fs2.BoolVar(verbose2, "v", false, "alias")

	args2 := []string{"--verbose"}
	if err := ParseFlagsLenient(fs2, args2); err != nil {
		t.Fatalf("ParseFlagsLenient failed: %v", err)
	}
	if !*verbose2 {
		t.Error("expected verbose2 to be true with --verbose")
	}
}

func TestShipper_IsRouteWardenLog_FilterValidation(t *testing.T) {
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
			name:     "Caddy structured JSON access log with nested request object",
			line:     `{"level":"info","ts":1710000000.123,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/admin","method":"GET"},"status":403}`,
			expected: true,
		},
		{
			name:     "NGINX JSON access log with remote_addr and request_uri",
			line:     `{"remote_addr":"198.51.100.44","status":403,"request_uri":"/.env","method":"GET"}`,
			expected: true,
		},
		{
			name:     "Docker log with UTC+05:30 timezone offset prefix 200 OK (filtered by default)",
			line:     `2026-10-21T13:18:12.123456789+05:30 198.51.100.1 - - [21/Oct/2026:07:48:12 +0000] "GET / HTTP/1.1" 200 123`,
			expected: false,
		},
		{
			name:     "Caddy startup non-access info message (should be filtered out)",
			line:     `{"level":"info","ts":1792517942.4564745,"msg":"maxprocs: Leaving GOMAXPROCS=2: CPU quota undefined"}`,
			expected: false,
		},
		{
			name:     "Caddy config load non-access info message (should be filtered out)",
			line:     `{"level":"info","ts":1792517942.456751,"msg":"using config from file","file":"/etc/caddy/Caddyfile"}`,
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
			cleanLine, ok := FilterRouteWardenLog(tc.line, false)
			if ok != tc.expected {
				t.Errorf("FilterRouteWardenLog(..., false) for %q got ok=%v, expected %v", tc.line, ok, tc.expected)
			}
			if ok && strings.HasPrefix(tc.line, "2026-10-20T14:00:01.123456789Z ") {
				if strings.HasPrefix(cleanLine, "2026-10-20T14:00:01.123456789Z ") {
					t.Errorf("expected docker timestamp prefix stripped, got: %s", cleanLine)
				}
			}
		})
	}
}

func TestShipper_FilterRouteWardenLog_AllLogsBypass(t *testing.T) {
	rawLine := `[DEBUG] (resolver) querying 1.1.1.1 for domain test.internal`
	clean, ok := FilterRouteWardenLog(rawLine, true)
	if !ok || clean != rawLine {
		t.Errorf("expected line to pass when allLogs=true, got ok=%v clean=%q", ok, clean)
	}

	cleanDefault, okDefault := FilterRouteWardenLog(rawLine, false)
	if okDefault || cleanDefault != "" {
		t.Errorf("expected line to be filtered when allLogs=false, got ok=%v clean=%q", okDefault, cleanDefault)
	}
}

func TestShipper_FilterRouteWardenLog_FilterOptions(t *testing.T) {
	caddy404 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/not-found","method":"GET"},"status":404}`
	caddy500 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/server-error","method":"GET"},"status":500}`
	caddy200 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/ok","method":"GET"},"status":200}`
	caddy403 := `{"level":"info","logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","uri":"/forbidden","method":"GET"},"status":403}`

	// 1. Default: only 403 passes (security event)
	if _, ok := FilterRouteWardenLogOpts(caddy200, FilterOptions{}); ok {
		t.Error("expected caddy 200 to be filtered by default")
	}
	if _, ok := FilterRouteWardenLogOpts(caddy404, FilterOptions{}); ok {
		t.Error("expected caddy 404 to be filtered by default")
	}
	if _, ok := FilterRouteWardenLogOpts(caddy403, FilterOptions{}); !ok {
		t.Error("expected caddy 403 to pass by default")
	}

	// 2. IncludeFailed: 404, 500, 403 pass, 200 fails
	if _, ok := FilterRouteWardenLogOpts(caddy404, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected caddy 404 to pass with IncludeFailed")
	}
	if _, ok := FilterRouteWardenLogOpts(caddy500, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected caddy 500 to pass with IncludeFailed")
	}
	if _, ok := FilterRouteWardenLogOpts(caddy200, FilterOptions{IncludeFailed: true}); ok {
		t.Error("expected caddy 200 to be filtered even with IncludeFailed")
	}

	// 3. AllTraffic: 200 passes
	if _, ok := FilterRouteWardenLogOpts(caddy200, FilterOptions{AllTraffic: true}); !ok {
		t.Error("expected caddy 200 to pass with AllTraffic")
	}
}

func TestShipper_PingDashboard_Success(t *testing.T) {
	_, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubStr := crypto.EncodePublicKey(pub)

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/api/v1/ping" {
				t.Errorf("unexpected path: %s", req.URL.Path)
			}
			if req.Header.Get("Authorization") != "Bearer test-tok" {
				t.Errorf("unexpected auth header: %s", req.Header.Get("Authorization"))
			}
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rec).Encode(map[string]interface{}{
				"status":     "ok",
				"public_key": pubStr,
				"version":    "5.2.2",
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})
			return rec.Result(), nil
		}),
	}

	res := PingDashboard(context.Background(), client, "http://localhost:7890", "test-tok", "agent-node")
	if !res.Connected {
		t.Fatalf("expected Connected=true, got false: %v", res.Err)
	}
	if res.ServerPubKey == nil {
		t.Fatal("expected non-nil ServerPubKey")
	}
	if res.ServerPubKeyStr != pubStr {
		t.Errorf("expected ServerPubKeyStr=%s, got %s", pubStr, res.ServerPubKeyStr)
	}
}

func TestShipper_PingDashboard_AuthFailure(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(rec).Encode(map[string]string{"error": "unauthorized"})
			return rec.Result(), nil
		}),
	}

	res := PingDashboard(context.Background(), client, "http://localhost:7890", "bad-tok", "agent-node")
	if res.Connected {
		t.Fatal("expected Connected=false for 401")
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected StatusCode=401, got %d", res.StatusCode)
	}
}

func TestShipper_SendBatchWithRetry_KeyRotationRecovery(t *testing.T) {
	_, oldPub, _ := crypto.GenerateKeyPair()
	newPriv, newPub, _ := crypto.GenerateKeyPair()
	newPubStr := crypto.EncodePublicKey(newPub)

	var attempts int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			var enc crypto.EncryptedPayload
			_ = json.NewDecoder(req.Body).Decode(&enc)

			rec := httptest.NewRecorder()
			dec, decErr := crypto.Decrypt(newPriv, &enc)
			if decErr != nil {
				rec.Header().Set("Content-Type", "application/json")
				rec.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rec).Encode(map[string]string{
					"error":      "decryption failed: " + decErr.Error(),
					"public_key": newPubStr,
				})
				return rec.Result(), nil
			}

			var p pushPayload
			if err := json.Unmarshal(dec, &p); err != nil {
				t.Errorf("failed to decode decrypted payload: %v", err)
				rec.WriteHeader(http.StatusBadRequest)
				return rec.Result(), nil
			}
			rec.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(rec).Encode(map[string]string{"status": "ok"})
			return rec.Result(), nil
		}),
	}

	var keyUpdated bool
	RegisterKeyUpdateCallback(func(pk *ecdh.PublicKey) {
		keyUpdated = true
	})

	batch := []string{"event-1", "event-2"}
	err := SendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", oldPub, batch)
	if err != nil {
		t.Fatalf("SendBatchWithRetry failed to auto-recover on key rotation: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if !keyUpdated {
		t.Error("expected key update callback to be notified")
	}
}

func TestShipper_HandlePush_Help(t *testing.T) {
	// Should not panic or exit on "help"
	HandlePush([]string{"help"}, "5.3.0")
}

func TestShipper_MultiProxy_ComprehensiveStatusMatrix(t *testing.T) {
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
			_, okDef := FilterRouteWardenLogOpts(tc.line, FilterOptions{})
			if okDef != tc.passDefault {
				t.Errorf("[%s] Default mode: got ok=%v, expected=%v for line: %s", tc.name, okDef, tc.passDefault, tc.line)
			}

			// Mode 2: IncludeFailed
			_, okFail := FilterRouteWardenLogOpts(tc.line, FilterOptions{IncludeFailed: true})
			if okFail != tc.passIncludeFailed {
				t.Errorf("[%s] IncludeFailed mode: got ok=%v, expected=%v for line: %s", tc.name, okFail, tc.passIncludeFailed, tc.line)
			}

			// Mode 3: AllTraffic
			_, okAll := FilterRouteWardenLogOpts(tc.line, FilterOptions{AllTraffic: true})
			if okAll != tc.passAllTraffic {
				t.Errorf("[%s] AllTraffic mode: got ok=%v, expected=%v for line: %s", tc.name, okAll, tc.passAllTraffic, tc.line)
			}

			// Mode 4: AllLogs (always true)
			_, okAllLogs := FilterRouteWardenLogOpts(tc.line, FilterOptions{AllLogs: true})
			if !okAllLogs {
				t.Errorf("[%s] AllLogs mode: expected true, got false", tc.name)
			}
		})
	}
}

func TestShipper_ExplicitSecurityTagsOverrideAllModes(t *testing.T) {
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
			// Must pass in default mode with no flags
			clean, ok := FilterRouteWardenLogOpts(item.line, FilterOptions{})
			if !ok || clean == "" {
				t.Fatalf("expected security event to pass by default, got ok=%v: %s", ok, item.line)
			}
		})
	}
}

func TestShipper_NonHTTPAndCorruptLogs(t *testing.T) {
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
			// Should be rejected in Default, IncludeFailed, and AllTraffic modes
			if _, ok := FilterRouteWardenLogOpts(item.line, FilterOptions{}); ok {
				t.Errorf("[%s] expected false in Default mode, got true", item.name)
			}
			if _, ok := FilterRouteWardenLogOpts(item.line, FilterOptions{IncludeFailed: true}); ok {
				t.Errorf("[%s] expected false in IncludeFailed mode, got true", item.name)
			}
			if _, ok := FilterRouteWardenLogOpts(item.line, FilterOptions{AllTraffic: true}); ok {
				t.Errorf("[%s] expected false in AllTraffic mode, got true", item.name)
			}

			// Should only pass when AllLogs is explicitly true (except empty/whitespace)
			clean, okAll := FilterRouteWardenLogOpts(item.line, FilterOptions{AllLogs: true})
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

func TestShipper_AgentConfig_PersistenceAndResolution(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "agent.json")

	cfg := &AgentConfig{
		DashboardURL:    "http://dashboard.internal:7890",
		AgentToken:      "rw_sec_test_token_12345",
		AgentID:         "agent-node-matrix",
		AgentName:       "matrix-01",
		ServerPublicKey: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
		IncludeFailed:   true,
		AllTraffic:      true,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	readBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var loaded AgentConfig
	if err := json.Unmarshal(readBytes, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !loaded.IncludeFailed {
		t.Errorf("expected IncludeFailed=true, got false")
	}
	if !loaded.AllTraffic {
		t.Errorf("expected AllTraffic=true, got false")
	}
}

func TestShipper_StringStatusCodesAndFlexibleParsing(t *testing.T) {
	// NGINX custom JSON logger commonly formats $status as quoted string: "status": "$status"
	nginxString404 := `{"remote_addr":"198.51.100.1","request_uri":"/missing","method":"GET","status":"404"}`
	nginxString500 := `{"remote_addr":"198.51.100.1","request_uri":"/crash","method":"GET","status":"500"}`
	nginxString403 := `{"remote_addr":"198.51.100.1","request_uri":"/forbidden","method":"GET","status":"403"}`
	nginxString200 := `{"remote_addr":"198.51.100.1","request_uri":"/ok","method":"GET","status":"200"}`

	// 1. Default mode: string "403" is recognized as security event and passes, while "200" and "404" are filtered
	if _, ok := FilterRouteWardenLogOpts(nginxString403, FilterOptions{}); !ok {
		t.Error("expected quoted status \"403\" to pass in default mode")
	}
	if _, ok := FilterRouteWardenLogOpts(nginxString200, FilterOptions{}); ok {
		t.Error("expected quoted status \"200\" to be filtered by default")
	}
	if _, ok := FilterRouteWardenLogOpts(nginxString404, FilterOptions{}); ok {
		t.Error("expected quoted status \"404\" to be filtered by default")
	}

	// 2. IncludeFailed mode: string "404" and "500" pass, "200" is filtered
	if _, ok := FilterRouteWardenLogOpts(nginxString404, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected quoted status \"404\" to pass with IncludeFailed")
	}
	if _, ok := FilterRouteWardenLogOpts(nginxString500, FilterOptions{IncludeFailed: true}); !ok {
		t.Error("expected quoted status \"500\" to pass with IncludeFailed")
	}
	if _, ok := FilterRouteWardenLogOpts(nginxString200, FilterOptions{IncludeFailed: true}); ok {
		t.Error("expected quoted status \"200\" to be filtered with IncludeFailed")
	}

	// 3. AllTraffic mode: string "200" passes
	if _, ok := FilterRouteWardenLogOpts(nginxString200, FilterOptions{AllTraffic: true}); !ok {
		t.Error("expected quoted status \"200\" to pass with AllTraffic")
	}
}

func TestStatusCodeFilter_ParsingAndMatching(t *testing.T) {
	// 1. Parsing ranges and single codes
	filter := ParseStatusCodeFilter("400-599, 301, 302, 4xx, 5xx")
	if len(filter) == 0 {
		t.Fatal("expected non-empty filter")
	}

	testCases := []struct {
		status   int
		expected bool
	}{
		{200, false},
		{204, false},
		{301, true},
		{302, true},
		{304, false},
		{400, true},
		{404, true},
		{418, true},
		{499, true},
		{500, true},
		{502, true},
		{503, true},
		{504, true},
	}

	for _, tc := range testCases {
		if got := filter.Matches(tc.status); got != tc.expected {
			t.Errorf("status %d: got %v, expected %v", tc.status, got, tc.expected)
		}
	}

	// 2. Wildcards (4xx, 5xx)
	wildcardFilter := ParseStatusCodeFilter("4xx, 5XX")
	if !wildcardFilter.Matches(404) || !wildcardFilter.Matches(499) || !wildcardFilter.Matches(500) || wildcardFilter.Matches(200) || wildcardFilter.Matches(301) {
		t.Errorf("unexpected wildcard matching behavior: %v", wildcardFilter)
	}

	// 3. Formatted string
	str := ParseStatusCodeFilter("400-599, 301").String()
	if str != "400-599, 301" {
		t.Errorf("expected '400-599, 301', got %q", str)
	}

	// 4. Edge cases
	empty := ParseStatusCodeFilter("")
	if empty != nil || empty.Matches(200) {
		t.Errorf("expected empty filter to be nil and not match")
	}
	invalid := ParseStatusCodeFilter("invalid, 9999, 50-10, -5")
	if len(invalid) != 0 {
		t.Errorf("expected invalid parts to be ignored, got %v", invalid)
	}
}

func TestFilterRouteWardenLog_ExplicitStatusCodes(t *testing.T) {
	opts := FilterOptions{
		StatusCodes: ParseStatusCodeFilter("400-599, 301"),
	}

	caddy301 := `{"level":"info","ts":1729432800.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","remote_addr":"198.51.100.1:4567","method":"GET","uri":"/redirect","proto":"HTTP/1.1"},"status":301,"size":0,"duration":0.001}`
	traefik301 := `{"ClientHost":"198.51.100.1","DownstreamStatus":301,"RequestPath":"/redirect","RequestMethod":"GET","OriginStatus":301}`
	nginx301 := `{"ip":"198.51.100.1","status":"301","request_uri":"/redirect","method":"GET","request_time":"0.002"}`
	combined301 := `198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /redirect HTTP/1.1" 301 0 "-" "-"`

	caddy200 := `{"level":"info","ts":1729432800.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","remote_addr":"198.51.100.1:4567","method":"GET","uri":"/clean","proto":"HTTP/1.1"},"status":200,"size":123,"duration":0.001}`
	caddy404 := `{"level":"info","ts":1729432800.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","remote_addr":"198.51.100.1:4567","method":"GET","uri":"/notfound","proto":"HTTP/1.1"},"status":404,"size":0,"duration":0.001}`
	caddy502 := `{"level":"info","ts":1729432800.0,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","remote_addr":"198.51.100.1:4567","method":"GET","uri":"/badgw","proto":"HTTP/1.1"},"status":502,"size":0,"duration":0.001}`

	// 1. Status 301 passes across all reverse proxies
	if _, ok := FilterRouteWardenLogOpts(caddy301, opts); !ok {
		t.Error("expected Caddy 301 to pass with status filter 400-599, 301")
	}
	if _, ok := FilterRouteWardenLogOpts(traefik301, opts); !ok {
		t.Error("expected Traefik 301 to pass with status filter 400-599, 301")
	}
	if _, ok := FilterRouteWardenLogOpts(nginx301, opts); !ok {
		t.Error("expected NGINX 301 to pass with status filter 400-599, 301")
	}
	if _, ok := FilterRouteWardenLogOpts(combined301, opts); !ok {
		t.Error("expected Combined 301 to pass with status filter 400-599, 301")
	}

	// 2. Status 404 and 502 pass
	if _, ok := FilterRouteWardenLogOpts(caddy404, opts); !ok {
		t.Error("expected Caddy 404 to pass with status filter 400-599, 301")
	}
	if _, ok := FilterRouteWardenLogOpts(caddy502, opts); !ok {
		t.Error("expected Caddy 502 to pass with status filter 400-599, 301")
	}

	// 3. Status 200 is filtered out
	if _, ok := FilterRouteWardenLogOpts(caddy200, opts); ok {
		t.Error("expected Caddy 200 to be filtered out with status filter 400-599, 301")
	}
}



