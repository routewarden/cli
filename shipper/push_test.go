package shipper

import (
	"context"
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
			name:     "Docker log with UTC+05:30 timezone offset prefix",
			line:     `2026-10-21T13:18:12.123456789+05:30 198.51.100.1 - - [21/Oct/2026:07:48:12 +0000] "GET / HTTP/1.1" 200 123`,
			expected: true,
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
