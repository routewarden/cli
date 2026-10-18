package observability_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/crypto"
	"github.com/routewarden/cli/observability"
)

func TestEventStore_AddAndGetStats(t *testing.T) {
	store := observability.NewEventStore()

	// Ingest sample events
	store.Add(&observability.SecurityEvent{
		ClientIP:  "198.51.100.10",
		Method:    "GET",
		Path:      "/index.html",
		Status:    200,
		Verdict:   "ALLOW",
		LatencyMs: 1.5,
	})

	store.Add(&observability.SecurityEvent{
		ClientIP:  "203.0.113.5",
		Method:    "POST",
		Path:      "/login",
		Status:    403,
		Verdict:   "BLOCK",
		Rule:      "sql-injection",
		LatencyMs: 0.9,
	})

	store.Add(&observability.SecurityEvent{
		ClientIP:  "203.0.113.5",
		Method:    "GET",
		Path:      "/wp-login.php",
		Status:    429,
		Verdict:   "TARPIT",
		Rule:      "scanner",
		LatencyMs: 5000.0,
	})

	stats := store.GetStats()
	if stats.TotalEvents == 0 {
		t.Errorf("expected non-zero total events, got %d", stats.TotalEvents)
	}

	// Verify top IP
	if len(stats.TopIPs) == 0 || stats.TopIPs[0].Name != "203.0.113.5" {
		t.Errorf("expected top IP 203.0.113.5, got %+v", stats.TopIPs)
	}
	if stats.TopIPs[0].Blocked != 1 || stats.TopIPs[0].Tarpit != 1 {
		t.Errorf("expected 1 blocked and 1 tarpit for top IP, got %+v", stats.TopIPs[0])
	}

	// Verify top rule
	if len(stats.TopRules) == 0 {
		t.Errorf("expected top rules, got empty")
	}

	// Verify recent events
	if len(stats.RecentEvents) != 3 {
		t.Errorf("expected 3 recent events, got %d", len(stats.RecentEvents))
	}
}

func TestEventStore_ParseAndIngest(t *testing.T) {
	store := observability.NewEventStore()

	// Test JSON parse
	jsonLine := `{"time":"2026-10-18T12:00:00Z","client_ip":"192.0.2.1","method":"DELETE","path":"/api/keys","status":403,"verdict":"BLOCK","rule":"unauthorized"}`
	ev1 := store.ParseAndIngest(jsonLine, "test-source")
	if ev1 == nil {
		t.Fatalf("expected non-nil event from JSON parse")
	}
	if ev1.Verdict != "BLOCK" || ev1.Rule != "unauthorized" || ev1.Method != "DELETE" {
		t.Errorf("unexpected event content: %+v", ev1)
	}

	// Test Combined log parse with verdict tag
	combinedLine := `198.51.100.99 - - [18/Oct/2026:12:00:00 +0000] "GET /etc/passwd HTTP/1.1" 403 0 "-" "[BLOCK: path-traversal]"`
	ev2 := store.ParseAndIngest(combinedLine, "file")
	if ev2 == nil {
		t.Fatalf("expected non-nil event from combined parse")
	}
	if ev2.Verdict != "BLOCK" || ev2.Rule != "path-traversal" || ev2.ClientIP != "198.51.100.99" {
		t.Errorf("unexpected combined event content: %+v", ev2)
	}
}

func TestEventStore_Subscription(t *testing.T) {
	store := observability.NewEventStore()
	ch, unsub := store.Subscribe()
	defer unsub()

	testEv := &observability.SecurityEvent{
		ClientIP: "1.2.3.4",
		Method:   "GET",
		Path:     "/test",
		Verdict:  "ALLOW",
		Status:   200,
	}

	go store.Add(testEv)

	select {
	case received := <-ch:
		if received.ClientIP != "1.2.3.4" || received.Path != "/test" {
			t.Errorf("unexpected received event: %+v", received)
		}
	}
}

func TestCustomDashboard_HTTPEndpoints(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-soc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPriv.PublicKey())

	logFilePath := tempDir + "/access.log"
	logFile, _ := os.Create(logFilePath)
	defer logFile.Close()

	handler := observability.NewDashboardHandler(tempDir, serverPriv, serverPubStr, logFile, nil, "")

	// 1. GET / should return 200 with custom SOC dashboard HTML
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "RouteWarden") || !strings.Contains(body, "SOC INTELLIGENCE") {
		t.Errorf("expected RouteWarden SOC dashboard HTML, got: %s", body[:min(200, len(body))])
	}

	// 2. GET /api/stats should return valid JSON
	reqStats := httptest.NewRequest("GET", "/api/stats", nil)
	rrStats := httptest.NewRecorder()
	handler.ServeHTTP(rrStats, reqStats)

	if rrStats.Code != http.StatusOK {
		t.Errorf("expected 200 OK for GET /api/stats, got %d", rrStats.Code)
	}
	var stats map[string]interface{}
	if err := json.Unmarshal(rrStats.Body.Bytes(), &stats); err != nil {
		t.Errorf("failed to parse /api/stats JSON: %v", err)
	}
	if _, ok := stats["total_events"]; !ok {
		t.Errorf("expected total_events key in /api/stats")
	}
}
