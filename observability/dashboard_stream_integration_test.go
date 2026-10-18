package observability_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/routewarden/cli/crypto"
	"github.com/routewarden/cli/observability"
)

func TestDashboard_SSEStream_Integration(t *testing.T) {
	store := observability.NewEventStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		observability.ServeSSE(rec, req, store)
	}()

	// Wait briefly for connection and subscription setup
	time.Sleep(20 * time.Millisecond)

	// Ingest a live security event
	store.Add(&observability.SecurityEvent{
		ClientIP: "198.51.100.77",
		Method:   "GET",
		Path:     "/admin/dashboard",
		Status:   403,
		Verdict:  "BLOCK",
		Rule:     "admin-protection",
	})

	time.Sleep(20 * time.Millisecond)
	cancel() // Close SSE context

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("ServeSSE did not terminate after context cancel")
	}

	res := rec.Result()
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: connected") {
		t.Errorf("expected initial connected event, got: %s", body)
	}
	if !strings.Contains(body, "event: event") || !strings.Contains(body, "198.51.100.77") || !strings.Contains(body, "/admin/dashboard") {
		t.Errorf("expected streamed event in body: %s", body)
	}
}

func TestDashboard_SourcesEndpoint(t *testing.T) {
	tempDir := t.TempDir()
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	serverPubStr := crypto.EncodePublicKey(serverPriv.PublicKey())
	logFile, _ := os.Create(tempDir + "/access.log")
	defer logFile.Close()

	handler := observability.NewDashboardHandler(tempDir, serverPriv, serverPubStr, logFile, nil, "")

	req := httptest.NewRequest("GET", "/api/sources", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/sources, got %d", rr.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode JSON from /api/sources: %v", err)
	}
	if _, ok := res["mode"]; !ok {
		t.Errorf("expected 'mode' in /api/sources response: %v", res)
	}
	if _, ok := res["agents"]; !ok {
		t.Errorf("expected 'agents' in /api/sources response: %v", res)
	}
}

func TestEventStore_SeedDemoData(t *testing.T) {
	store := observability.NewEventStore()
	store.SeedDemoData()

	stats := store.GetStats()
	if stats.TotalEvents == 0 {
		t.Fatalf("expected SeedDemoData to populate events, got 0")
	}

	if len(stats.TopIPs) == 0 {
		t.Errorf("expected SeedDemoData to generate top IPs")
	}
	if len(stats.TopPaths) == 0 {
		t.Errorf("expected SeedDemoData to generate top paths")
	}
	if len(stats.TopCountries) == 0 {
		t.Errorf("expected SeedDemoData to generate top countries")
	}
	if stats.BlockedCount == 0 {
		t.Errorf("expected SeedDemoData to contain blocked threats")
	}
	if stats.TarpitCount == 0 {
		t.Errorf("expected SeedDemoData to contain tarpitted sessions")
	}
}

func TestEventStore_ConcurrentSubscribers(t *testing.T) {
	store := observability.NewEventStore()
	var wg sync.WaitGroup
	subscriberCount := 20
	eventCount := 10

	receivedCounts := make([]int, subscriberCount)

	for i := 0; i < subscriberCount; i++ {
		idx := i
		ch, unsub := store.Subscribe()
		defer unsub()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < eventCount; j++ {
				select {
				case ev := <-ch:
					if ev != nil {
						receivedCounts[idx]++
					}
				case <-time.After(2 * time.Second):
					return
				}
			}
		}()
	}

	// Dispatch events concurrently
	for i := 0; i < eventCount; i++ {
		go store.Add(&observability.SecurityEvent{
			ClientIP: "10.0.0.1",
			Method:   "GET",
			Path:     "/concurrent",
			Verdict:  "ALLOW",
			Status:   200,
		})
	}

	wg.Wait()

	for i, count := range receivedCounts {
		if count == 0 {
			t.Errorf("subscriber %d received 0 events", i)
		}
	}
}
