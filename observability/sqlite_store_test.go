package observability_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/routewarden/cli/observability"
)

func TestSQLiteStore_CRUDAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_events.db")

	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	if store.DBPath() != dbPath {
		t.Errorf("expected DBPath %q, got %q", dbPath, store.DBPath())
	}

	// 1. Initially empty
	if count := store.Count(); count != 0 {
		t.Errorf("expected 0 events, got %d", count)
	}

	// 2. Insert events
	now := time.Now().UTC()
	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Add(-10 * time.Minute).Format(time.RFC3339),
		TimeStr:     "12:00:00",
		ClientIP:    "198.51.100.1",
		Method:      "GET",
		Path:        "/api/v1/health",
		Status:      200,
		Verdict:     "ALLOW",
		LatencyMs:   1.2,
		Source:      "gateway-1",
		Country:     "United States",
		CountryCode: "US",
	})

	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Add(-5 * time.Minute).Format(time.RFC3339),
		TimeStr:     "12:05:00",
		ClientIP:    "203.0.113.88",
		Method:      "POST",
		Path:        "/admin/login",
		Status:      403,
		Verdict:     "BLOCK",
		Rule:        "brute-force",
		LatencyMs:   0.8,
		Source:      "gateway-1",
		Country:     "Germany",
		CountryCode: "DE",
	})

	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Format(time.RFC3339),
		TimeStr:     "12:10:00",
		ClientIP:    "203.0.113.99",
		Method:      "GET",
		Path:        "/wp-admin/setup.php",
		Status:      429,
		Verdict:     "TARPIT",
		Rule:        "scanner",
		LatencyMs:   5000.0,
		Source:      "gateway-2",
		Country:     "Russia",
		CountryCode: "RU",
	})

	store.Flush()

	if count := store.Count(); count != 3 {
		t.Errorf("expected 3 stored events, got %d", count)
	}

	// 3. Query all recent
	recent, err := store.GetRecent(10)
	if err != nil {
		t.Fatalf("failed to get recent: %v", err)
	}
	if len(recent) != 3 {
		t.Fatalf("expected 3 events, got %d", len(recent))
	}

	// 4. Query with Verdict filter
	blocked, err := store.Query(observability.LogQueryFilter{Verdict: "BLOCK"})
	if err != nil {
		t.Fatalf("failed to query by verdict: %v", err)
	}
	if len(blocked) != 1 || blocked[0].Verdict != "BLOCK" || blocked[0].ClientIP != "203.0.113.88" {
		t.Errorf("expected 1 BLOCK event for 203.0.113.88, got %+v", blocked)
	}

	// 5. Query with Search filter
	searchRes, err := store.Query(observability.LogQueryFilter{Search: "wp-admin"})
	if err != nil {
		t.Fatalf("failed to query by search: %v", err)
	}
	if len(searchRes) != 1 || searchRes[0].Path != "/wp-admin/setup.php" {
		t.Errorf("expected 1 result for search 'wp-admin', got %+v", searchRes)
	}

	// 6. Query with Method and Status filter
	statusRes, err := store.Query(observability.LogQueryFilter{Method: "POST", Status: 403})
	if err != nil {
		t.Fatalf("failed to query by status: %v", err)
	}
	if len(statusRes) != 1 || statusRes[0].Status != 403 {
		t.Errorf("expected 1 POST 403 event, got %+v", statusRes)
	}

	// 7. Prune Max Rows
	if _, err := store.PruneMaxRows(2); err != nil {
		t.Fatalf("failed to prune max rows: %v", err)
	}
	if count := store.Count(); count != 2 {
		t.Errorf("expected 2 stored events after prune, got %d", count)
	}
}

func TestEventStore_AttachSQLiteAndPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist.db")

	sq, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}

	store := observability.NewEventStore()
	store.AttachSQLite(sq)

	if store.SQLite() == nil {
		t.Fatal("expected store.SQLite() to return attached store")
	}

	// Ingest event via store.Add
	store.Add(&observability.SecurityEvent{
		ClientIP:  "198.51.100.55",
		Method:    "GET",
		Path:      "/secret",
		Status:    403,
		Verdict:   "BLOCK",
		Rule:      "restricted-path",
		LatencyMs: 0.5,
	})

	sq.Flush()
	if count := sq.Count(); count != 1 {
		t.Fatalf("expected 1 event in SQLite, got %d", count)
	}
	_ = sq.Close()

	// Simulate restart with a new EventStore attaching the same database
	sq2, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen SQLiteStore: %v", err)
	}
	defer sq2.Close()

	newStore := observability.NewEventStore()
	newStore.AttachSQLite(sq2)

	stats := newStore.GetStats()
	if len(stats.RecentEvents) != 1 || stats.RecentEvents[0].ClientIP != "198.51.100.55" {
		t.Errorf("expected 1 preloaded event with IP 198.51.100.55, got %+v", stats.RecentEvents)
	}

	// SeedDemoData should be skipped because real persisted data exists
	newStore.SeedDemoData()
	if statsAfter := newStore.GetStats(); len(statsAfter.RecentEvents) != 1 {
		t.Errorf("expected SeedDemoData to be no-op when DB has events, got %d events", len(statsAfter.RecentEvents))
	}
}

func TestAPI_LogsEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "api_logs.db")

	sq, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init SQLiteStore: %v", err)
	}
	defer sq.Close()

	for i := 1; i <= 5; i++ {
		sq.Insert(&observability.SecurityEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("192.0.2.%d", i),
			Method:    "GET",
			Path:      fmt.Sprintf("/resource/%d", i),
			Status:    200,
			Verdict:   "ALLOW",
		})
	}
	sq.Flush()

	store := observability.GlobalStore()
	store.AttachSQLite(sq)

	// Create test handler
	handler := observability.NewDashboardHandler(tmpDir, nil, "", nil, nil, "")

	// 1. GET /api/logs with limit
	req := httptest.NewRequest("GET", "/api/logs?limit=3", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var resp struct {
		Events []*observability.SecurityEvent `json:"events"`
		Total  int64                          `json:"total"`
		Count  int                            `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode /api/logs JSON: %v", err)
	}

	if resp.Total != 5 {
		t.Errorf("expected total 5, got %d", resp.Total)
	}
	if resp.Count != 3 || len(resp.Events) != 3 {
		t.Errorf("expected 3 returned events, got %d", resp.Count)
	}

	// 2. Query /api/logs with IP search
	reqSearch := httptest.NewRequest("GET", "/api/logs?ip=192.0.2.3", nil)
	rrSearch := httptest.NewRecorder()
	handler.ServeHTTP(rrSearch, reqSearch)

	if rrSearch.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrSearch.Code)
	}

	var respSearch struct {
		Events []*observability.SecurityEvent `json:"events"`
		Total  int64                          `json:"total"`
		Count  int                            `json:"count"`
	}
	if err := json.Unmarshal(rrSearch.Body.Bytes(), &respSearch); err != nil {
		t.Fatalf("failed to decode search JSON: %v", err)
	}

	if respSearch.Count != 1 || respSearch.Events[0].ClientIP != "192.0.2.3" {
		t.Errorf("expected 1 result for IP 192.0.2.3, got %+v", respSearch)
	}
}
