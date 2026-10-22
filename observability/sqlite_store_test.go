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

	// 5. Query with Source filter
	sourceRes, err := store.Query(observability.LogQueryFilter{Source: "gateway-1"})
	if err != nil {
		t.Fatalf("failed to query by source: %v", err)
	}
	if len(sourceRes) != 2 {
		t.Errorf("expected 2 events for source 'gateway-1', got %d", len(sourceRes))
	}
	if count := store.CountFiltered(observability.LogQueryFilter{Source: "gateway-1"}); count != 2 {
		t.Errorf("expected filtered count 2 for source 'gateway-1', got %d", count)
	}

	// 6. Query with Search filter matching source
	searchSourceRes, err := store.Query(observability.LogQueryFilter{Search: "gateway-2"})
	if err != nil {
		t.Fatalf("failed to query by search on source: %v", err)
	}
	if len(searchSourceRes) != 1 || searchSourceRes[0].Source != "gateway-2" {
		t.Errorf("expected 1 result for search matching source 'gateway-2', got %+v", searchSourceRes)
	}

	// 7. Query with Search filter
	searchRes, err := store.Query(observability.LogQueryFilter{Search: "wp-admin"})
	if err != nil {
		t.Fatalf("failed to query by search: %v", err)
	}
	if len(searchRes) != 1 || searchRes[0].Path != "/wp-admin/setup.php" {
		t.Errorf("expected 1 result for search 'wp-admin', got %+v", searchRes)
	}

	// 8. Query with Method and Status filter
	statusRes, err := store.Query(observability.LogQueryFilter{Method: "POST", Status: 403})
	if err != nil {
		t.Fatalf("failed to query by status: %v", err)
	}
	if len(statusRes) != 1 || statusRes[0].Status != 403 {
		t.Errorf("expected 1 POST 403 event, got %+v", statusRes)
	}

	// 9. Prune Max Rows
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
		sourceName := "node-a"
		if i > 3 {
			sourceName = "node-b"
		}
		sq.Insert(&observability.SecurityEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("192.0.2.%d", i),
			Method:    "GET",
			Path:      fmt.Sprintf("/resource/%d", i),
			Status:    200,
			Verdict:   "ALLOW",
			Source:    sourceName,
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
		Events        []*observability.SecurityEvent `json:"events"`
		Total         int64                          `json:"total"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
		Limit         int                            `json:"limit"`
		Offset        int                            `json:"offset"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode /api/logs JSON: %v", err)
	}

	if resp.Total != 5 {
		t.Errorf("expected total 5, got %d", resp.Total)
	}
	if resp.FilteredTotal != 5 {
		t.Errorf("expected filtered_total 5, got %d", resp.FilteredTotal)
	}
	if resp.Count != 3 || len(resp.Events) != 3 {
		t.Errorf("expected 3 returned events, got %d", resp.Count)
	}
	if resp.Limit != 3 || resp.Offset != 0 {
		t.Errorf("expected limit 3 and offset 0, got limit %d offset %d", resp.Limit, resp.Offset)
	}

	// 2. Query /api/logs with IP search and verify filtered_total
	reqSearch := httptest.NewRequest("GET", "/api/logs?ip=192.0.2.3", nil)
	rrSearch := httptest.NewRecorder()
	handler.ServeHTTP(rrSearch, reqSearch)

	if rrSearch.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrSearch.Code)
	}

	var respSearch struct {
		Events        []*observability.SecurityEvent `json:"events"`
		Total         int64                          `json:"total"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
	}
	if err := json.Unmarshal(rrSearch.Body.Bytes(), &respSearch); err != nil {
		t.Fatalf("failed to decode search JSON: %v", err)
	}

	if respSearch.Total != 5 || respSearch.FilteredTotal != 1 {
		t.Errorf("expected total 5 and filtered_total 1, got total %d filtered_total %d", respSearch.Total, respSearch.FilteredTotal)
	}
	if respSearch.Count != 1 || respSearch.Events[0].ClientIP != "192.0.2.3" {
		t.Errorf("expected 1 result for IP 192.0.2.3, got %+v", respSearch)
	}

	// 3. Query /api/logs with pagination offset
	reqOffset := httptest.NewRequest("GET", "/api/logs?limit=2&offset=2", nil)
	rrOffset := httptest.NewRecorder()
	handler.ServeHTTP(rrOffset, reqOffset)

	var respOffset struct {
		Events []*observability.SecurityEvent `json:"events"`
		Total  int64                          `json:"total"`
		Count  int                            `json:"count"`
		Offset int                            `json:"offset"`
	}
	if err := json.Unmarshal(rrOffset.Body.Bytes(), &respOffset); err != nil {
		t.Fatalf("failed to decode offset JSON: %v", err)
	}
	if respOffset.Count != 2 || respOffset.Offset != 2 {
		t.Errorf("expected 2 events at offset 2, got count %d offset %d", respOffset.Count, respOffset.Offset)
	}

	// 4. Query /api/logs with status group "2xx" and pagination
	reqStatus := httptest.NewRequest("GET", "/api/logs?status=2xx&limit=2&offset=1", nil)
	rrStatus := httptest.NewRecorder()
	handler.ServeHTTP(rrStatus, reqStatus)

	var respStatus struct {
		Events        []*observability.SecurityEvent `json:"events"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
	}
	if err := json.Unmarshal(rrStatus.Body.Bytes(), &respStatus); err != nil {
		t.Fatalf("failed to decode status 2xx JSON: %v", err)
	}
	if respStatus.FilteredTotal != 5 || respStatus.Count != 2 {
		t.Errorf("expected filtered_total 5 and count 2 for 2xx status, got total %d count %d", respStatus.FilteredTotal, respStatus.Count)
	}

	// 5. Query /api/logs with node filter
	reqNode := httptest.NewRequest("GET", "/api/logs?node=node-a&limit=10", nil)
	rrNode := httptest.NewRecorder()
	handler.ServeHTTP(rrNode, reqNode)

	var respNode struct {
		Events        []*observability.SecurityEvent `json:"events"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
	}
	if err := json.Unmarshal(rrNode.Body.Bytes(), &respNode); err != nil {
		t.Fatalf("failed to decode node query JSON: %v", err)
	}
	if respNode.FilteredTotal != 3 || respNode.Count != 3 {
		t.Errorf("expected filtered_total 3 and count 3 for node-a, got total %d count %d", respNode.FilteredTotal, respNode.Count)
	}

	// 6. Query /api/logs with source alias filter
	reqSource := httptest.NewRequest("GET", "/api/logs?source=node-b&limit=10", nil)
	rrSource := httptest.NewRecorder()
	handler.ServeHTTP(rrSource, reqSource)

	var respSource struct {
		Events        []*observability.SecurityEvent `json:"events"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
	}
	if err := json.Unmarshal(rrSource.Body.Bytes(), &respSource); err != nil {
		t.Fatalf("failed to decode source query JSON: %v", err)
	}
	if respSource.FilteredTotal != 2 || respSource.Count != 2 {
		t.Errorf("expected filtered_total 2 and count 2 for node-b, got total %d count %d", respSource.FilteredTotal, respSource.Count)
	}

	// 7. In-Memory fallback pagination and node filtering when sq == nil
	store.AttachSQLite(nil)
	reqMem := httptest.NewRequest("GET", "/api/logs?node=node-a&limit=10&offset=0", nil)
	rrMem := httptest.NewRecorder()
	handler.ServeHTTP(rrMem, reqMem)

	var respMem struct {
		Events        []*observability.SecurityEvent `json:"events"`
		FilteredTotal int64                          `json:"filtered_total"`
		Count         int                            `json:"count"`
	}
	if err := json.Unmarshal(rrMem.Body.Bytes(), &respMem); err != nil {
		t.Fatalf("failed to decode in-memory JSON: %v", err)
	}
	if rrMem.Code != http.StatusOK {
		t.Errorf("expected 200 OK from in-memory fallback, got %d", rrMem.Code)
	}
	if respMem.FilteredTotal != 3 {
		t.Errorf("expected in-memory filtered_total 3 for node-a, got %d", respMem.FilteredTotal)
	}
}

func TestSQLiteStore_StatsSummary(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "stats_summary_test.db")

	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	// 1. Initially empty
	tot, blk, trp, err := store.StatsSummary()
	if err != nil {
		t.Fatalf("StatsSummary failed on empty db: %v", err)
	}
	if tot != 0 || blk != 0 || trp != 0 {
		t.Errorf("expected (0, 0, 0), got (%d, %d, %d)", tot, blk, trp)
	}

	// 2. Insert mixed events
	now := time.Now().UTC()
	store.Insert(&observability.SecurityEvent{
		Timestamp: now.Format(time.RFC3339),
		ClientIP:  "198.51.100.1",
		Status:    200,
		Verdict:   "ALLOW",
	})
	store.Insert(&observability.SecurityEvent{
		Timestamp: now.Add(time.Second).Format(time.RFC3339),
		ClientIP:  "198.51.100.2",
		Status:    403,
		Verdict:   "BLOCK",
	})
	store.Insert(&observability.SecurityEvent{
		Timestamp: now.Add(2 * time.Second).Format(time.RFC3339),
		ClientIP:  "198.51.100.3",
		Status:    429,
		Verdict:   "TARPIT",
	})
	store.Insert(&observability.SecurityEvent{
		Timestamp: now.Add(3 * time.Second).Format(time.RFC3339),
		ClientIP:  "198.51.100.4",
		Status:    403,
		Verdict:   "", // status 403 should be counted as blocked
	})
	store.Flush()

	tot, blk, trp, err = store.StatsSummary()
	if err != nil {
		t.Fatalf("StatsSummary failed: %v", err)
	}
	if tot != 4 || blk != 2 || trp != 1 {
		t.Errorf("expected (4, 2, 1), got (%d, %d, %d)", tot, blk, trp)
	}
}

func TestStatsAndLogsConsistency_Over500Events(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "consistency_test.db")

	sqStore, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer sqStore.Close()

	// Seed 650 events: 500 ALLOW, 100 BLOCK, 50 TARPIT
	now := time.Now().UTC()
	for i := range 500 {
		sqStore.Insert(&observability.SecurityEvent{
			Timestamp: now.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("192.168.1.%d", (i%250)+1),
			Method:    "GET",
			Path:      fmt.Sprintf("/page/%d", i),
			Status:    200,
			Verdict:   "ALLOW",
			Source:    "node-primary",
		})
	}
	for i := range 100 {
		sqStore.Insert(&observability.SecurityEvent{
			Timestamp: now.Add(time.Duration(500+i) * time.Millisecond).Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("10.0.0.%d", (i%250)+1),
			Method:    "POST",
			Path:      fmt.Sprintf("/admin/%d", i),
			Status:    403,
			Verdict:   "BLOCK",
			Source:    "node-primary",
		})
	}
	for i := range 50 {
		sqStore.Insert(&observability.SecurityEvent{
			Timestamp: now.Add(time.Duration(600+i) * time.Millisecond).Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("172.16.0.%d", (i%250)+1),
			Method:    "GET",
			Path:      fmt.Sprintf("/wp-login-%d", i),
			Status:    429,
			Verdict:   "TARPIT",
			Source:    "node-primary",
		})
	}
	sqStore.Flush()

	if totalInDB := sqStore.Count(); totalInDB != 650 {
		t.Fatalf("expected 650 events in DB, got %d", totalInDB)
	}

	// 1. Verify isolated EventStore
	eventStore := observability.NewEventStore()
	eventStore.AttachSQLite(sqStore)

	// Check in-memory GetStats(): must not be capped at 500 preloaded events!
	stats := eventStore.GetStats()
	if stats.TotalEvents != 650 {
		t.Fatalf("expected TotalEvents 650, got %d", stats.TotalEvents)
	}
	if stats.BlockedCount != 100 {
		t.Fatalf("expected BlockedCount 100, got %d", stats.BlockedCount)
	}
	if stats.TarpitCount != 50 {
		t.Fatalf("expected TarpitCount 50, got %d", stats.TarpitCount)
	}
	if stats.CleanCount != 500 {
		t.Fatalf("expected CleanCount 500, got %d", stats.CleanCount)
	}

	// 2. Attach to globalStore and verify consistency via HTTP endpoints
	gStore := observability.GlobalStore()
	gStore.AttachSQLite(sqStore)

	handler := observability.NewDashboardHandler(tmpDir, nil, "", nil, nil, "")

	// 1. Call /api/stats
	reqStats := httptest.NewRequest("GET", "/api/stats", nil)
	rrStats := httptest.NewRecorder()
	handler.ServeHTTP(rrStats, reqStats)

	var statsResp struct {
		TotalEvents  int64 `json:"total_events"`
		BlockedCount int64 `json:"blocked_count"`
		TarpitCount  int64 `json:"tarpit_count"`
	}
	if err := json.Unmarshal(rrStats.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to decode /api/stats: %v", err)
	}

	// 2. Call /api/logs
	reqLogs := httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	rrLogs := httptest.NewRecorder()
	handler.ServeHTTP(rrLogs, reqLogs)

	var logsResp struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(rrLogs.Body.Bytes(), &logsResp); err != nil {
		t.Fatalf("failed to decode /api/logs: %v", err)
	}

	// /api/stats and /api/logs MUST MATCH!
	if statsResp.TotalEvents != logsResp.Total {
		t.Fatalf("mismatch: /api/stats total_events (%d) != /api/logs total (%d)", statsResp.TotalEvents, logsResp.Total)
	}
	if statsResp.TotalEvents != 650 {
		t.Fatalf("expected both to report 650, got %d", statsResp.TotalEvents)
	}

	// 3. Ingest a new live event
	gStore.Add(&observability.SecurityEvent{
		Timestamp: now.Add(time.Hour).Format(time.RFC3339),
		ClientIP:  "198.51.100.200",
		Method:    "GET",
		Path:      "/new-event",
		Status:    200,
		Verdict:   "ALLOW",
	})
	sqStore.Flush()

	// Re-check both endpoints
	rrStats2 := httptest.NewRecorder()
	handler.ServeHTTP(rrStats2, reqStats)
	_ = json.Unmarshal(rrStats2.Body.Bytes(), &statsResp)

	rrLogs2 := httptest.NewRecorder()
	handler.ServeHTTP(rrLogs2, reqLogs)
	_ = json.Unmarshal(rrLogs2.Body.Bytes(), &logsResp)

	if statsResp.TotalEvents != 651 || logsResp.Total != 651 {
		t.Fatalf("expected both to report 651 after live event, got stats=%d logs=%d", statsResp.TotalEvents, logsResp.Total)
	}
}

func TestStatsReconciliation_DynamicSync(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dynamic_sync.db")

	sqStore, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer sqStore.Close()

	eventStore := observability.NewEventStore()
	eventStore.AttachSQLite(sqStore)

	// Initially 0
	stats := eventStore.GetStats()
	if stats.TotalEvents != 0 {
		t.Fatalf("expected initial TotalEvents 0, got %d", stats.TotalEvents)
	}

	// Insert events directly to SQLite out-of-band
	now := time.Now().UTC()
	for i := 0; i < 20; i++ {
		status := 200
		verdict := "ALLOW"
		if i < 5 {
			status = 403
			verdict = "BLOCK"
		} else if i < 8 {
			status = 429
			verdict = "TARPIT"
		}
		sqStore.Insert(&observability.SecurityEvent{
			Timestamp: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
			ClientIP:  fmt.Sprintf("10.10.10.%d", i),
			Status:    status,
			Verdict:   verdict,
		})
	}
	sqStore.Flush()

	// Calling GetStats() should detect that SQLite has 20 events while memory has 0,
	// and automatically reconcile total, blocked, and tarpit counts!
	reconciled := eventStore.GetStats()
	if reconciled.TotalEvents != 20 {
		t.Fatalf("expected reconciled TotalEvents 20, got %d", reconciled.TotalEvents)
	}
	if reconciled.BlockedCount != 5 {
		t.Fatalf("expected reconciled BlockedCount 5, got %d", reconciled.BlockedCount)
	}
	if reconciled.TarpitCount != 3 {
		t.Fatalf("expected reconciled TarpitCount 3, got %d", reconciled.TarpitCount)
	}
	if reconciled.CleanCount != 12 {
		t.Fatalf("expected reconciled CleanCount 12, got %d", reconciled.CleanCount)
	}
}

func TestSQLiteStore_SearchMethodAndStatus(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "search_test.db")
	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	store.Insert(&observability.SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ClientIP:  "192.0.2.1",
		Method:    "DELETE",
		Path:      "/resource/1",
		Status:    204,
		Verdict:   "ALLOW",
	})
	store.Insert(&observability.SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		ClientIP:  "192.0.2.2",
		Method:    "POST",
		Path:      "/login",
		Status:    403,
		Verdict:   "BLOCK",
		Rule:      "bruteforce",
	})
	store.Flush()

	// 1. Search by method "DELETE"
	delEvents, err := store.Query(observability.LogQueryFilter{Search: "DELETE"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(delEvents) != 1 || delEvents[0].Method != "DELETE" {
		t.Errorf("expected 1 DELETE event from search, got %d", len(delEvents))
	}

	// 2. Search by status code "403"
	statusEvents, err := store.Query(observability.LogQueryFilter{Search: "403"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(statusEvents) != 1 || statusEvents[0].Status != 403 {
		t.Errorf("expected 1 event with status 403 from search, got %d", len(statusEvents))
	}
}

