package observability

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestBugFixes_SQLiteStoreConcurrentFlushAndClose(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "flush_close.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}

	for i := 0; i < 50; i++ {
		store.Insert(&SecurityEvent{
			ClientIP: "192.168.1.10",
			Method:   "GET",
			Path:     "/test",
			Status:   200,
			Verdict:  "ALLOW",
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			store.Flush()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		_ = store.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: no deadlock or hang
	case <-time.After(3 * time.Second):
		t.Fatal("Flush and Close deadlocked or took too long")
	}

	// Insert after close should be a safe no-op
	store.Insert(&SecurityEvent{ClientIP: "1.2.3.4"})
	store.Flush()
}

func TestBugFixes_ValidateDashboardAuth(t *testing.T) {
	t.Run("user:pass with basic auth and constant-time match", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		req.SetBasicAuth("admin", "secret123")

		if !validateDashboardAuth(req, "admin", "secret123", "admin:secret123") {
			t.Error("expected valid credentials to pass")
		}

		// Wrong password
		badReq := httptest.NewRequest("GET", "/dashboard", nil)
		badReq.SetBasicAuth("admin", "wrongpass")
		if validateDashboardAuth(badReq, "admin", "secret123", "admin:secret123") {
			t.Error("expected wrong credentials to fail")
		}
	})

	t.Run("single token auth without colon", func(t *testing.T) {
		token := "my-api-secret-key-999"

		// Bearer header
		bearerReq := httptest.NewRequest("GET", "/api/stats", nil)
		bearerReq.Header.Set("Authorization", "Bearer "+token)
		if !validateDashboardAuth(bearerReq, token, "", token) {
			t.Error("expected bearer token to authenticate with single token auth")
		}

		// Query param ?token=
		queryReq := httptest.NewRequest("GET", "/api/stats?token="+token, nil)
		if !validateDashboardAuth(queryReq, token, "", token) {
			t.Error("expected query token to authenticate with single token auth")
		}

		// Basic auth with token as password
		basicPassReq := httptest.NewRequest("GET", "/", nil)
		basicPassReq.SetBasicAuth("", token)
		if !validateDashboardAuth(basicPassReq, token, "", token) {
			t.Error("expected token as basic auth password to authenticate")
		}

		// Basic auth with token as username
		basicUserReq := httptest.NewRequest("GET", "/", nil)
		basicUserReq.SetBasicAuth(token, "")
		if !validateDashboardAuth(basicUserReq, token, "", token) {
			t.Error("expected token as basic auth username to authenticate")
		}

		// Cookie with raw token
		cookieReq := httptest.NewRequest("GET", "/", nil)
		cookieReq.AddCookie(&http.Cookie{Name: "routewarden_auth", Value: token})
		if !validateDashboardAuth(cookieReq, token, "", token) {
			t.Error("expected raw token in cookie to authenticate")
		}

		// Cookie with base64 encoded token
		b64Token := base64.StdEncoding.EncodeToString([]byte(token))
		cookieB64Req := httptest.NewRequest("GET", "/", nil)
		cookieB64Req.AddCookie(&http.Cookie{Name: "routewarden_auth", Value: b64Token})
		if !validateDashboardAuth(cookieB64Req, token, "", token) {
			t.Error("expected base64 token in cookie to authenticate")
		}
	})
}

func TestBugFixes_EventStoreIsolatedCounters(t *testing.T) {
	s1 := NewEventStore()
	s2 := NewEventStore()

	s1.Add(&SecurityEvent{
		ClientIP: "1.1.1.1",
		Method:   "GET",
		Path:     "/.env",
		Status:   403,
		Verdict:  "BLOCK",
	})
	s1.Add(&SecurityEvent{
		ClientIP: "1.1.1.2",
		Method:   "GET",
		Path:     "/login",
		Status:   429,
		Verdict:  "TARPIT",
	})

	stats1 := s1.GetStats()
	if stats1.TotalEvents != 2 {
		t.Errorf("expected store 1 total=2, got %d", stats1.TotalEvents)
	}
	if stats1.BlockedCount != 1 {
		t.Errorf("expected store 1 blocked=1, got %d", stats1.BlockedCount)
	}
	if stats1.TarpitCount != 1 {
		t.Errorf("expected store 1 tarpit=1, got %d", stats1.TarpitCount)
	}

	stats2 := s2.GetStats()
	if stats2.TotalEvents != 0 {
		t.Errorf("expected store 2 total=0, got %d", stats2.TotalEvents)
	}
	if stats2.BlockedCount != 0 {
		t.Errorf("expected store 2 blocked=0, got %d", stats2.BlockedCount)
	}
}

func TestBugFixes_EventHashDeduplicationOnRestart(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "dedup_test.db")

	// 1. Initial Store Session
	store1, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}

	ev1 := &SecurityEvent{
		Timestamp: "2026-10-18T21:00:00Z",
		ClientIP:  "203.0.113.195",
		Method:    "GET",
		Path:      "/.env",
		Status:    403,
		Verdict:   "BLOCK",
		Rule:      "sensitive-files",
		Source:    "traefik",
	}

	h1 := ev1.EnsureHash()
	if h1 == "" {
		t.Fatal("expected non-empty hash for event")
	}

	store1.Insert(ev1)
	store1.Flush()

	if store1.Count() != 1 {
		t.Fatalf("expected 1 event in store1, got %d", store1.Count())
	}

	// Re-inserting identical event into store1 should be ignored
	store1.Insert(ev1)
	store1.Flush()
	if store1.Count() != 1 {
		t.Fatalf("expected store1 to still have 1 event after duplicate insert, got %d", store1.Count())
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("failed to close store1: %v", err)
	}

	// 2. Server Restart Simulation: Open new SQLiteStore pointing to same DB
	store2, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store2: %v", err)
	}
	defer store2.Close()

	if !store2.HasHash(h1) {
		t.Fatalf("expected store2 to recognize existing hash %s on restart", h1)
	}

	// Tail stream re-reads the same event stream on restart
	store2.Insert(ev1)
	store2.Flush()

	if store2.Count() != 1 {
		t.Fatalf("expected store2 count to remain 1 after re-reading stream, got %d", store2.Count())
	}

	// 3. EventStore in-memory deduplication across server restarts
	eventStore := NewEventStore()
	eventStore.AttachSQLite(store2)

	// Preloaded event count from DB
	stats := eventStore.GetStats()
	if stats.TotalEvents != 1 {
		t.Fatalf("expected preloaded totalEvents=1, got %d", stats.TotalEvents)
	}

	// Log stream re-reads the same line from docker logs / tail on restart
	reReadEvent := eventStore.ParseAndIngest(
		`203.0.113.195 - - [18/Oct/2026:21:00:00 +0000] "GET /.env HTTP/1.1" 403 0 "-" "[BLOCK: sensitive-files]"`,
		"traefik",
	)
	if reReadEvent == nil {
		t.Fatal("expected event to parse")
	}

	// Metrics should NOT be double-counted!
	statsAfterReRead := eventStore.GetStats()
	if statsAfterReRead.TotalEvents != 1 {
		t.Fatalf("expected totalEvents to remain 1 without duplicate ingestion, got %d", statsAfterReRead.TotalEvents)
	}
	if statsAfterReRead.BlockedCount != 1 {
		t.Fatalf("expected blockedCount to remain 1, got %d", statsAfterReRead.BlockedCount)
	}
}

func TestBugFixes_LegacyDatabaseMigrationWithoutHashColumn(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "legacy_no_hash.db")

	// 1. Manually create a legacy database without 'hash' column
	legacyDSN := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", legacyDSN)
	if err != nil {
		t.Fatalf("failed to open raw sqlite: %v", err)
	}

	legacySchema := `
	CREATE TABLE security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		time_str TEXT,
		client_ip TEXT NOT NULL,
		method TEXT,
		path TEXT,
		status INTEGER,
		verdict TEXT,
		rule TEXT,
		country TEXT,
		country_code TEXT,
		latency_ms REAL,
		source TEXT
	);
	`
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("failed to create legacy schema: %v", err)
	}

	// Insert 5 legacy events with NO hash column
	for i := 1; i <= 5; i++ {
		_, err := db.Exec(`
			INSERT INTO security_events (timestamp, time_str, client_ip, method, path, status, verdict, rule, country, country_code, latency_ms, source)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("2026-10-18T20:00:0%dZ", i),
			"20:00:00",
			fmt.Sprintf("198.51.100.%d", i),
			"GET",
			fmt.Sprintf("/path-%d", i),
			403,
			"BLOCK",
			"test-rule",
			"United States",
			"US",
			1.5,
			"traefik",
		)
		if err != nil {
			t.Fatalf("failed to insert legacy event %d: %v", i, err)
		}
	}
	_ = db.Close()

	// 2. Open legacy database with NewSQLiteStore; this must succeed and migrate seamlessly
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to migrate legacy database: %v", err)
	}
	defer store.Close()

	// Verify all 5 events are retained
	if store.Count() != 5 {
		t.Fatalf("expected 5 events retained after migration, got %d", store.Count())
	}

	// Verify hashes were backfilled and deduplication works
	recent, err := store.GetRecent(10)
	if err != nil {
		t.Fatalf("failed to query recent events: %v", err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected 5 recent events, got %d", len(recent))
	}
	for _, ev := range recent {
		if ev.Hash == "" {
			t.Errorf("expected backfilled hash on event id %d", ev.ID)
		}
		if !store.HasHash(ev.Hash) {
			t.Errorf("expected store to recognize backfilled hash %s", ev.Hash)
		}
	}

	// Re-inserting one of the legacy events must be rejected as duplicate
	store.Insert(recent[0])
	store.Flush()
	if store.Count() != 5 {
		t.Fatalf("expected count to remain 5 after inserting legacy duplicate, got %d", store.Count())
	}

	// 3. Attach to EventStore and verify preload
	eventStore := NewEventStore()
	eventStore.AttachSQLite(store)
	stats := eventStore.GetStats()
	if stats.TotalEvents != 5 {
		t.Fatalf("expected 5 preloaded events in EventStore, got %d", stats.TotalEvents)
	}
}
