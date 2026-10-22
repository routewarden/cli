package observability_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/routewarden/cli/observability"
)

func TestParseRetention(t *testing.T) {
	cases := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"", 30 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"14", 14 * 24 * time.Hour, false},
		{"48h", 48 * time.Hour, false},
		{"0", 0, false},
		{"unlimited", 0, false},
		{"none", 0, false},
		{"-5d", 0, false},
		{"invalid-format-xyz", 0, true},
	}

	for _, tc := range cases {
		got, err := observability.ParseRetention(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("ParseRetention(%q) expected error, got nil", tc.input)
		} else if !tc.wantErr && err != nil {
			t.Errorf("ParseRetention(%q) unexpected error: %v", tc.input, err)
		} else if !tc.wantErr && got != tc.expected {
			t.Errorf("ParseRetention(%q) = %v, expected %v", tc.input, got, tc.expected)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"", 50 * 1024 * 1024, false},
		{"50MB", 50 * 1024 * 1024, false},
		{"100M", 100 * 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"500KB", 500 * 1024, false},
		{"1024B", 1024, false},
		{"invalid_bytes", 0, true},
	}

	for _, tc := range cases {
		got, err := observability.ParseByteSize(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("ParseByteSize(%q) expected error, got nil", tc.input)
		} else if !tc.wantErr && err != nil {
			t.Errorf("ParseByteSize(%q) unexpected error: %v", tc.input, err)
		} else if !tc.wantErr && got != tc.expected {
			t.Errorf("ParseByteSize(%q) = %d, expected %d", tc.input, got, tc.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if got := observability.FormatBytes(500); got != "500 B" {
		t.Errorf("expected '500 B', got %q", got)
	}
	if got := observability.FormatBytes(1024 * 1024); got != "1.0 MB" {
		t.Errorf("expected '1.0 MB', got %q", got)
	}
	if got := observability.FormatBytes(50 * 1024 * 1024); got != "50.0 MB" {
		t.Errorf("expected '50.0 MB', got %q", got)
	}
}

func TestSQLiteStore_RetentionAndPruning(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "retention_test.db")

	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()

	// 1. Insert 5 events with timestamps: 40 days ago, 20 days ago, 10 days ago, 2 days ago, now
	ages := []time.Duration{
		40 * 24 * time.Hour,
		20 * 24 * time.Hour,
		10 * 24 * time.Hour,
		2 * 24 * time.Hour,
		0,
	}

	for i, age := range ages {
		store.Insert(&observability.SecurityEvent{
			Timestamp:   now.Add(-age).Format(time.RFC3339),
			ClientIP:    "192.0.2.1",
			Method:      "GET",
			Path:        filepath.Join("/test", string(rune('a'+i))),
			Status:      200,
			Verdict:     "ALLOW",
			Source:      "gw",
			Country:     "US",
			CountryCode: "US",
		})
	}
	store.Flush()

	stats, err := store.GetStorageStats()
	if err != nil {
		t.Fatalf("GetStorageStats failed: %v", err)
	}
	if stats.EventCount != 5 {
		t.Fatalf("expected 5 events before prune, got %d", stats.EventCount)
	}
	if stats.DatabaseSizeBytes <= 0 {
		t.Errorf("expected positive database size, got %d", stats.DatabaseSizeBytes)
	}

	// 2. Prune older than 15 days (should remove 40d ago and 20d ago -> 2 events removed)
	pruned, err := store.PruneOlderThanDuration(15 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PruneOlderThanDuration failed: %v", err)
	}
	if pruned != 2 {
		t.Errorf("expected 2 pruned events, got %d", pruned)
	}

	stats, err = store.GetStorageStats()
	if err != nil {
		t.Fatalf("GetStorageStats failed: %v", err)
	}
	if stats.EventCount != 3 {
		t.Errorf("expected 3 remaining events, got %d", stats.EventCount)
	}

	// 3. Prune Max Rows to 2 (should delete the oldest remaining event, leaving 2)
	prunedMax, err := store.PruneMaxRows(2)
	if err != nil {
		t.Fatalf("PruneMaxRows failed: %v", err)
	}
	if prunedMax != 1 {
		t.Errorf("expected 1 pruned event from max cap, got %d", prunedMax)
	}

	stats, _ = store.GetStorageStats()
	if stats.EventCount != 2 {
		t.Errorf("expected 2 events after PruneMaxRows, got %d", stats.EventCount)
	}

	// 4. Test Vacuum
	if err := store.Vacuum(); err != nil {
		t.Errorf("Vacuum failed: %v", err)
	}
}

func TestRetentionManager_AccessLogRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "access.log")

	// Create access.log with 200 bytes
	content := make([]byte, 200)
	for i := range content {
		content[i] = 'A'
	}
	if err := os.WriteFile(logPath, content, 0644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}

	policy := observability.RetentionPolicy{
		RetentionPeriod: 30 * 24 * time.Hour,
		MaxEvents:       1000,
		PruneInterval:   0,
		MaxLogSizeBytes: 100, // Small limit to trigger rotation
		AutoVacuum:      true,
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	mgr := observability.StartAutomatedRetention(context.Background(), store, tmpDir, policy)
	if mgr == nil {
		t.Fatalf("StartAutomatedRetention returned nil")
	}

	// Check that access.log.1 exists and access.log has been truncated/rotated
	backupPath := filepath.Join(tmpDir, "access.log.1")
	fiBackup, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("expected rotated access.log.1 to exist: %v", err)
	}
	if fiBackup.Size() != 200 {
		t.Errorf("expected access.log.1 size 200, got %d", fiBackup.Size())
	}

	fiLog, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("expected fresh access.log to exist: %v", err)
	}
	if fiLog.Size() != 0 {
		t.Errorf("expected fresh access.log size 0, got %d", fiLog.Size())
	}
}

func TestStorageAndPruneEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "events.db")

	store, err := observability.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Add(-40 * 24 * time.Hour).Format(time.RFC3339),
		ClientIP:    "1.2.3.4",
		Method:      "GET",
		Path:        "/old",
		Status:      200,
		Verdict:     "ALLOW",
		Source:      "gw",
		Country:     "US",
		CountryCode: "US",
	})
	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Format(time.RFC3339),
		ClientIP:    "5.6.7.8",
		Method:      "POST",
		Path:        "/new",
		Status:      403,
		Verdict:     "BLOCK",
		Source:      "gw",
		Country:     "DE",
		CountryCode: "DE",
	})
	store.Flush()

	policy := observability.RetentionPolicy{
		RetentionPeriod: 30 * 24 * time.Hour,
		MaxEvents:       1000,
		PruneInterval:   1 * time.Hour,
		MaxLogSizeBytes: 50 * 1024 * 1024,
		AutoVacuum:      true,
	}

	mgr := observability.StartAutomatedRetention(context.Background(), store, tmpDir, policy)
	observability.SetActiveRetentionManager(mgr)

	handler := observability.NewDashboardHandlerWithAuth(tmpDir, nil, "", nil, nil, "", "")

	// 1. Test GET /api/v1/storage
	req := httptest.NewRequest(http.MethodGet, "/api/v1/storage", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/storage returned status %d, body: %s", rr.Code, rr.Body.String())
	}

	var storageResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &storageResp); err != nil {
		t.Fatalf("failed to decode storage json: %v", err)
	}

	storageMap, ok := storageResp["storage"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'storage' field in response")
	}
	if count, ok := storageMap["event_count"].(float64); !ok || count <= 0 {
		t.Errorf("expected positive event_count, got %v", storageMap["event_count"])
	}

	// 2. Insert another expired event and test POST /api/v1/prune
	store.Insert(&observability.SecurityEvent{
		Timestamp:   now.Add(-45 * 24 * time.Hour).Format(time.RFC3339),
		ClientIP:    "9.9.9.9",
		Method:      "GET",
		Path:        "/expired2",
		Status:      200,
		Verdict:     "ALLOW",
		Source:      "gw",
		Country:     "FR",
		CountryCode: "FR",
	})
	store.Flush()

	pruneReq := httptest.NewRequest(http.MethodPost, "/api/v1/prune", nil)
	pruneRR := httptest.NewRecorder()
	handler.ServeHTTP(pruneRR, pruneReq)

	if pruneRR.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/prune returned status %d, body: %s", pruneRR.Code, pruneRR.Body.String())
	}

	var pruneResp map[string]interface{}
	if err := json.Unmarshal(pruneRR.Body.Bytes(), &pruneResp); err != nil {
		t.Fatalf("failed to decode prune json: %v", err)
	}

	if pruneResp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", pruneResp["status"])
	}
	if pruned, ok := pruneResp["pruned_events"].(float64); !ok || pruned < 1 {
		t.Errorf("expected at least 1 pruned event (old event 40d ago), got %v", pruneResp["pruned_events"])
	}
}
