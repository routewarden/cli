package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBanList_Memory(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	if bl.Count() != 0 {
		t.Fatalf("expected 0 bans, got %d", bl.Count())
	}

	bl.Ban("1.2.3.4", "test_reason", "ssh", 1*time.Hour)
	if bl.Count() != 1 {
		t.Fatalf("expected 1 ban, got %d", bl.Count())
	}

	entry, ok := bl.IsBanned("1.2.3.4")
	if !ok || entry.IP != "1.2.3.4" || entry.Reason != "test_reason" {
		t.Fatalf("unexpected ban entry: %+v", entry)
	}

	if !bl.Unban("1.2.3.4") {
		t.Fatal("expected unban to succeed")
	}
	if bl.Count() != 0 {
		t.Fatalf("expected 0 bans after unban, got %d", bl.Count())
	}
}

func TestBanList_SQLitePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "banlist-sqlite-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Step 1: Create BanList, add permanent and timed bans
	bl := NewBanList(tmpDir)
	bl.Ban("10.0.0.1", "brute_force", "ssh", 0) // permanent
	bl.Ban("10.0.0.2", "port_scan", "redis", 2*time.Hour)
	bl.Close()

	// Verify db file exists
	dbFile := filepath.Join(tmpDir, "bans.db")
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		t.Fatalf("expected bans.db file at %s", dbFile)
	}

	// Step 2: Re-open BanList on same directory (simulating restart)
	bl2 := NewBanList(tmpDir)
	defer bl2.Close()

	if bl2.Count() != 2 {
		t.Fatalf("expected 2 reloaded bans, got %d", bl2.Count())
	}

	e1, ok1 := bl2.IsBanned("10.0.0.1")
	if !ok1 || !e1.Permanent || e1.Reason != "brute_force" {
		t.Fatalf("unexpected reloaded entry for 10.0.0.1: %+v", e1)
	}

	e2, ok2 := bl2.IsBanned("10.0.0.2")
	if !ok2 || e2.Permanent || e2.Service != "redis" {
		t.Fatalf("unexpected reloaded entry for 10.0.0.2: %+v", e2)
	}

	// Step 3: Unban in bl2 and restart again to ensure deletion persisted
	if !bl2.Unban("10.0.0.2") {
		t.Fatal("expected unban to succeed")
	}
	bl2.Close()

	bl3 := NewBanList(tmpDir)
	defer bl3.Close()

	if bl3.Count() != 1 {
		t.Fatalf("expected 1 ban after deletion and restart, got %d", bl3.Count())
	}
	if _, ok := bl3.IsBanned("10.0.0.2"); ok {
		t.Fatal("expected 10.0.0.2 to remain unbanned across restarts")
	}
}

func TestBanList_LegacyJSONMigration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "banlist-migration-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create legacy bans.json file
	legacyEntries := []BanEntry{
		{
			IP:        "192.168.1.100",
			Reason:    "legacy_perm_ban",
			Service:   "ssh",
			BannedAt:  time.Now().Add(-1 * time.Hour),
			Permanent: true,
		},
		{
			IP:        "192.168.1.101",
			Reason:    "legacy_timed_ban",
			Service:   "postgres",
			BannedAt:  time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Hour),
			Permanent: false,
		},
		{
			IP:        "192.168.1.102",
			Reason:    "legacy_expired_ban",
			Service:   "redis",
			BannedAt:  time.Now().Add(-5 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			Permanent: false,
		},
	}

	data, err := json.Marshal(legacyEntries)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "bans.json"), data, 0o644); err != nil {
		t.Fatalf("write bans.json error: %v", err)
	}

	// Initialize BanList on the folder
	bl := NewBanList(tmpDir)
	defer bl.Close()

	// 100 (perm) and 101 (timed, active) should be imported; 102 (expired) should be skipped
	if bl.Count() != 2 {
		t.Fatalf("expected 2 migrated bans, got %d", bl.Count())
	}

	if _, ok := bl.IsBanned("192.168.1.100"); !ok {
		t.Fatal("expected 192.168.1.100 to be banned")
	}
	if _, ok := bl.IsBanned("192.168.1.101"); !ok {
		t.Fatal("expected 192.168.1.101 to be banned")
	}
	if _, ok := bl.IsBanned("192.168.1.102"); ok {
		t.Fatal("expected expired ban 192.168.1.102 to NOT be imported")
	}
}

// ── Bug #1: IsBanned must evict expired entries from the in-memory map on read ──

func TestBanList_IsBanned_EvictsExpiredEntryFromMemory(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	// Ban with a duration that has already elapsed.
	bl.Ban("192.0.2.1", "test", "ssh", 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond) // ensure expiry

	// IsBanned should return false for the expired entry …
	_, ok := bl.IsBanned("192.0.2.1")
	if ok {
		t.Fatal("expected expired ban to return not-banned")
	}

	// … and the entry must have been removed from the internal map.
	bl.mu.RLock()
	_, stillPresent := bl.entries["192.0.2.1"]
	bl.mu.RUnlock()

	if stillPresent {
		t.Error("Bug #1 regression: expired entry was not evicted from in-memory map by IsBanned")
	}
}

// ── Bug #7: Permanent bans must store the far-future sentinel, not zero time ──

func TestBanList_PermanentBan_StoresFarFutureSentinel(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	bl.Ban("10.0.0.1", "forever", "ssh", 0) // duration <= 0 → permanent

	bl.mu.RLock()
	entry, ok := bl.entries["10.0.0.1"]
	bl.mu.RUnlock()

	if !ok {
		t.Fatal("permanent ban entry not found in map")
	}
	if !entry.Permanent {
		t.Error("expected Permanent=true for a zero-duration ban")
	}
	if entry.ExpiresAt.IsZero() {
		t.Error("Bug #7 regression: permanent ban stored zero ExpiresAt instead of far-future sentinel")
	}
	// Sentinel must be in the far future (at least year 9000).
	if entry.ExpiresAt.Year() < 9000 {
		t.Errorf("Bug #7 regression: permanent ban ExpiresAt year is %d, expected >= 9000", entry.ExpiresAt.Year())
	}
	// Must still be considered banned.
	if _, banned := bl.IsBanned("10.0.0.1"); !banned {
		t.Error("permanent ban with far-future sentinel must still be reported as banned")
	}
}

// ── Round 3 Bug #1: TOCTOU race in IsBanned must not delete a concurrently added ban ──

func TestBanList_IsBanned_ConcurrentRefreshUnderLockUpgrade(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	// Seed with an expired ban
	expiredTime := time.Now().Add(-10 * time.Minute)
	bl.mu.Lock()
	bl.entries["198.51.100.1"] = BanEntry{
		IP:        "198.51.100.1",
		Reason:    "old_expired",
		ExpiresAt: expiredTime,
		Permanent: false,
	}
	bl.mu.Unlock()

	// Concurrently ban the IP with a fresh unexpired ban
	freshExpiry := time.Now().Add(1 * time.Hour)
	bl.Ban("198.51.100.1", "fresh_ban", "ssh", 1*time.Hour)

	entry, banned := bl.IsBanned("198.51.100.1")
	if !banned {
		t.Fatal("Round 3 Bug #1 regression: fresh ban was reported as not banned")
	}
	if entry.Reason != "fresh_ban" {
		t.Errorf("expected reason 'fresh_ban', got %q", entry.Reason)
	}
	if entry.ExpiresAt.Before(freshExpiry.Add(-10 * time.Second)) {
		t.Errorf("expected fresh ExpiresAt, got %v", entry.ExpiresAt)
	}

	// Verify the ban is still in memory
	bl.mu.RLock()
	_, inMap := bl.entries["198.51.100.1"]
	bl.mu.RUnlock()
	if !inMap {
		t.Error("Round 3 Bug #1 regression: newly refreshed ban was incorrectly evicted from memory")
	}
}

// ── SQL Injection Safety on Unban ──

func TestBanList_Unban_SQLInjectionSafety(t *testing.T) {
	tmpDir := t.TempDir()
	bl := NewBanList(tmpDir)
	defer bl.Close()

	// Legitimate ban
	bl.Ban("10.0.0.1", "brute_force", "ssh", 1*time.Hour)
	bl.Ban("10.0.0.2", "malicious_probe", "redis", 1*time.Hour)

	if bl.Count() != 2 {
		t.Fatalf("expected 2 initial bans, got %d", bl.Count())
	}

	// Attempt SQL injection payloads via Unban
	injectionPayloads := []string{
		"' OR '1'='1",
		"10.0.0.1'; DROP TABLE ban_entries; --",
		"10.0.0.1' OR '1'='1'; --",
		"\" OR \"\"=\"",
	}

	for _, payload := range injectionPayloads {
		res := bl.Unban(payload)
		if res {
			t.Errorf("expected unban with payload %q to return false, got true", payload)
		}
	}

	// Verify existing bans were not affected or wiped by injection attempts
	if bl.Count() != 2 {
		t.Fatalf("expected 2 bans to remain after injection attempts, got %d", bl.Count())
	}
	if _, ok := bl.IsBanned("10.0.0.1"); !ok {
		t.Error("expected 10.0.0.1 to still be banned")
	}
	if _, ok := bl.IsBanned("10.0.0.2"); !ok {
		t.Error("expected 10.0.0.2 to still be banned")
	}
}

// ── Unban IP that only exists in SQLite DB ──

func TestBanList_Unban_PresentOnlyInDB(t *testing.T) {
	tmpDir := t.TempDir()
	bl := NewBanList(tmpDir)
	defer bl.Close()

	bl.Ban("198.51.100.20", "direct_db_test", "ssh", 1*time.Hour)

	// Manually delete from in-memory map to simulate out-of-sync or DB-persisted state
	bl.mu.Lock()
	delete(bl.entries, "198.51.100.20")
	bl.mu.Unlock()

	// Unban should detect it in DB (RowsAffected > 0) and return true
	unbanned := bl.Unban("198.51.100.20")
	if !unbanned {
		t.Error("expected Unban to return true for entry present only in SQLite DB")
	}

	// A second unban should return false
	if bl.Unban("198.51.100.20") {
		t.Error("expected second Unban to return false")
	}
}

// ── IPv6 Handling in Banlist ──

func TestBanList_IPv6Handling(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	ipv6Addrs := []string{
		"::1",
		"2001:db8::1",
		"fe80::1",
		"2607:f8b0:4005:805::200e",
	}

	for _, ip := range ipv6Addrs {
		bl.Ban(ip, "ipv6_test", "ssh", 1*time.Hour)
		entry, banned := bl.IsBanned(ip)
		if !banned {
			t.Errorf("expected IPv6 address %q to be banned", ip)
		}
		if entry.IP != ip {
			t.Errorf("expected IP %q in entry, got %q", ip, entry.IP)
		}
	}

	if bl.Count() != len(ipv6Addrs) {
		t.Fatalf("expected count %d, got %d", len(ipv6Addrs), bl.Count())
	}

	for _, ip := range ipv6Addrs {
		if !bl.Unban(ip) {
			t.Errorf("expected Unban for %q to succeed", ip)
		}
	}

	if bl.Count() != 0 {
		t.Fatalf("expected 0 bans after unbanning all IPv6, got %d", bl.Count())
	}
}

// ── Concurrent Ban / Unban / IsBanned Stress Test ──

func TestBanList_ConcurrentStress(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	done := make(chan struct{})
	numWorkers := 8
	iterations := 200

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for j := 0; j < iterations; j++ {
				ip := fmt.Sprintf("192.168.%d.%d", workerID, j%10)
				bl.Ban(ip, "stress_test", "ssh", 100*time.Millisecond)
				_, _ = bl.IsBanned(ip)
				_ = bl.Count()
				_ = bl.All()
				if j%2 == 0 {
					bl.Unban(ip)
				}
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < numWorkers; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent banlist stress test timed out")
		}
	}
}

// ── Security Boundary Test: IPv4-mapped IPv6, port, and bracket canonicalization ──

func TestBanList_IPv4MappedIPv6AndBracketCanonicalization(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	// 1. Ban IPv4, query via IPv4-mapped IPv6
	bl.Ban("192.168.1.10", "dual_stack_test", "web", time.Hour)
	if entry, banned := bl.IsBanned("::ffff:192.168.1.10"); !banned {
		t.Error("expected ::ffff:192.168.1.10 to be banned when 192.168.1.10 is banned")
	} else if entry.IP != "192.168.1.10" {
		t.Errorf("expected canonical entry IP 192.168.1.10, got %s", entry.IP)
	}

	// 2. Ban via IPv4-mapped IPv6, query via standard IPv4
	bl.Ban("::ffff:10.0.0.5", "mapped_ban_test", "web", time.Hour)
	if entry, banned := bl.IsBanned("10.0.0.5"); !banned {
		t.Error("expected 10.0.0.5 to be banned when ::ffff:10.0.0.5 was banned")
	} else if entry.IP != "10.0.0.5" {
		t.Errorf("expected canonical entry IP 10.0.0.5, got %s", entry.IP)
	}

	// 3. Ban bracketed IPv6 with port, query plain IPv6
	bl.Ban("[2001:db8::1]:8443", "bracket_port_test", "web", time.Hour)
	if entry, banned := bl.IsBanned("2001:db8::1"); !banned {
		t.Error("expected 2001:db8::1 to be banned when [2001:db8::1]:8443 was banned")
	} else if entry.IP != "2001:db8::1" {
		t.Errorf("expected canonical entry IP 2001:db8::1, got %s", entry.IP)
	}

	// 4. Query with brackets and port should also match
	if _, banned := bl.IsBanned("[2001:db8::1]:9999"); !banned {
		t.Error("expected [2001:db8::1]:9999 to match ban for 2001:db8::1")
	}

	// 5. Unban using IPv4-mapped IPv6 format with brackets
	if !bl.Unban("[::ffff:192.168.1.10]") {
		t.Error("expected Unban for [::ffff:192.168.1.10] to return true")
	}
	if _, banned := bl.IsBanned("192.168.1.10"); banned {
		t.Error("expected 192.168.1.10 to no longer be banned after unban")
	}
}

// BL-1: Concurrent ban and unban operations
func TestBanList_ConcurrentRace(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	workers := 50
	done := make(chan struct{})

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			ip := fmt.Sprintf("192.0.2.%d", id%10)
			for j := 0; j < 50; j++ {
				bl.Ban(ip, "race_test", "ssh", time.Hour)
				_, _ = bl.IsBanned(ip)
				bl.Unban(ip)
				_ = bl.All()
			}
		}(i)
	}

	for i := 0; i < workers; i++ {
		<-done
	}
}

// BL-2 to BL-8: BanList Edge Cases
func TestBanList_EdgeCases(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()

	// BL-3: Query never-banned IP
	if _, ok := bl.IsBanned("203.0.113.1"); ok {
		t.Error("expected unbanned IP to return false")
	}

	// BL-4: Unban nonexistent IP
	if bl.Unban("203.0.113.1") {
		t.Error("expected Unban on unbanned IP to return false")
	}

	// BL-5: Ban with empty reason
	bl.Ban("10.0.0.99", "", "ssh", time.Hour)
	entry, ok := bl.IsBanned("10.0.0.99")
	if !ok || entry.Reason != "" {
		t.Errorf("expected empty reason ban to be accepted, got: %+v", entry)
	}
	bl.Unban("10.0.0.99")

	// BL-2: Banning same IP twice with new duration
	bl.Ban("10.0.0.100", "first", "ssh", 10*time.Minute)
	bl.Ban("10.0.0.100", "second", "ssh", 2*time.Hour)
	entry2, ok2 := bl.IsBanned("10.0.0.100")
	if !ok2 || entry2.Reason != "second" {
		t.Errorf("expected updated ban entry reason 'second', got: %+v", entry2)
	}

	// BL-8: All() returns accurate count
	bans := bl.All()
	if len(bans) != bl.Count() {
		t.Errorf("expected All() count %d to match bl.Count() %d", len(bans), bl.Count())
	}
}



