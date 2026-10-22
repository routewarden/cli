package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// BanEntry holds metadata for an actively banned IP address.
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Service   string    `json:"service"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

// TableName returns the database table name for bans.
func (BanEntry) TableName() string {
	return "bans"
}

// BanList provides a thread-safe in-memory ban cache with TTL expiration and
// embedded SQLite persistence. When a dataDir is provided, bans are
// persisted to <dataDir>/bans.db using SQLite with WAL mode enabled.
// If a legacy <dataDir>/bans.json file exists, it is automatically migrated into SQLite.
type BanList struct {
	mu      sync.RWMutex
	entries map[string]BanEntry

	// persistence
	dataDir string
	db      *sql.DB

	cancel context.CancelFunc
}

const (
	dbFilename         = "bans.db"
	legacyJSONFilename = "bans.json"
)

// NewBanList initialises a new BanList with embedded SQLite persistence.
// Pass dataDir="" to run purely in memory (no disk I/O).
func NewBanList(dataDir string) *BanList {
	ctx, cancel := context.WithCancel(context.Background())

	bl := &BanList{
		entries: make(map[string]BanEntry),
		dataDir: dataDir,
		cancel:  cancel,
	}

	if dataDir != "" {
		if err := bl.initDB(); err != nil {
			DefaultLogger().Warn("[BanList] SQLite init error for %s: %v (falling back to memory-only)", dataDir, err)
		} else {
			bl.migrateLegacyJSON()
			bl.load()
		}
	}

	go bl.cleanupLoop(ctx)
	return bl
}

func (b *BanList) initDB() error {
	if err := os.MkdirAll(b.dataDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", b.dataDir, err)
	}

	dbPath := filepath.Join(b.dataDir, dbFilename)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}

	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;
		PRAGMA busy_timeout = 5000;
	`); err != nil {
		_ = db.Close()
		return fmt.Errorf("sqlite pragmas %s: %w", dbPath, err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS bans (
		ip TEXT PRIMARY KEY,
		reason TEXT NOT NULL,
		service TEXT NOT NULL,
		banned_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		permanent BOOLEAN NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_bans_expires_at ON bans(expires_at);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return fmt.Errorf("sqlite schema %s: %w", dbPath, err)
	}

	b.db = db
	return nil
}

// migrateLegacyJSON imports any existing bans.json into the SQLite database.
func (b *BanList) migrateLegacyJSON() {
	if b.db == nil || b.dataDir == "" {
		return
	}
	legacyPath := filepath.Join(b.dataDir, legacyJSONFilename)
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return // No legacy file
	}

	var count int64
	row := b.db.QueryRow("SELECT COUNT(*) FROM bans")
	if err := row.Scan(&count); err == nil && count > 0 {
		return // DB already contains entries, skip migration
	}

	var entries []BanEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		DefaultLogger().Warn("[BanList] corrupt legacy %s: %v", legacyPath, err)
		return
	}

	now := time.Now().UTC()
	var toInsert []BanEntry
	for _, e := range entries {
		if e.Permanent || now.Before(e.ExpiresAt) {
			e.BannedAt = e.BannedAt.UTC()
			if e.Permanent && e.ExpiresAt.IsZero() {
				e.ExpiresAt = permanentBanExpiry
			} else {
				e.ExpiresAt = e.ExpiresAt.UTC()
			}
			toInsert = append(toInsert, e)
		}
	}

	if len(toInsert) > 0 {
		tx, err := b.db.Begin()
		if err != nil {
			DefaultLogger().Warn("[BanList] migration tx error: %v", err)
			return
		}
		stmt, err := tx.Prepare(`
			INSERT INTO bans (ip, reason, service, banned_at, expires_at, permanent)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				reason = excluded.reason,
				service = excluded.service,
				banned_at = excluded.banned_at,
				expires_at = excluded.expires_at,
				permanent = excluded.permanent
		`)
		if err != nil {
			_ = tx.Rollback()
			DefaultLogger().Warn("[BanList] migration stmt error: %v", err)
			return
		}
		defer stmt.Close()

		for _, e := range toInsert {
			if _, err := stmt.Exec(e.IP, e.Reason, e.Service, e.BannedAt, e.ExpiresAt, e.Permanent); err != nil {
				_ = tx.Rollback()
				DefaultLogger().Warn("[BanList] migration insert error: %v", err)
				return
			}
		}

		if err := tx.Commit(); err == nil {
			DefaultLogger().Info("✓  [BanList] migrated %d ban(s) from legacy %s into SQLite via GORM", len(toInsert), legacyPath)
			_ = os.Rename(legacyPath, legacyPath+".migrated.bak")
		} else {
			DefaultLogger().Warn("[BanList] migration commit error: %v", err)
		}
	}
}

// load reads active bans from SQLite into the in-memory cache.
func (b *BanList) load() {
	if b.db == nil {
		return
	}

	now := time.Now().UTC()
	rows, err := b.db.Query(`
		SELECT ip, reason, service, banned_at, expires_at, permanent
		FROM bans
		WHERE permanent = 1 OR permanent = 'true' OR expires_at > ?
	`, now)
	if err != nil {
		DefaultLogger().Warn("[BanList] query bans error: %v", err)
		return
	}
	defer rows.Close()

	var records []BanEntry
	for rows.Next() {
		var e BanEntry
		if err := rows.Scan(&e.IP, &e.Reason, &e.Service, &e.BannedAt, &e.ExpiresAt, &e.Permanent); err != nil {
			DefaultLogger().Warn("[BanList] scan ban error: %v", err)
			continue
		}
		records = append(records, e)
	}
	if err := rows.Err(); err != nil {
		DefaultLogger().Warn("[BanList] rows error: %v", err)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, e := range records {
		b.entries[e.IP] = e
	}

	if len(records) > 0 {
		DefaultLogger().Info("✓  [BanList] loaded %d active ban(s) from SQLite (%s)", len(records), filepath.Join(b.dataDir, dbFilename))
	}
}

// permanentBanExpiry is a far-future sentinel stored for permanent bans so the
// SQLite prune query (`expires_at <= ?`) is safe even if the `permanent` column
// were accidentally omitted from a future query.
var permanentBanExpiry = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// canonicalizeIP strips surrounding whitespace, brackets, ports, zone identifiers,
// and canonicalizes IPv4-mapped IPv6 addresses so that ban enforcement cannot be bypassed.
func canonicalizeIP(ip string) string {
	trimmed := strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	trimmed = strings.Trim(trimmed, "[]")
	if idx := strings.IndexByte(trimmed, '%'); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if parsed := net.ParseIP(trimmed); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return trimmed
}

// Ban records an IP address as banned for the given duration.
// Pass duration <= 0 for a permanent ban.
func (b *BanList) Ban(ip, reason, service string, duration time.Duration) {
	ip = canonicalizeIP(ip)
	now := time.Now().UTC()
	perm := duration <= 0
	var expires time.Time
	if perm {
		expires = permanentBanExpiry
	} else {
		expires = now.Add(duration)
	}

	entry := BanEntry{
		IP:        ip,
		Reason:    reason,
		Service:   service,
		BannedAt:  now,
		ExpiresAt: expires,
		Permanent: perm,
	}

	b.mu.Lock()
	b.entries[ip] = entry
	b.mu.Unlock()

	if b.db != nil {
		_, err := b.db.Exec(`
			INSERT INTO bans (ip, reason, service, banned_at, expires_at, permanent)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				reason = excluded.reason,
				service = excluded.service,
				banned_at = excluded.banned_at,
				expires_at = excluded.expires_at,
				permanent = excluded.permanent
		`, entry.IP, entry.Reason, entry.Service, entry.BannedAt, entry.ExpiresAt, entry.Permanent)
		if err != nil {
			DefaultLogger().Warn("[BanList] upsert error for %s: %v", ip, err)
		}
	}
}

// Unban removes an IP from the banlist. Returns true if the IP was present.
func (b *BanList) Unban(ip string) bool {
	ip = canonicalizeIP(ip)
	b.mu.Lock()
	_, exists := b.entries[ip]
	if exists {
		delete(b.entries, ip)
	}
	b.mu.Unlock()

	if b.db != nil {
		res, err := b.db.Exec("DELETE FROM bans WHERE ip = ?", ip)
		if err != nil {
			DefaultLogger().Warn("[BanList] delete error for %s: %v", ip, err)
		} else if !exists {
			if n, err := res.RowsAffected(); err == nil && n > 0 {
				exists = true
			}
		}
	}
	return exists
}

// IsBanned returns true and the ban entry if the IP is currently banned and unexpired.
// Expired entries are evicted from the in-memory map on detection to prevent
// unbounded accumulation under high ban-churn workloads.
func (b *BanList) IsBanned(ip string) (BanEntry, bool) {
	ip = canonicalizeIP(ip)
	b.mu.RLock()
	entry, ok := b.entries[ip]
	if !ok {
		b.mu.RUnlock()
		return BanEntry{}, false
	}
	if !entry.Permanent && time.Now().After(entry.ExpiresAt) {
		// Upgrade to write lock and evict the stale entry.
		b.mu.RUnlock()
		b.mu.Lock()
		defer b.mu.Unlock()
		// Re-check under write lock in case another goroutine refreshed or re-banned the IP
		if cur, exists := b.entries[ip]; exists {
			if !cur.Permanent && time.Now().After(cur.ExpiresAt) {
				delete(b.entries, ip)
				return BanEntry{}, false
			}
			return cur, true
		}
		return BanEntry{}, false
	}
	b.mu.RUnlock()
	return entry, true
}

// All returns a snapshot of all currently active (non-expired) bans.
func (b *BanList) All() []BanEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	res := make([]BanEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		if entry.Permanent || now.Before(entry.ExpiresAt) {
			res = append(res, entry)
		}
	}
	return res
}

// Count returns the number of currently active (non-expired) bans.
func (b *BanList) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, entry := range b.entries {
		if entry.Permanent || now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// Close stops background routines and closes the underlying SQLite database connection.
func (b *BanList) Close() {
	if b.cancel != nil {
		b.cancel()
	}
	if b.db != nil {
		_ = b.db.Close()
	}
}

// cleanupLoop periodically removes expired entries from memory and SQLite.
func (b *BanList) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()

			b.mu.Lock()
			for ip, entry := range b.entries {
				if !entry.Permanent && now.After(entry.ExpiresAt) {
					delete(b.entries, ip)
				}
			}
			b.mu.Unlock()

			if b.db != nil {
				if _, err := b.db.Exec("DELETE FROM bans WHERE (permanent = 0 OR permanent = 'false') AND expires_at <= ?", now); err != nil {
					if !errors.Is(err, sql.ErrConnDone) && !strings.Contains(err.Error(), "closed") {
						DefaultLogger().Warn("[BanList] prune error: %v", err)
					}
				}
			}
		}
	}
}
