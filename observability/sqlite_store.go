package observability

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// LogQueryFilter defines criteria for querying stored events from SQLite.
type LogQueryFilter struct {
	StartTime string // RFC3339 or ISO timestamp
	EndTime   string // RFC3339 or ISO timestamp
	Verdict   string // ALL, BLOCK, TARPIT, ALLOW
	ClientIP  string
	Country   string
	Method    string
	Path      string
	Source    string // connected node or agent name
	Status    int
	StatusStr string // e.g. "2xx", "403", "429", "4xx", "5xx"
	Rule      string
	Search    string
	Limit     int
	Offset    int
}

// SQLiteStore provides persistent embedded SQLite telemetry storage with WAL mode
// and batched background writing for zero ingest latency.
type SQLiteStore struct {
	dbPath     string
	db         *sql.DB
	insertChan chan *SecurityEvent
	flushChan  chan chan struct{}
	done       chan struct{}
	wg         sync.WaitGroup
	closed     int32
	seenMu     sync.RWMutex
	seenHashes map[string]struct{}
}

// NewSQLiteStore initializes a SQLite database at dbPath with WAL mode and schema migration.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create sqlite dir: %w", err)
	}

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-2000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite performs best with 1 writer connection
	db.SetMaxIdleConns(1)

	// Create table and indexes
	schema := `
	CREATE TABLE IF NOT EXISTS security_events (
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
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_client_ip ON security_events(client_ip);
	CREATE INDEX IF NOT EXISTS idx_events_verdict ON security_events(verdict);
	`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sqlite schema: %w", err)
	}

	// Ensure hash column exists in pre-migration databases
	_, _ = db.Exec("ALTER TABLE security_events ADD COLUMN hash TEXT")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_events_hash ON security_events(hash)")

	seenHashes := make(map[string]struct{})

	// Backfill missing hashes for legacy rows so deduplication works on historical data
	if rows, err := db.Query("SELECT id, timestamp, client_ip, method, path, status, verdict, rule, source FROM security_events WHERE hash IS NULL OR hash = ''"); err == nil {
		type legacyRow struct {
			id   int64
			hash string
		}
		var toUpdate []legacyRow
		for rows.Next() {
			var id int64
			var ts, ip, method, path, verdict, rule, source sql.NullString
			var status sql.NullInt64
			if err := rows.Scan(&id, &ts, &ip, &method, &path, &status, &verdict, &rule, &source); err == nil {
				ev := &SecurityEvent{
					Timestamp: ts.String,
					ClientIP:  ip.String,
					Method:    method.String,
					Path:      path.String,
					Status:    int(status.Int64),
					Verdict:   verdict.String,
					Rule:      rule.String,
					Source:    source.String,
				}
				h := ev.ComputeHash()
				toUpdate = append(toUpdate, legacyRow{id: id, hash: h})
			}
		}
		_ = rows.Err()
		_ = rows.Close()

		if len(toUpdate) > 0 {
			if tx, err := db.Begin(); err == nil {
				if stmt, err := tx.Prepare("UPDATE security_events SET hash = ? WHERE id = ?"); err == nil {
					for _, r := range toUpdate {
						_, _ = stmt.Exec(r.hash, r.id)
						seenHashes[r.hash] = struct{}{}
					}
					_ = stmt.Close()
				}
				_ = tx.Commit()
			}
		}
	}

	// Pre-populate deduplication cache from existing events in DB
	if rows, err := db.Query("SELECT hash FROM security_events WHERE hash IS NOT NULL AND hash != '' ORDER BY id DESC LIMIT 10000"); err == nil {
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err == nil && h != "" {
				seenHashes[h] = struct{}{}
			}
		}
		_ = rows.Err()
		_ = rows.Close()
	}

	store := &SQLiteStore{
		dbPath:     dbPath,
		db:         db,
		insertChan: make(chan *SecurityEvent, 5000),
		flushChan:  make(chan chan struct{}),
		done:       make(chan struct{}),
		seenHashes: seenHashes,
	}

	store.wg.Add(1)
	go store.batchWorker()

	return store, nil
}

// DBPath returns the file path of the database.
func (s *SQLiteStore) DBPath() string {
	return s.dbPath
}

// HasHash checks if an event hash already exists in memory cache or database.
func (s *SQLiteStore) HasHash(hash string) bool {
	if hash == "" {
		return false
	}
	s.seenMu.RLock()
	_, exists := s.seenHashes[hash]
	s.seenMu.RUnlock()
	if exists {
		return true
	}

	var count int
	row := s.db.QueryRow("SELECT COUNT(1) FROM security_events WHERE hash = ?", hash)
	if err := row.Scan(&count); err == nil && count > 0 {
		s.seenMu.Lock()
		s.seenHashes[hash] = struct{}{}
		s.seenMu.Unlock()
		return true
	}
	return false
}

// MarkHash adds an event hash to the local deduplication cache.
func (s *SQLiteStore) MarkHash(hash string) {
	if hash == "" {
		return
	}
	s.seenMu.Lock()
	s.seenHashes[hash] = struct{}{}
	if len(s.seenHashes) > 50000 {
		pruned := 0
		for k := range s.seenHashes {
			delete(s.seenHashes, k)
			pruned++
			if pruned >= 25000 {
				break
			}
		}
	}
	s.seenMu.Unlock()
}

// Insert queues a security event for asynchronous batched persistence after verifying hash.
func (s *SQLiteStore) Insert(ev *SecurityEvent) {
	if ev == nil || atomic.LoadInt32(&s.closed) == 1 {
		return
	}

	h := ev.EnsureHash()
	if h != "" && s.HasHash(h) {
		return // Duplicate event hash detected; skip adding to DB
	}
	if h != "" {
		s.MarkHash(h)
	}

	select {
	case s.insertChan <- ev:
	case <-s.done:
		return
	default:
		// If queue is completely backed up, perform non-blocking drop or inline insert
		// to prevent memory growth under extreme load
	}
}

// batchWorker flushes queued events in transactions every 200ms or when 100 events accumulate.
func (s *SQLiteStore) batchWorker() {
	defer s.wg.Done()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var batch []*SecurityEvent

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.flushBatch(batch)
		batch = batch[:0]
	}

	drainQueue := func() {
		for {
			select {
			case ev, ok := <-s.insertChan:
				if !ok {
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 100 {
					flush()
				}
			default:
				return
			}
		}
	}

	for {
		select {
		case ev, ok := <-s.insertChan:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= 100 {
				flush()
			}
		case done := <-s.flushChan:
			drainQueue()
			flush()
			close(done)
		case <-ticker.C:
			flush()
		case <-s.done:
			drainQueue()
			flush()
			return
		}
	}
}

func (s *SQLiteStore) flushBatch(batch []*SecurityEvent) {
	if len(batch) == 0 {
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO security_events (
			timestamp, time_str, client_ip, method, path, status, verdict, rule, country, country_code, latency_ms, source, hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, ev := range batch {
		ts := ev.Timestamp
		if ts == "" {
			ts = time.Now().Format(time.RFC3339)
		}
		tStr := ev.TimeStr
		if tStr == "" {
			tStr = time.Now().Format("15:04:05")
		}
		hash := ev.EnsureHash()
		_, _ = stmt.Exec(
			ts,
			tStr,
			ev.ClientIP,
			ev.Method,
			ev.Path,
			ev.Status,
			ev.Verdict,
			ev.Rule,
			ev.Country,
			ev.CountryCode,
			ev.LatencyMs,
			ev.Source,
			hash,
		)
	}

	_ = tx.Commit()
}

// Count returns the total number of events recorded in the database.
func (s *SQLiteStore) Count() int64 {
	var count int64
	row := s.db.QueryRow("SELECT COUNT(*) FROM security_events")
	_ = row.Scan(&count)
	return count
}

// GetRecent loads the latest N events in descending chronological order.
func (s *SQLiteStore) GetRecent(limit int) ([]*SecurityEvent, error) {
	if limit <= 0 {
		limit = 250
	}
	return s.Query(LogQueryFilter{Limit: limit})
}

func buildWhereClause(f LogQueryFilter) ([]string, []interface{}) {
	var where []string
	var args []interface{}

	if f.StartTime != "" {
		where = append(where, "timestamp >= ?")
		args = append(args, f.StartTime)
	}
	if f.EndTime != "" {
		where = append(where, "timestamp <= ?")
		args = append(args, f.EndTime)
	}
	if f.Verdict != "" && f.Verdict != "ALL" {
		where = append(where, "verdict = ?")
		args = append(args, strings.ToUpper(f.Verdict))
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if f.Country != "" && f.Country != "ALL" {
		where = append(where, "(country = ? OR country_code = ?)")
		args = append(args, f.Country, f.Country)
	}
	if f.Method != "" && f.Method != "ALL" {
		where = append(where, "method = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.Path != "" {
		where = append(where, "path = ?")
		args = append(args, f.Path)
	}
	if f.Source != "" && f.Source != "ALL" {
		where = append(where, "source = ?")
		args = append(args, f.Source)
	}
	if f.Status > 0 {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	} else if f.StatusStr != "" && f.StatusStr != "ALL" {
		switch strings.ToLower(f.StatusStr) {
		case "2xx":
			where = append(where, "status >= 200 AND status < 300")
		case "4xx":
			where = append(where, "status >= 400 AND status < 500")
		case "5xx":
			where = append(where, "status >= 500 AND status < 600")
		default:
			if st, err := strconv.Atoi(f.StatusStr); err == nil {
				where = append(where, "status = ?")
				args = append(args, st)
			}
		}
	}
	if f.Rule != "" && f.Rule != "ALL" {
		where = append(where, "rule = ?")
		args = append(args, f.Rule)
	}
	if f.Search != "" {
		where = append(where, "(client_ip LIKE ? OR path LIKE ? OR rule LIKE ? OR country LIKE ? OR source LIKE ?)")
		pattern := "%" + f.Search + "%"
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}
	return where, args
}

// CountFiltered returns the total number of events matching the provided LogQueryFilter.
func (s *SQLiteStore) CountFiltered(f LogQueryFilter) int64 {
	where, args := buildWhereClause(f)
	query := "SELECT COUNT(*) FROM security_events"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	var count int64
	row := s.db.QueryRow(query, args...)
	_ = row.Scan(&count)
	return count
}

// Query retrieves events matching the provided LogQueryFilter.
func (s *SQLiteStore) Query(f LogQueryFilter) ([]*SecurityEvent, error) {
	where, args := buildWhereClause(f)

	query := "SELECT id, timestamp, time_str, client_ip, method, path, status, verdict, rule, country, country_code, latency_ms, source, hash FROM security_events"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 250
	}
	if limit > 2000 {
		limit = 2000
	}
	query += " LIMIT ?"
	args = append(args, limit)

	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []*SecurityEvent
	for rows.Next() {
		var ev SecurityEvent
		var lat sql.NullFloat64
		var rule, cCode, src, hStr sql.NullString
		err := rows.Scan(
			&ev.ID,
			&ev.Timestamp,
			&ev.TimeStr,
			&ev.ClientIP,
			&ev.Method,
			&ev.Path,
			&ev.Status,
			&ev.Verdict,
			&rule,
			&ev.Country,
			&cCode,
			&lat,
			&src,
			&hStr,
		)
		if err != nil {
			continue
		}
		if rule.Valid {
			ev.Rule = rule.String
		}
		if cCode.Valid {
			ev.CountryCode = cCode.String
		}
		if lat.Valid {
			ev.LatencyMs = lat.Float64
		}
		if src.Valid {
			ev.Source = src.String
		}
		if hStr.Valid && hStr.String != "" {
			ev.Hash = hStr.String
		} else {
			ev.EnsureHash()
		}
		events = append(events, &ev)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}

	return events, nil
}

// PruneOlderThan deletes events older than the specified retention in days.
func (s *SQLiteStore) PruneOlderThan(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	res, err := s.db.Exec("DELETE FROM security_events WHERE timestamp < datetime('now', '-' || ? || ' days')", days)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneMaxRows keeps only the latest maxRows events and deletes older ones.
func (s *SQLiteStore) PruneMaxRows(maxRows int) (int64, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	res, err := s.db.Exec("DELETE FROM security_events WHERE id NOT IN (SELECT id FROM security_events ORDER BY id DESC LIMIT ?)", maxRows)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Flush forces immediate flush of any buffered insert queue.
func (s *SQLiteStore) Flush() {
	if atomic.LoadInt32(&s.closed) == 1 {
		return
	}
	done := make(chan struct{})
	select {
	case s.flushChan <- done:
		select {
		case <-done:
		case <-s.done:
		}
	case <-s.done:
	}
}

// Close gracefully flushes pending events and closes the SQLite database connection.
func (s *SQLiteStore) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}

	close(s.done)
	s.wg.Wait()
	return s.db.Close()
}
