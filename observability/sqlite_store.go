package observability

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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
	Status    int
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

	store := &SQLiteStore{
		dbPath:     dbPath,
		db:         db,
		insertChan: make(chan *SecurityEvent, 5000),
		flushChan:  make(chan chan struct{}),
		done:       make(chan struct{}),
	}

	store.wg.Add(1)
	go store.batchWorker()

	return store, nil
}

// DBPath returns the file path of the database.
func (s *SQLiteStore) DBPath() string {
	return s.dbPath
}

// Insert queues a security event for asynchronous batched persistence.
func (s *SQLiteStore) Insert(ev *SecurityEvent) {
	if ev == nil || atomic.LoadInt32(&s.closed) == 1 {
		return
	}

	select {
	case s.insertChan <- ev:
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
			timestamp, time_str, client_ip, method, path, status, verdict, rule, country, country_code, latency_ms, source
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

// Query retrieves events matching the provided LogQueryFilter.
func (s *SQLiteStore) Query(f LogQueryFilter) ([]*SecurityEvent, error) {
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
		where = append(where, "country = ?")
		args = append(args, f.Country)
	}
	if f.Method != "" && f.Method != "ALL" {
		where = append(where, "method = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.Status > 0 {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if f.Rule != "" && f.Rule != "ALL" {
		where = append(where, "rule = ?")
		args = append(args, f.Rule)
	}
	if f.Search != "" {
		where = append(where, "(client_ip LIKE ? OR path LIKE ? OR rule LIKE ? OR country LIKE ?)")
		pattern := "%" + f.Search + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}

	query := "SELECT id, timestamp, time_str, client_ip, method, path, status, verdict, rule, country, country_code, latency_ms, source FROM security_events"
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
		var rule, cCode, src sql.NullString
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
		events = append(events, &ev)
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
	s.flushChan <- done
	<-done
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
