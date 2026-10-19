package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityEvent represents a normalized, structured telemetry event from the gateway.
type SecurityEvent struct {
	ID          int64   `json:"id"`
	Timestamp   string  `json:"timestamp"`
	TimeStr     string  `json:"time_str"`
	ClientIP    string  `json:"client_ip"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Status      int     `json:"status"`
	Verdict     string  `json:"verdict"` // "BLOCK", "TARPIT", "ALLOW"
	Rule        string  `json:"rule"`    // e.g. "path-traversal", "scanner", "sql-injection"
	LatencyMs   float64 `json:"latency_ms"`
	Source      string  `json:"source,omitempty"`
	Hash        string  `json:"hash,omitempty"`
}

// ComputeHash computes a deterministic SHA-256 fingerprint from the event's immutable fields.
func (ev *SecurityEvent) ComputeHash() string {
	if ev == nil {
		return ""
	}
	ts := strings.TrimSpace(ev.Timestamp)
	ip := strings.TrimSpace(ev.ClientIP)
	m := strings.ToUpper(strings.TrimSpace(ev.Method))
	p := strings.TrimSpace(ev.Path)
	v := strings.ToUpper(strings.TrimSpace(ev.Verdict))
	r := strings.TrimSpace(ev.Rule)
	s := strings.TrimSpace(ev.Source)
	raw := fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s|%s", ts, ip, m, p, ev.Status, v, r, s)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// EnsureHash ensures ev.Hash is populated, computing it if missing.
func (ev *SecurityEvent) EnsureHash() string {
	if ev == nil {
		return ""
	}
	if ev.Hash == "" {
		ev.Hash = ev.ComputeHash()
	}
	return ev.Hash
}

// TimelinePoint represents aggregated events for a time bucket.
type TimelinePoint struct {
	Time    string `json:"time"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
	Tarpit  int64  `json:"tarpit"`
	Clean   int64  `json:"clean"`
}

// TopMetricItem represents a ranked metric entry (e.g. top IP, path, rule).
type TopMetricItem struct {
	Name        string `json:"name"`
	Count       int64  `json:"count"`
	Blocked     int64  `json:"blocked"`
	Tarpit      int64  `json:"tarpit"`
	Rule        string `json:"rule,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

// DashboardStats represents comprehensive real-time aggregated metrics.
type DashboardStats struct {
	TotalEvents  int64            `json:"total_events"`
	BlockedCount int64            `json:"blocked_count"`
	TarpitCount  int64            `json:"tarpit_count"`
	CleanCount   int64            `json:"clean_count"`
	BlockRate    string           `json:"block_rate"`
	EventsPerSec float64          `json:"events_per_sec"`
	Timeline     []TimelinePoint  `json:"timeline"`
	TopIPs       []TopMetricItem  `json:"top_ips"`
	TopPaths     []TopMetricItem  `json:"top_paths"`
	TopRules     []TopMetricItem  `json:"top_rules"`
	TopCountries []TopMetricItem  `json:"top_countries,omitempty"`
	StatusCodes  map[string]int64 `json:"status_codes"`
	RecentEvents []*SecurityEvent `json:"recent_events"`
	Sources      SourceInfo       `json:"sources"`
	AuthEnabled  bool             `json:"auth_enabled,omitempty"`
	AuthUser     string           `json:"auth_user,omitempty"`
}

// EventStore maintains in-memory telemetry, ring buffer, aggregates, and SSE subscribers.
type EventStore struct {
	mu            sync.RWMutex
	nextID        int64
	events        []*SecurityEvent
	maxEvents     int
	subscribers   map[chan *SecurityEvent]struct{}
	ipCounts      map[string]*TopMetricItem
	countryCounts map[string]*TopMetricItem
	pathCounts    map[string]*TopMetricItem
	ruleCounts    map[string]*TopMetricItem
	statusCounts  map[string]int64
	timeline      map[string]*TimelinePoint // keyed by HH:MM
	timelineKeys  []string
	startTime     time.Time
	sqlite        *SQLiteStore
	totalEvents   int64
	blockedCount  int64
	tarpitCount   int64
	seenHashes    map[string]struct{}
}

var globalStore = NewEventStore()

// NewEventStore creates a new telemetry event store.
func NewEventStore() *EventStore {
	return &EventStore{
		maxEvents:     1000,
		subscribers:   make(map[chan *SecurityEvent]struct{}),
		ipCounts:      make(map[string]*TopMetricItem),
		countryCounts: make(map[string]*TopMetricItem),
		pathCounts:    make(map[string]*TopMetricItem),
		ruleCounts:    make(map[string]*TopMetricItem),
		statusCounts:  make(map[string]int64),
		timeline:      make(map[string]*TimelinePoint),
		timelineKeys:  make([]string, 0),
		startTime:     time.Now(),
		seenHashes:    make(map[string]struct{}),
	}
}

// GlobalStore returns the singleton event store.
func GlobalStore() *EventStore {
	return globalStore
}

// AttachSQLite connects a persistent SQLiteStore to the EventStore.
// It also preloads the latest events from SQLite into memory.
func (s *EventStore) AttachSQLite(sq *SQLiteStore) {
	s.mu.Lock()
	s.sqlite = sq
	s.mu.Unlock()

	if sq != nil {
		if recent, err := sq.GetRecent(500); err == nil && len(recent) > 0 {
			// Populate from oldest to newest so s.events ends up in chronological order
			for i := len(recent) - 1; i >= 0; i-- {
				s.ingestInternal(recent[i], false)
			}
		}
	}
}

// SQLite returns the attached SQLiteStore, if any.
func (s *EventStore) SQLite() *SQLiteStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sqlite
}

// Subscribe returns a channel that receives newly ingested security events.
func (s *EventStore) Subscribe() (chan *SecurityEvent, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan *SecurityEvent, 100)
	s.subscribers[ch] = struct{}{}
	unsubscribe := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.subscribers, ch)
		close(ch)
	}
	return ch, unsubscribe
}

func parseFlexibleTimestamp(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t, true
	}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts); err == nil {
		return t, true
	}
	if t, err := time.Parse("02/Jan/2006:15:04:05", ts); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// Add adds a structured security event to the store and broadcasts it.
func (s *EventStore) Add(ev *SecurityEvent) {
	s.ingestInternal(ev, true)
}

func (s *EventStore) ingestInternal(ev *SecurityEvent, persist bool) {
	if ev == nil {
		return
	}
	s.mu.Lock()

	// Verify event hash to eliminate duplicate ingestion upon stream restart
	h := ev.EnsureHash()
	if h != "" {
		if _, exists := s.seenHashes[h]; exists {
			s.mu.Unlock()
			return
		}
		s.seenHashes[h] = struct{}{}
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
	}

	if ev.ID <= 0 {
		s.nextID++
		ev.ID = s.nextID
	} else if ev.ID > s.nextID {
		s.nextID = ev.ID
	}

	if ev.TimeStr == "" {
		if t, ok := parseFlexibleTimestamp(ev.Timestamp); ok {
			ev.TimeStr = t.Local().Format("15:04:05")
		} else {
			ev.TimeStr = time.Now().Format("15:04:05")
		}
	}

	// Update ring buffer
	s.events = append(s.events, ev)
	if len(s.events) > s.maxEvents {
		s.events = s.events[len(s.events)-s.maxEvents:]
	}

	// Update atomic counters
	atomic.AddInt64(&s.totalEvents, 1)
	isBlocked := ev.Verdict == "BLOCK" || ev.Status == 403
	isTarpit := ev.Verdict == "TARPIT" || ev.Status == 429
	if isBlocked {
		atomic.AddInt64(&s.blockedCount, 1)
	} else if isTarpit {
		atomic.AddInt64(&s.tarpitCount, 1)
	}

	if s == globalStore {
		atomic.AddInt64(&totalEvents, 1)
		if isBlocked {
			atomic.AddInt64(&blockedCount, 1)
		} else if isTarpit {
			atomic.AddInt64(&tarpitCount, 1)
		}
	}

	// Timeline bucket (HH:MM)
	bucketKey := time.Now().Format("15:04")
	if t, ok := parseFlexibleTimestamp(ev.Timestamp); ok {
		bucketKey = t.Local().Format("15:04")
	}
	tb, exists := s.timeline[bucketKey]
	if !exists {
		tb = &TimelinePoint{Time: bucketKey}
		s.timeline[bucketKey] = tb
		s.timelineKeys = append(s.timelineKeys, bucketKey)
		if len(s.timelineKeys) > 30 {
			oldKey := s.timelineKeys[0]
			s.timelineKeys = s.timelineKeys[1:]
			delete(s.timeline, oldKey)
		}
	}
	tb.Total++
	if isBlocked {
		tb.Blocked++
	} else if isTarpit {
		tb.Tarpit++
	} else {
		tb.Clean++
	}

	// Auto-detect country if missing
	if ev.ClientIP != "" {
		if ev.Country == "" || ev.CountryCode == "" {
			ev.Country, ev.CountryCode = AutoDetectCountry(ev.ClientIP)
		}
	}

	// Top IPs
	if ev.ClientIP != "" {
		ipItem, ok := s.ipCounts[ev.ClientIP]
		if !ok {
			ipItem = &TopMetricItem{
				Name:        ev.ClientIP,
				Country:     ev.Country,
				CountryCode: ev.CountryCode,
			}
			s.ipCounts[ev.ClientIP] = ipItem
		}
		ipItem.Count++
		if isBlocked {
			ipItem.Blocked++
		} else if isTarpit {
			ipItem.Tarpit++
		}
		if ev.Country != "" && ipItem.Country == "" {
			ipItem.Country = ev.Country
			ipItem.CountryCode = ev.CountryCode
		}
		if len(s.ipCounts) > 5000 {
			for k, v := range s.ipCounts {
				if v.Count <= 1 {
					delete(s.ipCounts, k)
				}
			}
			if len(s.ipCounts) > 4000 {
				pruned := 0
				for k := range s.ipCounts {
					delete(s.ipCounts, k)
					pruned++
					if pruned >= 2000 {
						break
					}
				}
			}
		}
	}

	// Top Countries
	countryName := ev.Country
	if countryName == "" {
		countryName = "Unknown"
	}
	cItem, ok := s.countryCounts[countryName]
	if !ok {
		cItem = &TopMetricItem{
			Name:        countryName,
			Country:     countryName,
			CountryCode: ev.CountryCode,
		}
		s.countryCounts[countryName] = cItem
	}
	cItem.Count++
	if isBlocked {
		cItem.Blocked++
	} else if isTarpit {
		cItem.Tarpit++
	}

	// Top Paths
	if ev.Path != "" {
		pathItem, ok := s.pathCounts[ev.Path]
		if !ok {
			pathItem = &TopMetricItem{Name: ev.Path, Rule: ev.Rule}
			s.pathCounts[ev.Path] = pathItem
		}
		pathItem.Count++
		if isBlocked {
			pathItem.Blocked++
		} else if isTarpit {
			pathItem.Tarpit++
		}
		if ev.Rule != "" {
			pathItem.Rule = ev.Rule
		}
		if len(s.pathCounts) > 5000 {
			for k, v := range s.pathCounts {
				if v.Count <= 1 {
					delete(s.pathCounts, k)
				}
			}
			if len(s.pathCounts) > 4000 {
				pruned := 0
				for k := range s.pathCounts {
					delete(s.pathCounts, k)
					pruned++
					if pruned >= 2000 {
						break
					}
				}
			}
		}
	}

	// Top Rules
	if ev.Rule != "" {
		ruleItem, ok := s.ruleCounts[ev.Rule]
		if !ok {
			ruleItem = &TopMetricItem{Name: ev.Rule}
			s.ruleCounts[ev.Rule] = ruleItem
		}
		ruleItem.Count++
		if isBlocked {
			ruleItem.Blocked++
		} else if isTarpit {
			ruleItem.Tarpit++
		}
		if len(s.ruleCounts) > 2000 {
			for k, v := range s.ruleCounts {
				if v.Count <= 1 {
					delete(s.ruleCounts, k)
				}
			}
		}
	}

	// Status Codes
	statKey := fmt.Sprintf("%d", ev.Status)
	s.statusCounts[statKey]++

	// Broadcast to active SSE subscribers
	for ch := range s.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}

	sq := s.sqlite
	s.mu.Unlock()

	// Persist asynchronously to SQLite if enabled
	if persist && sq != nil {
		sq.Insert(ev)
	}
}

// ParseAndIngest parses a raw line (JSON or Combined Log) into a SecurityEvent and ingests it.
func (s *EventStore) ParseAndIngest(line string, source string) *SecurityEvent {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	ev := &SecurityEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		TimeStr:   time.Now().Format("15:04:05"),
		Source:    source,
	}

	// Try JSON format
	var le logEvent
	if err := json.Unmarshal([]byte(line), &le); err == nil && (le.Path != "" || le.PathAlt != "" || le.RequestPath != "" || le.ClientIP != "" || le.ClientIPAlt != "" || le.ClientHost != "" || le.Verdict != "") {
		ev.ClientIP = le.ClientIP
		if ev.ClientIP == "" {
			ev.ClientIP = le.ClientIPAlt
		}
		if ev.ClientIP == "" {
			ev.ClientIP = le.ClientHost
		}
		if ev.ClientIP == "" {
			ev.ClientIP = "127.0.0.1"
		}

		ev.Path = le.Path
		if ev.Path == "" {
			ev.Path = le.PathAlt
		}
		if ev.Path == "" {
			ev.Path = le.RequestPath
		}
		if ev.Path == "" {
			ev.Path = "/"
		}

		ev.Method = le.Method
		if ev.Method == "" {
			ev.Method = le.RequestMethod
		}
		if ev.Method == "" {
			ev.Method = "GET"
		}

		ev.Status = le.StatusCode
		if ev.Status == 0 {
			ev.Status = le.StatusCodeAlt
		}
		if ev.Status == 0 {
			ev.Status = le.DownstreamStat
		}

		ev.Verdict = strings.ToUpper(le.Verdict)
		if ev.Verdict == "" {
			switch ev.Status {
			case 403:
				ev.Verdict = "BLOCK"
			case 429:
				ev.Verdict = "TARPIT"
			default:
				ev.Verdict = "ALLOW"
			}
		}
		if ev.Status == 0 {
			switch ev.Verdict {
			case "BLOCK":
				ev.Status = 403
			case "TARPIT":
				ev.Status = 429
			default:
				ev.Status = 200
			}
		}

		ev.Rule = le.MatchedPattern
		if ev.Rule == "" {
			ev.Rule = le.MatchedRuleAlt
		}

		ev.LatencyMs = le.LatencyMs
		if ev.LatencyMs == 0 {
			ev.LatencyMs = le.DurationMsAlt
		}
		if ev.LatencyMs == 0 {
			if ev.Verdict == "TARPIT" {
				ev.LatencyMs = 5000.0
			} else {
				ev.LatencyMs = 1.4
			}
		}

		if le.Timestamp != "" {
			ev.Timestamp = le.Timestamp
		} else if le.TimestampAlt != "" {
			ev.Timestamp = le.TimestampAlt
		}
		if t, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ev.TimeStr = t.Local().Format("15:04:05")
		} else if t, err := time.Parse("2006-01-02 15:04:05", ev.Timestamp); err == nil {
			ev.TimeStr = t.Local().Format("15:04:05")
		}

		s.Add(ev)
		return ev
	}

	// Try Combined Apache/Nginx format
	if match := combinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		ev.ClientIP = match[1]
		if len(match) > 2 && match[2] != "" {
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[2]); err == nil {
				ev.Timestamp = t.Format(time.RFC3339)
				ev.TimeStr = t.Local().Format("15:04:05")
			} else if t, err := time.Parse("02/Jan/2006:15:04:05", match[2]); err == nil {
				ev.Timestamp = t.Format(time.RFC3339)
				ev.TimeStr = t.Local().Format("15:04:05")
			} else if t, err := time.Parse(time.RFC3339, match[2]); err == nil {
				ev.Timestamp = t.Format(time.RFC3339)
				ev.TimeStr = t.Local().Format("15:04:05")
			}
		}
		ev.Method = match[3]
		ev.Path = match[4]
		fmt.Sscanf(match[5], "%d", &ev.Status)

		// Check User-Agent tag for Verdict and Rule
		if strings.Contains(line, "[BLOCK:") {
			ev.Verdict = "BLOCK"
			if idx := strings.Index(line, "[BLOCK:"); idx != -1 {
				rem := line[idx+7:]
				if end := strings.Index(rem, "]"); end != -1 {
					ev.Rule = strings.TrimSpace(rem[:end])
				}
			}
		} else if strings.Contains(line, "[TARPIT:") {
			ev.Verdict = "TARPIT"
			if idx := strings.Index(line, "[TARPIT:"); idx != -1 {
				rem := line[idx+8:]
				if end := strings.Index(rem, "]"); end != -1 {
					ev.Rule = strings.TrimSpace(rem[:end])
				}
			}
		} else if strings.Contains(line, "[RULE:") {
			if idx := strings.Index(line, "[RULE:"); idx != -1 {
				rem := line[idx+6:]
				if end := strings.Index(rem, "]"); end != -1 {
					ev.Rule = strings.TrimSpace(rem[:end])
				}
			}
			switch ev.Status {
			case 403:
				ev.Verdict = "BLOCK"
			case 429:
				ev.Verdict = "TARPIT"
			default:
				ev.Verdict = "ALLOW"
			}
		} else {
			switch ev.Status {
			case 403:
				ev.Verdict = "BLOCK"
			case 429:
				ev.Verdict = "TARPIT"
			default:
				ev.Verdict = "ALLOW"
			}
		}

		if ev.Verdict == "TARPIT" {
			ev.LatencyMs = 5000.0
		} else {
			ev.LatencyMs = 2.1
		}

		s.Add(ev)
		return ev
	}

	return nil
}

// GetStats returns structured summary metrics.
func (s *EventStore) GetStats() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := atomic.LoadInt64(&s.totalEvents)
	blocked := atomic.LoadInt64(&s.blockedCount)
	tarpit := atomic.LoadInt64(&s.tarpitCount)
	if s == globalStore {
		gTotal := atomic.LoadInt64(&totalEvents)
		if gTotal > total {
			total = gTotal
			blocked = atomic.LoadInt64(&blockedCount)
			tarpit = atomic.LoadInt64(&tarpitCount)
		}
	}
	clean := total - blocked - tarpit
	if clean < 0 {
		clean = 0
	}

	blockRate := "0.0%"
	if total > 0 {
		blockRate = fmt.Sprintf("%.1f%%", float64(blocked)/float64(total)*100.0)
	}

	elapsed := time.Since(s.startTime).Seconds()
	eps := 0.0
	if elapsed > 0 {
		eps = float64(total) / elapsed
	}

	// Timeline
	timelineList := make([]TimelinePoint, 0, len(s.timelineKeys))
	for _, key := range s.timelineKeys {
		if tb, ok := s.timeline[key]; ok {
			timelineList = append(timelineList, *tb)
		}
	}
	if len(timelineList) == 0 {
		nowKey := time.Now().Format("15:04")
		timelineList = append(timelineList, TimelinePoint{
			Time:    nowKey,
			Total:   total,
			Blocked: blocked,
			Tarpit:  tarpit,
			Clean:   clean,
		})
	}

	// Sort Top IPs (deterministic: count desc, then name asc)
	topIPs := make([]TopMetricItem, 0, len(s.ipCounts))
	for _, item := range s.ipCounts {
		if item.Country == "" || item.CountryCode == "" {
			item.Country, item.CountryCode = AutoDetectCountry(item.Name)
		}
		topIPs = append(topIPs, *item)
	}
	sort.Slice(topIPs, func(i, j int) bool {
		if topIPs[i].Count != topIPs[j].Count {
			return topIPs[i].Count > topIPs[j].Count
		}
		return topIPs[i].Name < topIPs[j].Name
	})
	if len(topIPs) > 10 {
		topIPs = topIPs[:10]
	}

	// Sort Top Countries (deterministic: count desc, then name asc)
	topCountries := make([]TopMetricItem, 0, len(s.countryCounts))
	for _, item := range s.countryCounts {
		topCountries = append(topCountries, *item)
	}
	sort.Slice(topCountries, func(i, j int) bool {
		if topCountries[i].Count != topCountries[j].Count {
			return topCountries[i].Count > topCountries[j].Count
		}
		return topCountries[i].Name < topCountries[j].Name
	})
	if len(topCountries) > 10 {
		topCountries = topCountries[:10]
	}

	// Sort Top Paths (deterministic: count desc, then name asc)
	topPaths := make([]TopMetricItem, 0, len(s.pathCounts))
	for _, item := range s.pathCounts {
		topPaths = append(topPaths, *item)
	}
	sort.Slice(topPaths, func(i, j int) bool {
		if topPaths[i].Count != topPaths[j].Count {
			return topPaths[i].Count > topPaths[j].Count
		}
		return topPaths[i].Name < topPaths[j].Name
	})
	if len(topPaths) > 10 {
		topPaths = topPaths[:10]
	}

	// Sort Top Rules (deterministic: count desc, then name asc)
	topRules := make([]TopMetricItem, 0, len(s.ruleCounts))
	for _, item := range s.ruleCounts {
		topRules = append(topRules, *item)
	}
	sort.Slice(topRules, func(i, j int) bool {
		if topRules[i].Count != topRules[j].Count {
			return topRules[i].Count > topRules[j].Count
		}
		return topRules[i].Name < topRules[j].Name
	})
	if len(topRules) > 10 {
		topRules = topRules[:10]
	}

	// Status Codes copy
	statCopy := make(map[string]int64, len(s.statusCounts))
	for k, v := range s.statusCounts {
		statCopy[k] = v
	}

	// Copy recent events in reverse order (newest first, up to 250)
	recent := make([]*SecurityEvent, len(s.events))
	for i, ev := range s.events {
		recent[len(s.events)-1-i] = ev
	}
	if len(recent) > 250 {
		recent = recent[:250]
	}

	return DashboardStats{
		TotalEvents:  total,
		BlockedCount: blocked,
		TarpitCount:  tarpit,
		CleanCount:   clean,
		BlockRate:    blockRate,
		EventsPerSec: eps,
		Timeline:     timelineList,
		TopIPs:       topIPs,
		TopPaths:     topPaths,
		TopRules:     topRules,
		TopCountries: topCountries,
		StatusCodes:  statCopy,
		RecentEvents: recent,
	}
}

// SeedDemoData adds initial sample gateway telemetry if store is empty.
func (s *EventStore) SeedDemoData() {
	s.mu.RLock()
	hasData := len(s.events) > 0 || (s.sqlite != nil && s.sqlite.Count() > 0)
	s.mu.RUnlock()
	if hasData {
		return
	}

	samples := []string{
		`{"time":"2026-10-18T12:55:01Z","client_ip":"198.51.100.24","method":"GET","path":"/health","status":200,"verdict":"ALLOW","latency_ms":1.2}`,
		`{"time":"2026-10-18T12:55:04Z","client_ip":"203.0.113.88","method":"GET","path":"/.env","status":403,"verdict":"BLOCK","rule":"scanner","latency_ms":0.8}`,
		`{"time":"2026-10-18T12:55:09Z","client_ip":"198.51.100.42","method":"POST","path":"/login?user=' OR 1=1--","status":403,"verdict":"BLOCK","rule":"sql-injection","latency_ms":1.1}`,
		`{"time":"2026-10-18T12:55:14Z","client_ip":"192.0.2.15","method":"GET","path":"/api/v1/users","status":200,"verdict":"ALLOW","latency_ms":2.4}`,
		`{"time":"2026-10-18T12:55:20Z","client_ip":"203.0.113.91","method":"GET","path":"/../../etc/passwd","status":403,"verdict":"BLOCK","rule":"path-traversal","latency_ms":0.9}`,
		`{"time":"2026-10-18T12:55:25Z","client_ip":"198.51.100.99","method":"GET","path":"/wp-admin/install.php","status":429,"verdict":"TARPIT","rule":"crawler-tarpit","latency_ms":5000.0}`,
		`{"time":"2026-10-18T12:55:31Z","client_ip":"192.0.2.44","method":"GET","path":"/api/v1/metrics","status":200,"verdict":"ALLOW","latency_ms":1.6}`,
		`{"time":"2026-10-18T12:55:38Z","client_ip":"203.0.113.88","method":"GET","path":"/actuator/env","status":403,"verdict":"BLOCK","rule":"scanner","latency_ms":1.0}`,
		`{"time":"2026-10-18T12:55:42Z","client_ip":"198.51.100.24","method":"GET","path":"/dashboard","status":200,"verdict":"ALLOW","latency_ms":3.1}`,
		`{"time":"2026-10-18T12:55:50Z","client_ip":"198.51.100.77","method":"POST","path":"/api/upload?name=cmd.jsp","status":403,"verdict":"BLOCK","rule":"rce-attempt","latency_ms":1.4}`,
	}
	for _, l := range samples {
		s.ParseAndIngest(l, "gateway-init")
	}
}

// ServeSSE streams security events as Server-Sent Events to the connected client.
func ServeSSE(w http.ResponseWriter, r *http.Request, store *EventStore) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch, unsubscribe := store.Subscribe()
	defer unsubscribe()

	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()

	pingTicker := time.NewTicker(15 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if ev != nil {
				data, err := json.Marshal(ev)
				if err == nil {
					fmt.Fprintf(w, "event: event\ndata: %s\n\n", data)
					flusher.Flush()
				}
			}
		case <-pingTicker.C:
			fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}

// IPDetails represents geolocation and ISP intelligence for an IP address.
type IPDetails struct {
	IP          string  `json:"ip"`
	Status      string  `json:"status"` // "success" or "fail"
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	RegionName  string  `json:"region_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Zip         string  `json:"zip,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
	AS          string  `json:"as,omitempty"`
	IsPrivate   bool    `json:"is_private"`
	Message     string  `json:"message,omitempty"`
}

type cachedIP struct {
	details   *IPDetails
	fetchedAt time.Time
}

var (
	ipCacheMu sync.RWMutex
	ipCache   = make(map[string]cachedIP)
)

type ipNetEntry struct {
	net         *net.IPNet
	country     string
	countryCode string
}

var (
	builtinIPDBOnce sync.Once
	builtinIPDB     []ipNetEntry
)

func initBuiltinIPDB() {
	// Attempt auto-discovery of local MaxMind database
	maxmindOnce.Do(func() {
		_ = InitMaxMind()
	})

	rawEntries := []struct {
		cidr        string
		country     string
		countryCode string
	}{
		// Private / Local / Test Networks
		{"127.0.0.0/8", "Localhost / Loopback", "LAN"},
		{"::1/128", "Localhost / Loopback", "LAN"},
		{"10.0.0.0/8", "Private Network (RFC 1918)", "LAN"},
		{"172.16.0.0/12", "Private Network (RFC 1918)", "LAN"},
		{"192.168.0.0/16", "Private Network (RFC 1918)", "LAN"},
		{"100.64.0.0/10", "Carrier-Grade NAT (RFC 6598)", "LAN"},
		{"169.254.0.0/16", "Link-Local", "LAN"},
		{"192.0.2.0/24", "TEST-NET-1 (RFC 5737)", "US"},
		{"198.51.100.0/24", "TEST-NET-2 (RFC 5737)", "US"},
		{"203.0.113.0/24", "TEST-NET-3 (RFC 5737)", "US"},
		{"224.0.0.0/4", "Multicast", "LAN"},
		{"240.0.0.0/4", "Reserved", "LAN"},
		{"fc00::/7", "Unique Local Address", "LAN"},
		{"fe80::/10", "Link-Local", "LAN"},

		// Major Public IPv4 Anycast / Cloud Providers & Subnets
		{"1.0.0.0/24", "United States", "US"},
		{"1.1.1.0/24", "United States", "US"},
		{"8.8.4.0/24", "United States", "US"},
		{"8.8.8.0/24", "United States", "US"},
		{"9.9.9.0/24", "United States", "US"},
		{"208.67.220.0/22", "United States", "US"},
		{"208.67.222.0/24", "United States", "US"},
		{"104.16.0.0/12", "United States", "US"},
		{"172.217.0.0/16", "United States", "US"},
		{"142.250.0.0/15", "United States", "US"},
		{"199.16.156.0/22", "United States", "US"},
		{"3.0.0.0/8", "United States", "US"},
		{"4.0.0.0/9", "United States", "US"},
		{"12.0.0.0/8", "United States", "US"},
		{"15.0.0.0/8", "United States", "US"},
		{"16.0.0.0/8", "United States", "US"},
		{"23.0.0.0/8", "United States", "US"},
		{"34.0.0.0/8", "United States", "US"},
		{"44.0.0.0/8", "United States", "US"},
		{"52.0.0.0/10", "United States", "US"},
		{"54.0.0.0/10", "United States", "US"},
		{"64.0.0.0/10", "United States", "US"},
		{"66.0.0.0/10", "United States", "US"},
		{"72.0.0.0/10", "United States", "US"},
		{"98.0.0.0/10", "United States", "US"},
		{"107.0.0.0/10", "United States", "US"},

		// Germany
		{"78.46.0.0/15", "Germany", "DE"},
		{"88.198.0.0/16", "Germany", "DE"},
		{"116.202.0.0/15", "Germany", "DE"},
		{"136.243.0.0/16", "Germany", "DE"},
		{"144.76.0.0/16", "Germany", "DE"},
		{"148.251.0.0/16", "Germany", "DE"},
		{"159.69.0.0/16", "Germany", "DE"},
		{"168.119.0.0/16", "Germany", "DE"},
		{"178.63.0.0/16", "Germany", "DE"},
		{"195.201.0.0/16", "Germany", "DE"},

		// United Kingdom
		{"51.0.0.0/10", "United Kingdom", "GB"},
		{"81.128.0.0/11", "United Kingdom", "GB"},
		{"82.0.0.0/11", "United Kingdom", "GB"},
		{"86.0.0.0/11", "United Kingdom", "GB"},
		{"185.125.188.0/22", "United Kingdom", "GB"},

		// France
		{"51.68.0.0/14", "France", "FR"},
		{"54.36.0.0/14", "France", "FR"},
		{"87.98.128.0/17", "France", "FR"},
		{"164.132.0.0/16", "France", "FR"},
		{"212.83.128.0/18", "France", "FR"},

		// China
		{"1.24.0.0/13", "China", "CN"},
		{"14.128.0.0/10", "China", "CN"},
		{"27.16.0.0/12", "China", "CN"},
		{"36.96.0.0/11", "China", "CN"},
		{"42.120.0.0/14", "China", "CN"},
		{"47.92.0.0/14", "China", "CN"},
		{"58.32.0.0/11", "China", "CN"},
		{"59.32.0.0/11", "China", "CN"},
		{"60.16.0.0/12", "China", "CN"},
		{"101.64.0.0/11", "China", "CN"},
		{"110.16.0.0/12", "China", "CN"},
		{"111.160.0.0/11", "China", "CN"},
		{"112.64.0.0/11", "China", "CN"},
		{"113.64.0.0/11", "China", "CN"},
		{"114.80.0.0/12", "China", "CN"},
		{"115.192.0.0/11", "China", "CN"},
		{"116.128.0.0/10", "China", "CN"},
		{"117.128.0.0/10", "China", "CN"},
		{"118.160.0.0/11", "China", "CN"},
		{"119.128.0.0/11", "China", "CN"},
		{"120.192.0.0/10", "China", "CN"},
		{"121.192.0.0/10", "China", "CN"},
		{"123.128.0.0/10", "China", "CN"},
		{"124.192.0.0/10", "China", "CN"},
		{"125.64.0.0/11", "China", "CN"},
		{"180.96.0.0/11", "China", "CN"},
		{"182.80.0.0/12", "China", "CN"},
		{"183.128.0.0/10", "China", "CN"},
		{"218.64.0.0/11", "China", "CN"},
		{"220.160.0.0/11", "China", "CN"},
		{"221.192.0.0/11", "China", "CN"},
		{"222.128.0.0/10", "China", "CN"},
		{"223.160.0.0/11", "China", "CN"},

		// Russia
		{"5.45.192.0/18", "Russia", "RU"},
		{"37.192.0.0/11", "Russia", "RU"},
		{"46.160.0.0/12", "Russia", "RU"},
		{"77.222.96.0/19", "Russia", "RU"},
		{"85.142.0.0/15", "Russia", "RU"},
		{"87.224.0.0/12", "Russia", "RU"},
		{"91.200.0.0/14", "Russia", "RU"},
		{"92.240.0.0/12", "Russia", "RU"},
		{"93.180.0.0/14", "Russia", "RU"},
		{"94.240.0.0/12", "Russia", "RU"},
		{"95.160.0.0/11", "Russia", "RU"},
		{"176.59.0.0/16", "Russia", "RU"},
		{"178.64.0.0/12", "Russia", "RU"},
		{"185.15.0.0/16", "Russia", "RU"},
		{"195.98.0.0/15", "Russia", "RU"},

		// India
		{"14.139.0.0/16", "India", "IN"},
		{"49.200.0.0/13", "India", "IN"},
		{"49.248.0.0/13", "India", "IN"},
		{"103.20.0.0/14", "India", "IN"},
		{"103.24.0.0/14", "India", "IN"},
		{"103.36.0.0/14", "India", "IN"},
		{"103.50.0.0/14", "India", "IN"},
		{"106.192.0.0/11", "India", "IN"},
		{"115.96.0.0/12", "India", "IN"},
		{"117.192.0.0/11", "India", "IN"},
		{"122.160.0.0/12", "India", "IN"},
		{"157.32.0.0/11", "India", "IN"},
		{"182.64.0.0/11", "India", "IN"},

		// Japan
		{"43.224.0.0/12", "Japan", "JP"},
		{"60.32.0.0/11", "Japan", "JP"},
		{"61.112.0.0/12", "Japan", "JP"},
		{"106.128.0.0/10", "Japan", "JP"},
		{"118.0.0.0/11", "Japan", "JP"},
		{"122.16.0.0/12", "Japan", "JP"},
		{"124.32.0.0/11", "Japan", "JP"},
		{"126.0.0.0/9", "Japan", "JP"},
		{"133.0.0.0/10", "Japan", "JP"},
		{"153.120.0.0/13", "Japan", "JP"},
		{"160.13.0.0/16", "Japan", "JP"},
		{"210.128.0.0/11", "Japan", "JP"},

		// Singapore
		{"43.240.0.0/13", "Singapore", "SG"},
		{"103.1.0.0/16", "Singapore", "SG"},
		{"116.12.0.0/14", "Singapore", "SG"},
		{"118.188.0.0/14", "Singapore", "SG"},
		{"128.106.0.0/16", "Singapore", "SG"},
		{"175.156.0.0/14", "Singapore", "SG"},

		// Canada
		{"24.200.0.0/13", "Canada", "CA"},
		{"64.230.0.0/15", "Canada", "CA"},
		{"70.24.0.0/13", "Canada", "CA"},
		{"72.38.0.0/15", "Canada", "CA"},
		{"142.150.0.0/15", "Canada", "CA"},
		{"198.84.0.0/14", "Canada", "CA"},

		// Brazil
		{"45.160.0.0/11", "Brazil", "BR"},
		{"177.0.0.0/10", "Brazil", "BR"},
		{"179.96.0.0/11", "Brazil", "BR"},
		{"187.0.0.0/10", "Brazil", "BR"},
		{"189.0.0.0/10", "Brazil", "BR"},
		{"191.160.0.0/11", "Brazil", "BR"},
		{"200.128.0.0/10", "Brazil", "BR"},
		{"201.0.0.0/10", "Brazil", "BR"},

		// Netherlands
		{"46.17.96.0/19", "Netherlands", "NL"},
		{"80.112.0.0/12", "Netherlands", "NL"},
		{"84.80.0.0/12", "Netherlands", "NL"},
		{"145.0.0.0/11", "Netherlands", "NL"},
		{"188.166.0.0/16", "Netherlands", "NL"},

		// Australia
		{"1.128.0.0/11", "Australia", "AU"},
		{"49.176.0.0/12", "Australia", "AU"},
		{"101.160.0.0/11", "Australia", "AU"},
		{"120.144.0.0/12", "Australia", "AU"},
		{"139.130.0.0/16", "Australia", "AU"},
		{"203.0.0.0/12", "Australia", "AU"},

		// South Korea
		{"1.208.0.0/12", "South Korea", "KR"},
		{"14.32.0.0/11", "South Korea", "KR"},
		{"27.112.0.0/12", "South Korea", "KR"},
		{"112.160.0.0/11", "South Korea", "KR"},
		{"121.128.0.0/10", "South Korea", "KR"},
		{"175.192.0.0/11", "South Korea", "KR"},
		{"211.168.0.0/13", "South Korea", "KR"},
	}

	for _, e := range rawEntries {
		_, ipNet, err := net.ParseCIDR(e.cidr)
		if err == nil {
			builtinIPDB = append(builtinIPDB, ipNetEntry{
				net:         ipNet,
				country:     e.country,
				countryCode: e.countryCode,
			})
		}
	}
}

func lookupBuiltinIPDB(ip net.IP) (string, string) {
	builtinIPDBOnce.Do(initBuiltinIPDB)

	if ip == nil {
		return "Unknown", ""
	}

	// 1. Exact CIDR match in built-in table
	for _, entry := range builtinIPDB {
		if entry.net.Contains(ip) {
			return entry.country, entry.countryCode
		}
	}

	// 2. Private/loopback check
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "Local / Private Network", "LAN"
	}

	// 3. IANA Regional RIR allocation fallbacks (IPv4)
	ip4 := ip.To4()
	if ip4 != nil {
		first := ip4[0]
		switch {
		// ARIN (North America)
		case first == 3 || first == 4 || first == 8 || first == 12 || (first >= 15 && first <= 16) ||
			first == 24 || (first >= 32 && first <= 35) || first == 40 || first == 44 ||
			first == 50 || first == 52 || first == 54 || (first >= 63 && first <= 76) ||
			(first >= 96 && first <= 100) || first == 104 || first == 107 || first == 108 ||
			(first >= 128 && first <= 132) || (first >= 134 && first <= 138) || first == 140 ||
			first == 142 || first == 144 || (first >= 146 && first <= 149) || first == 152 ||
			(first >= 155 && first <= 156) || (first >= 161 && first <= 162) ||
			(first >= 164 && first <= 169) || (first >= 172 && first <= 174) ||
			first == 198 || first == 199 || (first >= 204 && first <= 209):
			return "United States", "US"

		// RIPE NCC (Europe)
		case first == 2 || first == 5 || first == 31 || first == 37 || first == 46 ||
			first == 62 || (first >= 77 && first <= 95) || first == 109 || first == 141 ||
			first == 145 || first == 151 || first == 176 || first == 178 || first == 185 ||
			first == 188 || (first >= 193 && first <= 195) || first == 212 || first == 213 || first == 217:
			return "European Union", "EU"

		// APNIC (Asia-Pacific)
		case first == 1 || first == 14 || first == 27 || first == 36 || first == 39 ||
			first == 42 || first == 43 || first == 49 || (first >= 58 && first <= 61) ||
			first == 101 || first == 103 || first == 106 || (first >= 110 && first <= 126) ||
			first == 150 || first == 153 || first == 175 || first == 180 || first == 182 ||
			first == 183 || first == 202 || first == 203 || first == 210 || first == 211 ||
			(first >= 218 && first <= 223):
			return "Asia-Pacific", "AP"

		// LACNIC (Latin America)
		case first == 177 || first == 179 || first == 181 || (first >= 186 && first <= 187) ||
			first == 189 || first == 190 || first == 191 || first == 200 || first == 201:
			return "Brazil", "BR"

		// AFRINIC (Africa)
		case first == 41 || first == 102 || first == 105 || first == 154 || first == 196 || first == 197:
			return "South Africa", "ZA"
		}
	}

	return "Unknown", ""
}

// AutoDetectCountry automatically determines the country and country code for an IP address.
// It checks in-memory cache first, then the MaxMind database if loaded, followed by the
// built-in zero-dependency IP database, and triggers asynchronous background enrichment via ip-api.com.
func AutoDetectCountry(ipStr string) (string, string) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return "Unknown", ""
	}

	// 1. Check IP cache
	ipCacheMu.RLock()
	if c, ok := ipCache[ipStr]; ok && c.details != nil && c.details.Country != "" && c.details.CountryCode != "" {
		country, code := c.details.Country, c.details.CountryCode
		ipCacheMu.RUnlock()
		return country, code
	}
	ipCacheMu.RUnlock()

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return "Unknown", ""
	}

	// 2. MaxMind GeoIP database lookup (if loaded and not loopback/private)
	if IsMaxMindLoaded() && !parsed.IsLoopback() && !parsed.IsPrivate() && !parsed.IsLinkLocalUnicast() && !parsed.IsUnspecified() {
		if cName, cCode, ok := LookupMaxMind(parsed); ok {
			return cName, cCode
		}
	}

	// 3. Built-in IP Database lookup (includes detailed private/LAN and RFC CIDR matches)
	country, code := lookupBuiltinIPDB(parsed)

	// 5. Background enrich if public IP and not already queried
	ipCacheMu.Lock()
	if _, exists := ipCache[ipStr]; !exists {
		ipCache[ipStr] = cachedIP{
			details: &IPDetails{
				IP:          ipStr,
				Country:     country,
				CountryCode: code,
				Status:      "pending",
			},
			fetchedAt: time.Now(),
		}
		go func(targetIP string) {
			LookupIP(targetIP)
		}(ipStr)
	}
	ipCacheMu.Unlock()

	return country, code
}

// LookupIP queries IP intelligence using ip-api.com with local caching, MaxMind GeoIP, and private IP handling.
func LookupIP(ipStr string) *IPDetails {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return &IPDetails{IP: ipStr, Status: "fail", Message: "empty IP address"}
	}

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return &IPDetails{IP: ipStr, Status: "fail", Message: "invalid IP address format"}
	}

	// Detect private / loopback / link-local addresses
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
		return &IPDetails{
			IP:          ipStr,
			Status:      "success",
			Country:     "Local / Private Network",
			CountryCode: "LAN",
			RegionName:  "Internal Subnet",
			City:        "Private Network",
			ISP:         "RFC 1918 / Loopback",
			Org:         "Local Intranet",
			AS:          "AS0 (Private)",
			IsPrivate:   true,
		}
	}

	// Check cache (TTL 2 hours)
	ipCacheMu.RLock()
	if c, ok := ipCache[ipStr]; ok && c.details != nil && c.details.Status == "success" && time.Since(c.fetchedAt) < 2*time.Hour {
		ipCacheMu.RUnlock()
		return c.details
	}
	ipCacheMu.RUnlock()

	// Check MaxMind GeoIP if loaded
	if IsMaxMindLoaded() {
		if cName, cCode, ok := LookupMaxMind(parsed); ok {
			details := &IPDetails{
				IP:          ipStr,
				Status:      "success",
				Country:     cName,
				CountryCode: cCode,
				ISP:         "MaxMind GeoIP",
				Org:         "MaxMind Database (" + MaxMindDBPath() + ")",
			}
			ipCacheMu.Lock()
			ipCache[ipStr] = cachedIP{
				details:   details,
				fetchedAt: time.Now(),
			}
			ipCacheMu.Unlock()
			return details
		}
	}

	// Query ip-api.com over HTTP (fast, free tier)
	client := &http.Client{Timeout: 4 * time.Second}
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query", url.QueryEscape(ipStr))
	resp, err := client.Get(apiURL)
	if err != nil {
		if IsMaxMindLoaded() {
			if cName, cCode, ok := LookupMaxMind(parsed); ok {
				return &IPDetails{
					IP:          ipStr,
					Status:      "success",
					Country:     cName,
					CountryCode: cCode,
					ISP:         "MaxMind GeoIP",
					Org:         "MaxMind Database (" + MaxMindDBPath() + ")",
				}
			}
		}
		cName, cCode := lookupBuiltinIPDB(parsed)
		return &IPDetails{
			IP:          ipStr,
			Status:      "success",
			Country:     cName,
			CountryCode: cCode,
			ISP:         "Built-in GeoIP Database",
			Message:     "Offline database fallback: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	var details IPDetails
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		if IsMaxMindLoaded() {
			if cName, cCode, ok := LookupMaxMind(parsed); ok {
				return &IPDetails{
					IP:          ipStr,
					Status:      "success",
					Country:     cName,
					CountryCode: cCode,
					ISP:         "MaxMind GeoIP",
					Org:         "MaxMind Database (" + MaxMindDBPath() + ")",
				}
			}
		}
		cName, cCode := lookupBuiltinIPDB(parsed)
		return &IPDetails{
			IP:          ipStr,
			Status:      "success",
			Country:     cName,
			CountryCode: cCode,
			ISP:         "Built-in GeoIP Database",
			Message:     "JSON decode error: " + err.Error(),
		}
	}
	if details.IP == "" {
		details.IP = ipStr
	}
	if details.Country == "" {
		if IsMaxMindLoaded() {
			if cName, cCode, ok := LookupMaxMind(parsed); ok {
				details.Country = cName
				details.CountryCode = cCode
				if details.ISP == "" {
					details.ISP = "MaxMind GeoIP"
				}
			}
		}
		if details.Country == "" {
			details.Country, details.CountryCode = lookupBuiltinIPDB(parsed)
		}
	}

	// Cache successful or recognized lookups
	ipCacheMu.Lock()
	ipCache[ipStr] = cachedIP{
		details:   &details,
		fetchedAt: time.Now(),
	}
	ipCacheMu.Unlock()

	return &details
}

// CustomSOCDashboardHTML contains the complete, self-contained RouteWarden Executive SOC Dashboard.
const CustomSOCDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
  <meta name="theme-color" content="#07090e">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="description" content="RouteWarden SOC INTELLIGENCE & Threat Defense Console">
  <title>ROUTEWARDEN</title>
  <link rel="icon" type="image/svg+xml" href="/icon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <link rel="shortcut icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script>
    (function() {
      try {
        var saved = localStorage.getItem('rw-theme');
        if (saved === 'light' || saved === 'dark') {
          document.documentElement.setAttribute('data-theme', saved);
        }
      } catch(e) {}
    })();
  </script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
  <style>
    /* ═══════════════════════════════════════════════════════════════
       Catppuccin Mocha Terminal Theme (claude-tui Inspired)
       ═══════════════════════════════════════════════════════════════ */
        /* ── Dark Theme (Default) ────────────────────────────────── */
    :root, [data-theme="dark"] {
      --crust: #07090e;
      --base: #0c0f17;
      --panel: #111522;
      --surface: #182035;
      --surface-hi: #222c4a;
      --line: #1c243d;
      --line-hi: #2d3b63;
      --overlay: #64748b;
      --subtext: #94a3b8;
      --text: #e2e8f0;
      --text-hi: #ffffff;

      /* Electric Phosphor Accents */
      --green: #00ff9d;
      --green-bg: rgba(0, 255, 157, 0.08);
      --green-border: rgba(0, 255, 157, 0.3);
      --teal: #00e5ff;
      --teal-bg: rgba(0, 229, 255, 0.1);
      --teal-border: rgba(0, 229, 255, 0.3);
      --yellow: #ffb800;
      --yellow-bg: rgba(255, 184, 0, 0.12);
      --yellow-border: rgba(255, 184, 0, 0.4);
      --peach: #ff8c42;
      --pink: #ff3366;
      --pink-bg: rgba(255, 51, 102, 0.12);
      --pink-border: rgba(255, 51, 102, 0.4);
      --mauve: #b388ff;
      --mauve-bg: rgba(179, 136, 255, 0.12);
      --blue: #38bdf8;
      --blue-bg: rgba(56, 189, 248, 0.1);
      --blue-border: rgba(56, 189, 248, 0.3);

      --glow-text-green: 0 0 10px rgba(0, 255, 157, 0.45);
      --glow-text-teal: 0 0 10px rgba(0, 229, 255, 0.45);
      --glow-text-pink: 0 0 8px rgba(255, 51, 102, 0.45);
      --glow-text-yellow: 0 0 8px rgba(255, 184, 0, 0.45);
      --card-shadow: none;

      --bar-bg: rgba(12, 15, 23, 0.96);
      --map-tile-filter: brightness(0.6) invert(1) contrast(3) hue-rotate(200deg) saturate(0.3) brightness(0.7);
      --map-bg: #07090e;
      --marker-tag-bg: rgba(12, 15, 23, 0.94);
      --marker-tag-border: var(--line-hi);
      --marker-tag-text: var(--text-hi);
      --modal-card-bg: var(--base);
      --modal-overlay-bg: rgba(7, 9, 14, 0.85);

      --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      --col: 1540px;
    }

    /* ── Light Theme (Automatic via System Preference & Manual Toggle) ── */
    @media (prefers-color-scheme: light) {
      :root:not([data-theme="dark"]) {
        --crust: #f1f5f9;
        --base: #ffffff;
        --panel: #ffffff;
        --surface: #f8fafc;
        --surface-hi: #e2e8f0;
        --line: #e2e8f0;
        --line-hi: #cbd5e1;
        --overlay: #64748b;
        --subtext: #475569;
        --text: #1e293b;
        --text-hi: #0f172a;

        /* Crisp Executive Security Accents */
        --green: #059669;
        --green-bg: rgba(5, 150, 105, 0.1);
        --green-border: rgba(5, 150, 105, 0.28);
        --teal: #0284c7;
        --teal-bg: rgba(2, 132, 199, 0.1);
        --teal-border: rgba(2, 132, 199, 0.28);
        --yellow: #d97706;
        --yellow-bg: rgba(217, 119, 6, 0.1);
        --yellow-border: rgba(217, 119, 6, 0.28);
        --peach: #ea580c;
        --pink: #e11d48;
        --pink-bg: rgba(225, 29, 72, 0.1);
        --pink-border: rgba(225, 29, 72, 0.28);
        --mauve: #7c3aed;
        --mauve-bg: rgba(124, 58, 237, 0.1);
        --blue: #2563eb;
        --blue-bg: rgba(37, 99, 235, 0.1);
        --blue-border: rgba(37, 99, 235, 0.28);

        --glow-text-green: none;
        --glow-text-teal: none;
        --glow-text-pink: none;
        --glow-text-yellow: none;
        --card-shadow: 0 1px 3px rgba(15, 23, 42, 0.06), 0 1px 2px rgba(15, 23, 42, 0.04);

        --bar-bg: rgba(255, 255, 255, 0.94);
        --map-tile-filter: contrast(1.02) saturate(0.9);
        --map-bg: #e2e8f0;
        --marker-tag-bg: rgba(255, 255, 255, 0.96);
        --marker-tag-border: #94a3b8;
        --marker-tag-text: #0f172a;
        --modal-card-bg: #ffffff;
        --modal-overlay-bg: rgba(15, 23, 42, 0.55);
      }
    }

    [data-theme="light"] {
      --crust: #f1f5f9;
      --base: #ffffff;
      --panel: #ffffff;
      --surface: #f8fafc;
      --surface-hi: #e2e8f0;
      --line: #e2e8f0;
      --line-hi: #cbd5e1;
      --overlay: #64748b;
      --subtext: #475569;
      --text: #1e293b;
      --text-hi: #0f172a;

      /* Crisp Executive Security Accents */
      --green: #059669;
      --green-bg: rgba(5, 150, 105, 0.1);
      --green-border: rgba(5, 150, 105, 0.28);
      --teal: #0284c7;
      --teal-bg: rgba(2, 132, 199, 0.1);
      --teal-border: rgba(2, 132, 199, 0.28);
      --yellow: #d97706;
      --yellow-bg: rgba(217, 119, 6, 0.1);
      --yellow-border: rgba(217, 119, 6, 0.28);
      --peach: #ea580c;
      --pink: #e11d48;
      --pink-bg: rgba(225, 29, 72, 0.1);
      --pink-border: rgba(225, 29, 72, 0.28);
      --mauve: #7c3aed;
      --mauve-bg: rgba(124, 58, 237, 0.1);
      --blue: #2563eb;
      --blue-bg: rgba(37, 99, 235, 0.1);
      --blue-border: rgba(37, 99, 235, 0.28);

      --glow-text-green: none;
      --glow-text-teal: none;
      --glow-text-pink: none;
      --glow-text-yellow: none;
      --card-shadow: 0 1px 3px rgba(15, 23, 42, 0.06), 0 1px 2px rgba(15, 23, 42, 0.04);

      --bar-bg: rgba(255, 255, 255, 0.94);
      --map-tile-filter: contrast(1.02) saturate(0.9);
      --map-bg: #e2e8f0;
      --marker-tag-bg: rgba(255, 255, 255, 0.96);
      --marker-tag-border: #94a3b8;
      --marker-tag-text: #0f172a;
      --modal-card-bg: #ffffff;
      --modal-overlay-bg: rgba(15, 23, 42, 0.55);
    }

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html, body {
      background: var(--crust);
      color: var(--text);
      font-family: var(--mono);
      font-size: 12.5px;
      line-height: 1.5;
      font-variant-numeric: tabular-nums;
      -webkit-font-smoothing: antialiased;
    }

    a {
      color: var(--teal);
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }

    /* ── Sticky Top Terminal Bar (.bar) ──────────────────── */
    .bar {
      position: sticky;
      top: 0;
      z-index: 1000;
      background: var(--bar-bg);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--line);
      padding: 8px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      font-size: 11.5px;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
    }
    .bar-left {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      color: var(--text-hi);
      letter-spacing: 0.5px;
    }
    .bar-mid {
      display: flex;
      align-items: center;
      gap: 16px;
      color: var(--subtext);
    }
    .bar-right {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
      display: inline-block;
      animation: pulse-ring 2s infinite;
    }
    .pulse-dot.pulse-dot-paused {
      background: var(--yellow) !important;
      box-shadow: 0 0 8px var(--yellow) !important;
      animation: none !important;
    }
    @keyframes pulse-ring {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.3); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    /* ── Terminal Buttons (.tui-btn) ─────────────────────── */
    .tui-btn {
      font-family: var(--mono);
      font-size: 11px;
      padding: 4px 10px;
      border: 1px solid var(--line-hi);
      background: var(--panel);
      color: var(--text);
      border-radius: 3px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.12s ease;
      white-space: nowrap;
    }
    .tui-btn:hover {
      background: var(--surface);
      border-color: var(--teal);
      color: var(--text-hi);
      box-shadow: 0 0 10px rgba(0, 229, 255, 0.2);
    }
    .tui-btn.active {
      background: rgba(0, 229, 255, 0.12);
      border-color: var(--teal);
      color: var(--teal);
      font-weight: 700;
      box-shadow: 0 0 12px rgba(0, 229, 255, 0.28);
    }

    /* ── Main Container ──────────────────────────────────── */
    .wrap {
      max-width: var(--col);
      margin: 0 auto;
      padding: 18px 20px 60px;
    }

    /* ── Masthead with ASCII Wordmark & Spec Datasheet ───── */
    .masthead {
      display: grid;
      grid-template-columns: 1.25fr 1fr;
      gap: 24px;
      align-items: start;
      margin: 10px 0 20px;
    }
    @media (max-width: 1080px) {
      .masthead { grid-template-columns: 1fr; gap: 16px; }
    }

    .wordmark {
      margin: 0 0 10px;
      font-family: var(--mono);
      font-weight: 700;
      font-size: clamp(5px, 0.76vw, 8.5px);
      line-height: 1.15;
      white-space: pre;
      color: var(--text);
      overflow-x: auto;
      scrollbar-width: none;
    }
    .wordmark .hl { color: var(--green); text-shadow: var(--glow-text-green); }
    .wordmark .sub { color: var(--teal); text-shadow: var(--glow-text-teal); }

    .lede {
      color: var(--subtext);
      font-size: 12.5px;
      margin: 0 0 4px;
    }
    .lede.tight {
      color: var(--overlay);
      font-size: 11.5px;
    }

    /* ── System Specification HUD (.spec-card) ───────────── */
    .spec-card {
      background: var(--base);
      border: 1px solid var(--line);
      border-radius: 4px;
      box-shadow: var(--card-shadow);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .spec-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 7px 12px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: var(--text-hi);
    }
    .spec-grid {
      display: flex;
      flex-direction: column;
    }
    .spec-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 7px 12px;
      border-bottom: 1px solid var(--line);
      transition: background 0.12s ease;
      font-size: 11.5px;
    }
    .spec-row:last-child {
      border-bottom: none;
    }
    .spec-row:hover {
      background: var(--surface);
    }
    .spec-meta {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: 100px;
      flex-shrink: 0;
    }
    .spec-icon {
      font-size: 13px;
      line-height: 1;
    }
    .spec-key {
      font-size: 10.5px;
      font-weight: 700;
      letter-spacing: 0.8px;
      color: var(--overlay);
      text-transform: uppercase;
    }
    .spec-body {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-width: 0;
    }
    .spec-val {
      color: var(--text);
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .spec-pill {
      font-size: 9.5px;
      font-weight: 700;
      letter-spacing: 0.5px;
      padding: 1px 6px;
      border-radius: 3px;
      white-space: nowrap;
      flex-shrink: 0;
      border: 1px solid transparent;
    }
    .spec-pill-teal {
      background: var(--teal-bg);
      border-color: var(--teal-border);
      color: var(--teal);
    }
    .spec-pill-green {
      background: var(--green-bg);
      border-color: var(--green-border);
      color: var(--green);
    }
    .spec-pill-yellow {
      background: var(--yellow-bg);
      border-color: var(--yellow-border);
      color: var(--yellow);
    }
    .spec-pill-mauve {
      background: var(--mauve-bg);
      border-color: rgba(179, 136, 255, 0.3);
      color: var(--mauve);
    }
    @media (max-width: 640px) {
      .spec-row {
        flex-direction: column;
        align-items: flex-start;
        gap: 4px;
      }
      .spec-body {
        width: 100%;
        flex-wrap: wrap;
      }
    }

    /* ── Sources Ribbon ──────────────────────────────────── */
    .sources-ribbon {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      background: var(--base);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 7px 12px;
      font-size: 11px;
      color: var(--subtext);
      margin-bottom: 20px;
    }
    .source-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--panel);
      border: 1px solid var(--line-hi);
      padding: 2px 7px;
      border-radius: 3px;
      color: var(--text);
      font-size: 11px;
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
    }
    .source-tag:hover {
      border-color: var(--teal);
      color: var(--teal);
      transform: translateY(-1px);
    }
    .source-tag.active {
      background: rgba(34, 211, 238, 0.15);
      border-color: var(--teal);
      color: var(--teal);
      font-weight: 700;
      box-shadow: 0 0 8px rgba(34, 211, 238, 0.25);
    }

    /* ── Section Headings (.head) ────────────────────────── */
    .head {
      display: flex;
      align-items: baseline;
      gap: 12px;
      margin: 24px 0 10px;
    }
    .head h2 {
      font-size: 11.5px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--teal);
      margin: 0;
      font-weight: 700;
      white-space: nowrap;
      text-shadow: var(--glow-text-teal);
    }
    .head .rule {
      flex: 1;
      height: 1px;
      background: var(--line);
    }
    .head .cmd {
      color: var(--overlay);
      font-size: 11px;
      white-space: nowrap;
    }

    /* ── Terminal Window Frame (.term) ───────────────────── */
    .term {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 4px;
      overflow: hidden;
      margin-bottom: 20px;
      box-shadow: var(--card-shadow);
    }
    .term .cap {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      padding: 7px 12px;
      border-bottom: 1px solid var(--line);
      font-size: 11px;
      color: var(--subtext);
      background: var(--base);
    }
    .term .cap span:first-child {
      color: var(--text);
      font-weight: 600;
    }

    /* ── Section 01: KPI Spec Cards ──────────────────────── */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .kpi-card {
      border: 1px solid var(--line);
      background: var(--base);
      border-radius: 4px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
      box-shadow: var(--card-shadow);
      transition: all 0.15s ease;
    }
    .kpi-card:hover {
      border-color: var(--line-hi);
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
    }
    .kpi-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .kpi-label {
      font-size: 10.5px;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: var(--overlay);
      font-weight: 600;
    }
    .kpi-val {
      font-size: 26px;
      font-weight: 700;
      color: var(--text-hi);
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }
    .kpi-meter {
      font-size: 11px;
      color: var(--subtext);
      font-weight: 500;
      letter-spacing: 0.5px;
    }
    .kpi-sub {
      font-size: 11px;
      color: var(--overlay);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .tui-tag {
      display: inline-flex;
      align-items: center;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 10.5px;
      font-weight: 600;
      border: 1px solid transparent;
      white-space: nowrap;
      line-height: 1.4;
    }
    .tag-pink {
      background: var(--pink-bg);
      border-color: var(--pink-border);
      color: var(--pink);
      text-shadow: var(--glow-text-pink);
    }
    .tag-yellow {
      background: var(--yellow-bg);
      border-color: var(--yellow-border);
      color: var(--yellow);
      text-shadow: var(--glow-text-yellow);
    }
    .tag-green {
      background: var(--green-bg);
      border-color: var(--green-border);
      color: var(--green);
      text-shadow: var(--glow-text-green);
    }
    .tag-teal {
      background: var(--teal-bg);
      border-color: var(--teal-border);
      color: var(--teal);
      text-shadow: var(--glow-text-teal);
    }

    /* ── Section 02: World Map & Detection Layout ────────── */
    .map-body {
      display: grid;
      grid-template-columns: 1fr 340px;
      min-height: 420px;
    }
    @media (max-width: 1024px) {
      .map-body { grid-template-columns: 1fr; }
    }
    .map-stage {
      position: relative;
      background: var(--crust);
      overflow: hidden;
      border-right: 1px solid var(--line);
    }
    @media (max-width: 1024px) {
      .map-stage { border-right: none; border-bottom: 1px solid var(--line); }
    }
    #ascii-map-container {
      position: relative;
      width: 100%;
      height: 420px;
    }
    #ascii-matrix-canvas {
      width: 100%;
      height: 100%;
      display: block;
    }
    #osm-map-container {
      position: relative;
      width: 100%;
      height: 420px;
    }
    #leaflet-map {
      width: 100%;
      height: 430px;
      background: var(--map-bg) !important;
    }

    /* OSM Dark Inversion Filter for Retro Terminal Map */
    .leaflet-tile-pane {
      filter: var(--map-tile-filter);
    }
    .leaflet-container {
      font-family: var(--mono) !important;
    }
    .leaflet-popup-content-wrapper, .leaflet-popup-tip {
      background: var(--base) !important;
      color: var(--text) !important;
      border: 1px solid var(--line) !important;
      border-radius: 4px !important;
      box-shadow: 0 4px 16px rgba(0,0,0,0.6) !important;
    }

    /* Leaflet Div Icon Markers */
    .soc-marker-wrap {
      position: relative;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
    }
    .soc-marker-ring {
      position: absolute;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      border: 1.5px solid var(--green);
      animation: pulse-ring 2.2s infinite ease-out;
    }
    .soc-marker-core {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
      z-index: 2;
    }
    .soc-marker-label {
      position: absolute;
      top: 24px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--marker-tag-bg);
      border: 1px solid var(--marker-tag-border);
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 10px;
      font-weight: 600;
      white-space: nowrap;
      color: var(--marker-tag-text);
      pointer-events: none;
      box-shadow: 0 2px 8px rgba(0,0,0,0.18);
    }

    /* ASCII Tooltip Floating Box */
    .ascii-tip {
      position: absolute;
      display: none;
      pointer-events: none;
      z-index: 200;
      background: var(--panel);
      border: 1px solid var(--line-hi);
      padding: 8px 12px;
      border-radius: 3px;
      font-size: 11px;
      line-height: 1.45;
      color: var(--text-hi);
      box-shadow: 0 6px 20px rgba(0,0,0,0.25);
      white-space: pre;
    }

    /* Map Sidebar */
    .map-sidebar {
      background: var(--base);
      display: flex;
      flex-direction: column;
      max-height: 420px;
    }
    .map-sidebar-title {
      padding: 9px 14px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      color: var(--overlay);
    }
    .map-countries-list {
      flex: 1;
      overflow-y: auto;
      padding: 6px;
    }
    .map-country-item {
      padding: 7px 10px;
      border-radius: 3px;
      border: 1px solid transparent;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      gap: 3px;
      transition: all 0.12s ease;
      margin-bottom: 4px;
    }
    .map-country-item:hover {
      background: var(--panel);
      border-color: var(--line);
    }
    .map-country-item.active {
      background: var(--surface);
      border-color: var(--teal);
    }

    /* ── Section 03: Telemetry Dynamics (Timeline & Donut) ── */
    .charts-grid {
      display: grid;
      grid-template-columns: 2fr 1.1fr;
      gap: 16px;
      margin-bottom: 20px;
    }
    @media (max-width: 1024px) {
      .charts-grid { grid-template-columns: 1fr; }
    }
    .chart-card {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 4px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      box-shadow: var(--card-shadow);
    }
    .card-cap {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--base);
      font-size: 11px;
      color: var(--subtext);
    }
    .card-cap span:first-child {
      color: var(--text);
      font-weight: 600;
    }

    .timeline-container {
      position: relative;
      height: 240px;
      padding: 10px;
      background: var(--panel);
    }
    .timeline-svg {
      width: 100%;
      height: 100%;
      overflow: visible;
    }
    .timeline-legend {
      display: flex;
      gap: 12px;
      font-size: 11px;
    }
    .legend-item {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      cursor: pointer;
      user-select: none;
      color: var(--subtext);
    }
    .legend-item.dimmed {
      opacity: 0.35;
    }
    .chart-tooltip {
      position: absolute;
      display: none;
      pointer-events: none;
      transform: translateX(-50%);
      background: var(--base);
      border: 1px solid var(--line-hi);
      padding: 4px 10px;
      border-radius: 3px;
      font-size: 11px;
      color: var(--text);
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      white-space: nowrap;
      z-index: 10;
    }

    /* Donut Threat Ratio */
    .donut-wrap {
      display: flex;
      align-items: center;
      justify-content: space-around;
      padding: 14px 10px;
    }
    .donut-svg {
      width: 110px;
      height: 110px;
      transform: rotate(-90deg);
    }
    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11.5px;
    }

    .rules-list {
      padding: 8px 14px 14px;
      display: flex;
      flex-direction: column;
      gap: 7px;
    }
    .rule-item {
      padding: 5px 8px;
      border: 1px solid var(--line);
      background: var(--base);
      border-radius: 3px;
    }
    .rule-meta {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      margin-bottom: 4px;
    }
    .rule-name {
      color: var(--text);
      font-weight: 500;
    }
    .rule-count {
      color: var(--overlay);
    }
    .rule-bar-wrap {
      height: 4px;
      background: var(--surface);
      border-radius: 2px;
      overflow: hidden;
    }
    .rule-bar-fill {
      height: 100%;
      background: var(--pink);
      border-radius: 2px;
    }

    /* ── Section 04: Intelligence Vectors Grid ───────────── */
    .intel-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 20px;
    }
    @media (max-width: 1080px) {
      .intel-grid { grid-template-columns: 1fr; }
    }
    .intel-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11.5px;
      white-space: nowrap;
    }
    .threat-breakdown-cell {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
    }
    .intel-table th {
      text-align: left;
      padding: 7px 10px;
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--overlay);
      border-bottom: 1px solid var(--line);
      background: var(--base);
      font-weight: 600;
    }
    .intel-table td {
      padding: 7px 10px;
      border-bottom: 1px solid var(--line);
      color: var(--text);
    }
    .intel-table tr:hover td {
      background: var(--surface);
    }

    /* ── Section 05: Real-Time SOC Stream Table ──────────── */
    .console-toolbar {
      padding: 10px 14px;
      background: var(--base);
      border-bottom: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    /* ── Cyber SOC Filter Console Toolbar ─────────────── */
    .console-toolbar {
      padding: 10px 14px;
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .console-hud-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .prompt-row {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 11.5px;
      background: var(--base);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 5px 10px;
      box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.08);
      max-width: 100%;
      overflow: hidden;
    }
    .prompt-user {
      color: var(--green);
      font-weight: 700;
      letter-spacing: 0.3px;
      user-select: none;
      flex-shrink: 0;
    }
    .prompt-cmd {
      color: var(--teal);
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .prompt-cursor {
      color: var(--green);
      font-size: 10px;
      animation: blinkCursor 1s step-end infinite;
      flex-shrink: 0;
    }
    @keyframes blinkCursor {
      0%, 100% { opacity: 1; }
      50% { opacity: 0; }
    }

    /* Verdict Tabs (Segmented Control) */
    .filter-tabs {
      display: inline-flex;
      align-items: center;
      background: var(--base);
      border: 1px solid var(--line-hi);
      border-radius: 4px;
      padding: 2px;
      gap: 2px;
    }
    .tab-btn {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 500;
      background: transparent;
      border: 1px solid transparent;
      border-radius: 3px;
      padding: 4px 9px;
      color: var(--subtext);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.14s ease;
      user-select: none;
    }
    .tab-btn:hover {
      background: var(--surface-hi);
      color: var(--text-hi);
    }
    .tab-count {
      font-size: 10px;
      font-weight: 700;
      padding: 1px 5px;
      border-radius: 10px;
      background: var(--surface-hi);
      color: var(--overlay);
      line-height: 1.2;
    }
    .tab-btn.active {
      background: var(--surface);
      color: var(--text-hi);
      border-color: var(--line-hi);
      font-weight: 700;
    }
    .tab-btn[data-filter-verdict="ALL"].active {
      color: var(--teal);
      border-color: var(--teal-border);
      background: var(--teal-bg);
    }
    .tab-btn[data-filter-verdict="ALL"].active .tab-count {
      background: var(--teal);
      color: var(--crust);
    }
    .tab-btn[data-filter-verdict="BLOCK"].active {
      color: var(--pink);
      border-color: var(--pink-border);
      background: var(--pink-bg);
    }
    .tab-btn[data-filter-verdict="BLOCK"].active .tab-count {
      background: var(--pink);
      color: #ffffff;
    }
    .tab-btn[data-filter-verdict="TARPIT"].active {
      color: var(--yellow);
      border-color: var(--yellow-border);
      background: var(--yellow-bg);
    }
    .tab-btn[data-filter-verdict="TARPIT"].active .tab-count {
      background: var(--yellow);
      color: #000000;
    }
    .tab-btn[data-filter-verdict="ALLOW"].active {
      color: var(--green);
      border-color: var(--green-border);
      background: var(--green-bg);
    }
    .tab-btn[data-filter-verdict="ALLOW"].active .tab-count {
      background: var(--green);
      color: var(--crust);
    }

    /* Filters Matrix: Controls Grid */
    .filters-matrix {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }
    .filter-item {
      position: relative;
      display: inline-flex;
      align-items: center;
    }
    .filter-select {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 500;
      height: 30px;
      background-color: var(--base);
      border: 1px solid var(--line-hi);
      color: var(--text);
      padding: 0 28px 0 10px;
      border-radius: 4px;
      outline: none;
      transition: all 0.15s ease;
      cursor: pointer;
      appearance: none;
      -webkit-appearance: none;
      -moz-appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath fill='none' stroke='%238892b0' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round' d='M1 1l4 4 4-4'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 9px center;
    }
    [data-theme="light"] .filter-select {
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath fill='none' stroke='%23475569' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round' d='M1 1l4 4 4-4'/%3E%3C/svg%3E");
    }
    .filter-select:hover {
      border-color: var(--overlay);
      background-color: var(--surface);
    }
    .filter-select:focus {
      border-color: var(--teal);
      box-shadow: 0 0 0 2px var(--teal-bg);
      color: var(--text-hi);
    }
    .filter-select.filter-active {
      border-color: var(--teal);
      color: var(--teal);
      font-weight: 600;
      background-color: var(--teal-bg);
    }
    input[type="datetime-local"].filter-select {
      color-scheme: dark;
    }
    [data-theme="light"] input[type="datetime-local"].filter-select {
      color-scheme: light;
    }

    /* Enhanced Search Box */
    .search-wrap {
      flex: 1;
      min-width: 220px;
      position: relative;
      display: flex;
      align-items: center;
    }
    .search-icon {
      position: absolute;
      left: 9px;
      font-size: 11px;
      color: var(--overlay);
      pointer-events: none;
      line-height: 1;
    }
    .search-box {
      width: 100%;
      height: 30px;
      font-family: var(--mono);
      font-size: 11px;
      background: var(--base);
      border: 1px solid var(--line-hi);
      color: var(--text);
      padding: 0 46px 0 28px;
      border-radius: 4px;
      outline: none;
      transition: all 0.15s ease;
    }
    .search-box:hover {
      border-color: var(--overlay);
    }
    .search-box:focus {
      border-color: var(--teal);
      box-shadow: 0 0 0 2px var(--teal-bg);
      color: var(--text-hi);
    }
    .search-kbd-hint {
      position: absolute;
      right: 8px;
      font-family: var(--mono);
      font-size: 9.5px;
      color: var(--overlay);
      background: var(--surface-hi);
      border: 1px solid var(--line-hi);
      padding: 1px 5px;
      border-radius: 3px;
      pointer-events: none;
      line-height: 1.2;
    }
    .search-clear-btn {
      position: absolute;
      right: 26px;
      background: none;
      border: none;
      color: var(--overlay);
      font-size: 14px;
      line-height: 1;
      cursor: pointer;
      padding: 4px;
      border-radius: 50%;
    }
    .search-clear-btn:hover {
      color: var(--pink);
    }

    /* Active Filter Chips Bar */
    .active-chips-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 11px;
      padding-top: 4px;
      border-top: 1px dashed var(--line);
    }
    .active-chips-label {
      color: var(--overlay);
      font-weight: 700;
      font-size: 10px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .filter-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--base);
      border: 1px solid var(--line-hi);
      padding: 3px 8px;
      border-radius: 3px;
      color: var(--text-hi);
      font-weight: 600;
      font-size: 10.5px;
      box-shadow: var(--card-shadow);
      transition: all 0.12s ease;
    }
    .filter-chip:hover {
      border-color: var(--teal);
    }
    .chip-close {
      cursor: pointer;
      color: var(--overlay);
      font-size: 13px;
      line-height: 1;
      transition: color 0.12s ease;
    }
    .chip-close:hover {
      color: var(--pink);
    }
    .btn-clear-all {
      font-family: var(--mono);
      background: var(--pink-bg);
      border: 1px solid var(--pink-border);
      color: var(--pink);
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.5px;
      cursor: pointer;
      padding: 3px 8px;
      border-radius: 3px;
      transition: all 0.12s ease;
    }
    .btn-clear-all:hover {
      background: var(--pink);
      color: #ffffff;
    }

    .table-container {
      max-height: 480px;
      overflow-y: auto;
      overflow-x: auto;
      background: var(--panel);
    }
    .soc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11.5px;
      white-space: nowrap;
    }
    .soc-table th {
      position: sticky;
      top: 0;
      z-index: 5;
      text-align: left;
      padding: 8px 12px;
      font-size: 10.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--overlay);
      background: var(--base);
      border-bottom: 1px solid var(--line);
      font-weight: 600;
    }
    .soc-table td {
      padding: 7px 12px;
      border-bottom: 1px solid var(--line);
      color: var(--text);
    }
    .soc-table tr {
      cursor: pointer;
      transition: background 0.1s ease;
    }
    .soc-table tr:hover td {
      background: var(--surface);
    }

    /* ── Terminal Table Pagination Bar ───────────────────── */
    .table-pagination-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 9px 14px;
      background: var(--base);
      border-top: 1px solid var(--line-hi);
      font-size: 11px;
      font-family: var(--mono);
      color: var(--text);
      flex-wrap: wrap;
      gap: 10px;
    }
    .pagination-left, .pagination-nav {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .pagination-label {
      color: var(--overlay);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .pagination-select {
      background: var(--panel);
      color: var(--text-hi);
      border: 1px solid var(--line-hi);
      padding: 3px 8px;
      border-radius: 3px;
      font-family: var(--mono);
      font-size: 11px;
      cursor: pointer;
    }
    .pagination-select:focus {
      outline: none;
      border-color: var(--teal);
    }
    .pagination-info {
      color: var(--subtext);
      font-size: 11px;
      margin-left: 6px;
    }
    .pagination-btn {
      padding: 3px 9px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--mono);
    }
    .pagination-btn:disabled {
      opacity: 0.35;
      cursor: not-allowed;
      border-color: var(--line) !important;
      box-shadow: none !important;
    }
    .pagination-page-indicator {
      display: flex;
      align-items: center;
      gap: 5px;
      color: var(--subtext);
      font-size: 11px;
      margin: 0 4px;
    }
    .pagination-page-input {
      width: 44px;
      text-align: center;
      background: var(--panel);
      border: 1px solid var(--line-hi);
      color: var(--text-hi);
      font-family: var(--mono);
      font-size: 11px;
      padding: 2px 4px;
      border-radius: 3px;
    }
    .pagination-page-input:focus {
      outline: none;
      border-color: var(--teal);
    }


    /* Retro Bracket Badges with Cyber Glow */
    .bracket-badge {
      font-weight: 700;
      letter-spacing: 0.5px;
      font-size: 11px;
      display: inline-block;
      padding: 1px 7px;
      border-radius: 3px;
    }
    .verdict-allow {
      color: var(--green);
      background: var(--green-bg);
      border: 1px solid var(--green-border);
      text-shadow: var(--glow-text-green);
    }
    .verdict-block {
      color: var(--pink);
      background: var(--pink-bg);
      border: 1px solid var(--pink-border);
      text-shadow: var(--glow-text-pink);
    }
    .verdict-tarpit {
      color: var(--yellow);
      background: var(--yellow-bg);
      border: 1px solid var(--yellow-border);
      text-shadow: var(--glow-text-yellow);
    }

    .badge-method {
      padding: 1px 5px;
      border-radius: 3px;
      font-weight: 600;
      font-size: 10px;
      border: 1px solid var(--line-hi);
    }
    .method-get { color: var(--teal); background: var(--teal-bg); border-color: var(--teal-border); }
    .method-post { color: var(--blue); background: var(--blue-bg); border-color: var(--blue-border); }
    .method-put { color: var(--yellow); background: var(--yellow-bg); border-color: var(--yellow-border); }
    .method-delete { color: var(--pink); background: var(--pink-bg); border-color: var(--pink-border); }

    .ip-clickable {
      cursor: pointer;
      color: var(--teal);
    }
    .ip-clickable:hover {
      text-decoration: underline;
    }
    .rule-tag {
      display: inline-flex;
      align-items: center;
      color: var(--pink);
      padding: 1px 6px;
      border-radius: 3px;
      border: 1px solid var(--pink-border);
      background: var(--pink-bg);
      font-size: 10.5px;
      text-shadow: var(--glow-text-pink);
    }

    /* ── Inspector Modals ────────────────────────────────── */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: var(--modal-overlay-bg);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: none;
      justify-content: center;
      align-items: center;
      z-index: 2000;
      padding: 20px;
    }
    .modal-card {
      background: var(--modal-card-bg);
      border: 1px solid var(--line-hi);
      border-radius: 4px;
      width: 100%;
      max-width: 820px;
      max-height: 85vh;
      overflow-y: auto;
      box-shadow: 0 16px 48px rgba(0,0,0,0.8);
      display: flex;
      flex-direction: column;
    }
    .ip-modal-card {
      background: var(--modal-card-bg);
      border: 1px solid var(--line-hi);
      border-radius: 8px;
      width: 100%;
      max-width: 880px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 60px rgba(0,0,0,0.85);
      display: flex;
      flex-direction: column;
    }
    .modal-header {
      padding: 12px 18px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .modal-title {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: var(--text-hi);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .modal-close {
      cursor: pointer;
      color: var(--overlay);
      font-size: 20px;
      line-height: 1;
      padding: 4px;
      transition: color 0.15s ease;
    }
    .modal-close:hover {
      color: var(--pink);
    }
    .modal-body {
      padding: 16px;
      font-size: 12px;
      line-height: 1.6;
    }

    /* Redesigned IP Details & Threat Report */
    .ip-header-banner {
      padding: 16px 20px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
    }
    .ip-title-address {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 20px;
      font-weight: 800;
      color: var(--teal);
      letter-spacing: 0.5px;
    }
    .ip-geo-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--surface);
      border: 1px solid var(--line-hi);
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 11.5px;
      color: var(--text);
      font-weight: 500;
    }
    .ip-org-text {
      font-size: 11.5px;
      color: var(--subtext);
    }

    /* Risk Status Alert Banner */
    .ip-risk-card {
      margin: 16px 20px 0;
      padding: 12px 16px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .ip-risk-card.risk-high {
      background: rgba(255, 51, 102, 0.1);
      border: 1px solid var(--pink-border);
    }
    .ip-risk-card.risk-med {
      background: rgba(255, 184, 0, 0.1);
      border: 1px solid rgba(255, 184, 0, 0.4);
    }
    .ip-risk-card.risk-safe {
      background: rgba(0, 255, 157, 0.08);
      border: 1px solid var(--green-border);
    }
    .risk-left {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .risk-icon {
      font-size: 22px;
      line-height: 1;
    }
    .risk-title {
      font-size: 12.5px;
      font-weight: 700;
      letter-spacing: 0.3px;
    }
    .risk-high .risk-title { color: var(--pink); }
    .risk-med .risk-title { color: var(--yellow); }
    .risk-safe .risk-title { color: var(--green); }
    .risk-desc {
      font-size: 11px;
      color: var(--subtext);
      margin-top: 2px;
    }

    /* Metric Summary Strip */
    .ip-stat-strip {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      padding: 16px 20px 0;
    }
    @media (max-width: 640px) {
      .ip-stat-strip { grid-template-columns: repeat(2, 1fr); }
    }
    .ip-stat-card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px 14px;
    }
    .ip-stat-label {
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--overlay);
    }
    .ip-stat-val {
      font-size: 18px;
      font-weight: 800;
      color: var(--text-hi);
      margin: 4px 0 2px;
    }
    .ip-stat-sub {
      font-size: 10px;
      color: var(--subtext);
    }

    /* Two-Column Information Details */
    .ip-intel-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      padding: 16px 20px;
    }
    @media (max-width: 720px) {
      .ip-intel-grid { grid-template-columns: 1fr; }
    }
    .ip-box {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 6px;
      padding: 14px;
    }
    .ip-box-title {
      font-size: 11.5px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: var(--text-hi);
      margin-bottom: 10px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .ip-kv-row {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      font-size: 11.5px;
      padding: 5px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }
    .ip-kv-label {
      color: var(--overlay);
      font-weight: 500;
      flex-shrink: 0;
    }
    .ip-kv-val {
      color: var(--text);
      font-weight: 500;
      text-align: right;
      word-break: break-word;
    }

    /* Recent Requests from IP */
    .ip-recent-box {
      margin: 0 20px 16px;
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 6px;
      padding: 14px;
    }
    .ip-recent-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
      margin-top: 6px;
    }
    .ip-recent-table th {
      text-align: left;
      padding: 6px 8px;
      color: var(--overlay);
      font-weight: 600;
      border-bottom: 1px solid var(--line);
    }
    .ip-recent-table td {
      padding: 6px 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }

    /* Abuse Reporting Section */
    .abuse-section {
      padding: 16px 20px 20px;
      border-top: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .abuse-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 12px;
    }
    .abuse-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--pink);
      letter-spacing: 0.5px;
    }
    .abuse-desc {
      font-size: 11px;
      color: var(--subtext);
      margin-top: 3px;
      max-width: 520px;
      line-height: 1.4;
    }
    .abuse-actions-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .abuse-report-card {
      background: var(--crust);
      border: 1px solid var(--line-hi);
      border-radius: 6px;
      overflow: hidden;
    }
    .abuse-report-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--line);
      font-size: 11px;
      color: var(--subtext);
      font-weight: 600;
    }
    .abuse-report-textarea {
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.5;
      background: transparent;
      border: none;
      color: var(--text);
      padding: 12px;
      width: 100%;
      height: 140px;
      resize: vertical;
      outline: none;
      box-sizing: border-box;
    }
    .abuse-footer-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }
    .abuse-email-hint {
      font-size: 11px;
      color: var(--subtext);
    }

    /* ── Terminal Keybindings Status Bar ─────────────────── */
    .tui-footer {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: var(--base);
      border-top: 1px solid var(--line);
      padding: 5px 18px;
      font-size: 11px;
      color: var(--overlay);
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 900;
    }
    .footer-keys {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }
    .footer-key-item {
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .key-cap {
      background: var(--panel);
      border: 1px solid var(--line-hi);
      color: var(--teal);
      padding: 0 4px;
      border-radius: 2px;
      font-weight: 700;
      font-size: 10px;
    }

    /* ═══════════════════════════════════════════════════════════════
       Mobile & Tablet Responsive Optimizations (< 768px, < 480px)
       ═══════════════════════════════════════════════════════════════ */
    .soc-section {
      position: relative;
      margin-bottom: 24px;
    }
    .mobile-section-nav {
      display: none;
    }

    @media (max-width: 768px) {
      /* Mobile Viewport Spacing */
      .wrap {
        padding: 8px 10px 40px !important;
      }

      /* Compact Sticky Topbar */
      .bar {
        padding: 7px 10px !important;
        gap: 8px !important;
        flex-wrap: wrap !important;
      }
      .bar-left {
        gap: 8px !important;
        font-size: 11px !important;
      }
      .bar-mid {
        display: none !important; /* Hide verbose clock/live text in sticky bar on mobile */
      }
      .bar-right {
        gap: 5px !important;
      }
      .tui-btn {
        padding: 5px 8px !important;
        font-size: 10.5px !important;
        min-height: 32px !important;
      }

      /* Sticky Section Quick-Jump Ribbon */
      .mobile-section-nav {
        display: flex !important;
        align-items: center;
        gap: 6px;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: none;
        padding: 8px 4px 10px;
        margin: 4px 0 16px;
        position: sticky;
        top: 48px;
        z-index: 920;
        background: var(--bar-bg);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border-bottom: 1px solid var(--line);
      }
      .mobile-section-nav::-webkit-scrollbar {
        display: none;
      }
      .mobile-nav-chip {
        flex-shrink: 0;
        font-family: var(--mono);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.6px;
        padding: 5px 10px;
        border-radius: 4px;
        background: var(--panel);
        border: 1px solid var(--line-hi);
        color: var(--subtext);
        text-decoration: none;
        transition: all 0.15s ease;
        white-space: nowrap;
        -webkit-tap-highlight-color: transparent;
      }
      .mobile-nav-chip:hover, .mobile-nav-chip:active {
        color: var(--teal);
        border-color: var(--teal);
      }
      .mobile-nav-chip.active {
        background: var(--teal-bg);
        border-color: var(--teal);
        color: var(--teal);
        box-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
      }

      /* Section Segregation Containers & Dividers */
      .soc-section {
        margin-bottom: 28px !important;
        scroll-margin-top: 104px; /* Offset for sticky topbar + mobile nav strip */
      }
      .soc-section:not(:last-child)::after {
        content: "";
        display: block;
        height: 1px;
        margin-top: 26px;
        background: linear-gradient(90deg, transparent, var(--line-hi), transparent);
      }

      /* Prominent Cyber Section Header Banners on Mobile */
      .head {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        flex-direction: row !important;
        gap: 8px !important;
        margin: 20px 0 12px !important;
        padding: 8px 12px !important;
        background: var(--panel) !important;
        border: 1px solid var(--line-hi) !important;
        border-left: 4px solid var(--teal) !important;
        border-radius: 4px !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25) !important;
      }
      #sec-kpis .head { border-left-color: var(--teal) !important; }
      #sec-stream .head { border-left-color: var(--pink) !important; }
      #sec-geo .head { border-left-color: var(--yellow) !important; }
      #sec-charts .head { border-left-color: var(--green) !important; }
      #sec-intel .head { border-left-color: var(--peach) !important; }

      .head h2 {
        font-size: 11px !important;
        font-weight: 700 !important;
        letter-spacing: 0.8px !important;
        color: var(--text-hi) !important;
        white-space: normal !important;
        line-height: 1.3 !important;
        margin: 0 !important;
      }
      .head .rule {
        display: none !important;
      }
      .head .cmd {
        font-size: 9.5px !important;
        font-weight: 600 !important;
        color: var(--teal) !important;
        background: var(--teal-bg) !important;
        border: 1px solid var(--teal-border) !important;
        padding: 2px 7px !important;
        border-radius: 3px !important;
        flex-shrink: 0 !important;
      }
      #sec-stream .head .cmd {
        color: var(--pink) !important;
        background: var(--pink-bg) !important;
        border-color: var(--pink-border) !important;
      }
      #sec-geo .head .cmd {
        color: var(--yellow) !important;
        background: var(--yellow-bg) !important;
        border-color: var(--yellow-border) !important;
      }
      #sec-charts .head .cmd {
        color: var(--green) !important;
        background: var(--green-bg) !important;
        border-color: var(--green-border) !important;
      }
      #sec-intel .head .cmd {
        color: var(--peach) !important;
        background: rgba(255, 140, 66, 0.12) !important;
        border-color: rgba(255, 140, 66, 0.35) !important;
      }

      /* Monitored Nodes Ribbon Segregation */
      .sources-ribbon {
        background: var(--panel) !important;
        border: 1px solid var(--line-hi) !important;
        border-left: 3px solid var(--green) !important;
        padding: 8px 12px !important;
        border-radius: 4px !important;
        margin: 12px 0 16px !important;
        gap: 6px !important;
      }

      /* Display ASCII name on mobile with responsive fluid scaling & touch scroll */
      .wordmark {
        display: block !important;
        font-size: clamp(3.4px, 1.05vw, 6px) !important;
        line-height: 1.15 !important;
        white-space: pre !important;
        overflow-x: auto !important;
        -webkit-overflow-scrolling: touch !important;
        scrollbar-width: none !important;
        margin: 6px 0 10px !important;
      }
      .wordmark::-webkit-scrollbar {
        display: none !important;
      }

      /* Masthead Stack */
      .masthead {
        grid-template-columns: 1fr !important;
        gap: 12px !important;
        margin: 6px 0 14px !important;
      }
      .spec-card {
        border-radius: 6px !important;
        border: 1px solid var(--line-hi) !important;
        margin-top: 10px !important;
      }

      /* Hide fixed bottom keyboard shortcuts footer on touch devices */
      .tui-footer {
        display: none !important;
      }

      /* Compact 2-column KPI grid on mobile with distinct borders */
      .kpi-grid {
        grid-template-columns: repeat(2, 1fr) !important;
        gap: 8px !important;
        margin-bottom: 14px !important;
      }
      .kpi-card {
        padding: 9px 10px !important;
        border-radius: 6px !important;
        border: 1px solid var(--line-hi) !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12) !important;
      }
      .kpi-val {
        font-size: 20px !important;
      }
      .kpi-label {
        font-size: 9.5px !important;
      }
      .kpi-meter {
        font-size: 10px !important;
      }

      /* Card Framing for Terminals and Charts */
      .term {
        border-radius: 6px !important;
        border: 1px solid var(--line-hi) !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.2) !important;
      }
      .chart-card {
        margin-bottom: 14px !important;
        border-radius: 6px !important;
        border: 1px solid var(--line-hi) !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.2) !important;
      }

      /* Responsive World Map Stage */
      .map-stage {
        border-right: none !important;
        border-bottom: 1px solid var(--line) !important;
      }
      #osm-map-container, #ascii-map-container, #leaflet-map {
        height: 260px !important;
      }

      /* Responsive Charts */
      .charts-grid {
        grid-template-columns: 1fr !important;
        gap: 12px !important;
      }
      .timeline-container {
        height: 180px !important;
        padding: 6px !important;
      }

      /* Responsive Intelligence Tables */
      .intel-grid {
        grid-template-columns: 1fr !important;
        gap: 12px !important;
      }
      .intel-table th, .intel-table td {
        padding: 6px 8px !important;
        font-size: 10.5px !important;
      }

      /* Responsive Console Toolbar & Filters */
      .console-toolbar {
        padding: 8px 10px !important;
        gap: 8px !important;
      }
      .console-hud-bar {
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 8px !important;
      }
      .prompt-row {
        width: 100% !important;
        box-sizing: border-box !important;
      }
      .filter-tabs {
        width: 100% !important;
        display: flex !important;
      }
      .tab-btn {
        flex: 1 !important;
        justify-content: center !important;
        padding: 6px 4px !important;
        font-size: 10px !important;
      }
      .filters-matrix {
        display: grid !important;
        grid-template-columns: 1fr 1fr !important;
        gap: 6px !important;
        width: 100% !important;
      }
      .filter-item {
        width: 100% !important;
      }
      .filter-select {
        width: 100% !important;
        height: 36px !important;
        font-size: 12px !important;
      }
      .search-wrap {
        grid-column: 1 / -1 !important;
        width: 100% !important;
        min-width: 100% !important;
      }
      .search-box {
        height: 36px !important;
        font-size: 13px !important;
      }

      /* Stream Table Touch Scroll */
      .table-container {
        max-height: 420px !important;
        -webkit-overflow-scrolling: touch !important;
      }
      .soc-table th {
        padding: 7px 9px !important;
        font-size: 9.5px !important;
      }
      .soc-table td {
        padding: 8px 9px !important;
        font-size: 10.5px !important;
      }

      /* Responsive Pagination Bar */
      .table-pagination-bar {
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 8px !important;
        padding: 8px 10px !important;
      }
      .pagination-left, .pagination-nav {
        justify-content: space-between !important;
        width: 100% !important;
      }
      .pagination-btn {
        padding: 6px 10px !important;
        min-height: 34px !important;
      }

      /* Mobile Modal Bottom-Sheet Styling */
      .modal-overlay {
        padding: 10px 6px 0 !important;
        align-items: flex-end !important;
      }
      .modal-card, .ip-modal-card {
        max-width: 100% !important;
        max-height: 94vh !important;
        border-radius: 8px 8px 0 0 !important;
        margin: 0 !important;
      }
      .modal-header, .ip-header-banner {
        padding: 10px 12px !important;
      }
      .ip-title-address {
        font-size: 15px !important;
      }
      .ip-intel-grid {
        grid-template-columns: 1fr !important;
        gap: 10px !important;
        padding: 10px !important;
      }
    }

    @media (max-width: 480px) {
      .filters-matrix {
        grid-template-columns: 1fr !important;
      }
      .kpi-grid {
        grid-template-columns: 1fr 1fr !important;
        gap: 6px !important;
      }
      .kpi-card {
        padding: 7px 8px !important;
      }
      .kpi-val {
        font-size: 18px !important;
      }
      .bar-left span {
        font-size: 12px !important;
      }
    }
  </style>
</head>
<body>

<!-- ── Sticky Top Terminal Bar ─────────────────────────────── -->
<div class="bar">
  <div class="bar-left">
    <div style="display:flex; align-items:center; gap:8px;">
      <img src="/icon.svg" alt="RouteWarden Logo" style="width:17px; height:17px; border-radius:3px; display:inline-block; vertical-align:middle; filter:drop-shadow(0 0 5px rgba(56, 189, 248, 0.45));">
      <span>ROUTEWARDEN</span>
      <span class="dash-version-badge" style="font-size:10px; color:var(--overlay); font-family:var(--mono); border:1px solid var(--line-hi); padding:1px 5px; border-radius:3px;">v5.0.2</span>
    </div>
    <span id="auth-status-badge" style="display:none; font-size:10px; padding:2px 7px; border-radius:3px; background:rgba(34,211,238,0.12); border:1px solid var(--teal); color:var(--teal); font-weight:700;">🔒 AUTH</span>
    <button class="tui-btn" id="btn-logout" style="display:none; padding:2px 7px; font-size:10px; color:var(--pink); border-color:var(--pink-border); background:var(--pink-bg);" onclick="logoutDashboard()" title="Sign out of console">🚪 Sign Out</button>
  </div>
  <div class="bar-mid">
    <div style="display:flex; align-items:center; gap:6px;">
      <span class="pulse-dot" id="stream-pulse-dot"></span>
      <span id="stream-status" style="color:var(--green); font-weight:600;">LIVE STREAM</span>
    </div>
    <span style="color:var(--line-hi);">|</span>
    <span id="utc-clock">00:00:00</span>
  </div>
  <div class="bar-right">
    <button class="tui-btn" id="btn-toggle-theme" onclick="toggleTheme()" title="Toggle Theme (System / Light / Dark)">
      <span id="theme-btn-icon">🌓</span> <span id="theme-btn-text">AUTO</span>
    </button>
    <button class="tui-btn" id="btn-toggle-scroll" onclick="toggleStreamPause()">⏸ Pause</button>
    <button class="tui-btn" id="btn-export-json">📥 Export</button>
  </div>
</div>

<div class="wrap">
  <!-- ── Masthead with ASCII Wordmark & Spec Datasheet ─────── -->
  <header class="masthead">
    <div>
      <pre class="wordmark"><span class="hl">██████╗  ██████╗ ██╗   ██╗████████╗███████╗</span> <span class="sub">██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗</span>
<span class="hl">██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝</span> <span class="sub">██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║</span>
<span class="hl">██████╔╝██║   ██║██║   ██║   ██║   █████╗  </span> <span class="sub">██║ █╗ ██║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║</span>
<span class="hl">██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  </span> <span class="sub">██║███╗██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║</span>
<span class="hl">██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗</span> <span class="sub">╚███╔███╔╝██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║</span>
<span class="hl">╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝</span> <span class="sub"> ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝</span></pre>
      <p class="lede">Real-Time Reverse Proxy Security & Traffic Monitor</p>
      <p class="lede tight">Live traffic monitoring, automated threat defense, and rate limiting.</p>
    </div>

    <div class="spec-card">
      <div class="spec-header">
        <div style="display:flex; align-items:center; gap:6px;">
          <span>⚙️ SYSTEM DETAILS</span>
        </div>
        <span class="tui-tag tag-green">● LIVE MONITORING</span>
      </div>
      <div class="spec-grid">
        <div class="spec-row">
          <div class="spec-meta">
            <span class="spec-icon">🎯</span>
            <span class="spec-key">TARGET</span>
          </div>
          <div class="spec-body">
            <span class="spec-val">Reverse Proxy Security & Live Traffic</span>
            <span class="spec-pill spec-pill-teal">INGRESS</span>
          </div>
        </div>
        <div class="spec-row">
          <div class="spec-meta">
            <span class="spec-icon">⚡</span>
            <span class="spec-key">ENGINE</span>
          </div>
          <div class="spec-body">
            <span class="spec-val">RouteWarden Core v5.0.2 // Traffic & Security Engine</span>
            <span class="spec-pill spec-pill-green">CORE v5.0.2</span>
          </div>
        </div>
        <div class="spec-row">
          <div class="spec-meta">
            <span class="spec-icon">🌍</span>
            <span class="spec-key">ORIGIN</span>
          </div>
          <div class="spec-body">
            <span class="spec-val">MaxMind GeoLite2 Country Database</span>
            <span class="spec-pill spec-pill-yellow">GEO-RADAR</span>
          </div>
        </div>
        <div class="spec-row">
          <div class="spec-meta">
            <span class="spec-icon">🔒</span>
            <span class="spec-key">CIPHER</span>
          </div>
          <div class="spec-body">
            <span class="spec-val">Encrypted Zero-Knowledge Stream (X25519 + ChaCha20)</span>
            <span class="spec-pill spec-pill-mauve">ENCLAVE</span>
          </div>
        </div>
      </div>
    </div>
  </header>

  <!-- ── Monitored Nodes Ribbon ────────────────────────────── -->
  <div class="sources-ribbon" id="sources-container">
    <span style="font-weight: 600; color: var(--text-hi);">🌐 CONNECTED GATEWAYS & SERVERS:</span>
    <span style="color: var(--overlay); font-style: italic;">Waiting for gateway logs & remote agents...</span>
  </div>

  <!-- ── Mobile Section Quick Jump Strip ───────────────────── -->
  <nav class="mobile-section-nav" aria-label="Section Navigation">
    <a href="#sec-kpis" class="mobile-nav-chip active" data-target="sec-kpis"><span>01</span> OVERVIEW</a>
    <a href="#sec-stream" class="mobile-nav-chip" data-target="sec-stream"><span>02</span> LOGS</a>
    <a href="#sec-geo" class="mobile-nav-chip" data-target="sec-geo"><span>03</span> MAP</a>
    <a href="#sec-charts" class="mobile-nav-chip" data-target="sec-charts"><span>04</span> TRENDS</a>
    <a href="#sec-intel" class="mobile-nav-chip" data-target="sec-intel"><span>05</span> THREATS</a>
  </nav>

  <!-- ── Section 01: KPI Spec Cards ────────────────────────── -->
  <section class="soc-section" id="sec-kpis">
  <div class="head">
    <h2>01 // TRAFFIC & SECURITY OVERVIEW</h2>
    <div class="rule"></div>
    <span class="cmd">sys.stat.kpi</span>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card" style="border-top: 2px solid var(--teal);">
      <div class="kpi-top">
        <span class="kpi-label">Total Requests</span>
        <span style="font-size:14px;">🛡️</span>
      </div>
      <div class="kpi-val" id="kpi-total">0</div>
      <div class="kpi-meter" id="kpi-meter-total">[████████████████] 100.0%</div>
      <div class="kpi-sub">Incoming traffic events</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--pink);">
      <div class="kpi-top">
        <span class="kpi-label">Threats Blocked</span>
        <span style="font-size:14px;">🛑</span>
      </div>
      <div class="kpi-val" style="color: var(--pink);" id="kpi-blocked">0</div>
      <div class="kpi-meter" style="color: var(--pink);" id="kpi-meter-blocked">[░░░░░░░░░░░░░░░░] 0.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-pink" id="kpi-block-rate">0.0% Rate</span> 403 Blocked</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--yellow);">
      <div class="kpi-top">
        <span class="kpi-label">Slowed Down</span>
        <span style="font-size:14px;">⏳</span>
      </div>
      <div class="kpi-val" style="color: var(--yellow);" id="kpi-tarpit">0</div>
      <div class="kpi-meter" style="color: var(--yellow);" id="kpi-meter-tarpit">[░░░░░░░░░░░░░░░░] 0.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-yellow">429 Slowed</span> Rate limited / slowed down</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--green);">
      <div class="kpi-top">
        <span class="kpi-label">Normal Traffic</span>
        <span style="font-size:14px;">✅</span>
      </div>
      <div class="kpi-val" style="color: var(--green);" id="kpi-clean">0</div>
      <div class="kpi-meter" style="color: var(--green);" id="kpi-meter-clean">[████████████████] 100.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-green">200 OK</span> Allowed requests passed through</div>
    </div>
  </div>
  </section>

  <!-- ── Section 02: Real-Time SOC Security Event Stream ───── -->
  <section class="soc-section" id="sec-stream">
  <div class="head">
    <h2>02 // LIVE REQUEST LOG</h2>
    <div class="rule"></div>
    <span class="cmd">stream.audit.live</span>
  </div>

  <div class="term">
    <div class="console-toolbar">
      <div class="console-hud-bar">
        <div class="prompt-row">
          <span class="prompt-user">rwarden@gateway:~$</span>
          <span class="prompt-cmd" id="prompt-stream-cmd">Live request stream</span>
          <span class="prompt-cursor">█</span>
          <span id="pause-badge" style="display:none; margin-left:12px; padding:2px 8px; border-radius:3px; background:rgba(234,179,8,0.2); border:1px solid var(--yellow); color:var(--yellow); font-size:11px; font-weight:700; letter-spacing:0.05em;">⏸ STREAM PAUSED</span>
        </div>

        <div class="filter-tabs">
          <button class="tab-btn active" data-filter-verdict="ALL">
            <span>ALL</span>
            <span class="tab-count" id="count-tab-all">0</span>
          </button>
          <button class="tab-btn" data-filter-verdict="BLOCK">
            <span>🛑 Blocked</span>
            <span class="tab-count" id="count-tab-block">0</span>
          </button>
          <button class="tab-btn" data-filter-verdict="TARPIT">
            <span>⏳ Slowed</span>
            <span class="tab-count" id="count-tab-tarpit">0</span>
          </button>
          <button class="tab-btn" data-filter-verdict="ALLOW">
            <span>✅ Allowed</span>
            <span class="tab-count" id="count-tab-clean">0</span>
          </button>
        </div>
      </div>

      <div class="filters-matrix">
        <div class="filter-item">
          <select class="filter-select" id="select-time-range" title="Filter log stream by time range">
            <option value="ALL">⏱️ All Time (Live)</option>
            <option value="1m">⏱️ Last 1 min</option>
            <option value="5m">⏱️ Last 5 mins</option>
            <option value="15m">⏱️ Last 15 mins</option>
            <option value="30m">⏱️ Last 30 mins</option>
            <option value="1h">⏱️ Last 1 hour</option>
            <option value="6h">⏱️ Last 6 hours</option>
            <option value="24h">⏱️ Last 24 hours</option>
            <option value="custom">⏱️ Custom Range...</option>
          </select>
        </div>

        <div class="filter-item">
          <select class="filter-select" id="select-node" title="Filter log stream by connected node / source">
            <option value="ALL">📡 All Nodes</option>
          </select>
        </div>

        <div class="filter-item">
          <select class="filter-select" id="select-country" title="Filter by country origin">
            <option value="ALL">🌍 All Countries</option>
          </select>
        </div>

        <div class="filter-item">
          <select class="filter-select" id="select-method" title="Filter by HTTP method">
            <option value="ALL">📡 All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>

        <div class="filter-item">
          <select class="filter-select" id="select-status" title="Filter by HTTP status code">
            <option value="ALL">⚡ All Statuses</option>
            <option value="2xx">2xx Success</option>
            <option value="403">403 Forbidden</option>
            <option value="429">429 Tarpit</option>
            <option value="4xx">4xx Client Errors</option>
            <option value="5xx">5xx Server Errors</option>
          </select>
        </div>

        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" class="search-box" id="search-input" placeholder="Search IP, Path, Rule, Status...">
          <button class="search-clear-btn" id="search-clear-btn" title="Clear search" type="button" style="display:none;">&times;</button>
          <span class="search-kbd-hint">/</span>
        </div>
      </div>

      <div id="custom-time-row" style="display:none; align-items:center; gap:8px; margin-top:2px; padding:7px 12px; background:var(--base); border:1px solid var(--line-hi); border-radius:4px; flex-wrap:wrap; box-shadow:var(--card-shadow);">
        <span style="font-size:11px; font-weight:700; color:var(--text-hi); display:flex; align-items:center; gap:5px;">
          <span>⏱️</span> CUSTOM TIME RANGE:
        </span>
        <label for="custom-time-start" style="font-size:10.5px; color:var(--overlay); font-weight:600;">FROM</label>
        <input type="datetime-local" class="filter-select" id="custom-time-start">
        <label for="custom-time-end" style="font-size:10.5px; color:var(--overlay); font-weight:600;">TO</label>
        <input type="datetime-local" class="filter-select" id="custom-time-end">
        <button class="tui-btn" id="btn-apply-custom-time" style="padding:4px 12px; font-weight:700; background:var(--teal); color:var(--crust); border-color:var(--teal); cursor:pointer;">Apply</button>
        <button class="tui-btn" id="btn-cancel-custom-time" style="padding:4px 10px; color:var(--overlay); cursor:pointer;">Cancel</button>
      </div>

      <div class="active-chips-bar" id="active-chips-container" style="display:none;">
        <span class="active-chips-label">🎯 Active Filters:</span>
        <div id="chips-list" style="display:flex; flex-wrap:wrap; gap:6px;"></div>
        <button class="btn-clear-all" id="btn-reset-filters">[RESET ALL FILTERS]</button>
      </div>
    </div>

    <div class="table-container" id="stream-table-container" style="position:relative;">
      <table class="soc-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Verdict</th>
            <th>Method</th>
            <th>Path</th>
            <th>Client IP</th>
            <th>Status</th>
            <th>Rule</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody id="stream-tbody"></tbody>
      </table>
      <div style="position:sticky; bottom:12px; display:flex; justify-content:center; pointer-events:none; width:100%; margin-top:-36px;">
        <button id="btn-scroll-top" class="tui-btn" style="display:none; pointer-events:auto; background:var(--teal); color:var(--crust); font-weight:700; border-color:var(--teal); box-shadow:0 2px 10px rgba(0,0,0,0.35); cursor:pointer;" onclick="jumpToLatest()">▲ JUMP TO LATEST</button>
      </div>
    </div>

    <!-- Terminal Table Pagination Bar -->
    <div class="table-pagination-bar" id="stream-pagination-bar">
      <div class="pagination-left">
        <span class="pagination-label">Rows:</span>
        <select class="pagination-select" id="select-page-size" title="Select events displayed per page" onchange="changePageSize(this.value)">
          <option value="25">25</option>
          <option value="50" selected>50</option>
          <option value="100">100</option>
          <option value="250">250</option>
          <option value="500">500</option>
        </select>
        <span class="pagination-info" id="pagination-info">Showing 0–0 of 0 events</span>
        <button class="tui-btn pagination-btn" id="btn-load-more-db" style="display:none; margin-left:8px; color:var(--teal); border-color:var(--teal);" onclick="loadHistoricalLogs()">📥 Load More from DB</button>
      </div>
      <div class="pagination-nav">
        <button class="tui-btn pagination-btn" id="btn-page-first" title="First Page" onclick="goToPage(1)" disabled>⏮ First</button>
        <button class="tui-btn pagination-btn" id="btn-page-prev" title="Previous Page ( [ )" onclick="goToPrevPage()" disabled>◀ Prev</button>
        <span class="pagination-page-indicator">
          Page <input type="number" class="pagination-page-input" id="input-page-num" min="1" value="1" onchange="onPageInputChange(this.value)"> of <span id="pagination-total-pages">1</span>
        </span>
        <button class="tui-btn pagination-btn" id="btn-page-next" title="Next Page ( ] )" onclick="goToNextPage()" disabled>Next ▶</button>
        <button class="tui-btn pagination-btn" id="btn-page-last" title="Last Page" onclick="goToLastPage()" disabled>Last ⏭</button>
      </div>
    </div>
  </div>
  </section>

  <!-- ── Section 03: World Map & Threat Geo-Distribution ───── -->
  <section class="soc-section" id="sec-geo">
  <div class="head">
    <h2>03 // VISITOR & THREAT MAP</h2>
    <div class="rule"></div>
    <span class="cmd">geo.threat.matrix</span>
  </div>

  <div class="term">
    <div class="cap">
      <div style="display:flex; align-items:center; gap:8px;">
        <span>🌐 WORLD TRAFFIC & THREAT MAP</span>
        <span class="tui-tag tag-teal" id="map-country-count">0 Countries Active</span>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="display:flex; align-items:center; gap:10px; font-size:11px;">
          <span><span style="color:var(--green);">●</span> Normal</span>
          <span><span style="color:var(--pink);">■</span> Blocked</span>
          <span><span style="color:var(--yellow);">▲</span> Slowed</span>
        </div>
        <button class="tui-btn" id="btn-reset-map" onclick="resetMapZoom()">[⟲ Reset Map]</button>
      </div>
    </div>

    <div class="map-body">
      <div class="map-stage">
        <div id="leaflet-map"></div>
      </div>

      <!-- Right Sidebar: Detected Countries Breakdown -->
      <div class="map-sidebar">
        <div class="map-sidebar-title">
          <span>Top Countries</span>
          <span style="color:var(--teal);">Real-Time</span>
        </div>
        <div id="map-countries-list" class="map-countries-list">
          <div style="color:var(--overlay); font-size:11px; font-style:italic; padding:10px;">Waiting for visitor locations...</div>
        </div>
      </div>
    </div>
  </div>
  </section>

  <!-- ── Section 04: Telemetry Dynamics ────────────────────── -->
  <section class="soc-section" id="sec-charts">
  <div class="head">
    <h2>04 // TRAFFIC TRENDS & SECURITY RULES</h2>
    <div class="rule"></div>
    <span class="cmd">sig.threat.timeline</span>
  </div>

  <div class="charts-grid">
    <!-- Real-Time Timeline Curve -->
    <div class="chart-card">
      <div class="card-cap">
        <span>📈 REQUEST TRAFFIC OVER TIME</span>
        <div class="timeline-legend">
          <span class="legend-item" id="legend-clean"><span style="color:var(--green);">●</span> Normal</span>
          <span class="legend-item" id="legend-blocked"><span style="color:var(--pink);">■</span> Blocked</span>
          <span class="legend-item" id="legend-tarpit"><span style="color:var(--yellow);">▲</span> Slowed</span>
        </div>
      </div>
      <div class="timeline-container" id="timeline-box">
        <div class="chart-tooltip" id="timeline-tooltip"></div>
        <svg class="timeline-svg" id="timeline-svg" viewBox="0 0 800 240" preserveAspectRatio="none">
          <defs>
            <linearGradient id="grad-clean" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="var(--green)" stop-opacity="0.25"/>
              <stop offset="100%" stop-color="var(--green)" stop-opacity="0.0"/>
            </linearGradient>
            <linearGradient id="grad-blocked" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="var(--pink)" stop-opacity="0.3"/>
              <stop offset="100%" stop-color="var(--pink)" stop-opacity="0.0"/>
            </linearGradient>
          </defs>
          <g id="grid-group"></g>
          <g id="axes-group"></g>
          <path id="path-clean-area" fill="url(#grad-clean)"></path>
          <path id="path-blocked-area" fill="url(#grad-blocked)"></path>
          <path id="path-clean-line" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round"></path>
          <path id="path-blocked-line" fill="none" stroke="var(--pink)" stroke-width="2" stroke-linecap="round"></path>
          <path id="path-tarpit-line" fill="none" stroke="var(--yellow)" stroke-width="1.8" stroke-linecap="round" stroke-dasharray="3,3"></path>
          <g id="points-group"></g>
          <line id="crosshair-line" stroke="var(--teal)" stroke-width="1" stroke-dasharray="2,2" style="display:none;"></line>
          <circle id="crosshair-dot" r="4" fill="var(--teal)" stroke="var(--base)" stroke-width="2" style="display:none;"></circle>
          <rect id="chart-overlay" width="800" height="240" fill="transparent" style="cursor:crosshair;"></rect>
        </svg>
      </div>
    </div>

    <!-- Threat Ratio & Signatures -->
    <div class="chart-card">
      <div class="card-cap">
        <span>🎯 TRAFFIC BREAKDOWN & RULES</span>
      </div>
      <div class="donut-wrap">
        <svg class="donut-svg" viewBox="0 0 100 100" id="donut-svg">
          <circle cx="50" cy="50" r="38" fill="transparent" stroke="var(--line)" stroke-width="12"></circle>
          <circle id="donut-clean" cx="50" cy="50" r="38" fill="transparent" stroke="var(--green)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-blocked" cx="50" cy="50" r="38" fill="transparent" stroke="var(--pink)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-tarpit" cx="50" cy="50" r="38" fill="transparent" stroke="var(--yellow)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
        </svg>
        <div class="donut-legend">
          <div><span style="color:var(--green);">●</span> Normal: <span id="donut-clean-lbl">0%</span></div>
          <div><span style="color:var(--pink);">■</span> Blocked: <span id="donut-blocked-lbl">0%</span></div>
          <div><span style="color:var(--yellow);">▲</span> Slowed: <span id="donut-tarpit-lbl">0%</span></div>
        </div>
      </div>
      <div style="font-size:10.5px; font-weight:700; color:var(--overlay); text-transform:uppercase; letter-spacing:0.5px; padding:0 14px;">Most Triggered Rules:</div>
      <div class="rules-list" id="rules-container">
        <div style="color:var(--overlay); font-size:11px; font-style:italic;">No rules triggered yet</div>
      </div>
    </div>
  </div>
  </section>

  <!-- ── Section 05: Intelligence Vectors ──────────────────── -->
  <section class="soc-section" id="sec-intel">
  <div class="head">
    <h2>05 // TOP THREATS & TARGETED PAGES</h2>
    <div class="rule"></div>
    <span class="cmd">intel.vectors.query</span>
  </div>

  <div class="intel-grid">
    <div class="chart-card">
      <div class="card-cap">
        <span>🚨 TOP SUSPICIOUS IPS</span>
      </div>
      <div style="max-height:260px; overflow:auto;">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Visitor IP</th>
              <th>Location</th>
              <th>Requests</th>
              <th>Threat Details</th>
            </tr>
          </thead>
          <tbody id="top-ips-tbody">
            <tr><td colspan="4" style="color:var(--overlay); text-align:center;">No suspicious IPs recorded yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="chart-card">
      <div class="card-cap">
        <span>🎯 MOST TARGETED URL PATHS</span>
      </div>
      <div style="max-height:260px; overflow:auto;">
        <table class="intel-table">
          <thead>
            <tr>
              <th>URL Path</th>
              <th>Requests</th>
              <th>Rule Triggered</th>
            </tr>
          </thead>
          <tbody id="top-paths-tbody">
            <tr><td colspan="3" style="color:var(--overlay); text-align:center;">No paths recorded yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
  </section>

</div>

<!-- ── Telemetry Event Inspector Modal ──────────────────────── -->
<div class="modal-overlay" id="event-modal">
  <div class="modal-card">
    <div class="modal-header">
      <span class="modal-title">🔍 Request Details</span>
      <span class="modal-close" id="modal-close-btn">&times;</span>
    </div>
    <div class="modal-body" id="modal-content"></div>
  </div>
</div>

<!-- ── IP Threat Intelligence & Abuse Hub Modal ─────────────── -->
<div class="modal-overlay" id="ip-modal">
  <div class="ip-modal-card">
    <div class="modal-header">
      <span class="modal-title">🌐 IP Details & Threat Report</span>
      <span class="modal-close" id="ip-modal-close-btn">&times;</span>
    </div>
    <div id="ip-modal-content"></div>
  </div>
</div>

<!-- ── Terminal Keybindings Status Footer ────────────────────── -->
<div class="tui-footer">
  <div class="footer-keys">
    <span class="footer-key-item"><span class="key-cap">Space</span> Pause</span>
    <span class="footer-key-item"><span class="key-cap">T</span> Theme</span>
    <span class="footer-key-item"><span class="key-cap">W</span> Time Range</span>
    <span class="footer-key-item"><span class="key-cap">/</span> Search</span>
    <span class="footer-key-item"><span class="key-cap">F</span> Filter Country</span>
    <span class="footer-key-item"><span class="key-cap">R</span> Reset Filters</span>
    <span class="footer-key-item"><span class="key-cap">[</span> <span class="key-cap">]</span> Page</span>
    <span class="footer-key-item"><span class="key-cap">ESC</span> Close Modal</span>
  </div>
  <div>ROUTEWARDEN SOC // ACTIVE DEFENSE</div>
</div>

<script>
(function() {
  var autoScroll = true;
  var isPaused = false;
  var pausedBufferedCount = 0;
  var allEvents = [];
  var timelineData = [];

  // Table Pagination State
  var currentPage = 1;
  var pageSize = 50;
  var currentEvents = [];
  var totalFilteredCount = 0;
  var searchDebounceTimer = null;

  // Active Filter State
  var filters = {
    verdict: 'ALL',
    timeRange: 'ALL',
    customStart: null,
    customEnd: null,
    node: 'ALL',
    country: 'ALL',
    method: 'ALL',
    status: 'ALL',
    search: '',
    ip: '',
    path: ''
  };

  var latestStats = null;
  var lastSources = null;

  // Visibilities
  var visibleSeries = {
    clean: true,
    blocked: true,
    tarpit: true
  };

  // DOM Elements
  var kpiTotal = document.getElementById('kpi-total');
  var kpiBlocked = document.getElementById('kpi-blocked');
  var kpiTarpit = document.getElementById('kpi-tarpit');
  var kpiClean = document.getElementById('kpi-clean');
  var kpiBlockRate = document.getElementById('kpi-block-rate');
  var streamTbody = document.getElementById('stream-tbody');
  var streamContainer = document.getElementById('stream-table-container');
  var sourcesContainer = document.getElementById('sources-container');
  var rulesContainer = document.getElementById('rules-container');
  var topIpsTbody = document.getElementById('top-ips-tbody');
  var topPathsTbody = document.getElementById('top-paths-tbody');
  var btnToggleScroll = document.getElementById('btn-toggle-scroll');
  var btnExportJSON = document.getElementById('btn-export-json');
  var btnResetFilters = document.getElementById('btn-reset-filters');
  var searchInput = document.getElementById('search-input');
  var searchClearBtn = document.getElementById('search-clear-btn');
  var selectTimeRange = document.getElementById('select-time-range');
  var customTimeRow = document.getElementById('custom-time-row');
  var customTimeStart = document.getElementById('custom-time-start');
  var customTimeEnd = document.getElementById('custom-time-end');
  var btnApplyCustomTime = document.getElementById('btn-apply-custom-time');
  var btnCancelCustomTime = document.getElementById('btn-cancel-custom-time');
  var selectNode = document.getElementById('select-node');
  var selectCountry = document.getElementById('select-country');
  var selectMethod = document.getElementById('select-method');
  var selectStatus = document.getElementById('select-status');
  var chipsContainer = document.getElementById('active-chips-container');
  var chipsList = document.getElementById('chips-list');
  var modal = document.getElementById('event-modal');
  var modalContent = document.getElementById('modal-content');
  var modalClose = document.getElementById('modal-close-btn');

  // ═══════════════════════════════════════════════════════════════
  // Theme Management (System theme by default with override)
  // ═══════════════════════════════════════════════════════════════
  function getSystemTheme() {
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }

  function applyTheme(themeMode) {
    var root = document.documentElement;
    var icon = document.getElementById('theme-btn-icon');
    var text = document.getElementById('theme-btn-text');

    if (themeMode === 'light') {
      root.setAttribute('data-theme', 'light');
      if (icon) icon.textContent = '☀️';
      if (text) text.textContent = 'LIGHT';
    } else if (themeMode === 'dark') {
      root.setAttribute('data-theme', 'dark');
      if (icon) icon.textContent = '🌙';
      if (text) text.textContent = 'DARK';
    } else {
      root.removeAttribute('data-theme');
      var sys = getSystemTheme();
      if (icon) icon.textContent = sys === 'light' ? '☀️' : '🌙';
      if (text) text.textContent = 'AUTO';
    }
  }

  window.toggleTheme = function() {
    var currentStored = localStorage.getItem('rw-theme') || 'auto';
    var next = 'auto';
    if (currentStored === 'auto') {
      next = getSystemTheme() === 'light' ? 'dark' : 'light';
    } else if (currentStored === 'dark') {
      next = 'light';
    } else if (currentStored === 'light') {
      next = 'auto';
    }
    try {
      localStorage.setItem('rw-theme', next);
    } catch(e) {}
    applyTheme(next);
  };

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', function() {
      var currentStored = localStorage.getItem('rw-theme') || 'auto';
      if (currentStored === 'auto') {
        applyTheme('auto');
      }
    });
  }

  // Initial theme initialization
  var savedTheme = 'auto';
  try {
    savedTheme = localStorage.getItem('rw-theme') || 'auto';
  } catch(e) {}
  applyTheme(savedTheme);

  // Live System Timezone Clock
  function updateClock() {
    var now = new Date();
    var h = String(now.getHours()).padStart(2, '0');
    var m = String(now.getMinutes()).padStart(2, '0');
    var s = String(now.getSeconds()).padStart(2, '0');
    var tz = '';
    try {
      var parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(now);
      var tzPart = parts.find(function(p) { return p.type === 'timeZoneName'; });
      if (tzPart) tz = ' ' + tzPart.value;
    } catch(e) {}
    var el = document.getElementById('utc-clock');
    if (el) el.textContent = h + ':' + m + ':' + s + tz;
  }
  setInterval(updateClock, 1000);
  updateClock();

  function formatLocalTime(ev) {
    if (ev && ev.timestamp) {
      var d = new Date(ev.timestamp);
      if (!isNaN(d.getTime())) {
        var h = String(d.getHours()).padStart(2, '0');
        var m = String(d.getMinutes()).padStart(2, '0');
        var s = String(d.getSeconds()).padStart(2, '0');
        return h + ':' + m + ':' + s;
      }
    }
    return (ev && ev.time_str) || '';
  }

  // Legend Toggles
  function setupLegendToggle(id, key) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', function() {
      visibleSeries[key] = !visibleSeries[key];
      el.classList.toggle('dimmed', !visibleSeries[key]);
      drawTimeline(timelineData);
    });
  }
  setupLegendToggle('legend-clean', 'clean');
  setupLegendToggle('legend-blocked', 'blocked');
  setupLegendToggle('legend-tarpit', 'tarpit');

  // Tab Filtering
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      filters.verdict = btn.getAttribute('data-filter-verdict');
      renderActiveChips();
      renderTable();
    });
  });

  function parseEventTime(ev) {
    if (!ev) return null;
    var raw = ev.timestamp || ev.time;
    if (raw) {
      if (typeof raw === 'number') return raw;
      var d = new Date(raw);
      var ms = d.getTime();
      if (!isNaN(ms)) return ms;
      var dt = new Date(String(raw).replace(' ', 'T'));
      if (!isNaN(dt.getTime())) return dt.getTime();
      var clfMatch = String(raw).match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
      if (clfMatch) {
        var months = {Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
        var mIdx = months[clfMatch[2]];
        if (mIdx !== undefined) {
          var clfDate = new Date(parseInt(clfMatch[3], 10), mIdx, parseInt(clfMatch[1], 10),
            parseInt(clfMatch[4], 10), parseInt(clfMatch[5], 10), parseInt(clfMatch[6], 10));
          if (!isNaN(clfDate.getTime())) return clfDate.getTime();
        }
      }
    }
    if (ev.time_str && typeof ev.time_str === 'string') {
      var parts = ev.time_str.split(':');
      if (parts.length >= 2) {
        var now = new Date();
        var d2 = new Date(now.getFullYear(), now.getMonth(), now.getDate(),
          parseInt(parts[0], 10), parseInt(parts[1], 10), parseInt(parts[2] || 0, 10));
        if (!isNaN(d2.getTime())) return d2.getTime();
      }
    }
    return null;
  }

  function toDateTimeLocalString(d) {
    var pad = function(n) { return String(n).padStart(2, '0'); };
    return d.getFullYear() + '-' +
      pad(d.getMonth() + 1) + '-' +
      pad(d.getDate()) + 'T' +
      pad(d.getHours()) + ':' +
      pad(d.getMinutes());
  }

  function updatePromptCommand() {
    var cmd = 'filter --stream=live';
    if (filters.timeRange && filters.timeRange !== 'ALL') {
      if (filters.timeRange === 'custom') {
        cmd += ' --time=custom';
      } else {
        cmd += ' --time=' + filters.timeRange;
      }
    }
    if (filters.verdict !== 'ALL') cmd += ' --verdict=' + filters.verdict.toLowerCase();
    if (filters.node && filters.node !== 'ALL') cmd += ' --node=' + filters.node;
    if (filters.country !== 'ALL') cmd += ' --country=' + filters.country;
    if (filters.method !== 'ALL') cmd += ' --method=' + filters.method;
    if (filters.status !== 'ALL') cmd += ' --status=' + filters.status;
    if (filters.ip) cmd += ' --ip=' + filters.ip;
    if (filters.path) cmd += ' --path=' + filters.path;
    if (filters.search) cmd += ' --grep="' + filters.search + '"';
    var promptEl = document.getElementById('prompt-stream-cmd');
    if (promptEl) {
      promptEl.textContent = cmd;
    }
  }

  if (selectTimeRange) {
    selectTimeRange.addEventListener('change', function(e) {
      var val = e.target.value;
      filters.timeRange = val;
      if (val === 'custom') {
        if (customTimeRow) {
          customTimeRow.style.display = 'flex';
          var now = new Date();
          if (!customTimeEnd.value) customTimeEnd.value = toDateTimeLocalString(now);
          if (!customTimeStart.value) customTimeStart.value = toDateTimeLocalString(new Date(now.getTime() - 60 * 60 * 1000));
        }
      } else {
        if (customTimeRow) customTimeRow.style.display = 'none';
        filters.customStart = null;
        filters.customEnd = null;
        renderActiveChips();
        renderTable();
      }
    });
  }

  if (btnApplyCustomTime) {
    btnApplyCustomTime.addEventListener('click', function() {
      var startVal = customTimeStart.value;
      var endVal = customTimeEnd.value;
      if (startVal) {
        var sDate = new Date(startVal);
        filters.customStart = !isNaN(sDate.getTime()) ? sDate.getTime() : null;
      } else {
        filters.customStart = null;
      }
      if (endVal) {
        var eDate = new Date(endVal);
        filters.customEnd = !isNaN(eDate.getTime()) ? eDate.getTime() : null;
      } else {
        filters.customEnd = null;
      }
      filters.timeRange = 'custom';
      renderActiveChips();
      renderTable();
    });
  }

  if (btnCancelCustomTime) {
    btnCancelCustomTime.addEventListener('click', function() {
      if (customTimeRow) customTimeRow.style.display = 'none';
      filters.timeRange = 'ALL';
      filters.customStart = null;
      filters.customEnd = null;
      if (selectTimeRange) selectTimeRange.value = 'ALL';
      renderActiveChips();
      renderTable();
    });
  }

  if (selectNode) {
    selectNode.addEventListener('change', function(e) {
      filters.node = e.target.value;
      currentPage = 1;
      renderActiveChips();
      renderTable();
      if (lastSources) renderSources(lastSources);
    });
  }

  selectCountry.addEventListener('change', function(e) {
    filters.country = e.target.value;
    renderActiveChips();
    renderTable();
  });

  selectMethod.addEventListener('change', function(e) {
    filters.method = e.target.value;
    renderActiveChips();
    renderTable();
  });

  selectStatus.addEventListener('change', function(e) {
    filters.status = e.target.value;
    renderActiveChips();
    renderTable();
  });

  searchInput.addEventListener('input', function(e) {
    filters.search = e.target.value.toLowerCase().trim();
    if (searchClearBtn) {
      searchClearBtn.style.display = e.target.value ? 'inline-block' : 'none';
    }
    currentPage = 1;
    renderActiveChips();
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(function() {
      fetchFilteredLogs(1, true);
    }, 250);
  });

  if (searchClearBtn) {
    searchClearBtn.addEventListener('click', function() {
      searchInput.value = '';
      filters.search = '';
      searchClearBtn.style.display = 'none';
      currentPage = 1;
      renderActiveChips();
      fetchFilteredLogs(1, true);
      searchInput.focus();
    });
  }

  window.toggleStreamPause = function() {
    isPaused = !isPaused;
    autoScroll = !isPaused;
    var btn = document.getElementById('btn-toggle-scroll');
    var statusEl = document.getElementById('stream-status');
    var pulseDot = document.getElementById('stream-pulse-dot');
    var pauseBadge = document.getElementById('pause-badge');

    if (isPaused) {
      pausedBufferedCount = 0;
      if (btn) {
        btn.innerHTML = '▶ Resume';
        btn.style.background = 'var(--yellow)';
        btn.style.color = '#000000';
        btn.style.fontWeight = '700';
        btn.style.borderColor = 'var(--yellow)';
      }
      if (statusEl) {
        statusEl.textContent = 'STREAM PAUSED';
        statusEl.style.color = 'var(--yellow)';
      }
      if (pulseDot) {
        pulseDot.classList.add('pulse-dot-paused');
      }
      if (pauseBadge) {
        pauseBadge.textContent = '⏸ STREAM PAUSED';
        pauseBadge.style.display = 'inline-block';
      }
    } else {
      if (btn) {
        btn.innerHTML = '⏸ Pause';
        btn.style.background = '';
        btn.style.color = '';
        btn.style.fontWeight = '';
        btn.style.borderColor = '';
      }
      if (statusEl) {
        statusEl.textContent = 'LIVE STREAM';
        statusEl.style.color = 'var(--green)';
      }
      if (pulseDot) {
        pulseDot.classList.remove('pulse-dot-paused');
      }
      if (pauseBadge) {
        pauseBadge.style.display = 'none';
      }
      pausedBufferedCount = 0;
      renderTable();
      fetchStats();
    }
  };

  window.jumpToLatest = function() {
    currentPage = 1;
    renderTable();
    if (streamContainer) {
      streamContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
    if (isPaused) {
      toggleStreamPause();
    }
  };

  if (streamContainer) {
    streamContainer.addEventListener('scroll', function() {
      var btn = document.getElementById('btn-scroll-top');
      if (btn) {
        btn.style.display = streamContainer.scrollTop > 100 ? 'inline-flex' : 'none';
      }
    });
  }

  btnResetFilters.addEventListener('click', function() {
    resetAllFilters();
  });

  function resetAllFilters() {
    filters.verdict = 'ALL';
    filters.timeRange = 'ALL';
    filters.customStart = null;
    filters.customEnd = null;
    filters.node = 'ALL';
    filters.country = 'ALL';
    filters.method = 'ALL';
    filters.status = 'ALL';
    filters.rule = 'ALL';
    filters.search = '';
    filters.ip = '';
    filters.path = '';

    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    var allBtn = document.querySelector('[data-filter-verdict="ALL"]');
    if (allBtn) allBtn.classList.add('active');

    if (selectTimeRange) selectTimeRange.value = 'ALL';
    if (customTimeRow) customTimeRow.style.display = 'none';
    if (customTimeStart) customTimeStart.value = '';
    if (customTimeEnd) customTimeEnd.value = '';
    if (selectNode) selectNode.value = 'ALL';
    selectCountry.value = 'ALL';
    selectMethod.value = 'ALL';
    selectStatus.value = 'ALL';
    searchInput.value = '';
    if (searchClearBtn) searchClearBtn.style.display = 'none';

    renderActiveChips();
    renderTable();
    if (lastSources) renderSources(lastSources);    if (latestStats) updateWorldMap(latestStats);
  }

  btnExportJSON.addEventListener('click', function() {
    var filtered = getFilteredEvents();
    var blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'routewarden-soc-events-' + new Date().toISOString() + '.json';
    a.click();
    URL.revokeObjectURL(url);
  });

  modalClose.addEventListener('click', function() { modal.style.display = 'none'; });
  window.addEventListener('click', function(e) { if (e.target === modal) modal.style.display = 'none'; });

  // Keyboard Shortcuts
  window.addEventListener('keydown', function(e) {
    if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT')) {
      if (e.key === 'Escape') {
        e.target.blur();
      }
      return;
    }
    if (e.key === 'Escape') {
      modal.style.display = 'none';
      var ipModal = document.getElementById('ip-modal');
      if (ipModal) ipModal.style.display = 'none';
    } else if (e.code === 'Space' || e.key === ' ') {
      e.preventDefault();
      toggleStreamPause();
    } else if (e.key === 't' || e.key === 'T') {
      toggleTheme();
    } else if (e.key === 'w' || e.key === 'W') {
      if (selectTimeRange) selectTimeRange.focus();
    } else if (e.key === '/') {
      e.preventDefault();
      searchInput.focus();
    } else if (e.key === 'r' || e.key === 'R') {
      resetAllFilters();
    } else if (e.key === 'f' || e.key === 'F') {
      selectCountry.focus();
    } else if (e.key === 'p' || e.key === 'P') {
      searchInput.focus();
    } else if (e.key === '[' || e.key === 'ArrowLeft') {
      window.goToPrevPage();
    } else if (e.key === ']' || e.key === 'ArrowRight') {
      window.goToNextPage();
    }
  });

  function renderActiveChips() {
    currentPage = 1;
    var chips = [];
    if (filters.timeRange !== 'ALL') {
      var timeLabel = 'Time: ' + filters.timeRange;
      if (filters.timeRange === '1m') timeLabel = 'Time: Last 1m';
      else if (filters.timeRange === '5m') timeLabel = 'Time: Last 5m';
      else if (filters.timeRange === '15m') timeLabel = 'Time: Last 15m';
      else if (filters.timeRange === '30m') timeLabel = 'Time: Last 30m';
      else if (filters.timeRange === '1h') timeLabel = 'Time: Last 1h';
      else if (filters.timeRange === '6h') timeLabel = 'Time: Last 6h';
      else if (filters.timeRange === '24h') timeLabel = 'Time: Last 24h';
      else if (filters.timeRange === 'custom') {
        timeLabel = 'Time: Custom Range';
      }
      chips.push({
        label: timeLabel,
        clear: function() {
          filters.timeRange = 'ALL';
          filters.customStart = null;
          filters.customEnd = null;
          if (selectTimeRange) selectTimeRange.value = 'ALL';
          if (customTimeRow) customTimeRow.style.display = 'none';
        }
      });
    }
    if (filters.verdict !== 'ALL') chips.push({ label: 'Verdict: ' + filters.verdict, clear: function() {
      filters.verdict = 'ALL';
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      var ab = document.querySelector('[data-filter-verdict="ALL"]');
      if (ab) ab.classList.add('active');
    }});
    if (filters.node !== 'ALL') chips.push({ label: 'Node: ' + filters.node, clear: function() { filters.node = 'ALL'; if (selectNode) selectNode.value = 'ALL'; if (lastSources) renderSources(lastSources); }});
    if (filters.country !== 'ALL') chips.push({ label: 'Country: ' + filters.country, clear: function() { filters.country = 'ALL'; selectCountry.value = 'ALL'; }});
    if (filters.method !== 'ALL') chips.push({ label: 'Method: ' + filters.method, clear: function() { filters.method = 'ALL'; selectMethod.value = 'ALL'; }});
    if (filters.status !== 'ALL') chips.push({ label: 'Status: ' + filters.status, clear: function() { filters.status = 'ALL'; selectStatus.value = 'ALL'; }});
    if (filters.search) chips.push({ label: 'Search: "' + filters.search + '"', clear: function() {
      filters.search = '';
      searchInput.value = '';
      if (searchClearBtn) searchClearBtn.style.display = 'none';
    }});
    if (filters.ip) chips.push({ label: 'IP: ' + filters.ip, clear: function() { filters.ip = ''; }});
    if (filters.path) chips.push({ label: 'Path: ' + filters.path, clear: function() { filters.path = ''; }});

    if (selectTimeRange) selectTimeRange.classList.toggle('filter-active', filters.timeRange !== 'ALL');
    if (selectNode) selectNode.classList.toggle('filter-active', filters.node !== 'ALL');
    if (selectCountry) selectCountry.classList.toggle('filter-active', filters.country !== 'ALL');
    if (selectMethod) selectMethod.classList.toggle('filter-active', filters.method !== 'ALL');
    if (selectStatus) selectStatus.classList.toggle('filter-active', filters.status !== 'ALL');

    updatePromptCommand();

    if (chips.length > 0) {
      chipsContainer.style.display = 'flex';
      var h = '';
      chips.forEach(function(c, i) {
        h += '<span class="filter-chip">' + c.label + ' <span class="chip-close" data-chip-idx="' + i + '">&times;</span></span>';
      });
      chipsList.innerHTML = h;

      chipsList.querySelectorAll('.chip-close').forEach(function(el) {
        el.addEventListener('click', function() {
          var idx = parseInt(el.getAttribute('data-chip-idx'), 10);
          if (chips[idx]) chips[idx].clear();
          renderActiveChips();
          renderTable();
          if (latestStats) updateWorldMap(latestStats);
        });
      });
    } else {
      chipsContainer.style.display = 'none';
    }
  }

  function getFilteredEvents() {
    var now = Date.now();
    var timeLimitMs = 0;
    if (filters.timeRange === '1m') timeLimitMs = 60 * 1000;
    else if (filters.timeRange === '5m') timeLimitMs = 5 * 60 * 1000;
    else if (filters.timeRange === '15m') timeLimitMs = 15 * 60 * 1000;
    else if (filters.timeRange === '30m') timeLimitMs = 30 * 60 * 1000;
    else if (filters.timeRange === '1h') timeLimitMs = 60 * 60 * 1000;
    else if (filters.timeRange === '6h') timeLimitMs = 6 * 60 * 60 * 1000;
    else if (filters.timeRange === '24h') timeLimitMs = 24 * 60 * 60 * 1000;

    return allEvents.filter(function(ev) {
      if (filters.verdict !== 'ALL' && ev.verdict !== filters.verdict) return false;
      if (filters.node && filters.node !== 'ALL' && (ev.source || '') !== filters.node) return false;
      if (filters.country !== 'ALL' && ev.country !== filters.country && ev.country_code !== filters.country) return false;
      if (filters.method !== 'ALL' && (ev.method || '').toUpperCase() !== filters.method) return false;
      if (filters.ip && ev.client_ip !== filters.ip) return false;
      if (filters.path && ev.path !== filters.path) return false;

      // Time range filtering
      if (timeLimitMs > 0) {
        var evTime = parseEventTime(ev);
        if (evTime !== null) {
          var diff = now - evTime;
          // allow events within timeLimit, with 30s tolerance for clock drift
          if (diff > timeLimitMs || diff < -30000) return false;
        }
      } else if (filters.timeRange === 'custom') {
        var evTime = parseEventTime(ev);
        if (evTime !== null) {
          if (filters.customStart && evTime < filters.customStart) return false;
          if (filters.customEnd && evTime > filters.customEnd) return false;
        }
      }

      if (filters.status !== 'ALL') {
        var s = ev.status;
        if (filters.status === '2xx' && (s < 200 || s >= 300)) return false;
        if (filters.status === '403' && s !== 403) return false;
        if (filters.status === '429' && s !== 429) return false;
        if (filters.status === '4xx' && (s < 400 || s >= 500)) return false;
        if (filters.status === '5xx' && (s < 500 || s >= 600)) return false;
      }

      if (filters.search) {
        var str = (ev.client_ip + ' ' + (ev.country || '') + ' ' + ev.path + ' ' + (ev.rule || '') + ' ' + ev.method + ' ' + ev.status + ' ' + (ev.source || '')).toLowerCase();
        if (str.indexOf(filters.search) === -1) return false;
      }
      return true;
    });
  }

  function matchesCurrentFilters(ev) {
    if (!ev) return false;
    if (filters.verdict !== 'ALL' && ev.verdict !== filters.verdict) return false;
    if (filters.node && filters.node !== 'ALL' && (ev.source || '') !== filters.node) return false;
    if (filters.country !== 'ALL' && ev.country !== filters.country && ev.country_code !== filters.country) return false;
    if (filters.method !== 'ALL' && (ev.method || '').toUpperCase() !== filters.method) return false;
    if (filters.ip && ev.client_ip !== filters.ip) return false;
    if (filters.path && ev.path !== filters.path) return false;

    if (filters.status !== 'ALL') {
      var s = ev.status;
      if (filters.status === '2xx' && (s < 200 || s >= 300)) return false;
      if (filters.status === '403' && s !== 403) return false;
      if (filters.status === '429' && s !== 429) return false;
      if (filters.status === '4xx' && (s < 400 || s >= 500)) return false;
      if (filters.status === '5xx' && (s < 500 || s >= 600)) return false;
    }

    if (filters.search) {
      var str = (ev.client_ip + ' ' + (ev.country || '') + ' ' + ev.path + ' ' + (ev.rule || '') + ' ' + ev.method + ' ' + ev.status + ' ' + (ev.source || '')).toLowerCase();
      if (str.indexOf(filters.search) === -1) return false;
    }
    return true;
  }

  function buildFilterQueryString(page, size) {
    var p = page || currentPage;
    var s = size || pageSize;
    var offset = (p - 1) * s;
    var params = ['limit=' + s, 'offset=' + offset];

    if (filters.verdict && filters.verdict !== 'ALL') {
      params.push('verdict=' + encodeURIComponent(filters.verdict));
    }
    if (filters.node && filters.node !== 'ALL') {
      params.push('node=' + encodeURIComponent(filters.node));
    }
    if (filters.country && filters.country !== 'ALL') {
      params.push('country=' + encodeURIComponent(filters.country));
    }
    if (filters.method && filters.method !== 'ALL') {
      params.push('method=' + encodeURIComponent(filters.method));
    }
    if (filters.status && filters.status !== 'ALL') {
      params.push('status=' + encodeURIComponent(filters.status));
    }
    if (filters.ip) {
      params.push('ip=' + encodeURIComponent(filters.ip));
    }
    if (filters.path) {
      params.push('path=' + encodeURIComponent(filters.path));
    }
    if (filters.search) {
      params.push('search=' + encodeURIComponent(filters.search));
    }
    if (filters.timeRange && filters.timeRange !== 'ALL') {
      if (filters.timeRange === 'custom') {
        if (filters.customStart) params.push('start=' + encodeURIComponent(new Date(filters.customStart).toISOString()));
        if (filters.customEnd) params.push('end=' + encodeURIComponent(new Date(filters.customEnd).toISOString()));
      } else {
        params.push('time=' + encodeURIComponent(filters.timeRange));
      }
    }
    return params.join('&');
  }

  function renderRowsHTML(events) {
    var rowsHTML = '';
    events.forEach(function(ev) {
      var verdictClass = 'verdict-allow';
      var verdictLabel = '[ ALLOW ]';
      if (ev.verdict === 'BLOCK') {
        verdictClass = 'verdict-block';
        verdictLabel = '[ BLOCKED ]';
      } else if (ev.verdict === 'TARPIT') {
        verdictClass = 'verdict-tarpit';
        verdictLabel = '[ TARPIT ]';
      }

      var ruleHTML = '<span style="color:var(--overlay);">—</span>';
      if (ev.rule) {
        ruleHTML = '<span class="rule-tag">🛡️ ' + ev.rule + '</span>';
      }

      var methodClass = 'method-get';
      var m = (ev.method || 'GET').toUpperCase();
      if (m === 'POST') methodClass = 'method-post';
      else if (m === 'PUT') methodClass = 'method-put';
      else if (m === 'DELETE') methodClass = 'method-delete';

      var flag = getFlagEmoji(ev.country_code);
      var countryTitle = ev.country ? (flag + ' ' + ev.country) : 'Client IP';

      rowsHTML += '<tr onclick="inspectEvent(' + ev.id + ')">' +
        '<td>' + formatLocalTime(ev) + '</td>' +
        '<td><span class="bracket-badge ' + verdictClass + '">' + verdictLabel + '</span></td>' +
        '<td><span class="badge-method ' + methodClass + '">' + m + '</span></td>' +
        '<td style="max-width:300px; overflow:hidden; text-overflow:ellipsis;" title="' + ev.path + '">' + ev.path + '</td>' +
        '<td><span class="ip-clickable" title="' + countryTitle + '" onclick="event.stopPropagation(); inspectIP(\'' + ev.client_ip + '\')">' +
          '<span style="margin-right:5px;">' + flag + '</span>' + ev.client_ip +
        '</span></td>' +
        '<td>[' + ev.status + ']</td>' +
        '<td>' + ruleHTML + '</td>' +
        '<td style="color:var(--subtext);">' + ev.latency_ms.toFixed(1) + 'ms</td>' +
      '</tr>';
    });

    var emptyMessage = 'No matching events';
    if (filters.timeRange !== 'ALL') {
      var tDesc = filters.timeRange;
      if (filters.timeRange === '1m') tDesc = 'last 1 minute';
      else if (filters.timeRange === '5m') tDesc = 'last 5 minutes';
      else if (filters.timeRange === '15m') tDesc = 'last 15 minutes';
      else if (filters.timeRange === '30m') tDesc = 'last 30 minutes';
      else if (filters.timeRange === '1h') tDesc = 'last 1 hour';
      else if (filters.timeRange === '6h') tDesc = 'last 6 hours';
      else if (filters.timeRange === '24h') tDesc = 'last 24 hours';
      else if (filters.timeRange === 'custom') tDesc = 'custom time window';
      emptyMessage = '<div style="font-size:16px; margin-bottom:6px;">⏱️</div>NO LOGS IN SELECTED TIME RANGE (' + tDesc.toUpperCase() + ')<div style="font-size:10.5px; margin-top:4px; color:var(--subtext);">Select a broader time window or reset filters to view earlier security events.</div>';
    } else if (filters.search || filters.node !== 'ALL' || filters.country !== 'ALL' || filters.method !== 'ALL' || filters.status !== 'ALL' || filters.verdict !== 'ALL') {
      emptyMessage = '<div style="font-size:16px; margin-bottom:6px;">🔍</div>NO EVENTS MATCHING ACTIVE FILTERS<div style="font-size:10.5px; margin-top:4px; color:var(--subtext);">Click [RESET ALL FILTERS] to clear query parameters.</div>';
    }

    streamTbody.innerHTML = rowsHTML || '<tr><td colspan="8" style="color:var(--overlay); text-align:center; padding:28px 12px; font-family:var(--mono);">' + emptyMessage + '</td></tr>';
  }

  function fetchFilteredLogs(page, resetScroll) {
    if (page) currentPage = page;
    var qs = buildFilterQueryString(currentPage, pageSize);
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/logs?' + qs, true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 401) {
          window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
          return;
        }
        if (xhr.status === 200) {
          try {
            var data = JSON.parse(xhr.responseText);
            currentEvents = data.events || [];
            totalFilteredCount = (typeof data.filtered_total === 'number') ? data.filtered_total : (data.total || currentEvents.length);
            var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            var startIndex = (currentPage - 1) * pageSize;
            var endIndex = Math.min(startIndex + currentEvents.length, totalFilteredCount);

            renderRowsHTML(currentEvents);
            updatePaginationUI(totalFilteredCount, totalPages, startIndex, endIndex);

            if (resetScroll && streamContainer) {
              streamContainer.scrollTop = 0;
            }
            return;
          } catch(e) {}
        }
        renderTableFallback();
      }
    };
    xhr.send();
  }

  function renderTableFallback() {
    var filtered = getFilteredEvents();
    totalFilteredCount = filtered.length;
    var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    var startIndex = (currentPage - 1) * pageSize;
    var endIndex = Math.min(startIndex + pageSize, totalFilteredCount);
    currentEvents = filtered.slice(startIndex, endIndex);

    renderRowsHTML(currentEvents);
    updatePaginationUI(totalFilteredCount, totalPages, startIndex, endIndex);
  }

  function renderTable() {
    fetchFilteredLogs(currentPage, false);
  }

  function updatePaginationUI(totalFiltered, totalPages, startIndex, endIndex) {
    var info = document.getElementById('pagination-info');
    var totalPagesEl = document.getElementById('pagination-total-pages');
    var inputPage = document.getElementById('input-page-num');
    var btnFirst = document.getElementById('btn-page-first');
    var btnPrev = document.getElementById('btn-page-prev');
    var btnNext = document.getElementById('btn-page-next');
    var btnLast = document.getElementById('btn-page-last');
    var btnLoadMore = document.getElementById('btn-load-more-db');

    if (info) {
      if (totalFiltered === 0) {
        info.textContent = 'Showing 0–0 of 0 events';
      } else {
        info.textContent = 'Showing ' + (startIndex + 1) + '–' + endIndex + ' of ' + totalFiltered + ' events';
      }
    }
    if (totalPagesEl) totalPagesEl.textContent = totalPages;
    if (inputPage) {
      inputPage.value = currentPage;
      inputPage.max = totalPages;
    }

    if (btnFirst) btnFirst.disabled = (currentPage <= 1);
    if (btnPrev) btnPrev.disabled = (currentPage <= 1);
    if (btnNext) btnNext.disabled = (currentPage >= totalPages);
    if (btnLast) btnLast.disabled = (currentPage >= totalPages);

    if (btnLoadMore) {
      if (totalFiltered > (startIndex + currentEvents.length)) {
        btnLoadMore.style.display = 'inline-flex';
        btnLoadMore.textContent = 'Next Page ▶';
        btnLoadMore.onclick = function() { window.goToNextPage(); };
      } else {
        btnLoadMore.style.display = 'none';
      }
    }
  }

  window.goToPage = function(page) {
    var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
    var p = parseInt(page, 10);
    if (isNaN(p)) return;
    if (p < 1) p = 1;
    if (p > totalPages) p = totalPages;
    if (p !== currentPage) {
      currentPage = p;
      fetchFilteredLogs(p, true);
    }
  };

  window.goToPrevPage = function() {
    if (currentPage > 1) {
      window.goToPage(currentPage - 1);
    }
  };

  window.goToNextPage = function() {
    var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
    if (currentPage < totalPages) {
      window.goToPage(currentPage + 1);
    }
  };

  window.goToLastPage = function() {
    var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
    window.goToPage(totalPages);
  };

  window.changePageSize = function(size) {
    var s = parseInt(size, 10);
    if (!isNaN(s) && s > 0) {
      pageSize = s;
      currentPage = 1;
      fetchFilteredLogs(1, true);
    }
  };

  window.onPageInputChange = function(val) {
    window.goToPage(val);
  };

  window.loadHistoricalLogs = function() {
    window.goToNextPage();
  };

  // Periodically refresh table if time filter is active (so time window naturally rolls forward)
  setInterval(function() {
    if (filters.timeRange !== 'ALL' && filters.timeRange !== 'custom' && !isPaused) {
      renderTable();
    }
  }, 5000);

  window.inspectEvent = function(id) {
    var found = currentEvents.find(function(e) { return e.id === id; }) || allEvents.find(function(e) { return e.id === id; });
    if (!found) return;

    modalContent.innerHTML = '<div style="margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; border-bottom:1px solid var(--line); padding-bottom:10px;">' +
      '<div>SOURCE IP: <b style="color:var(--teal);">' + found.client_ip + '</b>' + (found.country ? ' <span style="margin-left:8px;">' + getFlagEmoji(found.country_code) + ' ' + found.country + '</span>' : '') +
      ' <span style="margin-left:14px; color:var(--mauve); font-size:11px; font-weight:600;">NODE / SOURCE: ' + (found.source || 'local') + '</span></div>' +
      '<button class="tui-btn" onclick="inspectIP(\'' + found.client_ip + '\')">🌐 IP INTEL & ABUSE HUB</button>' +
    '</div>' +
    '<pre style="margin:0; overflow-x:auto; background:var(--crust); padding:12px; border-radius:3px; border:1px solid var(--line);">' + JSON.stringify(found, null, 2) + '</pre>';
    modal.style.display = 'flex';
  };

  function updateKPIs(stats) {
    if (!stats) return;
    var total = stats.total_events || 0;
    var blocked = stats.blocked_count || 0;
    var tarpit = stats.tarpit_count || 0;
    var clean = stats.clean_count || 0;

    kpiTotal.textContent = Number(total).toLocaleString();
    kpiBlocked.textContent = Number(blocked).toLocaleString();
    kpiTarpit.textContent = Number(tarpit).toLocaleString();
    kpiClean.textContent = Number(clean).toLocaleString();
    kpiBlockRate.textContent = (stats.block_rate || '0.0%') + ' Rate';

    // Update ASCII meters
    function makeMeter(val, max) {
      if (max <= 0) return '[░░░░░░░░░░░░░░░░] 0.0%';
      var pct = Math.min(100, (val / max) * 100);
      var filled = Math.round((pct / 100) * 16);
      var bar = '';
      for (var i = 0; i < 16; i++) {
        bar += (i < filled) ? '█' : '░';
      }
      return '[' + bar + '] ' + pct.toFixed(1) + '%';
    }

    var meterBlocked = document.getElementById('kpi-meter-blocked');
    var meterTarpit = document.getElementById('kpi-meter-tarpit');
    var meterClean = document.getElementById('kpi-meter-clean');
    if (meterBlocked) meterBlocked.textContent = makeMeter(blocked, total);
    if (meterTarpit) meterTarpit.textContent = makeMeter(tarpit, total);
    if (meterClean) meterClean.textContent = makeMeter(clean, total);

    document.getElementById('count-tab-all').textContent = total;
    document.getElementById('count-tab-block').textContent = blocked;
    document.getElementById('count-tab-tarpit').textContent = tarpit;
    document.getElementById('count-tab-clean').textContent = clean;

    // Update Donut Chart
    updateDonut(clean, blocked, tarpit, total);

    // Populate Rule List
    if (stats.top_rules && stats.top_rules.length > 0) {
      var maxRuleCount = stats.top_rules[0].count || 1;
      var rHTML = '';
      stats.top_rules.forEach(function(r) {
        var pct = ((r.count / maxRuleCount) * 100).toFixed(1);
        rHTML += '<div class="rule-item">' +
          '<div class="rule-meta">' +
            '<span class="rule-name">🛡️ ' + r.name + '</span>' +
            '<span class="rule-count">' + Number(r.count).toLocaleString() + ' hits</span>' +
          '</div>' +
          '<div class="rule-bar-wrap"><div class="rule-bar-fill" style="width:' + pct + '%;"></div></div>' +
        '</div>';
      });
      if (rulesContainer.innerHTML !== rHTML) {
        rulesContainer.innerHTML = rHTML;
      }
    }

    // Populate Country Dropdown
    if (stats.top_countries && stats.top_countries.length > 0) {
      var currentCountry = selectCountry.value;
      var cOptHTML = '<option value="ALL">All Countries</option>';
      stats.top_countries.forEach(function(c) {
        var fl = getFlagEmoji(c.country_code);
        cOptHTML += '<option value="' + c.name + '">' + fl + ' ' + c.name + ' (' + c.count + ')</option>';
      });
      if (selectCountry.innerHTML !== cOptHTML) {
        selectCountry.innerHTML = cOptHTML;
        selectCountry.value = currentCountry;
      }
    }

    // Top IPs
    if (stats.top_ips && stats.top_ips.length > 0) {
      var ipHTML = '';
      stats.top_ips.forEach(function(item) {
        var flag = getFlagEmoji(item.country_code);
        var countryName = item.country || 'Unknown';
        ipHTML += '<tr>' +
          '<td><span class="ip-clickable" onclick="inspectIP(\'' + item.name + '\')">' + item.name + '</span></td>' +
          '<td>' + flag + ' ' + countryName + '</td>' +
          '<td>' + Number(item.count).toLocaleString() + '</td>' +
          '<td><div class="threat-breakdown-cell"><span class="tui-tag tag-pink">' + item.blocked + ' blk</span><span class="tui-tag tag-yellow">' + item.tarpit + ' tar</span>' +
          '<button class="tui-btn" style="padding:1px 6px; font-size:10px;" onclick="inspectIP(\'' + item.name + '\')">🚨 Report</button></div></td>' +
        '</tr>';
      });
      if (topIpsTbody.innerHTML !== ipHTML) {
        topIpsTbody.innerHTML = ipHTML;
      }
    }

    // Top Paths
    if (stats.top_paths && stats.top_paths.length > 0) {
      var pHTML = '';
      stats.top_paths.forEach(function(item) {
        var ruleBadge = item.rule ? '<span class="tui-tag tag-pink">' + item.rule + '</span>' : '<span style="color:var(--overlay);">—</span>';
        pHTML += '<tr>' +
          '<td style="max-width:240px; overflow:hidden; text-overflow:ellipsis;">' + item.name + '</td>' +
          '<td>' + Number(item.count).toLocaleString() + '</td>' +
          '<td>' + ruleBadge + '</td>' +
        '</tr>';
      });
      if (topPathsTbody.innerHTML !== pHTML) {
        topPathsTbody.innerHTML = pHTML;
      }
    }

    // Timeline SVG
    if (stats.timeline && stats.timeline.length > 0) {
      timelineData = stats.timeline;
      drawTimeline(timelineData);
    }

    latestStats = stats;
    updateWorldMap(stats);
  }

  function scrollToLiveLog() {
    var sec = document.getElementById('sec-stream');
    if (sec) {
      sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  window.filterByCountry = function(country) {
    if (filters.country === country) {
      filters.country = 'ALL';
      selectCountry.value = 'ALL';
    } else {
      filters.country = country;
      selectCountry.value = country;
    }
    renderActiveChips();
    renderTable();
    if (latestStats) updateWorldMap(latestStats);
    scrollToLiveLog();
  };

  window.filterByIP = function(ip) {
    filters.ip = ip;
    renderActiveChips();
    renderTable();
    scrollToLiveLog();
  };

  window.filterByPath = function(path) {
    filters.path = path;
    renderActiveChips();
    renderTable();
    scrollToLiveLog();
  };

  // Precise GPS coordinates (latitude, longitude) for countries worldwide
  var countryCoords = {
    'US': { lat: 37.0902, lon: -95.7129, name: 'United States' },
    'CA': { lat: 56.1304, lon: -106.3468, name: 'Canada' },
    'MX': { lat: 23.6345, lon: -102.5528, name: 'Mexico' },
    'BR': { lat: -14.2350, lon: -51.9253, name: 'Brazil' },
    'AR': { lat: -38.4161, lon: -63.6167, name: 'Argentina' },
    'CL': { lat: -35.6751, lon: -71.5430, name: 'Chile' },
    'CO': { lat: 4.5709, lon: -74.2973, name: 'Colombia' },
    'PE': { lat: -9.1900, lon: -75.0152, name: 'Peru' },
    'VE': { lat: 6.4238, lon: -66.5897, name: 'Venezuela' },
    'EC': { lat: -1.8312, lon: -78.1834, name: 'Ecuador' },
    'GB': { lat: 55.3781, lon: -3.4360, name: 'United Kingdom' },
    'IE': { lat: 53.1424, lon: -7.6921, name: 'Ireland' },
    'FR': { lat: 46.2276, lon: 2.2137, name: 'France' },
    'DE': { lat: 51.1657, lon: 10.4515, name: 'Germany' },
    'NL': { lat: 52.1326, lon: 5.2913, name: 'Netherlands' },
    'BE': { lat: 50.5039, lon: 4.4699, name: 'Belgium' },
    'LU': { lat: 49.8153, lon: 6.1296, name: 'Luxembourg' },
    'ES': { lat: 40.4637, lon: -3.7492, name: 'Spain' },
    'PT': { lat: 39.3999, lon: -8.2245, name: 'Portugal' },
    'IT': { lat: 41.8719, lon: 12.5674, name: 'Italy' },
    'CH': { lat: 46.8182, lon: 8.2275, name: 'Switzerland' },
    'AT': { lat: 47.5162, lon: 14.5501, name: 'Austria' },
    'SE': { lat: 60.1282, lon: 18.6435, name: 'Sweden' },
    'NO': { lat: 60.4720, lon: 8.4689, name: 'Norway' },
    'FI': { lat: 61.9241, lon: 25.7482, name: 'Finland' },
    'DK': { lat: 56.2639, lon: 9.5018, name: 'Denmark' },
    'IS': { lat: 64.9631, lon: -19.0208, name: 'Iceland' },
    'PL': { lat: 51.9194, lon: 19.1451, name: 'Poland' },
    'CZ': { lat: 49.8175, lon: 15.4730, name: 'Czech Republic' },
    'SK': { lat: 48.6690, lon: 19.6990, name: 'Slovakia' },
    'HU': { lat: 47.1625, lon: 19.5033, name: 'Hungary' },
    'RO': { lat: 45.9432, lon: 24.9668, name: 'Romania' },
    'BG': { lat: 42.7339, lon: 25.4858, name: 'Bulgaria' },
    'UA': { lat: 48.3794, lon: 31.1656, name: 'Ukraine' },
    'EE': { lat: 58.5953, lon: 25.0136, name: 'Estonia' },
    'LV': { lat: 56.8796, lon: 24.6032, name: 'Latvia' },
    'LT': { lat: 55.1694, lon: 23.8813, name: 'Lithuania' },
    'GR': { lat: 39.0742, lon: 21.8243, name: 'Greece' },
    'CY': { lat: 35.1264, lon: 33.4299, name: 'Cyprus' },
    'HR': { lat: 45.1000, lon: 15.2000, name: 'Croatia' },
    'SI': { lat: 46.1512, lon: 14.9955, name: 'Slovenia' },
    'RS': { lat: 44.0165, lon: 21.0059, name: 'Serbia' },
    'RU': { lat: 61.5240, lon: 105.3188, name: 'Russia' },
    'TR': { lat: 38.9637, lon: 35.2433, name: 'Turkey' },
    'CN': { lat: 35.8617, lon: 104.1954, name: 'China' },
    'JP': { lat: 36.2048, lon: 138.2529, name: 'Japan' },
    'KR': { lat: 35.9078, lon: 127.7669, name: 'South Korea' },
    'IN': { lat: 20.5937, lon: 78.9629, name: 'India' },
    'PK': { lat: 30.3753, lon: 69.3451, name: 'Pakistan' },
    'BD': { lat: 23.6850, lon: 90.3563, name: 'Bangladesh' },
    'LK': { lat: 7.8731, lon: 80.7718, name: 'Sri Lanka' },
    'SG': { lat: 1.3521, lon: 103.8198, name: 'Singapore' },
    'MY': { lat: 4.2105, lon: 101.9758, name: 'Malaysia' },
    'ID': { lat: -0.7893, lon: 113.9213, name: 'Indonesia' },
    'PH': { lat: 12.8797, lon: 121.7740, name: 'Philippines' },
    'TH': { lat: 15.8700, lon: 100.9925, name: 'Thailand' },
    'VN': { lat: 14.0583, lon: 108.2772, name: 'Vietnam' },
    'TW': { lat: 23.6978, lon: 120.9605, name: 'Taiwan' },
    'HK': { lat: 22.3193, lon: 114.1694, name: 'Hong Kong' },
    'AU': { lat: -25.2744, lon: 133.7751, name: 'Australia' },
    'NZ': { lat: -40.9006, lon: 174.8860, name: 'New Zealand' },
    'ZA': { lat: -30.5595, lon: 22.9375, name: 'South Africa' },
    'EG': { lat: 26.8206, lon: 30.8025, name: 'Egypt' },
    'NG': { lat: 9.0820, lon: 8.6753, name: 'Nigeria' },
    'KE': { lat: -0.0236, lon: 37.9062, name: 'Kenya' },
    'MA': { lat: 31.7917, lon: -7.0926, name: 'Morocco' },
    'DZ': { lat: 28.0339, lon: 1.6596, name: 'Algeria' },
    'SA': { lat: 23.8859, lon: 45.0792, name: 'Saudi Arabia' },
    'AE': { lat: 23.4241, lon: 53.8478, name: 'United Arab Emirates' },
    'IL': { lat: 31.0461, lon: 34.8516, name: 'Israel' },
    'QA': { lat: 25.3548, lon: 51.1839, name: 'Qatar' },
    'KW': { lat: 29.3117, lon: 47.4818, name: 'Kuwait' }
  };

  // ═══════════════════════════════════════════════════════════════
  // Leaflet OSM Dark Engine
  // ═══════════════════════════════════════════════════════════════
  var leafletMap = null;
  var mapMarkersLayer = null;

  function initLeafletMap() {
    if (typeof L === 'undefined') return;
    var container = document.getElementById('leaflet-map');
    if (!container || leafletMap) return;

    try {
      leafletMap = L.map('leaflet-map', {
        center: [22, 10],
        zoom: 2,
        minZoom: 1.5,
        maxZoom: 12,
        zoomControl: false,
        attributionControl: false
      });

      L.control.zoom({ position: 'topright' }).addTo(leafletMap);

      L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap'
      }).addTo(leafletMap);

      mapMarkersLayer = L.layerGroup().addTo(leafletMap);

      setTimeout(function() {
        if (leafletMap) leafletMap.invalidateSize();
      }, 300);
    } catch(e) {
      console.warn('Map initialization error:', e);
    }
  }

  window.resetMapZoom = function() {
    if (leafletMap) {
      leafletMap.setView([22, 10], 2);
    }
  };

  window.addEventListener('resize', function() {
    if (leafletMap) leafletMap.invalidateSize();
  });

  function updateWorldMap(stats) {
    if (!stats) return;
    var countries = stats.top_countries || [];
    var countEl = document.getElementById('map-country-count');
    if (countEl) {
      countEl.textContent = countries.length + (countries.length === 1 ? ' Country Detected' : ' Countries Detected');
    }

    // 1. Render Interactive Markers on Leaflet map (if active)
    if (leafletMap && mapMarkersLayer) {
      mapMarkersLayer.clearLayers();

      countries.forEach(function(c) {
        var code = (c.country_code || '').toUpperCase();
        if (!code || code === 'LAN' || code === 'LOCAL') return;
        var geo = countryCoords[code];
        if (!geo) return;

        var total = c.count || 0;
        var blocked = c.blocked || 0;
        var tarpit = c.tarpit || 0;
        var clean = Math.max(0, total - blocked - tarpit);

        var color = '#00ff9d';
        if (blocked > 0) color = '#ff3366';
        else if (tarpit > 0) color = '#ffb800';

        var flag = getFlagEmoji(code);
        var isFilterActive = filters.country === c.name || filters.country === code;

        var markerHtml = '<div class="soc-marker-wrap">' +
          '<div class="soc-marker-ring" style="border-color:' + color + ';"></div>' +
          '<div class="soc-marker-core" style="background:' + color + '; box-shadow:0 0 8px ' + color + ';"></div>' +
          '<div class="soc-marker-label" style="' + (isFilterActive ? 'border:1px solid #00e5ff; color:#00e5ff; box-shadow:0 0 8px rgba(0,229,255,0.4);' : '') + '">' + flag + ' ' + Number(total).toLocaleString() + '</div>' +
        '</div>';

        var customIcon = L.divIcon({
          className: 'soc-leaflet-div-icon',
          html: markerHtml,
          iconSize: [24, 24],
          iconAnchor: [12, 12]
        });

        var marker = L.marker([geo.lat, geo.lon], { icon: customIcon });

        var blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) + '%' : '0.0%';
        var tipHtml = '<div style="font-weight:700; font-size:12px; margin-bottom:4px; font-family:var(--mono);">' +
            flag + ' ' + (geo.name || c.name) + ' [' + code + ']' +
          '</div>' +
          '<div style="display:grid; grid-template-columns:auto auto; gap:2px 10px; font-family:var(--mono); font-size:11px;">' +
            '<span style="color:var(--overlay);">Hits:</span><b style="color:var(--text);">' + Number(total).toLocaleString() + '</b>' +
            '<span style="color:var(--overlay);">Blocked:</span><b style="color:var(--pink);">' + blocked + ' (' + blockRate + ')</b>' +
            '<span style="color:var(--overlay);">Tarpit:</span><b style="color:var(--yellow);">' + tarpit + '</b>' +
            '<span style="color:var(--overlay);">Clean:</span><b style="color:var(--green);">' + clean + '</b>' +
          '</div>' +
          '<div style="font-size:10px; color:var(--teal); margin-top:4px;">Click marker to filter ➔</div>';

        marker.bindTooltip(tipHtml, {
          direction: 'top',
          offset: [0, -12]
        });

        marker.on('click', function() {
          filterByCountry(c.name);
        });

        marker.addTo(mapMarkersLayer);
      });
    }

    // 2. Render Sidebar country breakdown with ASCII Progress Bars
    var listEl = document.getElementById('map-countries-list');
    if (listEl) {
      if (countries.length === 0) {
        listEl.innerHTML = '<div style="color:var(--overlay); font-size:11px; font-style:italic; padding:10px;">No countries detected yet</div>';
        return;
      }

      var listHTML = '';
      var maxHits = countries[0].count || 1;
      countries.forEach(function(c) {
        var code = (c.country_code || '').toUpperCase();
        var flag = getFlagEmoji(code);
        var total = c.count || 0;
        var blocked = c.blocked || 0;
        var tarpit = c.tarpit || 0;
        var isFilterActive = filters.country === c.name || filters.country === code;

        // Make ASCII mini bar (10 chars)
        var pct = (total / maxHits);
        var filled = Math.max(1, Math.round(pct * 10));
        var bar = '';
        for (var b = 0; b < 10; b++) {
          bar += (b < filled) ? '█' : '░';
        }

        var barColor = blocked > 0 ? 'var(--pink)' : (tarpit > 0 ? 'var(--yellow)' : 'var(--green)');

        listHTML += '<div class="map-country-item' + (isFilterActive ? ' active' : '') + '" onclick="filterByCountry(\'' + c.name + '\')">' +
          '<div style="display:flex; justify-content:space-between; align-items:center;">' +
            '<span style="font-weight:600; color:var(--text);">' + flag + ' ' + c.name + '</span>' +
            '<span style="font-weight:700; color:' + (blocked > 0 ? 'var(--pink)' : 'var(--teal)') + ';">' + Number(total).toLocaleString() + '</span>' +
          '</div>' +
          '<div style="display:flex; justify-content:space-between; align-items:center; font-size:10.5px; color:var(--overlay); margin-top:2px;">' +
            '<span style="color:' + barColor + ';">[' + bar + ']</span>' +
            '<span>' + (blocked > 0 ? '<span style="color:var(--pink);">' + blocked + ' blk</span> ' : '') +
            (tarpit > 0 ? '<span style="color:var(--yellow);">' + tarpit + ' tar</span> ' : '') + '</span>' +
          '</div>' +
        '</div>';
      });
      listEl.innerHTML = listHTML;
    }
  }

  function updateDonut(clean, blocked, tarpit, total) {
    if (total === 0) total = 1;
    var circ = 2 * Math.PI * 38; // ~238.76

    var pClean = clean / total;
    var pBlocked = blocked / total;
    var pTarpit = tarpit / total;

    var elClean = document.getElementById('donut-clean');
    var elBlocked = document.getElementById('donut-blocked');
    var elTarpit = document.getElementById('donut-tarpit');

    var lClean = pClean * circ;
    var lBlocked = pBlocked * circ;
    var lTarpit = pTarpit * circ;

    elClean.setAttribute('stroke-dasharray', lClean + ' ' + (circ - lClean));
    elClean.setAttribute('stroke-dashoffset', '0');

    elBlocked.setAttribute('stroke-dasharray', lBlocked + ' ' + (circ - lBlocked));
    elBlocked.setAttribute('stroke-dashoffset', -lClean);

    elTarpit.setAttribute('stroke-dasharray', lTarpit + ' ' + (circ - lTarpit));
    elTarpit.setAttribute('stroke-dashoffset', -(lClean + lBlocked));

    document.getElementById('donut-clean-lbl').textContent = (pClean * 100).toFixed(1) + '%';
    document.getElementById('donut-blocked-lbl').textContent = (pBlocked * 100).toFixed(1) + '%';
    document.getElementById('donut-tarpit-lbl').textContent = (pTarpit * 100).toFixed(1) + '%';
  }

  // Draw Highly Readable Timeline with Coordinate Grids, Axes & Crosshair
  function drawTimeline(data) {
    if (!data || data.length === 0) return;

    var cleanArea = document.getElementById('path-clean-area');
    var blockedArea = document.getElementById('path-blocked-area');
    var cleanLine = document.getElementById('path-clean-line');
    var blockedLine = document.getElementById('path-blocked-line');
    var tarpitLine = document.getElementById('path-tarpit-line');
    var gridGroup = document.getElementById('grid-group');
    var axesGroup = document.getElementById('axes-group');
    var pointsGroup = document.getElementById('points-group');
    var overlay = document.getElementById('chart-overlay');
    var crosshair = document.getElementById('crosshair-line');
    var crosshairDot = document.getElementById('crosshair-dot');
    var tooltip = document.getElementById('timeline-tooltip');

    var w = 800;
    var h = 240;
    var padLeft = 45;
    var padRight = 15;
    var padTop = 15;
    var padBottom = 26;

    var chartW = w - padLeft - padRight;
    var chartH = h - padTop - padBottom;

    var maxVal = 5;
    data.forEach(function(d) {
      if (d.total > maxVal) maxVal = d.total;
    });
    maxVal = Math.ceil(maxVal * 1.15);

    // 1. Draw Y-Axis Gridlines & Labels
    var gridHTML = '';
    var axesHTML = '';
    var yTicks = 4;
    for (var i = 0; i <= yTicks; i++) {
      var val = Math.round((maxVal / yTicks) * i);
      var y = padTop + chartH - (i / yTicks) * chartH;
      gridHTML += '<line x1="' + padLeft + '" y1="' + y + '" x2="' + (w - padRight) + '" y2="' + y + '" stroke="var(--line)" stroke-dasharray="2,2" />';
      axesHTML += '<text x="' + (padLeft - 8) + '" y="' + (y + 4) + '" fill="var(--overlay)" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">' + val + '</text>';
    }

    // 2. Draw X-Axis Ticks & Labels
    var step = chartW / Math.max(1, data.length - 1);
    var tickIndices = [];
    if (data.length === 1) {
      tickIndices = [0];
    } else if (data.length <= 5) {
      for (var k = 0; k < data.length; k++) tickIndices.push(k);
    } else {
      var numTicks = 5;
      for (var t = 0; t < numTicks; t++) {
        var idx = Math.round((t / (numTicks - 1)) * (data.length - 1));
        if (tickIndices.indexOf(idx) === -1) {
          tickIndices.push(idx);
        }
      }
    }

    tickIndices.forEach(function(idx) {
      var d = data[idx];
      if (!d) return;
      var x = padLeft + idx * step;
      var anchor = 'middle';
      if (idx === 0) anchor = 'start';
      else if (idx === data.length - 1) anchor = 'end';

      axesHTML += '<text x="' + x + '" y="' + (h - 6) + '" fill="var(--overlay)" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="' + anchor + '">' + (d.time || '') + '</text>';
      gridHTML += '<line x1="' + x + '" y1="' + padTop + '" x2="' + x + '" y2="' + (h - padBottom) + '" stroke="var(--line)" />';
    });

    gridGroup.innerHTML = gridHTML;
    axesGroup.innerHTML = axesHTML;

    // 3. Calculate Path Coordinates
    var ptsClean = [];
    var ptsBlocked = [];
    var ptsTarpit = [];
    var pointMap = [];

    if (data.length === 1) {
      var single = data[0];
      var yC = padTop + chartH - (single.clean / maxVal) * chartH;
      var yB = padTop + chartH - (single.blocked / maxVal) * chartH;
      var yT = padTop + chartH - (single.tarpit / maxVal) * chartH;
      ptsClean.push({ x: padLeft, y: yC }, { x: w - padRight, y: yC });
      ptsBlocked.push({ x: padLeft, y: yB }, { x: w - padRight, y: yB });
      ptsTarpit.push({ x: padLeft, y: yT }, { x: w - padRight, y: yT });
      pointMap.push({ x: (padLeft + w - padRight) / 2, yTotal: yC, data: single });
    } else {
      data.forEach(function(d, i) {
        var x = padLeft + i * step;
        var yClean = padTop + chartH - (d.clean / maxVal) * chartH;
        var yBlocked = padTop + chartH - (d.blocked / maxVal) * chartH;
        var yTarpit = padTop + chartH - (d.tarpit / maxVal) * chartH;
        var yTot = padTop + chartH - (d.total / maxVal) * chartH;
        ptsClean.push({ x: x, y: yClean });
        ptsBlocked.push({ x: x, y: yBlocked });
        ptsTarpit.push({ x: x, y: yTarpit });
        pointMap.push({ x: x, yTotal: yTot, data: d });
      });
    }

    function makePath(pts) {
      if (pts.length === 0) return '';
      var p = 'M ' + pts[0].x.toFixed(1) + ' ' + pts[0].y.toFixed(1);
      for (var i = 1; i < pts.length; i++) {
        p += ' L ' + pts[i].x.toFixed(1) + ' ' + pts[i].y.toFixed(1);
      }
      return p;
    }

    if (visibleSeries.clean) {
      cleanLine.setAttribute('d', makePath(ptsClean));
      cleanLine.style.display = 'inline';
      var areaClean = makePath(ptsClean) + ' L ' + ptsClean[ptsClean.length - 1].x.toFixed(1) + ' ' + (padTop + chartH) + ' L ' + ptsClean[0].x.toFixed(1) + ' ' + (padTop + chartH) + ' Z';
      cleanArea.setAttribute('d', areaClean);
      cleanArea.style.display = 'inline';
    } else {
      cleanLine.style.display = 'none';
      cleanArea.style.display = 'none';
    }

    if (visibleSeries.blocked) {
      blockedLine.setAttribute('d', makePath(ptsBlocked));
      blockedLine.style.display = 'inline';
      var areaBlocked = makePath(ptsBlocked) + ' L ' + ptsBlocked[ptsBlocked.length - 1].x.toFixed(1) + ' ' + (padTop + chartH) + ' L ' + ptsBlocked[0].x.toFixed(1) + ' ' + (padTop + chartH) + ' Z';
      blockedArea.setAttribute('d', areaBlocked);
      blockedArea.style.display = 'inline';
    } else {
      blockedLine.style.display = 'none';
      blockedArea.style.display = 'none';
    }

    if (visibleSeries.tarpit) {
      tarpitLine.setAttribute('d', makePath(ptsTarpit));
      tarpitLine.style.display = 'inline';
    } else {
      tarpitLine.style.display = 'none';
    }

    // Interactive Hover
    overlay.onmousemove = function(e) {
      var rect = overlay.getBoundingClientRect();
      var mouseX = (e.clientX - rect.left) * (w / rect.width);
      if (mouseX < padLeft || mouseX > w - padRight) {
        crosshair.style.display = 'none';
        if (crosshairDot) crosshairDot.style.display = 'none';
        tooltip.style.display = 'none';
        return;
      }

      var closest = pointMap[0];
      var minDiff = 999999;
      pointMap.forEach(function(pt) {
        var diff = Math.abs(pt.x - mouseX);
        if (diff < minDiff) {
          minDiff = diff;
          closest = pt;
        }
      });

      if (!closest) return;

      crosshair.setAttribute('x1', closest.x);
      crosshair.setAttribute('y1', padTop);
      crosshair.setAttribute('x2', closest.x);
      crosshair.setAttribute('y2', padTop + chartH);
      crosshair.style.display = 'inline';

      if (crosshairDot) {
        crosshairDot.setAttribute('cx', closest.x);
        crosshairDot.setAttribute('cy', closest.yTotal || padTop);
        crosshairDot.style.display = 'inline';
      }

      var d = closest.data;
      var rate = d.total > 0 ? ((d.blocked / d.total) * 100).toFixed(1) + '%' : '0.0%';
      var toolHTML = '<span style="color:var(--teal); font-weight:700;">⏱ ' + d.time + '</span> &nbsp;|&nbsp; ' +
        '<span style="color:var(--text-hi);">Total: <b>' + d.total + '</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:var(--green);">Clean: <b>' + d.clean + '</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:var(--pink);">Blocked: <b>' + d.blocked + ' (' + rate + ')</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:var(--yellow);">Tarpit: <b>' + d.tarpit + '</b></span>';

      tooltip.innerHTML = toolHTML;

      var box = document.getElementById('timeline-box');
      var boxW = box ? box.clientWidth : 800;
      var clientX = (closest.x / w) * boxW;
      var halfTip = 160;
      if (clientX < halfTip + 12) clientX = halfTip + 12;
      if (clientX > boxW - halfTip - 12) clientX = boxW - halfTip - 12;
      tooltip.style.left = clientX + 'px';
      tooltip.style.top = '10px';
      tooltip.style.display = 'block';
    };

    overlay.onmouseleave = function() {
      crosshair.style.display = 'none';
      if (crosshairDot) crosshairDot.style.display = 'none';
      tooltip.style.display = 'none';
    };
  }

  function renderSources(sources) {
    if (sources) {
      lastSources = sources;
    } else {
      sources = lastSources;
    }
    if (!sources) return;
    var sHTML = '<span style="font-weight: 600; color: var(--text-hi);">🌐 CONNECTED GATEWAYS & SERVERS:</span>';
    var count = 0;
    var nodeNames = [];

    if (sources.mode === 'file') {
      var fname = sources.file || 'Local Log File';
      nodeNames.push(fname);
      var isAct = (filters.node === fname);
      sHTML += '<span class="source-tag' + (isAct ? ' active' : '') + '" onclick="filterByNode(\'' + fname.replace(/'/g, "\\'") + '\')" title="Filter events from ' + fname.replace(/"/g, '&quot;') + '">📁 ' + fname + '</span>';
      count++;
    }

    if (sources.targets && sources.targets.length > 0) {
      sources.targets.forEach(function(t) {
        nodeNames.push(t.name);
        var sid = (t.id && t.id.length > 12) ? t.id.substring(0, 12) : t.id;
        var isAct = (filters.node === t.name);
        sHTML += '<span class="source-tag' + (isAct ? ' active' : '') + '" onclick="filterByNode(\'' + t.name.replace(/'/g, "\\'") + '\')" title="Filter events from container: ' + t.name.replace(/"/g, '&quot;') + '">🐳 ' + t.name + ' (' + sid + ')</span>';
        count++;
      });
    }

    if (sources.agents && sources.agents.length > 0) {
      sources.agents.forEach(function(ag) {
        nodeNames.push(ag.name);
        var isAct = (filters.node === ag.name);
        sHTML += '<span class="source-tag' + (isAct ? ' active' : '') + '" onclick="filterByNode(\'' + ag.name.replace(/'/g, "\\'") + '\')" title="Filter events from agent: ' + ag.name.replace(/"/g, '&quot;') + '">🌐 ' + ag.name + ' (' + (ag.remote_ip || 'remote') + ') <span style="color:var(--mauve);">🔒 X25519</span></span>';
        count++;
      });
    }

    if (count === 0 && sources.mode !== 'file') {
      sHTML += '<span style="color: var(--overlay); font-style: italic;">Awaiting local containers or remote agents (<code>rwarden push</code>)...</span>';
    }
    sourcesContainer.innerHTML = sHTML;

    // Harvest extra sources from allEvents or currentEvents
    if (allEvents && allEvents.length > 0) {
      allEvents.forEach(function(e) {
        if (e.source) nodeNames.push(e.source);
      });
    }

    if (selectNode) {
      var currentNode = filters.node || 'ALL';
      var nOptHTML = '<option value="ALL">📡 All Nodes</option>';
      var seen = {};
      nodeNames.forEach(function(name) {
        if (!name || seen[name]) return;
        seen[name] = true;
        var sel = (name === currentNode) ? ' selected' : '';
        nOptHTML += '<option value="' + name.replace(/"/g, '&quot;') + '"' + sel + '>📡 ' + name + '</option>';
      });
      if (currentNode !== 'ALL' && !seen[currentNode]) {
        nOptHTML += '<option value="' + currentNode.replace(/"/g, '&quot;') + '" selected>📡 ' + currentNode + '</option>';
      }
      if (selectNode.innerHTML !== nOptHTML) {
        selectNode.innerHTML = nOptHTML;
        selectNode.value = currentNode;
      }
    }
  }

  window.filterByNode = function(node) {
    if (!node || node === filters.node) {
      filters.node = 'ALL';
    } else {
      filters.node = node;
    }
    if (selectNode) selectNode.value = filters.node;
    currentPage = 1;
    renderActiveChips();
    renderTable();
    if (lastSources) renderSources(lastSources);
    scrollToLiveLog();
  };

  // IP Intelligence & Abuse Hub
  var ipModal = document.getElementById('ip-modal');
  var ipModalClose = document.getElementById('ip-modal-close-btn');
  if (ipModalClose) {
    ipModalClose.addEventListener('click', function() { ipModal.style.display = 'none'; });
  }
  window.addEventListener('click', function(e) {
    if (e.target === ipModal) ipModal.style.display = 'none';
  });

  function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode === 'LAN' || countryCode === 'LOCAL') return '🏠';
    if (countryCode.length !== 2) return '🌐';
    var c1 = countryCode.toUpperCase().charCodeAt(0);
    var c2 = countryCode.toUpperCase().charCodeAt(1);
    if (c1 < 65 || c1 > 90 || c2 < 65 || c2 > 90) return '🌐';
    return String.fromCodePoint(127397 + c1, 127397 + c2);
  }

  function generateAbuseReport(ip, info, eventsForIP) {
    var isp = (info && info.isp) ? info.isp : 'Network Provider';
    var as = (info && info.as) ? info.as : 'Unknown Network';
    var loc = ((info && info.city) ? info.city + ', ' : '') + ((info && info.country) ? info.country : 'Unknown Location');

    var rulesSet = {};
    var pathsSet = {};
    var sampleLines = [];
    eventsForIP.forEach(function(ev) {
      if (ev.rule) rulesSet[ev.rule] = true;
      if (ev.path) pathsSet[ev.path] = true;
      if (sampleLines.length < 8) {
        sampleLines.push('[' + formatLocalTime(ev) + '] ' + ev.method + ' ' + ev.path + ' -> HTTP ' + ev.status + ' (' + ev.verdict + (ev.rule ? ' - Rule: ' + ev.rule : '') + ')');
      }
    });

    var rulesList = Object.keys(rulesSet).join(', ') || 'Suspicious automated scanning or unauthorized requests';
    var pathsList = Object.keys(pathsSet).slice(0, 5).join(', ') || 'N/A';

    var report = 'Subject: Abuse Report: Suspicious or Hostile Activity Originating from IP ' + ip + '\n\n' +
      'Hello ' + isp + ' Abuse Team,\n\n' +
      'We are reporting suspicious or harmful network traffic originating from an IP address assigned to your network:\n\n' +
      '  * Offending IP Address: ' + ip + '\n' +
      '  * Network Provider: ' + isp + ' (' + as + ')\n' +
      '  * Estimated Location: ' + loc + '\n' +
      '  * Report Generated: ' + new Date().toLocaleString() + '\n' +
      '  * Triggered Security Rules: ' + rulesList + '\n' +
      '  * Targeted Web Paths: ' + pathsList + '\n\n' +
      'Summary of Activity:\n' +
      'This IP address made repeated unauthorized requests, vulnerability probes, or abusive requests that violated our web application security rules.\n\n' +
      'Log Excerpts:\n' +
      (sampleLines.length > 0 ? sampleLines.join('\n') : '[No specific request lines available]') + '\n\n' +
      'Please review this activity and take appropriate administrative action to prevent further abuse.\n\n' +
      'Thank you,\n' +
      'RouteWarden Security Team';

    return report;
  }

  window.inspectIP = function(ip) {
    if (!ip) return;
    var modal = document.getElementById('ip-modal');
    var content = document.getElementById('ip-modal-content');
    content.innerHTML = '<div style="text-align:center; padding:40px; color:var(--subtext);"><div class="pulse-dot" style="margin:0 auto 12px auto;"></div>Looking up location and security details for <b>' + ip + '</b>...</div>';
    modal.style.display = 'flex';

    var eventsForIP = allEvents.filter(function(e) { return e.client_ip === ip; });
    var totalHits = eventsForIP.length;
    var blockedHits = eventsForIP.filter(function(e) { return e.verdict === 'BLOCK'; }).length;
    var tarpitHits = eventsForIP.filter(function(e) { return e.verdict === 'TARPIT'; }).length;

    var rulesMap = {};
    eventsForIP.forEach(function(e) {
      if (e.rule) rulesMap[e.rule] = (rulesMap[e.rule] || 0) + 1;
    });
    var rulesList = Object.keys(rulesMap).join(', ') || 'None';

    function onData(info) {
      renderIPModal(ip, info, totalHits, blockedHits, tarpitHits, rulesList, eventsForIP);
    }

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/ip-lookup?ip=' + encodeURIComponent(ip), true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 200) {
          try {
            var data = JSON.parse(xhr.responseText);
            onData(data);
            return;
          } catch(e) {}
        }
        // Fallback directly to ip-api.com
        var fXhr = new XMLHttpRequest();
        fXhr.open('GET', 'http://ip-api.com/json/' + encodeURIComponent(ip) + '?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query', true);
        fXhr.onreadystatechange = function() {
          if (fXhr.readyState === 4) {
            try {
              var d = JSON.parse(fXhr.responseText);
              onData(d);
            } catch(err) {
              onData({ status: 'fail', message: 'Unable to connect to ip-api.com' });
            }
          }
        };
        fXhr.send();
      }
    };
    xhr.send();
  };

  function renderIPModal(ip, info, totalHits, blockedHits, tarpitHits, rulesList, eventsForIP) {
    var content = document.getElementById('ip-modal-content');
    var isPrivate = (info && info.is_private) || (info && info.message === 'reserved range');
    var countryCode = (info && info.country_code) || (info && info.countryCode) || (isPrivate ? 'LAN' : '');
    var flag = getFlagEmoji(countryCode);
    var country = (info && info.country) || (isPrivate ? 'Local / Private Network' : 'Unknown Country');
    var city = (info && info.city) || (isPrivate ? 'Local Subnet' : 'Unknown City');
    var region = (info && info.region_name) || (info && info.regionName) || (info && info.region) || '';
    var isp = (info && info.isp) || (isPrivate ? 'Private Network / Localhost' : 'Unknown Internet Provider');
    var org = (info && info.org) || (info && info.isp) || 'Unknown Organization';
    var asNum = (info && info.as) || 'N/A';
    var timezone = (info && info.timezone) || 'N/A';
    var latLon = (info && info.lat && info.lon) ? (info.lat + ', ' + info.lon) : 'N/A';

    var cleanHits = Math.max(0, totalHits - blockedHits - tarpitHits);

    // Determine Risk Assessment in plain English
    var riskClass = 'risk-safe';
    var riskIcon = '✅';
    var riskTitle = 'Normal Traffic — Safe';
    var riskDesc = 'This IP address has only made standard, allowed requests with no security rule violations.';
    var riskBadge = '<span class="tui-tag tag-green">ALLOWED</span>';

    if (blockedHits > 0) {
      riskClass = 'risk-high';
      riskIcon = '🛑';
      riskTitle = 'High Risk — Blocked by Security Rules';
      riskDesc = 'This IP made harmful requests (such as exploit attempts, unauthorized access, or malicious scanning) and was blocked.';
      riskBadge = '<span class="tui-tag tag-pink">BLOCKED</span>';
    } else if (tarpitHits > 0) {
      riskClass = 'risk-med';
      riskIcon = '⏳';
      riskTitle = 'Suspicious — Rate Throttled';
      riskDesc = 'This IP sent requests too fast or triggered rate limits, so its traffic was intentionally slowed down.';
      riskBadge = '<span class="tui-tag tag-yellow">SLOWED</span>';
    }

    var abuseReportText = generateAbuseReport(ip, info, eventsForIP);

    // Collect targeted paths
    var pathsMap = {};
    eventsForIP.forEach(function(e) {
      if (e.path) pathsMap[e.path] = (pathsMap[e.path] || 0) + 1;
    });
    var topPaths = Object.keys(pathsMap).sort(function(a, b) { return pathsMap[b] - pathsMap[a]; }).slice(0, 4).join(', ') || 'N/A';

    // Recent requests rows (up to 5)
    var recentEvents = eventsForIP.slice(0, 5);
    var recentRowsHTML = '';
    if (recentEvents.length === 0) {
      recentRowsHTML = '<tr><td colspan="4" style="color:var(--overlay); text-align:center; padding:12px;">No logged requests for this IP yet.</td></tr>';
    } else {
      recentEvents.forEach(function(ev) {
        var vTag = '<span class="tui-tag tag-green">Allowed</span>';
        if (ev.verdict === 'BLOCK') vTag = '<span class="tui-tag tag-pink">Blocked</span>';
        if (ev.verdict === 'TARPIT') vTag = '<span class="tui-tag tag-yellow">Slowed</span>';

        recentRowsHTML += '<tr>' +
          '<td style="color:var(--overlay); font-family:var(--mono); white-space:nowrap;">' + formatLocalTime(ev) + '</td>' +
          '<td><span class="method-tag method-' + (ev.method || 'GET').toLowerCase() + '">' + (ev.method || 'GET') + '</span></td>' +
          '<td style="color:var(--text); word-break:break-all; font-family:var(--mono);">' + (ev.path || '/') + '</td>' +
          '<td>' + vTag + '</td>' +
        '</tr>';
      });
    }

    var abuseEmail = 'abuse@' + encodeURIComponent(isp.toLowerCase().replace(/[^a-z0-9]/g, '') + '.com');

    var html = '' +
      '<div class="ip-header-banner">' +
        '<div class="ip-header-main">' +
          '<div class="ip-title-address">' +
            '<span>' + ip + '</span>' +
            '<button class="tui-btn" style="padding:3px 8px; font-size:11px;" onclick="copyText(\'' + ip + '\', this)">📋 Copy IP</button>' +
          '</div>' +
          '<div style="margin-top:6px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">' +
            '<span class="ip-geo-badge">' + flag + ' ' + country + (city ? ' — ' + city : '') + '</span>' +
            '<span class="ip-org-text">' + org + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="ip-header-actions">' +
          '<button class="tui-btn" onclick="filterAndCloseIP(\'' + ip + '\')" title="Filter request logs by this IP and scroll to results">🔍 Filter Logs</button>' +
        '</div>' +
      '</div>' +

      '<!-- Risk Status Alert Banner -->' +
      '<div class="ip-risk-card ' + riskClass + '">' +
        '<div class="risk-left">' +
          '<div class="risk-icon">' + riskIcon + '</div>' +
          '<div>' +
            '<div class="risk-title">' + riskTitle + '</div>' +
            '<div class="risk-desc">' + riskDesc + '</div>' +
          '</div>' +
        '</div>' +
        '<div>' + riskBadge + '</div>' +
      '</div>' +

      '<!-- Quick Numbers -->' +
      '<div class="ip-stat-strip">' +
        '<div class="ip-stat-card">' +
          '<div class="ip-stat-label">Total Requests</div>' +
          '<div class="ip-stat-val">' + totalHits + '</div>' +
          '<div class="ip-stat-sub">From this visitor</div>' +
        '</div>' +
        '<div class="ip-stat-card">' +
          '<div class="ip-stat-label">Blocked</div>' +
          '<div class="ip-stat-val" style="color:var(--pink);">' + blockedHits + '</div>' +
          '<div class="ip-stat-sub">403 Forbidden</div>' +
        '</div>' +
        '<div class="ip-stat-card">' +
          '<div class="ip-stat-label">Slowed Down</div>' +
          '<div class="ip-stat-val" style="color:var(--yellow);">' + tarpitHits + '</div>' +
          '<div class="ip-stat-sub">429 Rate Throttled</div>' +
        '</div>' +
        '<div class="ip-stat-card">' +
          '<div class="ip-stat-label">Passed Clean</div>' +
          '<div class="ip-stat-val" style="color:var(--green);">' + cleanHits + '</div>' +
          '<div class="ip-stat-sub">200 Normal Traffic</div>' +
        '</div>' +
      '</div>' +

      '<!-- Two Information Columns -->' +
      '<div class="ip-intel-grid">' +
        '<div class="ip-box">' +
          '<div class="ip-box-title">🌍 Location & Internet Provider</div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Country:</span><span class="ip-kv-val">' + flag + ' ' + country + ' (' + (countryCode || 'N/A') + ')</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">City / Region:</span><span class="ip-kv-val">' + city + (region ? ', ' + region : '') + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Internet Provider:</span><span class="ip-kv-val">' + isp + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Network (ASN):</span><span class="ip-kv-val">' + asNum + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Coordinates:</span><span class="ip-kv-val">' + latLon + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Timezone:</span><span class="ip-kv-val">' + timezone + '</span></div>' +
        '</div>' +

        '<div class="ip-box">' +
          '<div class="ip-box-title">🛡️ Security Summary & Activity</div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Triggered Rules:</span><span class="ip-kv-val" style="color:var(--text);">' + (rulesList === 'None' ? 'None (No rules violated)' : rulesList) + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Targeted Paths:</span><span class="ip-kv-val" style="font-family:var(--mono);">' + topPaths + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Observed Sessions:</span><span class="ip-kv-val">' + totalHits + ' total requests</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Threat Classification:</span><span class="ip-kv-val">' + (blockedHits > 0 ? '<span class="tui-tag tag-pink">HOSTILE</span>' : (tarpitHits > 0 ? '<span class="tui-tag tag-yellow">SUSPICIOUS</span>' : '<span class="tui-tag tag-green">BENIGN</span>')) + '</span></div>' +
          '<div class="ip-kv-row"><span class="ip-kv-label">Enforcement Action:</span><span class="ip-kv-val">' + (blockedHits > 0 ? 'Blocked at edge' : (tarpitHits > 0 ? 'Throttled in tarpit' : 'Forwarded normally')) + '</span></div>' +
        '</div>' +
      '</div>' +

      '<!-- Recent Requests Box -->' +
      '<div class="ip-recent-box">' +
        '<div class="ip-box-title">📋 Recent Requests From This IP</div>' +
        '<div style="overflow-x:auto;">' +
          '<table class="ip-recent-table">' +
            '<thead>' +
              '<tr>' +
                '<th>Time</th>' +
                '<th>Method</th>' +
                '<th>URL Path</th>' +
                '<th>Result</th>' +
              '</tr>' +
            '</thead>' +
            '<tbody>' + recentRowsHTML + '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<!-- Abuse Reporting Section -->' +
      '<div class="abuse-section">' +
        '<div class="abuse-header">' +
          '<div>' +
            '<div class="abuse-title">🚨 Report This IP & External Lookups</div>' +
            '<div class="abuse-desc">If this visitor is attacking your application, you can check external threat databases or send a pre-filled incident report to their internet hosting provider.</div>' +
          '</div>' +
          '<div class="abuse-actions-row">' +
            '<a href="https://www.abuseipdb.com/check/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🚨 Check on AbuseIPDB</a>' +
            '<a href="https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🔬 Check on VirusTotal</a>' +
            '<a href="https://who.is/whois-ip/ip-address/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🌐 View WHOIS</a>' +
          '</div>' +
        '</div>' +

        '<div class="abuse-report-card">' +
          '<div class="abuse-report-header">' +
            '<span>✉️ Ready-to-Send Incident Report</span>' +
            '<button class="tui-btn" id="btn-copy-report" onclick="copyReport()"><span id="copy-report-icon">📋</span> Copy Incident Report</button>' +
          '</div>' +
          '<textarea class="abuse-report-textarea" id="abuse-report-text" readonly>' + abuseReportText + '</textarea>' +
        '</div>' +

        '<div class="abuse-footer-actions">' +
          '<span class="abuse-email-hint">Provider abuse contact: <b>' + abuseEmail + '</b></span>' +
          '<a href="mailto:' + abuseEmail + '?subject=' + encodeURIComponent('Abuse Report: Malicious Activity from ' + ip) + '&body=' + encodeURIComponent(abuseReportText) + '" class="tui-btn">📧 Email Hosting Provider</a>' +
        '</div>' +
      '</div>';

    content.innerHTML = html;
  }

  window.filterAndCloseIP = function(ip) {
    document.getElementById('ip-modal').style.display = 'none';
    filterByIP(ip);
    setTimeout(scrollToLiveLog, 50);
  };

  window.copyText = function(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        var orig = btn.innerHTML;
        btn.innerHTML = '✅ Copied!';
        setTimeout(function() { btn.innerHTML = orig; }, 1800);
      });
    }
  };

  window.copyReport = function() {
    var area = document.getElementById('abuse-report-text');
    if (!area) return;
    area.select();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(area.value).then(function() {
        var btn = document.getElementById('btn-copy-report');
        if (btn) {
          btn.innerHTML = '<span>✅</span> Report Copied!';
          setTimeout(function() { btn.innerHTML = '<span>📋</span> Copy Incident Report'; }, 2000);
        }
      });
    } else {
      document.execCommand('copy');
      var btn = document.getElementById('btn-copy-report');
      if (btn) {
        btn.innerHTML = '<span>✅</span> Report Copied!';
        setTimeout(function() { btn.innerHTML = '<span>📋</span> Copy Incident Report'; }, 2000);
      }
    }
  };

  // Fetch initial stats
  function fetchStats() {
    if (isPaused) {
      return;
    }
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/stats', true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        if (xhr.status === 401) {
          window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
          return;
        }
        if (xhr.status === 200) {
          try {
            var data = JSON.parse(xhr.responseText);
            updateKPIs(data);
            if (data.auth_enabled) {
              var authBadge = document.getElementById('auth-status-badge');
              if (authBadge) {
                authBadge.textContent = '🔒 AUTH: ' + (data.auth_user || 'ACTIVE');
                authBadge.style.display = 'inline-block';
              }
              var btnLogout = document.getElementById('btn-logout');
              if (btnLogout) {
                btnLogout.style.display = 'inline-flex';
              }
            }
            if (data.sources) renderSources(data.sources);
            if (data.recent_events && allEvents.length === 0) {
              allEvents = data.recent_events;
              renderTable();
            }
          } catch(e) {}
        }
      }
    };
    xhr.send();
  }

  // Dashboard Sign Out
  window.logoutDashboard = function() {
    fetch('/api/auth/logout', { method: 'POST' })
      .then(function() {
        try { localStorage.removeItem('routewarden_auth'); } catch(e) {}
        window.location.href = '/login';
      })
      .catch(function() {
        window.location.href = '/logout';
      });
  };

  // Real-Time SSE Stream
  function initSSE() {
    var es = new EventSource('/api/stream');
    es.addEventListener('event', function(e) {
      try {
        var ev = JSON.parse(e.data);
        allEvents.unshift(ev);
        if (allEvents.length > 1000) allEvents.pop();

        if (isPaused) {
          pausedBufferedCount++;
          var pauseBadge = document.getElementById('pause-badge');
          if (pauseBadge) {
            pauseBadge.textContent = '⏸ PAUSED (+' + pausedBufferedCount + ' new)';
            pauseBadge.style.display = 'inline-block';
          }
        } else {
          if (matchesCurrentFilters(ev)) {
            if (currentPage === 1 && (!filters.timeRange || filters.timeRange === 'ALL')) {
              currentEvents.unshift(ev);
              if (currentEvents.length > pageSize) currentEvents.pop();
              totalFilteredCount++;
              var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
              renderRowsHTML(currentEvents);
              updatePaginationUI(totalFilteredCount, totalPages, 0, currentEvents.length);
              if (autoScroll && streamContainer && streamContainer.scrollTop <= 30) {
                streamContainer.scrollTop = 0;
              }
            } else {
              totalFilteredCount++;
              var totalPages = Math.max(1, Math.ceil(totalFilteredCount / pageSize));
              var startIndex = (currentPage - 1) * pageSize;
              var endIndex = Math.min(startIndex + currentEvents.length, totalFilteredCount);
              updatePaginationUI(totalFilteredCount, totalPages, startIndex, endIndex);
            }
          }
        }
      } catch(err) {}
    });
    es.addEventListener('connected', function() {
      var el = document.getElementById('stream-status');
      if (el && !isPaused) el.textContent = 'LIVE STREAM';
    });
    es.onerror = function() {
      var el = document.getElementById('stream-status');
      if (el && !isPaused) el.textContent = 'RECONNECTING...';
    };
  }

  function initMobileNavObserver() {
    var chips = document.querySelectorAll('.mobile-nav-chip');
    var sections = document.querySelectorAll('.soc-section');
    if (!sections.length || !chips.length) return;

    // Smooth click handler
    chips.forEach(function(chip) {
      chip.addEventListener('click', function(e) {
        var targetId = chip.getAttribute('data-target');
        var targetEl = document.getElementById(targetId);
        if (targetEl) {
          e.preventDefault();
          targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          chips.forEach(function(c) { c.classList.remove('active'); });
          chip.classList.add('active');
        }
      });
    });

    // Scroll spy via IntersectionObserver if supported
    if ('IntersectionObserver' in window) {
      var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            var id = entry.target.id;
            chips.forEach(function(c) {
              if (c.getAttribute('data-target') === id) {
                c.classList.add('active');
                if (c.scrollIntoViewIfNeeded) {
                  c.scrollIntoViewIfNeeded({ inline: 'center' });
                } else {
                  c.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'nearest' });
                }
              } else {
                c.classList.remove('active');
              }
            });
          }
        });
      }, {
        rootMargin: '-20% 0px -70% 0px',
        threshold: 0
      });

      sections.forEach(function(sec) {
        observer.observe(sec);
      });
    }
  }

  // Initial startup
  initLeafletMap();
  initMobileNavObserver();
  fetchStats();
  initSSE();
  setInterval(fetchStats, 3000);
})();
</script>
</body>
</html>`
