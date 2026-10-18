package observability

import (
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
	}
}

// GlobalStore returns the singleton event store.
func GlobalStore() *EventStore {
	return globalStore
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

// Add adds a structured security event to the store and broadcasts it.
func (s *EventStore) Add(ev *SecurityEvent) {
	if ev == nil {
		return
	}
	s.mu.Lock()

	s.nextID++
	ev.ID = s.nextID
	if ev.TimeStr == "" {
		if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
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
	atomic.AddInt64(&totalEvents, 1)
	isBlocked := ev.Verdict == "BLOCK" || ev.Status == 403
	isTarpit := ev.Verdict == "TARPIT" || ev.Status == 429
	if isBlocked {
		atomic.AddInt64(&blockedCount, 1)
	} else if isTarpit {
		atomic.AddInt64(&tarpitCount, 1)
	}

	// Timeline bucket (HH:MM)
	bucketKey := time.Now().Format("15:04")
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

	s.mu.Unlock()
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

		s.Add(ev)
		return ev
	}

	// Try Combined Apache/Nginx format
	if match := combinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		ev.ClientIP = match[1]
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
			if ev.Status == 403 {
				ev.Verdict = "BLOCK"
			} else if ev.Status == 429 {
				ev.Verdict = "TARPIT"
			} else {
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

	total := atomic.LoadInt64(&totalEvents)
	blocked := atomic.LoadInt64(&blockedCount)
	tarpit := atomic.LoadInt64(&tarpitCount)
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
	hasData := len(s.events) > 0
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="RouteWarden SOC INTELLIGENCE & Threat Defense Console">
  <title>[ 🛡️ ROUTEWARDEN ]</title>
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

    /* Datasheet (.spec) */
    .spec {
      border: 1px solid var(--line);
      background: var(--base);
      border-radius: 4px;
      overflow: hidden;
    }
    .spec div {
      display: flex;
      gap: 14px;
      padding: 6px 12px;
      font-size: 11.5px;
      border-bottom: 1px solid var(--line);
    }
    .spec div:last-child {
      border-bottom: 0;
    }
    .spec dt {
      color: var(--overlay);
      width: 8.5em;
      flex: none;
      margin: 0;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .spec dd {
      margin: 0;
      color: var(--text);
      min-width: 0;
      overflow-wrap: anywhere;
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
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 10.5px;
      font-weight: 600;
      border: 1px solid transparent;
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
      cursor: pointer;
      padding: 5px 8px;
      border: 1px solid var(--line);
      background: var(--base);
      border-radius: 3px;
      transition: border-color 0.12s ease;
    }
    .rule-item:hover {
      border-color: var(--line-hi);
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
    @media (max-width: 960px) {
      .intel-grid { grid-template-columns: 1fr; }
    }
    .intel-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 11.5px;
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
    .prompt-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 11.5px;
      color: var(--green);
      font-weight: 600;
    }
    .filters-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
    }
    .filter-tabs {
      display: inline-flex;
      border: 1px solid var(--line-hi);
      background: var(--panel);
      border-radius: 3px;
      overflow: hidden;
    }
    .tab-btn {
      font-family: var(--mono);
      font-size: 11px;
      background: transparent;
      border: none;
      padding: 4px 10px;
      color: var(--subtext);
      cursor: pointer;
      border-right: 1px solid var(--line-hi);
      transition: all 0.12s ease;
    }
    .tab-btn:last-child {
      border-right: none;
    }
    .tab-btn:hover {
      background: var(--surface);
      color: var(--text-hi);
    }
    .tab-btn.active {
      background: var(--surface);
      color: var(--teal);
      font-weight: 600;
    }

    .filter-select, .search-box {
      font-family: var(--mono);
      font-size: 11px;
      background: var(--panel);
      border: 1px solid var(--line-hi);
      color: var(--text);
      padding: 4px 8px;
      border-radius: 3px;
      outline: none;
      transition: border-color 0.12s ease;
    }
    .filter-select:focus, .search-box:focus {
      border-color: var(--teal);
    }
    .search-box {
      min-width: 200px;
      flex: 1;
    }

    .active-chips-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 11px;
    }
    .filter-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      background: var(--panel);
      border: 1px solid var(--line-hi);
      padding: 2px 7px;
      border-radius: 3px;
      color: var(--text);
    }
    .chip-close {
      cursor: pointer;
      color: var(--overlay);
    }
    .chip-close:hover {
      color: var(--pink);
    }
    .btn-clear-all {
      font-family: var(--mono);
      background: transparent;
      border: none;
      color: var(--pink);
      font-size: 11px;
      cursor: pointer;
      padding: 2px 4px;
    }
    .btn-clear-all:hover {
      text-decoration: underline;
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
      cursor: pointer;
      color: var(--pink);
      padding: 1px 6px;
      border-radius: 3px;
      border: 1px solid var(--pink-border);
      background: var(--pink-bg);
      font-size: 10.5px;
      text-shadow: var(--glow-text-pink);
      transition: all 0.12s ease;
    }
    .rule-tag:hover {
      background: var(--pink);
      color: var(--base);
      border-color: var(--pink);
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
      border-radius: 4px;
      width: 100%;
      max-width: 860px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 16px 48px rgba(0,0,0,0.8);
      display: flex;
      flex-direction: column;
    }
    .modal-header {
      padding: 10px 16px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-title {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: var(--text-hi);
    }
    .modal-close {
      cursor: pointer;
      color: var(--overlay);
      font-size: 18px;
      line-height: 1;
    }
    .modal-close:hover {
      color: var(--pink);
    }
    .modal-body {
      padding: 16px;
      font-size: 12px;
      line-height: 1.6;
    }

    /* IP Intelligence Details */
    .ip-header-banner {
      padding: 14px 16px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .ip-title-address {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 18px;
      font-weight: 700;
      color: var(--teal);
    }
    .ip-geo-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--surface);
      border: 1px solid var(--line-hi);
      padding: 2px 8px;
      border-radius: 3px;
      font-size: 11px;
      color: var(--text);
    }
    .ip-intel-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      padding: 16px;
    }
    @media (max-width: 720px) {
      .ip-intel-grid { grid-template-columns: 1fr; }
    }
    .ip-box {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 4px;
      padding: 12px;
    }
    .ip-box-title {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      color: var(--overlay);
      margin-bottom: 8px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 4px;
    }
    .ip-kv-row {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      font-size: 11.5px;
      padding: 4px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.02);
    }
    .ip-kv-label {
      color: var(--overlay);
    }
    .ip-kv-val {
      color: var(--text);
      font-weight: 500;
      text-align: right;
    }

    .abuse-section {
      padding: 14px 16px;
      border-top: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .abuse-actions-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .abuse-report-textarea {
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.5;
      background: var(--crust);
      border: 1px solid var(--line-hi);
      color: var(--text);
      padding: 10px;
      border-radius: 3px;
      width: 100%;
      height: 140px;
      resize: vertical;
      outline: none;
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
  </style>
</head>
<body>

<!-- ── Sticky Top Terminal Bar ─────────────────────────────── -->
<div class="bar">
  <div class="bar-left">
    <span>[ 🛡️ ROUTEWARDEN ]</span>
  </div>
  <div class="bar-mid">
    <div style="display:flex; align-items:center; gap:6px;">
      <span class="pulse-dot"></span>
      <span id="stream-status" style="color:var(--green); font-weight:600;">LIVE STREAM</span>
    </div>
    <span style="color:var(--line-hi);">|</span>
    <span id="utc-clock">00:00:00</span>
  </div>
  <div class="bar-right">
    <button class="tui-btn" id="btn-toggle-theme" onclick="toggleTheme()" title="Toggle Theme (System / Light / Dark)">
      <span id="theme-btn-icon">🌓</span> <span id="theme-btn-text">AUTO</span>
    </button>
    <button class="tui-btn" id="btn-toggle-scroll">⏸ Pause</button>
    <button class="tui-btn" id="btn-export-json">📥 Export</button>
    <button class="tui-btn" id="btn-clear-logs">🗑 Clear</button>
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
      <p class="lede">Real-time Reverse Proxy Intrusion Telemetry & Threat Defense</p>
      <p class="lede tight">Deterministic zero-knowledge cipher stream, edge tarpitting & active geo-surveillance.</p>
    </div>

    <dl class="spec">
      <div>
        <dt>TARGET</dt>
        <dd>Reverse Proxy Security Telemetry & Live SOC Stream</dd>
      </div>
      <div>
        <dt>ENGINE</dt>
        <dd>RouteWarden Core v5.0 // GoAccess Ingress Parser</dd>
      </div>
      <div>
        <dt>ORIGIN</dt>
        <dd>MaxMind GeoLite2 Autonomous Country Engine</dd>
      </div>
      <div>
        <dt>CIPHER</dt>
        <dd>X25519 + ChaCha20-Poly1305 / AES Zero-Knowledge</dd>
      </div>
    </dl>
  </header>

  <!-- ── Monitored Nodes Ribbon ────────────────────────────── -->
  <div class="sources-ribbon" id="sources-container">
    <span style="font-weight: 600; color: var(--text-hi);">🌐 MONITORED NODES:</span>
    <span style="color: var(--overlay); font-style: italic;">Discovering active containers & remote agents...</span>
  </div>

  <!-- ── Section 01: KPI Spec Cards ────────────────────────── -->
  <div class="head">
    <h2>01 // INGRESS TELEMETRY & ATTACK COUNTERS</h2>
    <div class="rule"></div>
    <span class="cmd">sys.stat.kpi</span>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card" style="border-top: 2px solid var(--teal);">
      <div class="kpi-top">
        <span class="kpi-label">Total Ingress</span>
        <span style="font-size:14px;">🛡️</span>
      </div>
      <div class="kpi-val" id="kpi-total">0</div>
      <div class="kpi-meter" id="kpi-meter-total">[████████████████] 100.0%</div>
      <div class="kpi-sub">Gateway ingress events</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--pink);">
      <div class="kpi-top">
        <span class="kpi-label">Threats Blocked</span>
        <span style="font-size:14px;">🛑</span>
      </div>
      <div class="kpi-val" style="color: var(--pink);" id="kpi-blocked">0</div>
      <div class="kpi-meter" style="color: var(--pink);" id="kpi-meter-blocked">[░░░░░░░░░░░░░░░░] 0.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-pink" id="kpi-block-rate">0.0% Rate</span> 403 Forbidden</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--yellow);">
      <div class="kpi-top">
        <span class="kpi-label">Throttled / Tarpit</span>
        <span style="font-size:14px;">⏳</span>
      </div>
      <div class="kpi-val" style="color: var(--yellow);" id="kpi-tarpit">0</div>
      <div class="kpi-meter" style="color: var(--yellow);" id="kpi-meter-tarpit">[░░░░░░░░░░░░░░░░] 0.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-yellow">429 Slowed</span> Hostile bots</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--green);">
      <div class="kpi-top">
        <span class="kpi-label">Clean Ingress</span>
        <span style="font-size:14px;">✅</span>
      </div>
      <div class="kpi-val" style="color: var(--green);" id="kpi-clean">0</div>
      <div class="kpi-meter" style="color: var(--green);" id="kpi-meter-clean">[████████████████] 100.0%</div>
      <div class="kpi-sub"><span class="tui-tag tag-green">200 OK</span> Legitimate traffic</div>
    </div>

    <div class="kpi-card" style="border-top: 2px solid var(--mauve);">
      <div class="kpi-top">
        <span class="kpi-label">Telemetry Cipher</span>
        <span style="font-size:14px;">🔒</span>
      </div>
      <div class="kpi-val" style="font-size: 18px; margin-top: 4px; color: var(--mauve);">X25519 + AES</div>
      <div class="kpi-meter" style="color: var(--mauve);">[ENCLAVE: ACTIVE]</div>
      <div class="kpi-sub"><span class="tui-tag tag-teal">Zero-Knowledge</span> ECDH Stream</div>
    </div>
  </div>

  <!-- ── Section 02: Real-Time SOC Security Event Stream ───── -->
  <div class="head">
    <h2>02 // SECURITY OPERATIONS LOG STREAM</h2>
    <div class="rule"></div>
    <span class="cmd">stream.audit.live</span>
  </div>

  <div class="term">
    <div class="console-toolbar">
      <div class="prompt-row">
        <span>rwarden@soc:~$</span>
        <span style="color:var(--text);">filter --stream=live</span>
      </div>

      <div class="filters-row">
        <div class="filter-tabs">
          <button class="tab-btn active" data-filter-verdict="ALL">[ALL: <span id="count-tab-all">0</span>]</button>
          <button class="tab-btn" data-filter-verdict="BLOCK">[🛑 BLOCKED: <span id="count-tab-block">0</span>]</button>
          <button class="tab-btn" data-filter-verdict="TARPIT">[⏳ TARPIT: <span id="count-tab-tarpit">0</span>]</button>
          <button class="tab-btn" data-filter-verdict="ALLOW">[✅ CLEAN: <span id="count-tab-clean">0</span>]</button>
        </div>

        <select class="filter-select" id="select-country">
          <option value="ALL">All Countries</option>
        </select>

        <select class="filter-select" id="select-method">
          <option value="ALL">All Methods</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>

        <select class="filter-select" id="select-status">
          <option value="ALL">All Statuses</option>
          <option value="2xx">2xx Success</option>
          <option value="403">403 Forbidden</option>
          <option value="429">429 Tarpit</option>
          <option value="4xx">4xx Client Errors</option>
          <option value="5xx">5xx Server Errors</option>
        </select>

        <select class="filter-select" id="select-rule">
          <option value="ALL">All Threat Rules</option>
        </select>

        <input type="text" class="search-box" id="search-input" placeholder="Search IP, Path, Rule, Status...">
      </div>

      <div class="active-chips-bar" id="active-chips-container" style="display:none;">
        <span style="color:var(--overlay);">ACTIVE FILTERS:</span>
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
  </div>

  <!-- ── Section 03: World Map & Threat Geo-Distribution ───── -->
  <div class="head">
    <h2>03 // GEO-DISTRIBUTION & ATTACK MATRIX</h2>
    <div class="rule"></div>
    <span class="cmd">geo.threat.matrix</span>
  </div>

  <div class="term">
    <div class="cap">
      <div style="display:flex; align-items:center; gap:8px;">
        <span>🌐 GLOBAL THREAT & INGRESS RADAR</span>
        <span class="tui-tag tag-teal" id="map-country-count">0 Countries Detected</span>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="display:flex; align-items:center; gap:10px; font-size:11px;">
          <span><span style="color:var(--green);">●</span> Clean</span>
          <span><span style="color:var(--pink);">■</span> Threats</span>
          <span><span style="color:var(--yellow);">▲</span> Tarpit</span>
        </div>
        <button class="tui-btn" id="btn-reset-map" onclick="resetMapZoom()">[⟲ RESET VIEW]</button>
      </div>
    </div>

    <div class="map-body">
      <div class="map-stage">
        <div id="leaflet-map"></div>
      </div>

      <!-- Right Sidebar: Detected Countries Breakdown -->
      <div class="map-sidebar">
        <div class="map-sidebar-title">
          <span>Detected Countries</span>
          <span style="color:var(--teal);">Real-Time</span>
        </div>
        <div id="map-countries-list" class="map-countries-list">
          <div style="color:var(--overlay); font-size:11px; font-style:italic; padding:10px;">Awaiting parsed telemetry...</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Section 04: Telemetry Dynamics ────────────────────── -->
  <div class="head">
    <h2>04 // TELEMETRY DYNAMICS & THREAT SIGNATURES</h2>
    <div class="rule"></div>
    <span class="cmd">sig.threat.timeline</span>
  </div>

  <div class="charts-grid">
    <!-- Real-Time Timeline Curve -->
    <div class="chart-card">
      <div class="card-cap">
        <span>📈 INGRESS VELOCITY & THREAT TIMELINE</span>
        <div class="timeline-legend">
          <span class="legend-item" id="legend-clean"><span style="color:var(--green);">●</span> Clean</span>
          <span class="legend-item" id="legend-blocked"><span style="color:var(--pink);">■</span> Blocked</span>
          <span class="legend-item" id="legend-tarpit"><span style="color:var(--yellow);">▲</span> Tarpit</span>
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
        <span>🎯 THREAT RATIO & SIGNATURES</span>
      </div>
      <div class="donut-wrap">
        <svg class="donut-svg" viewBox="0 0 100 100" id="donut-svg">
          <circle cx="50" cy="50" r="38" fill="transparent" stroke="var(--line)" stroke-width="12"></circle>
          <circle id="donut-clean" cx="50" cy="50" r="38" fill="transparent" stroke="var(--green)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-blocked" cx="50" cy="50" r="38" fill="transparent" stroke="var(--pink)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-tarpit" cx="50" cy="50" r="38" fill="transparent" stroke="var(--yellow)" stroke-width="12" stroke-dasharray="0 238.7"></circle>
        </svg>
        <div class="donut-legend">
          <div><span style="color:var(--green);">●</span> Clean: <span id="donut-clean-lbl">0%</span></div>
          <div><span style="color:var(--pink);">■</span> Blocked: <span id="donut-blocked-lbl">0%</span></div>
          <div><span style="color:var(--yellow);">▲</span> Tarpit: <span id="donut-tarpit-lbl">0%</span></div>
        </div>
      </div>
      <div style="font-size:10.5px; font-weight:700; color:var(--overlay); text-transform:uppercase; letter-spacing:0.5px; padding:0 14px;">Top Triggered Rules:</div>
      <div class="rules-list" id="rules-container">
        <div style="color:var(--overlay); font-size:11px; font-style:italic;">Awaiting rule triggers...</div>
      </div>
    </div>
  </div>

  <!-- ── Section 05: Intelligence Vectors ──────────────────── -->
  <div class="head">
    <h2>05 // INTELLIGENCE VECTORS & HOTSPOTS</h2>
    <div class="rule"></div>
    <span class="cmd">intel.vectors.query</span>
  </div>

  <div class="intel-grid">
    <div class="chart-card">
      <div class="card-cap">
        <span>🚨 TOP ATTACKING CLIENT IPS</span>
        <span style="font-size:10.5px; color:var(--overlay);">Click row to inspect</span>
      </div>
      <div style="max-height:260px; overflow-y:auto;">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Client IP</th>
              <th>Origin</th>
              <th>Hits</th>
              <th>Threat Breakdown</th>
            </tr>
          </thead>
          <tbody id="top-ips-tbody">
            <tr><td colspan="4" style="color:var(--overlay); text-align:center;">No threat IPs logged yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="chart-card">
      <div class="card-cap">
        <span>🎯 TOP TARGETED ENDPOINTS</span>
        <span style="font-size:10.5px; color:var(--overlay);">Click row to filter</span>
      </div>
      <div style="max-height:260px; overflow-y:auto;">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Target Path</th>
              <th>Requests</th>
              <th>Triggered Rule</th>
            </tr>
          </thead>
          <tbody id="top-paths-tbody">
            <tr><td colspan="3" style="color:var(--overlay); text-align:center;">No endpoints logged yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

</div>

<!-- ── Telemetry Event Inspector Modal ──────────────────────── -->
<div class="modal-overlay" id="event-modal">
  <div class="modal-card">
    <div class="modal-header">
      <span class="modal-title">🔍 TELEMETRY EVENT INSPECTOR</span>
      <span class="modal-close" id="modal-close-btn">&times;</span>
    </div>
    <div class="modal-body" id="modal-content"></div>
  </div>
</div>

<!-- ── IP Threat Intelligence & Abuse Hub Modal ─────────────── -->
<div class="modal-overlay" id="ip-modal">
  <div class="ip-modal-card">
    <div class="modal-header">
      <span class="modal-title">🌐 IP THREAT INTELLIGENCE & ABUSE HUB</span>
      <span class="modal-close" id="ip-modal-close-btn">&times;</span>
    </div>
    <div id="ip-modal-content"></div>
  </div>
</div>

<!-- ── Terminal Keybindings Status Footer ────────────────────── -->
<div class="tui-footer">
  <div class="footer-keys">
    <span class="footer-key-item"><span class="key-cap">T</span> Theme</span>
    <span class="footer-key-item"><span class="key-cap">F</span> Filter Country</span>
    <span class="footer-key-item"><span class="key-cap">P</span> Filter Path</span>
    <span class="footer-key-item"><span class="key-cap">I</span> Inspect IP</span>
    <span class="footer-key-item"><span class="key-cap">R</span> Reset Filters</span>
    <span class="footer-key-item"><span class="key-cap">ESC</span> Close Modal</span>
  </div>
  <div>ROUTEWARDEN SOC // ACTIVE DEFENSE</div>
</div>

<script>
(function() {
  var autoScroll = true;
  var allEvents = [];
  var timelineData = [];

  // Active Filter State
  var filters = {
    verdict: 'ALL',
    country: 'ALL',
    method: 'ALL',
    status: 'ALL',
    rule: 'ALL',
    search: '',
    ip: '',
    path: ''
  };

  var latestStats = null;

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
  var btnClearLogs = document.getElementById('btn-clear-logs');
  var btnExportJSON = document.getElementById('btn-export-json');
  var btnResetFilters = document.getElementById('btn-reset-filters');
  var searchInput = document.getElementById('search-input');
  var selectCountry = document.getElementById('select-country');
  var selectMethod = document.getElementById('select-method');
  var selectStatus = document.getElementById('select-status');
  var selectRule = document.getElementById('select-rule');
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

  selectRule.addEventListener('change', function(e) {
    filters.rule = e.target.value;
    renderActiveChips();
    renderTable();
  });

  searchInput.addEventListener('input', function(e) {
    filters.search = e.target.value.toLowerCase().trim();
    renderActiveChips();
    renderTable();
  });

  btnToggleScroll.addEventListener('click', function() {
    autoScroll = !autoScroll;
    btnToggleScroll.textContent = autoScroll ? '⏸ Pause' : '▶ Resume';
    btnToggleScroll.style.color = autoScroll ? 'var(--text)' : 'var(--yellow)';
    if (autoScroll) {
      renderTable();
    }
  });

  window.jumpToLatest = function() {
    if (streamContainer) {
      streamContainer.scrollTo({ top: 0, behavior: 'smooth' });
    }
    if (!autoScroll) {
      btnToggleScroll.click();
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

  btnClearLogs.addEventListener('click', function() {
    allEvents = [];
    renderTable();
  });

  btnResetFilters.addEventListener('click', function() {
    resetAllFilters();
  });

  function resetAllFilters() {
    filters.verdict = 'ALL';
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

    selectCountry.value = 'ALL';
    selectMethod.value = 'ALL';
    selectStatus.value = 'ALL';
    selectRule.value = 'ALL';
    searchInput.value = '';

    renderActiveChips();
    renderTable();
    if (latestStats) updateWorldMap(latestStats);
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
    } else if (e.key === 't' || e.key === 'T') {
      toggleTheme();
    } else if (e.key === 'r' || e.key === 'R') {
      resetAllFilters();
    } else if (e.key === 'f' || e.key === 'F') {
      selectCountry.focus();
    } else if (e.key === 'p' || e.key === 'P') {
      searchInput.focus();
    }
  });

  function renderActiveChips() {
    var chips = [];
    if (filters.verdict !== 'ALL') chips.push({ label: 'Verdict: ' + filters.verdict, clear: function() {
      filters.verdict = 'ALL';
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      var ab = document.querySelector('[data-filter-verdict="ALL"]');
      if (ab) ab.classList.add('active');
    }});
    if (filters.country !== 'ALL') chips.push({ label: 'Country: ' + filters.country, clear: function() { filters.country = 'ALL'; selectCountry.value = 'ALL'; }});
    if (filters.method !== 'ALL') chips.push({ label: 'Method: ' + filters.method, clear: function() { filters.method = 'ALL'; selectMethod.value = 'ALL'; }});
    if (filters.status !== 'ALL') chips.push({ label: 'Status: ' + filters.status, clear: function() { filters.status = 'ALL'; selectStatus.value = 'ALL'; }});
    if (filters.rule !== 'ALL') chips.push({ label: 'Rule: ' + filters.rule, clear: function() { filters.rule = 'ALL'; selectRule.value = 'ALL'; }});
    if (filters.search) chips.push({ label: 'Search: "' + filters.search + '"', clear: function() { filters.search = ''; searchInput.value = ''; }});
    if (filters.ip) chips.push({ label: 'IP: ' + filters.ip, clear: function() { filters.ip = ''; }});
    if (filters.path) chips.push({ label: 'Path: ' + filters.path, clear: function() { filters.path = ''; }});

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
    return allEvents.filter(function(ev) {
      if (filters.verdict !== 'ALL' && ev.verdict !== filters.verdict) return false;
      if (filters.country !== 'ALL' && ev.country !== filters.country && ev.country_code !== filters.country) return false;
      if (filters.method !== 'ALL' && (ev.method || '').toUpperCase() !== filters.method) return false;
      if (filters.rule !== 'ALL' && (ev.rule || '') !== filters.rule) return false;
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
        var str = (ev.client_ip + ' ' + (ev.country || '') + ' ' + ev.path + ' ' + (ev.rule || '') + ' ' + ev.method + ' ' + ev.status).toLowerCase();
        if (str.indexOf(filters.search) === -1) return false;
      }
      return true;
    });
  }

  function renderTable() {
    var filtered = getFilteredEvents();
    var rowsHTML = '';
    filtered.slice(0, 250).forEach(function(ev) {
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
        ruleHTML = '<span class="rule-tag" title="Filter by rule: ' + ev.rule + '" onclick="event.stopPropagation(); filterByRule(\'' + ev.rule + '\')">🛡️ ' + ev.rule + '</span>';
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

    streamTbody.innerHTML = rowsHTML || '<tr><td colspan="8" style="color:var(--overlay); text-align:center; padding:20px;">No matching events</td></tr>';

    if (streamContainer) {
      if (autoScroll && streamContainer.scrollTop <= 30) {
        streamContainer.scrollTop = 0;
      }
    }
  }

  window.inspectEvent = function(id) {
    var found = allEvents.find(function(e) { return e.id === id; });
    if (!found) return;

    modalContent.innerHTML = '<div style="margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; border-bottom:1px solid var(--line); padding-bottom:10px;">' +
      '<div>SOURCE IP: <b style="color:var(--teal);">' + found.client_ip + '</b>' + (found.country ? ' <span style="margin-left:8px;">' + getFlagEmoji(found.country_code) + ' ' + found.country + '</span>' : '') + '</div>' +
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

    // Populate Rule Dropdown & List
    if (stats.top_rules && stats.top_rules.length > 0) {
      var currentSel = selectRule.value;
      var optHTML = '<option value="ALL">All Threat Rules</option>';
      stats.top_rules.forEach(function(r) {
        optHTML += '<option value="' + r.name + '">' + r.name + ' (' + r.count + ')</option>';
      });
      if (selectRule.innerHTML !== optHTML) {
        selectRule.innerHTML = optHTML;
        selectRule.value = currentSel;
      }

      var maxRuleCount = stats.top_rules[0].count || 1;
      var rHTML = '';
      stats.top_rules.forEach(function(r) {
        var pct = ((r.count / maxRuleCount) * 100).toFixed(1);
        rHTML += '<div class="rule-item" onclick="filterByRule(\'' + r.name + '\')">' +
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
          '<td><span style="cursor:pointer;" onclick="filterByCountry(\'' + countryName + '\')">' + flag + ' ' + countryName + '</span></td>' +
          '<td>' + Number(item.count).toLocaleString() + '</td>' +
          '<td><span class="tui-tag tag-pink">' + item.blocked + ' blk</span> <span class="tui-tag tag-yellow">' + item.tarpit + ' tar</span> ' +
          '<button class="tui-btn" style="padding:1px 6px; font-size:10px; margin-left:6px;" onclick="inspectIP(\'' + item.name + '\')">🚨 Report</button></td>' +
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
        pHTML += '<tr onclick="filterByPath(\'' + item.name + '\')" style="cursor:pointer;">' +
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
  };

  window.filterByRule = function(rule) {
    filters.rule = rule;
    selectRule.value = rule;
    renderActiveChips();
    renderTable();
  };

  window.filterByIP = function(ip) {
    filters.ip = ip;
    renderActiveChips();
    renderTable();
  };

  window.filterByPath = function(path) {
    filters.path = path;
    renderActiveChips();
    renderTable();
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
    if (!sources) return;
    var sHTML = '<span style="font-weight: 600; color: var(--text-hi);">🌐 MONITORED NODES:</span>';
    var count = 0;

    if (sources.mode === 'file') {
      sHTML += '<span class="source-tag">📁 ' + (sources.file || 'Local Log File') + '</span>';
      count++;
    }

    if (sources.targets && sources.targets.length > 0) {
      sources.targets.forEach(function(t) {
        var sid = (t.id && t.id.length > 12) ? t.id.substring(0, 12) : t.id;
        sHTML += '<span class="source-tag">🐳 ' + t.name + ' (' + sid + ')</span>';
        count++;
      });
    }

    if (sources.agents && sources.agents.length > 0) {
      sources.agents.forEach(function(ag) {
        sHTML += '<span class="source-tag">🌐 ' + ag.name + ' (' + (ag.remote_ip || 'remote') + ') <span style="color:var(--mauve);">🔒 X25519</span></span>';
        count++;
      });
    }

    if (count === 0 && sources.mode !== 'file') {
      sHTML += '<span style="color: var(--overlay); font-style: italic;">Awaiting local containers or remote agents (<code>rwarden push</code>)...</span>';
    }
    sourcesContainer.innerHTML = sHTML;
  }

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
    var now = new Date().toISOString();
    var isp = (info && info.isp) ? info.isp : 'Network Provider';
    var as = (info && info.as) ? info.as : 'Unknown AS';
    var loc = ((info && info.city) ? info.city + ', ' : '') + ((info && info.country) ? info.country : 'Unknown Location');

    var rulesSet = {};
    var pathsSet = {};
    var sampleLines = [];
    eventsForIP.forEach(function(ev) {
      if (ev.rule) rulesSet[ev.rule] = true;
      if (ev.path) pathsSet[ev.path] = true;
      if (sampleLines.length < 6) {
        sampleLines.push('[' + formatLocalTime(ev) + '] ' + ev.method + ' ' + ev.path + ' -> HTTP ' + ev.status + ' (' + ev.verdict + (ev.rule ? ' - Rule: ' + ev.rule : '') + ')');
      }
    });

    var rulesList = Object.keys(rulesSet).join(', ') || 'Hostile Automated Scanning / Exploit Probing';

    var report = 'Subject: Abuse Report: Hostile Activity Originating from ' + ip + '\n\n' +
      'Dear ' + isp + ' Abuse Team,\n\n' +
      'We are writing to report malicious security incidents originating from an IP address assigned to your network:\n\n' +
      '  * Offending IP: ' + ip + '\n' +
      '  * Network Provider: ' + isp + ' (' + as + ')\n' +
      '  * Origin Location: ' + loc + '\n' +
      '  * Reported At: ' + new Date().toLocaleString() + '\n' +
      '  * Attack Categories: ' + rulesList + '\n' +
      '  * Target Gateway: RouteWarden SOC Protected Ingress\n\n' +
      'Incident Summary:\n' +
      'The aforementioned IP address engaged in unauthorized access attempts, vulnerability scanning, and hostile exploitation against our services.\n\n' +
      'Sample Incident Logs:\n' +
      (sampleLines.length > 0 ? sampleLines.join('\n') : '[Sample: Hostile vulnerability scan detected by RouteWarden]') + '\n\n' +
      'Please investigate this activity and take appropriate administrative action to mitigate further abuse.\n\n' +
      'Regards,\n' +
      'Security Operations Center (RouteWarden Gateway Defense)';

    return report;
  }

  window.inspectIP = function(ip) {
    if (!ip) return;
    var modal = document.getElementById('ip-modal');
    var content = document.getElementById('ip-modal-content');
    content.innerHTML = '<div style="text-align:center; padding:40px; color:var(--subtext);"><div class="pulse-dot" style="margin:0 auto 12px auto;"></div>Fetching IP geolocation & threat intelligence for <b>' + ip + '</b>...</div>';
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
    var isp = (info && info.isp) || (isPrivate ? 'RFC 1918 / Loopback' : 'Unknown ISP');
    var org = (info && info.org) || (info && info.isp) || 'Unknown Organization';
    var asNum = (info && info.as) || 'N/A';
    var timezone = (info && info.timezone) || 'N/A';
    var latLon = (info && info.lat && info.lon) ? (info.lat + ', ' + info.lon) : 'N/A';

    var abuseReportText = generateAbuseReport(ip, info, eventsForIP);

    var html = '<div class="ip-header-banner">' +
      '<div>' +
        '<div class="ip-title-address">' +
          '<span>' + ip + '</span>' +
          '<button class="tui-btn" style="padding:2px 6px; font-size:10.5px;" onclick="copyText(\'' + ip + '\', this)">📋 Copy</button>' +
        '</div>' +
        '<div style="margin-top:6px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">' +
          '<span class="ip-geo-badge">' + flag + ' ' + country + (city ? ' — ' + city : '') + '</span>' +
          '<span style="font-size:11px; color:var(--subtext);">' + org + '</span>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex; gap:8px;">' +
        '<button class="tui-btn" onclick="filterAndCloseIP(\'' + ip + '\')">🔍 Filter Logs</button>' +
      '</div>' +
    '</div>' +

    '<div class="ip-intel-grid">' +
      '<div class="ip-box">' +
        '<div class="ip-box-title">🌍 Geolocation & Network (MaxMind / IP-API)</div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Country:</span><span class="ip-kv-val">' + flag + ' ' + country + ' (' + (countryCode || 'N/A') + ')</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">City / Region:</span><span class="ip-kv-val">' + city + (region ? ', ' + region : '') + '</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">ISP:</span><span class="ip-kv-val">' + isp + '</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Autonomous System:</span><span class="ip-kv-val">' + asNum + '</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Coordinates:</span><span class="ip-kv-val">' + latLon + '</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Timezone:</span><span class="ip-kv-val">' + timezone + '</span></div>' +
      '</div>' +

      '<div class="ip-box">' +
        '<div class="ip-box-title">🛡️ RouteWarden Gateway Telemetry</div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Observed Hits:</span><span class="ip-kv-val" style="color:var(--text-hi);">' + totalHits + ' requests</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Blocked (403):</span><span class="ip-kv-val" style="color:var(--pink);">' + blockedHits + ' threats</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Tarpitted (429):</span><span class="ip-kv-val" style="color:var(--yellow);">' + tarpitHits + ' throttled</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Triggered Rules:</span><span class="ip-kv-val" style="color:var(--text);">' + rulesList + '</span></div>' +
        '<div class="ip-kv-row"><span class="ip-kv-label">Threat Severity:</span><span class="ip-kv-val">' + (blockedHits > 0 ? '<span class="tui-tag tag-pink">HOSTILE</span>' : (tarpitHits > 0 ? '<span class="tui-tag tag-yellow">SUSPICIOUS</span>' : '<span class="tui-tag tag-green">BENIGN</span>')) + '</span></div>' +
      '</div>' +
    '</div>' +

    '<div class="abuse-section">' +
      '<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">' +
        '<span style="font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; color:var(--pink);">🚨 Abuse Reporting & External Intelligence</span>' +
        '<div class="abuse-actions-row">' +
          '<a href="https://www.abuseipdb.com/check/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🚨 AbuseIPDB</a>' +
          '<a href="https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🔬 VirusTotal</a>' +
          '<a href="https://who.is/whois-ip/ip-address/' + encodeURIComponent(ip) + '" target="_blank" rel="noopener noreferrer" class="tui-btn">🌐 WHOIS</a>' +
        '</div>' +
      '</div>' +

      '<div style="font-size:10.5px; color:var(--subtext);">Standardized incident report generated from RouteWarden logs (ready to submit to host / CERT):</div>' +
      '<textarea class="abuse-report-textarea" id="abuse-report-text" readonly>' + abuseReportText + '</textarea>' +

      '<div style="display:flex; justify-content:flex-end; gap:8px; align-items:center; flex-wrap:wrap;">' +
        '<button class="tui-btn" id="btn-copy-report" onclick="copyReport()"><span id="copy-report-icon">📋</span> Copy Incident Report</button>' +
        '<a href="mailto:abuse@' + encodeURIComponent(isp.toLowerCase().replace(/[^a-z0-9]/g, '') + '.com') + '?subject=' + encodeURIComponent('Abuse Report: Malicious Activity from ' + ip) + '&body=' + encodeURIComponent(abuseReportText) + '" class="tui-btn">📧 Mail Host Abuse Contact</a>' +
      '</div>' +
    '</div>';

    content.innerHTML = html;
  }

  window.filterAndCloseIP = function(ip) {
    document.getElementById('ip-modal').style.display = 'none';
    filterByIP(ip);
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
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/stats', true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          updateKPIs(data);
          if (data.sources) renderSources(data.sources);
          if (data.recent_events && allEvents.length === 0) {
            allEvents = data.recent_events;
            renderTable();
          }
        } catch(e) {}
      }
    };
    xhr.send();
  }

  // Real-Time SSE Stream
  function initSSE() {
    var es = new EventSource('/api/stream');
    es.addEventListener('event', function(e) {
      try {
        var ev = JSON.parse(e.data);
        allEvents.unshift(ev);
        if (allEvents.length > 1000) allEvents.pop();
        if (autoScroll) {
          renderTable();
        }
      } catch(err) {}
    });
    es.addEventListener('connected', function() {
      var el = document.getElementById('stream-status');
      if (el) el.textContent = 'LIVE STREAM';
    });
    es.onerror = function() {
      var el = document.getElementById('stream-status');
      if (el) el.textContent = 'RECONNECTING...';
    };
  }

  // Initial startup
  initLeafletMap();
  fetchStats();
  initSSE();
  setInterval(fetchStats, 3000);
})();
</script>
</body>
</html>`
