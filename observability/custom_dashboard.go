package observability

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityEvent represents a normalized, structured telemetry event from the gateway.
type SecurityEvent struct {
	ID        int64   `json:"id"`
	Timestamp string  `json:"timestamp"`
	TimeStr   string  `json:"time_str"`
	ClientIP  string  `json:"client_ip"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	Verdict   string  `json:"verdict"` // "BLOCK", "TARPIT", "ALLOW"
	Rule      string  `json:"rule"`    // e.g. "path-traversal", "scanner", "sql-injection"
	LatencyMs float64 `json:"latency_ms"`
	Source    string  `json:"source,omitempty"`
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
	Name    string `json:"name"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked"`
	Tarpit  int64  `json:"tarpit"`
	Rule    string `json:"rule,omitempty"`
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
	StatusCodes  map[string]int64 `json:"status_codes"`
	RecentEvents []*SecurityEvent `json:"recent_events"`
	Sources      SourceInfo       `json:"sources"`
}

// EventStore maintains in-memory telemetry, ring buffer, aggregates, and SSE subscribers.
type EventStore struct {
	mu           sync.RWMutex
	nextID       int64
	events       []*SecurityEvent
	maxEvents    int
	subscribers  map[chan *SecurityEvent]struct{}
	ipCounts     map[string]*TopMetricItem
	pathCounts   map[string]*TopMetricItem
	ruleCounts   map[string]*TopMetricItem
	statusCounts map[string]int64
	timeline     map[string]*TimelinePoint // keyed by HH:MM
	timelineKeys []string
	startTime    time.Time
}

var globalStore = NewEventStore()

// NewEventStore creates a new telemetry event store.
func NewEventStore() *EventStore {
	return &EventStore{
		maxEvents:    1000,
		subscribers:  make(map[chan *SecurityEvent]struct{}),
		ipCounts:     make(map[string]*TopMetricItem),
		pathCounts:   make(map[string]*TopMetricItem),
		ruleCounts:   make(map[string]*TopMetricItem),
		statusCounts: make(map[string]int64),
		timeline:     make(map[string]*TimelinePoint),
		timelineKeys: make([]string, 0),
		startTime:    time.Now(),
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
			ev.TimeStr = t.Format("15:04:05")
		} else {
			ev.TimeStr = time.Now().UTC().Format("15:04:05")
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
	bucketKey := time.Now().UTC().Format("15:04")
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

	// Top IPs
	if ev.ClientIP != "" {
		ipItem, ok := s.ipCounts[ev.ClientIP]
		if !ok {
			ipItem = &TopMetricItem{Name: ev.ClientIP}
			s.ipCounts[ev.ClientIP] = ipItem
		}
		ipItem.Count++
		if isBlocked {
			ipItem.Blocked++
		} else if isTarpit {
			ipItem.Tarpit++
		}
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
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TimeStr:   time.Now().UTC().Format("15:04:05"),
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
			if ev.Status == 403 {
				ev.Verdict = "BLOCK"
			} else if ev.Status == 429 {
				ev.Verdict = "TARPIT"
			} else {
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
			if ev.Status == 403 {
				ev.Verdict = "BLOCK"
			} else if ev.Status == 429 {
				ev.Verdict = "TARPIT"
			} else {
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
		nowKey := time.Now().UTC().Format("15:04")
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

// CustomSOCDashboardHTML contains the complete, self-contained RouteWarden Executive SOC Dashboard.
const CustomSOCDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RouteWarden — Security Operations Center & Gateway Intelligence</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #070b14;
      --bg-secondary: #0b1120;
      --card-bg: rgba(15, 23, 42, 0.72);
      --card-border: rgba(255, 255, 255, 0.08);
      --card-hover-border: rgba(56, 189, 248, 0.35);
      --accent-cyan: #38bdf8;
      --accent-blue: #60a5fa;
      --accent-indigo: #6366f1;
      --accent-green: #10b981;
      --accent-red: #f43f5e;
      --accent-amber: #f59e0b;
      --accent-purple: #a855f7;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-primary);
      background-image: 
        radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 100%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 50%, rgba(15, 23, 42, 0.5) 0px, transparent 100%);
      background-attachment: fixed;
      color: var(--text-primary);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    .dashboard-wrap {
      max-width: 1540px;
      margin: 0 auto;
      padding: 20px 24px 40px 24px;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    /* Top Header Bar */
    header.soc-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      background: var(--card-bg);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 14px 22px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
    }

    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-logo {
      font-size: 26px;
      filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.6));
    }
    .brand-title {
      font-size: 19px;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #ffffff 40%, #93c5fd 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-badge {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      background: rgba(99, 102, 241, 0.2);
      color: #c7d2fe;
      border: 1px solid rgba(99, 102, 241, 0.4);
      padding: 2px 8px;
      border-radius: 6px;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .live-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      color: #6ee7b7;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background-color: var(--accent-green);
      border-radius: 50%;
      box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
      animation: pulse-anim 2s infinite;
    }
    @keyframes pulse-anim {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
      70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .btn-action {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: #cbd5e1;
      padding: 7px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s ease;
    }
    .btn-action:hover {
      background: rgba(56, 189, 248, 0.15);
      border-color: rgba(56, 189, 248, 0.4);
      color: #38bdf8;
      box-shadow: 0 0 12px rgba(56, 189, 248, 0.2);
    }

    /* Monitored Sources Ribbon */
    .sources-ribbon {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 10px 16px;
      font-size: 12px;
      color: var(--text-secondary);
    }
    .source-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 4px 10px;
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: #93c5fd;
    }

    /* Executive KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 16px;
    }
    .kpi-card {
      background: var(--card-bg);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 20px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .kpi-card:hover {
      transform: translateY(-2px);
      border-color: var(--card-hover-border);
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.5);
    }
    .kpi-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .kpi-label {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: var(--text-secondary);
    }
    .kpi-icon {
      font-size: 20px;
      opacity: 0.85;
    }
    .kpi-val {
      font-size: 32px;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
      color: #ffffff;
      line-height: 1.1;
      letter-spacing: -0.02em;
    }
    .kpi-sub {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 8px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .pill-threat {
      background: rgba(244, 63, 94, 0.16);
      color: #fb7185;
      border: 1px solid rgba(244, 63, 94, 0.35);
      padding: 2px 7px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
    }
    .pill-tarpit {
      background: rgba(245, 158, 11, 0.16);
      color: #fcd34d;
      border: 1px solid rgba(245, 158, 11, 0.35);
      padding: 2px 7px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
    }
    .pill-clean {
      background: rgba(16, 185, 129, 0.16);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.35);
      padding: 2px 7px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
    }
    .pill-cipher {
      background: rgba(168, 85, 247, 0.16);
      color: #d8b4fe;
      border: 1px solid rgba(168, 85, 247, 0.35);
      padding: 2px 7px;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
    }

    /* Charts Section */
    .charts-grid {
      display: grid;
      grid-template-columns: 2.1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 1080px) {
      .charts-grid {
        grid-template-columns: 1fr;
      }
    }

    .chart-card {
      background: var(--card-bg);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-width: 0;
    }
    .card-header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-height: 28px;
    }
    .card-title {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Timeline Controls & Legend */
    .timeline-legend {
      display: flex;
      align-items: center;
      gap: 14px;
      font-size: 11px;
      font-weight: 600;
      flex-wrap: wrap;
    }
    .legend-item {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      user-select: none;
      transition: opacity 0.2s;
    }
    .legend-item.dimmed {
      opacity: 0.35;
    }
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 3px;
    }

    .timeline-container {
      width: 100%;
      height: 260px;
      position: relative;
      overflow: hidden;
      border-radius: 10px;
      background: rgba(5, 8, 16, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.04);
    }
    .timeline-svg {
      width: 100%;
      height: 100%;
      display: block;
    }

    /* Non-Overlapping HUD Chart Tooltip */
    .chart-tooltip {
      position: absolute;
      display: none;
      pointer-events: none;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(56, 189, 248, 0.4);
      border-radius: 8px;
      padding: 8px 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.7), 0 0 15px rgba(56, 189, 248, 0.2);
      z-index: 50;
      line-height: 1.5;
      transform: translateX(-50%);
      top: 12px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    /* Donut & Rules Stack */
    .donut-wrap {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 20px;
      padding: 8px 0;
      flex-wrap: wrap;
    }
    .donut-svg {
      width: 120px;
      height: 120px;
      transform: rotate(-90deg);
      flex-shrink: 0;
    }
    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      min-width: 120px;
    }

    /* Rules Progress Bars */
    .rules-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 190px;
      overflow-y: auto;
      padding-right: 4px;
    }
    .rules-list::-webkit-scrollbar {
      width: 4px;
    }
    .rules-list::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.15);
      border-radius: 4px;
    }
    .rule-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      cursor: pointer;
      padding: 6px 8px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      transition: background 0.15s ease, border-color 0.15s ease;
    }
    .rule-item:hover {
      background: rgba(56, 189, 248, 0.08);
      border-color: rgba(56, 189, 248, 0.25);
    }
    .rule-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
    }
    .rule-name {
      color: #e2e8f0;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 170px;
      min-width: 0;
    }
    .rule-count {
      color: #94a3b8;
      flex-shrink: 0;
      font-size: 10px;
    }
    .rule-bar-wrap {
      width: 100%;
      height: 5px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: 4px;
      overflow: hidden;
    }
    .rule-bar-fill {
      height: 100%;
      border-radius: 4px;
      background: linear-gradient(90deg, #6366f1, #38bdf8);
      transition: width 0.4s ease;
    }

    /* Intelligence Split Grid */
    .intel-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      .intel-grid {
        grid-template-columns: 1fr;
      }
    }

    .table-responsive {
      width: 100%;
      overflow-x: auto;
    }

    .intel-table {
      width: 100%;
      min-width: 360px;
      border-collapse: collapse;
      font-size: 12px;
    }
    .intel-table th {
      text-align: left;
      padding: 8px 12px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }
    .intel-table td {
      padding: 8px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: #cbd5e1;
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
    }
    .intel-table tr:hover td {
      background: rgba(255, 255, 255, 0.04);
      cursor: pointer;
    }

    /* Multi-Dimensional SOC Console Filters */
    .console-card {
      background: var(--card-bg);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-width: 0;
    }

    .console-toolbar {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .filters-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
    }

    .filter-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .tab-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-secondary);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s ease;
    }
    .tab-btn:hover {
      background: rgba(255, 255, 255, 0.09);
      color: #ffffff;
    }
    .tab-btn.active {
      background: rgba(56, 189, 248, 0.15);
      border-color: rgba(56, 189, 248, 0.4);
      color: #38bdf8;
    }

    .filter-select {
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 6px;
      color: #e2e8f0;
      font-size: 12px;
      padding: 6px 10px;
      font-family: 'JetBrains Mono', monospace;
      outline: none;
      cursor: pointer;
      max-width: 200px;
      transition: border-color 0.2s;
    }
    .filter-select:focus {
      border-color: var(--accent-cyan);
    }

    .search-box {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 6px 12px;
      color: #f8fafc;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      outline: none;
      min-width: 180px;
      flex: 1 1 200px;
      transition: border-color 0.2s ease;
    }
    .search-box:focus {
      border-color: var(--accent-cyan);
    }

    /* Active Filter Chips Bar */
    .active-chips-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      font-size: 11px;
      padding: 8px 12px;
      background: rgba(56, 189, 248, 0.05);
      border: 1px dashed rgba(56, 189, 248, 0.22);
      border-radius: 8px;
    }
    .filter-chip {
      background: rgba(56, 189, 248, 0.15);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: #7dd3fc;
      padding: 3px 8px;
      border-radius: 5px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
    }
    .chip-close {
      cursor: pointer;
      font-weight: 700;
      color: #38bdf8;
    }
    .chip-close:hover {
      color: #ffffff;
    }
    .btn-clear-all {
      color: #fb7185;
      background: none;
      border: none;
      cursor: pointer;
      font-size: 11px;
      font-weight: 600;
      text-decoration: underline;
      margin-left: auto;
    }

    .table-container {
      max-height: 480px;
      overflow-x: auto;
      overflow-y: auto;
      border: 1px solid var(--card-border);
      border-radius: 10px;
      background: rgba(5, 8, 16, 0.5);
    }
    table.soc-table {
      width: 100%;
      min-width: 900px;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }
    table.soc-table th {
      position: sticky;
      top: 0;
      background: #0f172a;
      padding: 10px 14px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--text-muted);
      border-bottom: 1px solid var(--card-border);
      z-index: 2;
    }
    table.soc-table td {
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      color: #cbd5e1;
      font-family: 'JetBrains Mono', monospace;
      white-space: nowrap;
    }
    table.soc-table tr:hover td {
      background: rgba(255, 255, 255, 0.04);
      cursor: pointer;
    }

    /* Verdict Badges */
    .verdict-block {
      background: rgba(244, 63, 94, 0.16);
      color: #fb7185;
      border: 1px solid rgba(244, 63, 94, 0.35);
      padding: 3px 8px;
      border-radius: 5px;
      font-weight: 700;
      font-size: 11px;
    }
    .verdict-tarpit {
      background: rgba(245, 158, 11, 0.16);
      color: #fcd34d;
      border: 1px solid rgba(245, 158, 11, 0.35);
      padding: 3px 8px;
      border-radius: 5px;
      font-weight: 700;
      font-size: 11px;
    }
    .verdict-allow {
      background: rgba(16, 185, 129, 0.14);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 3px 8px;
      border-radius: 5px;
      font-weight: 700;
      font-size: 11px;
    }

    .badge-method {
      padding: 2px 6px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 10px;
    }
    .method-get { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
    .method-post { background: rgba(168, 85, 247, 0.15); color: #c084fc; }
    .method-put { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .method-delete { background: rgba(244, 63, 94, 0.15); color: #fb7185; }

    /* Modal Inspector */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    }
    .modal-card {
      background: #0f172a;
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 14px;
      width: 90%;
      max-width: 650px;
      padding: 24px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 12px;
    }
    .modal-title {
      font-size: 16px;
      font-weight: 700;
      color: #ffffff;
    }
    .modal-close {
      cursor: pointer;
      font-size: 18px;
      color: var(--text-muted);
    }
    .modal-body {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      background: #070b14;
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
      color: #e2e8f0;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>

<div class="dashboard-wrap">
  <!-- Header Bar -->
  <header class="soc-header">
    <div class="brand-wrap">
      <div class="brand-logo">🛡️</div>
      <div>
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="brand-title">RouteWarden</span>
          <span class="brand-badge">SOC INTELLIGENCE</span>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top:2px;">Real-Time Reverse Proxy Security Telemetry</div>
      </div>
    </div>

    <div class="header-actions">
      <div class="live-indicator">
        <span class="pulse-dot"></span>
        <span id="stream-status">LIVE STREAM</span>
      </div>
      <button class="btn-action" id="btn-toggle-scroll">⏸ Pause</button>
      <button class="btn-action" id="btn-export-json">📥 Export</button>
      <button class="btn-action" id="btn-clear-logs">🗑 Clear</button>
    </div>
  </header>

  <!-- Monitored Sources Ribbon -->
  <div class="sources-ribbon" id="sources-container">
    <span style="font-weight: 600; color: #cbd5e1;">🌐 Monitored Nodes:</span>
    <span style="color: #64748b; font-style: italic;">Discovering active containers & remote agents...</span>
  </div>

  <!-- Executive KPI Grid -->
  <div class="kpi-grid">
    <div class="kpi-card" style="border-top: 3px solid var(--accent-cyan);">
      <div class="kpi-top">
        <span class="kpi-label">Total Ingress</span>
        <span class="kpi-icon">🛡️</span>
      </div>
      <div class="kpi-val" id="kpi-total">0</div>
      <div class="kpi-sub">Gateway ingress events</div>
    </div>

    <div class="kpi-card" style="border-top: 3px solid var(--accent-red);">
      <div class="kpi-top">
        <span class="kpi-label">Threats Blocked</span>
        <span class="kpi-icon">🛑</span>
      </div>
      <div class="kpi-val" style="color: #fb7185;" id="kpi-blocked">0</div>
      <div class="kpi-sub"><span class="pill-threat" id="kpi-block-rate">0.0% Rate</span> 403 Forbidden</div>
    </div>

    <div class="kpi-card" style="border-top: 3px solid var(--accent-amber);">
      <div class="kpi-top">
        <span class="kpi-label">Throttled / Tarpit</span>
        <span class="kpi-icon">⏳</span>
      </div>
      <div class="kpi-val" style="color: #fcd34d;" id="kpi-tarpit">0</div>
      <div class="kpi-sub"><span class="pill-tarpit">429 Slowed</span> Hostile bots</div>
    </div>

    <div class="kpi-card" style="border-top: 3px solid var(--accent-green);">
      <div class="kpi-top">
        <span class="kpi-label">Clean Ingress</span>
        <span class="kpi-icon">✅</span>
      </div>
      <div class="kpi-val" style="color: #6ee7b7;" id="kpi-clean">0</div>
      <div class="kpi-sub"><span class="pill-clean">200 OK</span> Legitimate traffic</div>
    </div>

    <div class="kpi-card" style="border-top: 3px solid var(--accent-purple);">
      <div class="kpi-top">
        <span class="kpi-label">Telemetry Cipher</span>
        <span class="kpi-icon">🔒</span>
      </div>
      <div class="kpi-val" style="font-size: 18px; margin-top: 6px; color: #d8b4fe;">X25519 + AES</div>
      <div class="kpi-sub"><span class="pill-cipher">Zero-Knowledge</span> ECDH Stream</div>
    </div>
  </div>

  <!-- Visual Graphs Grid -->
  <div class="charts-grid">
    <!-- Real-Time Timeline Curve with Full Scales & Legend -->
    <div class="chart-card">
      <div class="card-header">
        <span class="card-title">📈 Ingress Velocity & Threat Timeline</span>
        <div class="timeline-legend">
          <span class="legend-item" id="legend-clean"><span class="legend-dot" style="background:#10b981;"></span> Clean</span>
          <span class="legend-item" id="legend-blocked"><span class="legend-dot" style="background:#f43f5e;"></span> Blocked</span>
          <span class="legend-item" id="legend-tarpit"><span class="legend-dot" style="background:#f59e0b;"></span> Tarpit</span>
        </div>
      </div>
      <div class="timeline-container" id="timeline-box">
        <div class="chart-tooltip" id="timeline-tooltip"></div>
        <svg class="timeline-svg" id="timeline-svg" viewBox="0 0 800 240" preserveAspectRatio="none">
          <defs>
            <linearGradient id="grad-clean" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="#10b981" stop-opacity="0.2"/>
              <stop offset="100%" stop-color="#10b981" stop-opacity="0.0"/>
            </linearGradient>
            <linearGradient id="grad-blocked" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="#f43f5e" stop-opacity="0.3"/>
              <stop offset="100%" stop-color="#f43f5e" stop-opacity="0.0"/>
            </linearGradient>
          </defs>
          <g id="grid-group"></g>
          <g id="axes-group"></g>
          <path id="path-clean-area" fill="url(#grad-clean)"></path>
          <path id="path-blocked-area" fill="url(#grad-blocked)"></path>
          <path id="path-clean-line" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round"></path>
          <path id="path-blocked-line" fill="none" stroke="#f43f5e" stroke-width="2.5" stroke-linecap="round"></path>
          <path id="path-tarpit-line" fill="none" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" stroke-dasharray="4,3"></path>
          <g id="points-group"></g>
          <line id="crosshair-line" stroke="#38bdf8" stroke-width="1" stroke-dasharray="3,3" style="display:none;"></line>
          <circle id="crosshair-dot" r="4.5" fill="#38bdf8" stroke="#0f172a" stroke-width="2" style="display:none;"></circle>
          <rect id="chart-overlay" width="800" height="240" fill="transparent" style="cursor:crosshair;"></rect>
        </svg>
      </div>
    </div>

    <!-- Threat Breakdown (Donut + Top Rules) -->
    <div class="chart-card">
      <div class="card-header">
        <span class="card-title">🎯 Threat Ratio & Signatures</span>
      </div>
      <div class="donut-wrap">
        <svg class="donut-svg" viewBox="0 0 100 100" id="donut-svg">
          <circle cx="50" cy="50" r="38" fill="transparent" stroke="rgba(255,255,255,0.06)" stroke-width="12"></circle>
          <circle id="donut-clean" cx="50" cy="50" r="38" fill="transparent" stroke="#10b981" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-blocked" cx="50" cy="50" r="38" fill="transparent" stroke="#f43f5e" stroke-width="12" stroke-dasharray="0 238.7"></circle>
          <circle id="donut-tarpit" cx="50" cy="50" r="38" fill="transparent" stroke="#f59e0b" stroke-width="12" stroke-dasharray="0 238.7"></circle>
        </svg>
        <div class="donut-legend">
          <div><span style="color:#10b981;">●</span> Clean: <span id="donut-clean-lbl">0%</span></div>
          <div><span style="color:#f43f5e;">●</span> Blocked: <span id="donut-blocked-lbl">0%</span></div>
          <div><span style="color:#f59e0b;">●</span> Tarpit: <span id="donut-tarpit-lbl">0%</span></div>
        </div>
      </div>
      <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em; margin-top:4px;">Top Triggered Rules (Click to filter):</div>
      <div class="rules-list" id="rules-container">
        <div style="color: #64748b; font-size: 11px; font-style: italic;">Awaiting rule triggers...</div>
      </div>
    </div>
  </div>

  <!-- Intelligence Tables -->
  <div class="intel-grid">
    <div class="chart-card">
      <div class="card-header">
        <span class="card-title">🚨 Top Attacking Client IPs</span>
        <span style="font-size:11px; color:var(--text-muted);">Click row to filter</span>
      </div>
      <div class="table-responsive">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Client IP</th>
              <th>Total Hits</th>
              <th>Threat Breakdown</th>
            </tr>
          </thead>
          <tbody id="top-ips-tbody">
            <tr><td colspan="3" style="color:#64748b; text-align:center;">No threat IPs logged yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="chart-card">
      <div class="card-header">
        <span class="card-title">🎯 Top Targeted Endpoints</span>
        <span style="font-size:11px; color:var(--text-muted);">Click row to filter</span>
      </div>
      <div class="table-responsive">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Target Path</th>
              <th>Requests</th>
              <th>Triggered Rule</th>
            </tr>
          </thead>
          <tbody id="top-paths-tbody">
            <tr><td colspan="3" style="color:#64748b; text-align:center;">No endpoints logged yet</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Real-Time Multi-Dimensional SOC Console -->
  <div class="console-card">
    <div class="console-toolbar">
      <!-- Row 1: Verdict Tabs, Selectors, Search -->
      <div class="filters-row">
        <div class="filter-tabs">
          <button class="tab-btn active" data-filter-verdict="ALL">All (<span id="count-tab-all">0</span>)</button>
          <button class="tab-btn" data-filter-verdict="BLOCK">🛑 Blocked (<span id="count-tab-block">0</span>)</button>
          <button class="tab-btn" data-filter-verdict="TARPIT">⏳ Tarpit (<span id="count-tab-tarpit">0</span>)</button>
          <button class="tab-btn" data-filter-verdict="ALLOW">✅ Clean (<span id="count-tab-clean">0</span>)</button>
        </div>

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

      <!-- Row 2: Active Filter Chips Bar -->
      <div class="active-chips-bar" id="active-chips-container" style="display:none;">
        <span style="color:var(--text-muted);">Active Filters:</span>
        <div id="chips-list" style="display:flex; flex-wrap:wrap; gap:6px;"></div>
        <button class="btn-clear-all" id="btn-reset-filters">Reset All Filters</button>
      </div>
    </div>

    <div class="table-container" id="stream-table-container">
      <table class="soc-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Verdict & Rule</th>
            <th>Method</th>
            <th>Path</th>
            <th>Client IP</th>
            <th>Status</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody id="stream-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Modal Inspector -->
<div class="modal-overlay" id="event-modal">
  <div class="modal-card">
    <div class="modal-header">
      <span class="modal-title">🔍 Telemetry Event Inspector</span>
      <span class="modal-close" id="modal-close-btn">&times;</span>
    </div>
    <div class="modal-body" id="modal-content"></div>
  </div>
</div>

<script>
(function() {
  var autoScroll = true;
  var allEvents = [];
  var timelineData = [];

  // Active Filter State
  var filters = {
    verdict: 'ALL',
    method: 'ALL',
    status: 'ALL',
    rule: 'ALL',
    search: '',
    ip: '',
    path: ''
  };

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
  var selectMethod = document.getElementById('select-method');
  var selectStatus = document.getElementById('select-status');
  var selectRule = document.getElementById('select-rule');
  var chipsContainer = document.getElementById('active-chips-container');
  var chipsList = document.getElementById('chips-list');
  var modal = document.getElementById('event-modal');
  var modalContent = document.getElementById('modal-content');
  var modalClose = document.getElementById('modal-close-btn');

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
    btnToggleScroll.style.color = autoScroll ? '#cbd5e1' : '#f59e0b';
  });

  btnClearLogs.addEventListener('click', function() {
    allEvents = [];
    renderTable();
  });

  btnResetFilters.addEventListener('click', function() {
    filters.verdict = 'ALL';
    filters.method = 'ALL';
    filters.status = 'ALL';
    filters.rule = 'ALL';
    filters.search = '';
    filters.ip = '';
    filters.path = '';

    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    var allBtn = document.querySelector('[data-filter-verdict="ALL"]');
    if (allBtn) allBtn.classList.add('active');

    selectMethod.value = 'ALL';
    selectStatus.value = 'ALL';
    selectRule.value = 'ALL';
    searchInput.value = '';

    renderActiveChips();
    renderTable();
  });

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

  function renderActiveChips() {
    var chips = [];
    if (filters.verdict !== 'ALL') chips.push({ label: 'Verdict: ' + filters.verdict, clear: function() {
      filters.verdict = 'ALL';
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      var ab = document.querySelector('[data-filter-verdict="ALL"]');
      if (ab) ab.classList.add('active');
    }});
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
        });
      });
    } else {
      chipsContainer.style.display = 'none';
    }
  }

  function getFilteredEvents() {
    return allEvents.filter(function(ev) {
      if (filters.verdict !== 'ALL' && ev.verdict !== filters.verdict) return false;
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
        var str = (ev.client_ip + ' ' + ev.path + ' ' + (ev.rule || '') + ' ' + ev.method + ' ' + ev.status).toLowerCase();
        if (str.indexOf(filters.search) === -1) return false;
      }
      return true;
    });
  }

  function renderTable() {
    var filtered = getFilteredEvents();
    var rowsHTML = '';
    filtered.slice(-200).forEach(function(ev) {
      var verdictClass = 'verdict-allow';
      var verdictLabel = 'ALLOW';
      if (ev.verdict === 'BLOCK') {
        verdictClass = 'verdict-block';
        verdictLabel = ev.rule ? '🛑 BLOCK: ' + ev.rule : '🛑 BLOCK';
      } else if (ev.verdict === 'TARPIT') {
        verdictClass = 'verdict-tarpit';
        verdictLabel = ev.rule ? '⏳ TARPIT: ' + ev.rule : '⏳ TARPIT';
      }

      var methodClass = 'method-get';
      var m = (ev.method || 'GET').toUpperCase();
      if (m === 'POST') methodClass = 'method-post';
      else if (m === 'PUT') methodClass = 'method-put';
      else if (m === 'DELETE') methodClass = 'method-delete';

      var latencyColor = ev.latency_ms > 1000 ? '#f59e0b' : '#94a3b8';

      rowsHTML += '<tr onclick="inspectEvent(' + ev.id + ')">' +
        '<td>' + (ev.time_str || '') + '</td>' +
        '<td><span class="' + verdictClass + '">' + verdictLabel + '</span></td>' +
        '<td><span class="badge-method ' + methodClass + '">' + m + '</span></td>' +
        '<td style="max-width:320px; overflow:hidden; text-overflow:ellipsis;" title="' + ev.path + '">' + ev.path + '</td>' +
        '<td>' + ev.client_ip + '</td>' +
        '<td>' + ev.status + '</td>' +
        '<td style="color:' + latencyColor + ';">' + ev.latency_ms.toFixed(1) + 'ms</td>' +
      '</tr>';
    });

    streamTbody.innerHTML = rowsHTML || '<tr><td colspan="7" style="color:#64748b; text-align:center;">No matching events</td></tr>';

    if (autoScroll && streamContainer) {
      streamContainer.scrollTop = streamContainer.scrollHeight;
    }
  }

  window.inspectEvent = function(id) {
    var found = allEvents.find(function(e) { return e.id === id; });
    if (!found) return;
    modalContent.textContent = JSON.stringify(found, null, 2);
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

    document.getElementById('count-tab-all').textContent = total;
    document.getElementById('count-tab-block').textContent = blocked;
    document.getElementById('count-tab-tarpit').textContent = tarpit;
    document.getElementById('count-tab-clean').textContent = clean;

    // Update Donut Chart
    updateDonut(clean, blocked, tarpit, total);

    // Populate Rule Dropdown & List
    if (stats.top_rules && stats.top_rules.length > 0) {
      // Dropdown sync
      var currentSel = selectRule.value;
      var optHTML = '<option value="ALL">All Threat Rules</option>';
      stats.top_rules.forEach(function(r) {
        optHTML += '<option value="' + r.name + '">' + r.name + ' (' + r.count + ')</option>';
      });
      if (selectRule.innerHTML !== optHTML) {
        selectRule.innerHTML = optHTML;
        selectRule.value = currentSel;
      }

      // Progress bars
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

    // Top IPs
    if (stats.top_ips && stats.top_ips.length > 0) {
      var ipHTML = '';
      stats.top_ips.forEach(function(item) {
        ipHTML += '<tr onclick="filterByIP(\'' + item.name + '\')">' +
          '<td>' + item.name + '</td>' +
          '<td>' + Number(item.count).toLocaleString() + '</td>' +
          '<td><span class="pill-threat">' + item.blocked + ' Blocked</span> <span class="pill-tarpit">' + item.tarpit + ' Tarpit</span></td>' +
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
        var ruleBadge = item.rule ? '<span class="pill-threat">' + item.rule + '</span>' : '<span style="color:#64748b;">—</span>';
        pHTML += '<tr onclick="filterByPath(\'' + item.name + '\')">' +
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
  }

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
    var padLeft = 55;
    var padRight = 20;
    var padTop = 20;
    var padBottom = 32;

    var chartW = w - padLeft - padRight;
    var chartH = h - padTop - padBottom;

    var maxVal = 5;
    data.forEach(function(d) {
      if (d.total > maxVal) maxVal = d.total;
    });
    // Round maxVal up to nice increment
    maxVal = Math.ceil(maxVal * 1.15);

    // 1. Draw Y-Axis Gridlines & Labels
    var gridHTML = '';
    var axesHTML = '';
    var yTicks = 4;
    for (var i = 0; i <= yTicks; i++) {
      var val = Math.round((maxVal / yTicks) * i);
      var y = padTop + chartH - (i / yTicks) * chartH;
      // Dotted horizontal gridline
      gridHTML += '<line x1="' + padLeft + '" y1="' + y + '" x2="' + (w - padRight) + '" y2="' + y + '" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" />';
      // Y-axis tick text with guaranteed padding from axis line
      axesHTML += '<text x="' + (padLeft - 10) + '" y="' + (y + 4) + '" fill="#64748b" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">' + val + '</text>';
    }

    // 2. Draw X-Axis Ticks & Labels (Deduplicated, Evenly Distributed, Zero Overlap)
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

      axesHTML += '<text x="' + x + '" y="' + (h - 8) + '" fill="#64748b" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="' + anchor + '">' + (d.time || '') + '</text>';
      gridHTML += '<line x1="' + x + '" y1="' + padTop + '" x2="' + x + '" y2="' + (h - padBottom) + '" stroke="rgba(255,255,255,0.03)" />';
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

    // Data points indicator (circles)
    if (pointsGroup) {
      var ptsHTML = '';
      if (data.length <= 30) {
        data.forEach(function(d, i) {
          if (i < ptsClean.length && visibleSeries.clean && d.clean > 0) {
            ptsHTML += '<circle cx="' + ptsClean[i].x.toFixed(1) + '" cy="' + ptsClean[i].y.toFixed(1) + '" r="3" fill="#10b981" stroke="#070b14" stroke-width="1.5" />';
          }
          if (i < ptsBlocked.length && visibleSeries.blocked && d.blocked > 0) {
            ptsHTML += '<circle cx="' + ptsBlocked[i].x.toFixed(1) + '" cy="' + ptsBlocked[i].y.toFixed(1) + '" r="3" fill="#f43f5e" stroke="#070b14" stroke-width="1.5" />';
          }
        });
      }
      pointsGroup.innerHTML = ptsHTML;
    }

    // 4. Interactive Crosshair & Tooltip Hover
    overlay.onmousemove = function(e) {
      var rect = overlay.getBoundingClientRect();
      var mouseX = (e.clientX - rect.left) * (w / rect.width);
      if (mouseX < padLeft || mouseX > w - padRight) {
        crosshair.style.display = 'none';
        if (crosshairDot) crosshairDot.style.display = 'none';
        tooltip.style.display = 'none';
        return;
      }

      // Find nearest data point
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
      var toolHTML = '<span style="color:#38bdf8; font-weight:700;">⏱ ' + d.time + ' UTC</span> &nbsp;|&nbsp; ' +
        '<span style="color:#ffffff;">Total: <b>' + d.total + '</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:#10b981;">Clean: <b>' + d.clean + '</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:#f43f5e;">Blocked: <b>' + d.blocked + ' (' + rate + ')</b></span> &nbsp;|&nbsp; ' +
        '<span style="color:#f59e0b;">Tarpit: <b>' + d.tarpit + '</b></span>';

      tooltip.innerHTML = toolHTML;

      // Position HUD banner neatly centered at top of chart without overflowing card title
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
    var sHTML = '<span style="font-weight: 600; color: #cbd5e1;">🌐 Monitored Nodes:</span>';
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
        sHTML += '<span class="source-tag">🌐 ' + ag.name + ' (' + (ag.remote_ip || 'remote') + ') <span style="color:#a78bfa;">🔒 X25519</span></span>';
        count++;
      });
    }

    if (count === 0 && sources.mode !== 'file') {
      sHTML += '<span style="color: #64748b; font-style: italic;">Awaiting local containers or remote agents (<code>rwarden push</code>)...</span>';
    }
    sourcesContainer.innerHTML = sHTML;
  }

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
            allEvents = data.recent_events.reverse();
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
        allEvents.push(ev);
        if (allEvents.length > 1000) allEvents.shift();
        renderTable();
      } catch(err) {}
    });
    es.addEventListener('connected', function() {
      document.getElementById('stream-status').textContent = 'LIVE STREAM';
    });
    es.onerror = function() {
      document.getElementById('stream-status').textContent = 'RECONNECTING...';
    };
  }

  fetchStats();
  initSSE();
  setInterval(fetchStats, 3000);
})();
</script>
</body>
</html>
`
