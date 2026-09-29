// Package dashboard implements the rwarden dashboard server: a lightweight,
// self-hosted web UI that streams RouteWarden security events in real time.
// Events are sourced from Docker container stdout, tailed log files, or a live
// tcp-warden daemon SSE stream.
package dashboard

import "time"

// SecurityEvent is a single structured log entry emitted by any RouteWarden
// middleware (traefik-warden, caddy-warden, nginx-warden) or tcp-warden daemon.
// HTTP-specific fields are empty for TCP events; TCP-specific fields are empty
// for HTTP events. Use EventKind ("http" | "tcp") to discriminate.
type SecurityEvent struct {
	// Core identification
	Type      string    `json:"type"`      // always "security_event"
	Timestamp time.Time `json:"timestamp"` // UTC event time
	Plugin    string    `json:"plugin"`    // e.g. "traefik-warden", "tcp-warden"

	// HTTP-layer fields (empty for TCP events)
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"` // normalized candidate path that matched
	Query  string `json:"query,omitempty"`

	// Rule that matched (HTTP)
	Pattern string `json:"pattern,omitempty"`

	// Response delivered (HTTP)
	Status       int    `json:"status,omitempty"`       // HTTP status code
	ResponseMode string `json:"response_mode,omitempty"` // tarpit, gzip-bomb, etc.

	// TCP-layer fields (empty for HTTP events)
	Service    string `json:"service,omitempty"`    // e.g. "ssh-bastion", "postgres"
	Protocol   string `json:"protocol,omitempty"`   // "ssh", "smtp", "postgres", "redis", "tcp"
	BytesIn    int64  `json:"bytes_in,omitempty"`
	BytesOut   int64  `json:"bytes_out,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`

	// Shared fields
	ClientIP string `json:"client_ip"`
	Action   string `json:"action"`           // "blocked" | "allowed" | "throttled"
	Reason   string `json:"reason,omitempty"` // "ip_denied", "rate_limit_exceeded", etc.

	// Discriminator — populated by the watcher that produced this event.
	// "http" = HTTP-layer middleware event; "tcp" = tcp-warden event; "" = unknown/legacy.
	EventKind string `json:"event_kind,omitempty"`

	// Source metadata (added by dashboard, not the middleware)
	Source   string `json:"source,omitempty"`    // container name or file path
	SourceID string `json:"source_id,omitempty"` // container ID or file path hash

	// GeoIP metadata (added by dashboard)
	CountryCode string `json:"country_code,omitempty"` // e.g. "US", "DE", "LAN"
	CountryName string `json:"country_name,omitempty"` // e.g. "United States", "Local Network"
	FlagEmoji   string `json:"flag_emoji,omitempty"`   // e.g. "🇺🇸", "🏠"
}

// ConfigResponse is returned by GET /api/config/:id.
type ConfigResponse struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	HasConfig bool           `json:"has_config"`
	LabelKey  string         `json:"label_key,omitempty"`
	Config    map[string]any `json:"config,omitempty"`
	Raw       string         `json:"raw,omitempty"`
	Error     string         `json:"error,omitempty"`
	Hint      string         `json:"hint,omitempty"`
}

// Source represents a single log origin: a Docker container or a log file.
type Source struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`   // "docker" | "file"
	Plugin  string `json:"plugin"` // detected plugin type
	Status  string `json:"status"` // "live" | "stopped" | "error"
	Details string `json:"details,omitempty"`
}

// StatsSnapshot holds aggregated metrics computed from the ring buffer.
type StatsSnapshot struct {
	TotalEvents   int          `json:"total_events"`
	UniqueIPs     int          `json:"unique_ips"`
	BlocksPerMin  float64      `json:"blocks_per_min"`
	TopPaths      []CountEntry `json:"top_paths"`
	TopIPs        []CountEntry `json:"top_ips"`
	ResponseModes []CountEntry `json:"response_modes"`
	RateOverTime  []RatePoint  `json:"rate_over_time"`
	ByGateway     []CountEntry `json:"by_gateway"`
}

// CountEntry is a label + count pair used in bar/donut charts.
type CountEntry struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// RatePoint is a time + count pair used in the line chart.
type RatePoint struct {
	Minute string `json:"minute"` // "HH:MM" UTC
	Count  int    `json:"count"`
}

// IPDetailsResponse represents comprehensive intelligence and historical events for a single IP.
type IPDetailsResponse struct {
	IP          string          `json:"ip"`
	Geo         GeoResult       `json:"geo"`
	TotalEvents int             `json:"total_events"`
	FirstSeen   *time.Time      `json:"first_seen,omitempty"`
	LastSeen    *time.Time      `json:"last_seen,omitempty"`
	RiskScore   string          `json:"risk_score"`  // "critical" | "high" | "medium" | "low"
	RiskReason  string          `json:"risk_reason"` // human readable reason for threat classification
	TopPaths    []CountEntry    `json:"top_paths"`
	TopMethods  []CountEntry    `json:"top_methods"`
	TopPatterns []CountEntry    `json:"top_patterns"`
	ResponseModes []CountEntry  `json:"response_modes"`
	TargetSources []CountEntry  `json:"target_sources"`
	Events      []SecurityEvent `json:"events"`
}
