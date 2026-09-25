// Package dashboard implements the rwarden dashboard server: a lightweight,
// self-hosted web UI that streams RouteWarden security events in real time.
// Events are sourced either from Docker container stdout or from tailed log files.
package dashboard

import "time"

// SecurityEvent is a single structured log entry emitted by any RouteWarden
// middleware (traefik-warden, caddy-warden, nginx-warden).
// Fields mirror the JSON format the middleware already writes to stdout.
type SecurityEvent struct {
	// Core identification
	Type      string    `json:"type"`      // always "security_event"
	Timestamp time.Time `json:"timestamp"` // UTC event time
	Plugin    string    `json:"plugin"`    // e.g. "traefik-warden"

	// Request details
	ClientIP string `json:"client_ip"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Target   string `json:"target,omitempty"` // normalized candidate path that matched
	Query    string `json:"query,omitempty"`

	// Rule that matched
	Pattern string `json:"pattern,omitempty"`
	Reason  string `json:"reason,omitempty"`

	// Response delivered
	Action       string `json:"action"`                 // "blocked" | "allowed"
	Status       int    `json:"status,omitempty"`       // HTTP status code
	ResponseMode string `json:"response_mode,omitempty"` // tarpit, gzip-bomb, etc.

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
	TotalEvents    int            `json:"total_events"`
	UniqueIPs      int            `json:"unique_ips"`
	BlocksPerMin   float64        `json:"blocks_per_min"`
	TopPaths       []CountEntry   `json:"top_paths"`
	TopIPs         []CountEntry   `json:"top_ips"`
	ResponseModes  []CountEntry   `json:"response_modes"`
	RateOverTime   []RatePoint    `json:"rate_over_time"`
	ByGateway      []CountEntry   `json:"by_gateway"`
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
	IP            string          `json:"ip"`
	Geo           GeoResult       `json:"geo"`
	TotalEvents   int             `json:"total_events"`
	FirstSeen     *time.Time      `json:"first_seen,omitempty"`
	LastSeen      *time.Time      `json:"last_seen,omitempty"`
	RiskScore     string          `json:"risk_score"`  // "critical" | "high" | "medium" | "low"
	RiskReason    string          `json:"risk_reason"` // human readable reason for threat classification
	TopPaths      []CountEntry    `json:"top_paths"`
	TopMethods    []CountEntry    `json:"top_methods"`
	TopPatterns   []CountEntry    `json:"top_patterns"`
	ResponseModes []CountEntry    `json:"response_modes"`
	TargetSources []CountEntry    `json:"target_sources"`
	Events        []SecurityEvent `json:"events"`
}
