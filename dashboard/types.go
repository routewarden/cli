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
