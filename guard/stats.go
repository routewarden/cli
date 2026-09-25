package guard

import (
	"sync"
	"sync/atomic"
	"time"
)

// ServiceStats tracks live connection and traffic metrics for a single proxied service.
type ServiceStats struct {
	Name         string
	Protocol     string
	Listen       string
	Upstream     string
	TotalConns   atomic.Int64
	ActiveConns  atomic.Int64
	BlockedConns atomic.Int64
	BytesIn      atomic.Int64
	BytesOut     atomic.Int64
	AuthFailures atomic.Int64
}

// ServiceStatsSnapshot is a JSON-friendly copy of ServiceStats.
type ServiceStatsSnapshot struct {
	Name         string `json:"name"`
	Protocol     string `json:"protocol"`
	Listen       string `json:"listen"`
	Upstream     string `json:"upstream"`
	TotalConns   int64  `json:"total_connections"`
	ActiveConns  int64  `json:"active_connections"`
	BlockedConns int64  `json:"blocked_connections"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	AuthFailures int64  `json:"auth_failures"`
}

// Snapshot returns a point-in-time copy of the metrics.
func (s *ServiceStats) Snapshot() ServiceStatsSnapshot {
	return ServiceStatsSnapshot{
		Name:         s.Name,
		Protocol:     s.Protocol,
		Listen:       s.Listen,
		Upstream:     s.Upstream,
		TotalConns:   s.TotalConns.Load(),
		ActiveConns:  s.ActiveConns.Load(),
		BlockedConns: s.BlockedConns.Load(),
		BytesIn:      s.BytesIn.Load(),
		BytesOut:     s.BytesOut.Load(),
		AuthFailures: s.AuthFailures.Load(),
	}
}

// StatsRegistry holds metrics for all services.
type StatsRegistry struct {
	mu        sync.RWMutex
	services  map[string]*ServiceStats
	startTime time.Time
}

// NewStatsRegistry creates a new empty metrics registry.
func NewStatsRegistry() *StatsRegistry {
	return &StatsRegistry{
		services:  make(map[string]*ServiceStats),
		startTime: time.Now(),
	}
}

// RegisterService adds a service to the registry.
func (r *StatsRegistry) RegisterService(name, protocol, listen, upstream string) *ServiceStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	st := &ServiceStats{
		Name:     name,
		Protocol: protocol,
		Listen:   listen,
		Upstream: upstream,
	}
	r.services[name] = st
	return st
}

// Get returns the stats for a given service.
func (r *StatsRegistry) Get(name string) *ServiceStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.services[name]
}

// SnapshotAll returns snapshots for all registered services and global aggregates.
func (r *StatsRegistry) SnapshotAll() (map[string]ServiceStatsSnapshot, map[string]int64, time.Duration) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]ServiceStatsSnapshot, len(r.services))
	totals := map[string]int64{
		"total_connections":   0,
		"active_connections":  0,
		"blocked_connections": 0,
		"bytes_in":            0,
		"bytes_out":           0,
		"auth_failures":       0,
	}

	for name, st := range r.services {
		snap := st.Snapshot()
		result[name] = snap
		totals["total_connections"] += snap.TotalConns
		totals["active_connections"] += snap.ActiveConns
		totals["blocked_connections"] += snap.BlockedConns
		totals["bytes_in"] += snap.BytesIn
		totals["bytes_out"] += snap.BytesOut
		totals["auth_failures"] += snap.AuthFailures
	}

	uptime := time.Since(r.startTime)
	return result, totals, uptime
}
