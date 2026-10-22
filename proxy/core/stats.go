package core

import (
	"sync"
	"sync/atomic"
)

// ServiceStats holds atomic operational metrics for a single service.
type ServiceStats struct {
	Name              string `json:"name"`
	TotalConnections  int64  `json:"total_connections"`
	ActiveConnections int64  `json:"active_connections"`
	AllowedConnections int64 `json:"allowed_connections"`
	BlockedConnections int64 `json:"blocked_connections"`
	BytesIn           int64  `json:"bytes_in"`
	BytesOut          int64  `json:"bytes_out"`

	totalConns  atomic.Int64
	activeConns atomic.Int64
	allowed     atomic.Int64
	blocked     atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

func (s *ServiceStats) Snapshot() ServiceStats {
	return ServiceStats{
		Name:               s.Name,
		TotalConnections:   s.totalConns.Load(),
		ActiveConnections:  s.activeConns.Load(),
		AllowedConnections: s.allowed.Load(),
		BlockedConnections: s.blocked.Load(),
		BytesIn:            s.bytesIn.Load(),
		BytesOut:           s.bytesOut.Load(),
	}
}

func (s *ServiceStats) ConnAccepted() {
	s.totalConns.Add(1)
	s.activeConns.Add(1)
}

func (s *ServiceStats) ConnClosed() {
	for {
		cur := s.activeConns.Load()
		if cur <= 0 {
			return
		}
		if s.activeConns.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

func (s *ServiceStats) AddAllowed() {
	s.allowed.Add(1)
}

func (s *ServiceStats) AddBlocked() {
	s.blocked.Add(1)
}

func (s *ServiceStats) AddBytes(in, out int64) {
	s.bytesIn.Add(in)
	s.bytesOut.Add(out)
}

// StatsRegistry tracks statistics for all services and daemon overall.
type StatsRegistry struct {
	mu       sync.RWMutex
	services map[string]*ServiceStats
}

// NewStatsRegistry creates a new StatsRegistry.
func NewStatsRegistry() *StatsRegistry {
	return &StatsRegistry{
		services: make(map[string]*ServiceStats),
	}
}

// GetOrCreate retrieves or allocates stats counters for serviceName.
func (r *StatsRegistry) GetOrCreate(serviceName string) *ServiceStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, exists := r.services[serviceName]
	if !exists {
		st = &ServiceStats{Name: serviceName}
		r.services[serviceName] = st
	}
	return st
}

// Snapshot returns stats for all registered services.
func (r *StatsRegistry) Snapshot() map[string]ServiceStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make(map[string]ServiceStats, len(r.services))
	for name, st := range r.services {
		res[name] = st.Snapshot()
	}
	return res
}
