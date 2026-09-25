package guard

import (
	"sync"
	"time"
)

// ringCounter is a fixed-size circular buffer that counts events in a
// sliding time window without allocating per event.
type ringCounter struct {
	mu       sync.Mutex
	slots    []time.Time // timestamps of recent events
	head     int
	size     int
	capacity int
	window   time.Duration
}

func newRingCounter(capacity int, window time.Duration) *ringCounter {
	return &ringCounter{
		slots:    make([]time.Time, capacity),
		capacity: capacity,
		window:   window,
	}
}

// Add records a new event and returns the current count within the window.
func (r *ringCounter) Add() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()

	// Evict expired slots
	cutoff := now.Add(-r.window)
	valid := 0
	for i := 0; i < r.size; i++ {
		idx := (r.head - r.size + i + r.capacity) % r.capacity
		if r.slots[idx].After(cutoff) {
			valid++
		}
	}
	// Rebuild size based on non-expired count
	r.size = valid

	// Record new event
	r.slots[r.head%r.capacity] = now
	r.head = (r.head + 1) % r.capacity
	if r.size < r.capacity {
		r.size++
	}

	return r.count(now)
}

// Count returns the number of events in the current window (read-only).
func (r *ringCounter) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count(time.Now())
}

func (r *ringCounter) count(now time.Time) int {
	cutoff := now.Add(-r.window)
	n := 0
	for i := 0; i < r.size; i++ {
		idx := (r.head - r.size + i + r.capacity) % r.capacity
		if r.slots[idx].After(cutoff) {
			n++
		}
	}
	return n
}

// RateLimiter tracks per-IP sliding-window counters for connections and
// auth attempts. It is safe for concurrent use.
type RateLimiter struct {
	mu       sync.Mutex
	counters map[string]*ringCounter // key: "ip:metric"
}

// NewRateLimiter creates an empty RateLimiter.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{counters: make(map[string]*ringCounter)}
	go rl.sweep()
	return rl
}

// AllowConnection checks (and records) a new connection attempt from ip.
// Returns false if the per-minute limit is exceeded.
func (rl *RateLimiter) AllowConnection(ip string, limit int) bool {
	if limit <= 0 {
		return true
	}
	return rl.check(ip+":conn", limit, time.Minute)
}

// AllowAuth checks (and records) an auth attempt from ip.
// Returns false if the per-minute auth limit is exceeded.
func (rl *RateLimiter) AllowAuth(ip string, limit int) bool {
	if limit <= 0 {
		return true
	}
	return rl.check(ip+":auth", limit, time.Minute)
}

func (rl *RateLimiter) check(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	rc, ok := rl.counters[key]
	if !ok {
		// capacity = limit*2 to give the ring buffer enough slots
		rc = newRingCounter(limit*2+10, window)
		rl.counters[key] = rc
	}
	rl.mu.Unlock()
	return rc.Add() <= limit
}

// sweep periodically removes idle counters to prevent unbounded growth.
func (rl *RateLimiter) sweep() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for k, rc := range rl.counters {
			if rc.Count() == 0 {
				delete(rl.counters, k)
			}
		}
		rl.mu.Unlock()
	}
}
