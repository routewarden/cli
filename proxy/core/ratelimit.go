package core

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	rateLimiterBucketTTL    = 10 * time.Minute
	failureTrackerWindowTTL = 30 * time.Minute
)

type ipRateLimiter struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter manages per-service and per-IP token buckets using standard rate.Limiter.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipRateLimiter // key = service:ip
	cancel  context.CancelFunc
}

// NewRateLimiter creates a new RateLimiter and starts background bucket cleanup.
func NewRateLimiter() *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		buckets: make(map[string]*ipRateLimiter),
		cancel:  cancel,
	}
	go rl.cleanupLoop(ctx)
	return rl
}

// Allow checks if a connection from ip on service is allowed under limits.
func (r *RateLimiter) Allow(service, ip string, connsPerMin, burst int) bool {
	if connsPerMin <= 0 {
		return true
	}

	capacity := burst
	if capacity <= 0 {
		capacity = connsPerMin / 6 // default burst
		if capacity < 2 {
			capacity = 2
		}
	}
	refillRate := rate.Limit(float64(connsPerMin) / 60.0)

	key := service + ":" + ip

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, exists := r.buckets[key]
	if !exists {
		entry = &ipRateLimiter{
			limiter:    rate.NewLimiter(refillRate, capacity),
			lastAccess: time.Now(),
		}
		r.buckets[key] = entry
	} else {
		entry.lastAccess = time.Now()
		if entry.limiter.Limit() != refillRate {
			entry.limiter.SetLimit(refillRate)
		}
		if entry.limiter.Burst() != capacity {
			entry.limiter.SetBurst(capacity)
		}
	}

	return entry.limiter.Allow()
}

// Stop shuts down the background cleanup goroutine.
func (r *RateLimiter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *RateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-rateLimiterBucketTTL)
			r.mu.Lock()
			for key, b := range r.buckets {
				if b.lastAccess.Before(cutoff) {
					delete(r.buckets, key)
				}
			}
			r.mu.Unlock()
		}
	}
}

// FailureTracker tracks auth failures per IP within a sliding window.
type FailureTracker struct {
	mu       sync.Mutex
	failures map[string][]time.Time // key = service:ip
	cancel   context.CancelFunc
}

// NewFailureTracker creates a new FailureTracker and starts background key cleanup.
func NewFailureTracker() *FailureTracker {
	ctx, cancel := context.WithCancel(context.Background())
	ft := &FailureTracker{
		failures: make(map[string][]time.Time),
		cancel:   cancel,
	}
	go ft.cleanupLoop(ctx)
	return ft
}

// RecordFailure records an authentication failure and returns the failure count in the last window.
func (f *FailureTracker) RecordFailure(service, ip string, window time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := service + ":" + ip
	now := time.Now()
	cutoff := now.Add(-window)

	list := f.failures[key]
	valid := make([]time.Time, 0, len(list)+1)
	for _, t := range list {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	f.failures[key] = valid

	return len(valid)
}

// Reset clears failure counts for the given service and IP.
func (f *FailureTracker) Reset(service, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, service+":"+ip)
}

// Stop shuts down the background cleanup goroutine.
func (f *FailureTracker) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
}

func (f *FailureTracker) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-failureTrackerWindowTTL)
			f.mu.Lock()
			for key, times := range f.failures {
				// Evict key if all timestamps are older than the eviction TTL.
				if len(times) == 0 || times[len(times)-1].Before(cutoff) {
					delete(f.failures, key)
				}
			}
			f.mu.Unlock()
		}
	}
}
