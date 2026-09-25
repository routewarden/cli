package dashboard

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

const defaultRingSize = 10_000

// RingBuffer is a fixed-capacity, thread-safe circular buffer of SecurityEvents.
// When the buffer is full, the oldest events are overwritten.
// No disk writes — everything lives in memory.
type RingBuffer struct {
	mu       sync.RWMutex
	events   []SecurityEvent
	size     int
	head     int // next write position
	count    int // total events ever written (never resets)
	stored   int // current number of events stored (max = cap)
	capacity int
}

// NewRingBuffer creates a ring buffer with the given capacity.
// Use defaultRingSize (10 000) for normal dashboard operation.
func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		events:   make([]SecurityEvent, capacity),
		capacity: capacity,
	}
}

// Push appends a new event to the ring buffer.
func (r *RingBuffer) Push(e SecurityEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[r.head] = e
	r.head = (r.head + 1) % r.capacity
	r.count++
	if r.stored < r.capacity {
		r.stored++
	}
}

// Recent returns up to n events in chronological order (oldest first).
// If n <= 0 or n > stored count, all stored events are returned.
func (r *RingBuffer) Recent(n int) []SecurityEvent {
	return r.RecentFiltered(n, "")
}

// RecentFiltered returns up to n events matching source (container or file) in chronological order.
func (r *RingBuffer) RecentFiltered(n int, source string) []SecurityEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.stored == 0 {
		return make([]SecurityEvent, 0)
	}

	total := r.stored
	start := ((r.head - total) % r.capacity + r.capacity) % r.capacity

	var out []SecurityEvent
	for i := 0; i < total; i++ {
		e := r.events[(start+i)%r.capacity]
		if source == "" || e.Source == source || e.SourceID == source {
			out = append(out, e)
		}
	}

	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// Stats computes an aggregated StatsSnapshot from all stored events.
// The time window is the last `hours` hours (0 = all).
// An optional source filter can be provided to restrict stats to a specific container/source.
func (r *RingBuffer) Stats(hours int, source ...string) StatsSnapshot {
	var srcFilter string
	if len(source) > 0 {
		srcFilter = source[0]
	}

	r.mu.RLock()
	events := r.Recent(0)
	r.mu.RUnlock()

	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(hours) * time.Hour)

	ipSet := make(map[string]struct{})
	pathCount := make(map[string]int)
	ipCount := make(map[string]int)
	modeCount := make(map[string]int)
	gwCount := make(map[string]int)

	// minute bucket → count for rate chart (last 60 minutes)
	rateBuckets := make(map[string]int)
	rateStart := now.Add(-60 * time.Minute)

	var firstTime, lastTime time.Time
	var totalInWindow int

	for _, e := range events {
		if hours > 0 && e.Timestamp.Before(cutoff) {
			continue
		}
		if srcFilter != "" && e.Source != srcFilter && e.SourceID != srcFilter {
			continue
		}
		totalInWindow++
		ipSet[e.ClientIP] = struct{}{}
		if e.Path != "" {
			pathCount[e.Path]++
		}
		if e.ClientIP != "" {
			ipCount[e.ClientIP]++
		}
		mode := e.ResponseMode
		if mode == "" {
			mode = "block"
		}
		modeCount[mode]++
		if e.Plugin != "" {
			gwCount[e.Plugin]++
		}

		// rate chart: per-minute bucket for last 60 min
		if !e.Timestamp.Before(rateStart) {
			bucket := e.Timestamp.Format("15:04")
			rateBuckets[bucket]++
		}

		if firstTime.IsZero() || e.Timestamp.Before(firstTime) {
			firstTime = e.Timestamp
		}
		if e.Timestamp.After(lastTime) {
			lastTime = e.Timestamp
		}
	}

	// Blocks per minute rate
	var blocksPerMin float64
	if !firstTime.IsZero() && !lastTime.IsZero() {
		dur := lastTime.Sub(firstTime).Minutes()
		if dur > 0 {
			blocksPerMin = math.Round(float64(totalInWindow)/dur*10) / 10
		}
	}

	rateList := make([]RatePoint, 0, len(rateBuckets))
	for min, cnt := range rateBuckets {
		rateList = append(rateList, RatePoint{Minute: min, Count: cnt})
	}
	sort.Slice(rateList, func(i, j int) bool {
		return rateList[i].Minute < rateList[j].Minute
	})

	snap := StatsSnapshot{
		TotalEvents:   totalInWindow,
		UniqueIPs:     len(ipSet),
		BlocksPerMin:  blocksPerMin,
		TopPaths:      topN(pathCount, 10),
		TopIPs:        topN(ipCount, 10),
		ResponseModes: topN(modeCount, 0),
		RateOverTime:  rateList,
		ByGateway:     topN(gwCount, 0),
	}

	return snap
}

// MarshalRecent returns JSON of the n most recent events (optionally filtered by source).
func (r *RingBuffer) MarshalRecent(n int, source ...string) ([]byte, error) {
	if len(source) > 0 && source[0] != "" {
		return json.Marshal(r.RecentFiltered(n, source[0]))
	}
	return json.Marshal(r.Recent(n))
}

// topN converts a count map into a sorted []CountEntry, capped at n entries.
// Pass n=0 to return all.
func topN(m map[string]int, n int) []CountEntry {
	entries := make([]CountEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, CountEntry{Label: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if n > 0 && len(entries) > n {
		return entries[:n]
	}
	return entries
}
