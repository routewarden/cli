package guard

import (
	"net"
	"sync"
	"time"
)

// banEntry records why and until when an IP is banned.
type banEntry struct {
	reason    string
	service   string
	bannedAt  time.Time
	expiresAt time.Time
}

// BanList is a thread-safe in-memory IP ban store with TTL expiry.
// Bans are global across all services: an SSH brute-forcer is also
// banned from SMTP, POP3, etc.
type BanList struct {
	mu      sync.RWMutex
	entries map[string]banEntry // keyed by IP string
}

// NewBanList creates an empty BanList and starts the background reaper.
func NewBanList() *BanList {
	bl := &BanList{entries: make(map[string]banEntry)}
	go bl.reap()
	return bl
}

// Ban adds or refreshes a ban for the given IP.
func (b *BanList) Ban(ip, reason, service string, duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.entries[ip] = banEntry{
		reason:    reason,
		service:   service,
		bannedAt:  now,
		expiresAt: now.Add(duration),
	}
}

// IsBanned returns true if the IP currently has an active ban.
func (b *BanList) IsBanned(ip string) (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if e, ok := b.entries[ip]; ok {
		if time.Now().Before(e.expiresAt) {
			return true, e.reason
		}
	}
	return false, ""
}

// Unban removes an IP from the banlist immediately.
func (b *BanList) Unban(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, ip)
}

// Snapshot returns a copy of all current active bans for API/UI display.
func (b *BanList) Snapshot() []BanEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	now := time.Now()
	var out []BanEntry
	for ip, e := range b.entries {
		if now.Before(e.expiresAt) {
			out = append(out, BanEntry{
				IP:        ip,
				Reason:    e.reason,
				Service:   e.service,
				BannedAt:  e.bannedAt,
				ExpiresAt: e.expiresAt,
			})
		}
	}
	return out
}

// BanEntry is the JSON-serialisable form of a ban (used by the API).
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Service   string    `json:"service"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// reap periodically removes expired entries to prevent unbounded growth.
func (b *BanList) reap() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		b.mu.Lock()
		for ip, e := range b.entries {
			if now.After(e.expiresAt) {
				delete(b.entries, ip)
			}
		}
		b.mu.Unlock()
	}
}

// FailureTracker counts per-IP failures per service and auto-bans when
// the threshold is exceeded.
type FailureTracker struct {
	mu       sync.Mutex
	failures map[string]int // key: "ip:service"
	banlist  *BanList
}

// NewFailureTracker creates a tracker wired to the given BanList.
func NewFailureTracker(bl *BanList) *FailureTracker {
	return &FailureTracker{
		failures: make(map[string]int),
		banlist:  bl,
	}
}

// Record increments the failure count for (ip, service). If the count
// reaches threshold, the IP is banned for banDuration and true is returned.
func (f *FailureTracker) Record(ip, service, reason string, threshold int, banDuration time.Duration) bool {
	if threshold <= 0 {
		return false
	}
	key := ip + ":" + service
	f.mu.Lock()
	f.failures[key]++
	count := f.failures[key]
	f.mu.Unlock()

	if count >= threshold {
		f.banlist.Ban(ip, reason, service, banDuration)
		f.Reset(ip, service)
		return true
	}
	return false
}

// Reset clears the failure counter for (ip, service).
func (f *FailureTracker) Reset(ip, service string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.failures, ip+":"+service)
}

// parseClientIP extracts the host portion from a net.Conn remote address.
func parseClientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
