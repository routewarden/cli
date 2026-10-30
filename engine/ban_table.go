package engine

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BanTable maintains a thread-safe, bounded in-memory table of banned IP addresses with expiration TTLs.
type BanTable struct {
	mu         sync.RWMutex
	entries    map[string]time.Time
	maxEntries int
}

// NewBanTable creates an in-memory BanTable with a maximum capacity.
func NewBanTable(maxEntries int) *BanTable {
	if maxEntries <= 0 {
		maxEntries = 10000 // default capacity: 10,000 IPs
	}
	return &BanTable{
		entries:    make(map[string]time.Time),
		maxEntries: maxEntries,
	}
}

// ParseBanDuration parses a duration string supporting Go duration formats ("24h", "1h30m", "300s")
// as well as bare integer seconds ("86400"). Defaults to 24h if empty or invalid.
func ParseBanDuration(d string) time.Duration {
	d = strings.TrimSpace(d)
	if d == "" {
		return 24 * time.Hour
	}
	if dur, err := time.ParseDuration(d); err == nil && dur > 0 {
		return dur
	}
	if secs, err := strconv.ParseInt(d, 10, 64); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 24 * time.Hour
}

func normalizeIPKey(ip string) string {
	ip = strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return strings.ToLower(ip)
}

// Ban records an IP address in the table with an expiration TTL.
func (bt *BanTable) Ban(ip string, duration time.Duration) {
	if bt == nil || duration <= 0 {
		return
	}
	key := normalizeIPKey(ip)
	if key == "" {
		return
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()
	// Bounded capacity check
	if len(bt.entries) >= bt.maxEntries {
		// Evict expired entries
		for k, exp := range bt.entries {
			if now.After(exp) {
				delete(bt.entries, k)
			}
		}
		// If still over capacity, remove an arbitrary entry
		if len(bt.entries) >= bt.maxEntries {
			for k := range bt.entries {
				delete(bt.entries, k)
				break
			}
		}
	}

	bt.entries[key] = now.Add(duration)
}

// IsBanned checks if an IP is currently banned and not expired.
func (bt *BanTable) IsBanned(ip string) bool {
	if bt == nil {
		return false
	}
	key := normalizeIPKey(ip)
	if key == "" {
		return false
	}

	bt.mu.RLock()
	expiry, exists := bt.entries[key]
	bt.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		// Lazily clean up expired entry
		bt.mu.Lock()
		if curExp, stillExists := bt.entries[key]; stillExists && time.Now().After(curExp) {
			delete(bt.entries, key)
		}
		bt.mu.Unlock()
		return false
	}

	return true
}

// Len returns the current number of tracked entries (including potentially expired ones).
func (bt *BanTable) Len() int {
	if bt == nil {
		return 0
	}
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return len(bt.entries)
}

// Clear resets the ban table.
func (bt *BanTable) Clear() {
	if bt == nil {
		return
	}
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.entries = make(map[string]time.Time)
}

