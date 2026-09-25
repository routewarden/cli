// Package guard implements rwarden guard: a protocol-aware TCP security proxy
// that sits in front of non-HTTP services (SSH, SMTP, POP3, raw TCP) and
// integrates natively with the RouteWarden dashboard.
package guard

import (
	"sync"
	"time"
)

// GuardEvent is a single connection event emitted by the guard daemon.
// It is compatible with the dashboard SecurityEvent wire format so the
// existing dashboard Live Feed, IP Intelligence, and Analytics tabs work
// for TCP events without any UI changes.
type GuardEvent struct {
	// Core identification
	Type      string    `json:"type"`      // always "guard_event"
	Timestamp time.Time `json:"timestamp"` // UTC

	// TCP-level fields
	ClientIP     string `json:"client_ip"`
	Service      string `json:"service"`            // "ssh", "smtp", "pop3", "tcp"
	Protocol     string `json:"protocol"`           // same as service
	ListenPort   int    `json:"port"`
	UpstreamAddr string `json:"upstream,omitempty"`

	// Decision
	Action       string `json:"action"`                  // "ALLOW", "BLOCK", "TARPIT", "BAN"
	Reason       string `json:"reason,omitempty"`        // human-readable
	ResponseMode string `json:"response_mode,omitempty"` // "drop", "reject", "tarpit", "silent"

	// Metrics
	DurationMs int64 `json:"duration_ms,omitempty"`
	BytesIn    int64 `json:"bytes_in,omitempty"`
	BytesOut   int64 `json:"bytes_out,omitempty"`

	// GeoIP (populated by pipeline, reusing dashboard/geoip.go)
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	FlagEmoji   string `json:"flag_emoji,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`

	// Source tag for dashboard
	Source   string `json:"source,omitempty"`    // "guard:<service>"
	SourceID string `json:"source_id,omitempty"` // deterministic hash
}

// EventBus distributes GuardEvents to all registered subscribers.
// Subscribers that fall behind are dropped (non-blocking send) to avoid
// back-pressure blocking the connection pipeline.
type EventBus struct {
	mu   sync.RWMutex
	subs map[uint64]chan GuardEvent
	next uint64
}

// NewEventBus creates a ready-to-use EventBus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[uint64]chan GuardEvent)}
}

// Subscribe registers a new subscriber and returns its channel and an
// unsubscribe function. The caller owns the channel and must drain it.
func (b *EventBus) Subscribe(bufSize int) (<-chan GuardEvent, func()) {
	ch := make(chan GuardEvent, bufSize)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
		close(ch)
	}
}

// Publish sends an event to all current subscribers (non-blocking).
func (b *EventBus) Publish(ev GuardEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- ev:
		default: // subscriber too slow — drop
		}
	}
}
