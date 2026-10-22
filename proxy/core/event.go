package core

import (
	"sync"
	"time"
)

// SecurityEvent is the standard structured log entry emitted by tcp-warden.
// Fields align with the RouteWarden ecosystem standard format.
type SecurityEvent struct {
	Type        string    `json:"type"`                   // always "security_event"
	Timestamp   time.Time `json:"timestamp"`              // UTC event time
	Level       string    `json:"level,omitempty"`        // "warn", "info", "error"
	Plugin      string    `json:"plugin"`                 // "tcp-warden"
	Service     string    `json:"service"`                // e.g. "ssh", "smtp"
	Protocol    string    `json:"protocol"`               // "ssh", "smtp", "pop3", "imap", "tcp"
	ClientIP    string    `json:"client_ip"`
	CountryCode string    `json:"country_code,omitempty"` // e.g. "US", "DE", "LAN"
	CountryName string    `json:"country_name,omitempty"` // e.g. "United States"
	FlagEmoji   string    `json:"flag_emoji,omitempty"`   // e.g. "🇺🇸", "🏠"
	Action      string    `json:"action"`                 // "allowed" | "blocked" | "throttled"
	Reason      string    `json:"reason,omitempty"`       // "ip_denied", "rate_limit_exceeded", "crowdsec_ban", etc.
	BytesIn     int64     `json:"bytes_in,omitempty"`
	BytesOut    int64     `json:"bytes_out,omitempty"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
}

// EventBus provides in-memory publish/subscribe for security events.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[chan SecurityEvent]struct{}
	closed      bool
}

// NewEventBus creates a new EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan SecurityEvent]struct{}),
	}
}

// Subscribe returns a channel that receives published security events.
func (b *EventBus) Subscribe(bufSize int) (<-chan SecurityEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		ch := make(chan SecurityEvent)
		close(ch)
		return ch, func() {}
	}

	ch := make(chan SecurityEvent, bufSize)
	b.subscribers[ch] = struct{}{}

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.subscribers != nil {
			if _, exists := b.subscribers[ch]; exists {
				delete(b.subscribers, ch)
				close(ch)
			}
		}
	}

	return ch, unsubscribe
}

// Publish broadcasts an event to all active subscribers.
func (b *EventBus) Publish(ev SecurityEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// Drop if subscriber channel buffer is full to prevent pipeline stall
		}
	}
}

// Close shuts down the bus and closes all subscriber channels.
func (b *EventBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subscribers {
		close(ch)
	}
	b.subscribers = nil
}
