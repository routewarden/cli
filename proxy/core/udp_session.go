package core

import (
	"net"
	"sync"
	"time"

	"github.com/routewarden/cli/proxy/plugins/sdk"
)

// UDPSession tracks a single logical client ↔ upstream UDP flow.
// Because UDP is connectionless, the daemon creates one UDPSession per unique
// client address and maintains it until it goes idle for SessionTimeout.
type UDPSession struct {
	// ClientAddr is the remote address of the originating client.
	ClientAddr *net.UDPAddr

	// Upstream is the dialed UDP connection to the backend service.
	Upstream *net.UDPConn

	// Inspector is the optional protocol-aware datagram inspector for this session.
	// Nil when no UDPPlugin is configured for the service.
	Inspector sdk.UDPInspector

	lastSeen  time.Time
	mu        sync.Mutex
	closeOnce sync.Once
	onClose   func()
}

// Touch updates the last-seen timestamp to prevent idle expiry.
func (s *UDPSession) Touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// isIdle reports whether the session has been inactive for longer than timeout.
func (s *UDPSession) isIdle(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastSeen) > timeout
}

// close releases upstream resources and notifies any attached inspector and callback.
func (s *UDPSession) close() {
	s.closeOnce.Do(func() {
		if s.Upstream != nil {
			_ = s.Upstream.Close()
		}
		if s.Inspector != nil {
			_ = s.Inspector.Close()
		}
		if s.onClose != nil {
			s.onClose()
		}
	})
}

// UDPSessionTable maps "clientIP:port" → *UDPSession, providing connection tracking
// for the stateless UDP transport.  A background reaper goroutine expires idle sessions.
type UDPSessionTable struct {
	sessions  sync.Map
	timeout   time.Duration
	stop      chan struct{}
	closeOnce sync.Once
}

// NewUDPSessionTable creates a session table and starts the background idle reaper.
// The reaper fires at half the timeout interval to ensure timely cleanup.
func NewUDPSessionTable(timeout time.Duration) *UDPSessionTable {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	t := &UDPSessionTable{
		timeout: timeout,
		stop:    make(chan struct{}),
	}
	go t.reap()
	return t
}

// GetOrCreate returns the existing session for key, or calls create() to build a new one.
// Reports whether the session is freshly created (isNew).
func (t *UDPSessionTable) GetOrCreate(
	key string,
	create func() (*UDPSession, error),
) (session *UDPSession, isNew bool, err error) {
	if v, ok := t.sessions.Load(key); ok {
		s := v.(*UDPSession)
		s.Touch()
		return s, false, nil
	}

	s, err := create()
	if err != nil {
		return nil, false, err
	}
	s.Touch()

	// Use LoadOrStore to handle the race where two goroutines create a session
	// for the same key simultaneously — only one wins.
	if actual, loaded := t.sessions.LoadOrStore(key, s); loaded {
		// Our session lost the race; close ours and reuse the winner's.
		s.close()
		winner := actual.(*UDPSession)
		winner.Touch()
		return winner, false, nil
	}
	return s, true, nil
}

// Delete removes and closes the session identified by key.
func (t *UDPSessionTable) Delete(key string) {
	if v, ok := t.sessions.LoadAndDelete(key); ok {
		v.(*UDPSession).close()
	}
}

// Len returns the number of active sessions (O(n) — intended for metrics only).
func (t *UDPSessionTable) Len() int {
	count := 0
	t.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// Close stops the reaper and closes all active sessions.
func (t *UDPSessionTable) Close() {
	t.closeOnce.Do(func() {
		close(t.stop)
		t.sessions.Range(func(k, v any) bool {
			t.sessions.Delete(k)
			v.(*UDPSession).close()
			return true
		})
	})
}

// reap runs in the background and removes sessions that have been idle for longer
// than the configured timeout.
func (t *UDPSessionTable) reap() {
	interval := t.timeout / 2
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.sessions.Range(func(k, v any) bool {
				s := v.(*UDPSession)
				if s.isIdle(t.timeout) {
					// LoadAndDelete is safe here: close() is idempotent and the
					// only consequence of a concurrent delete is a double-close,
					// which net.UDPConn handles gracefully.
					if _, ok := t.sessions.LoadAndDelete(k); ok {
						s.close()
					}
				}
				return true
			})
		}
	}
}
