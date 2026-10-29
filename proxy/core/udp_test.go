package core

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/geoip"
)

// ── UDPSessionTable tests ─────────────────────────────────────────────────────

func TestUDPSessionTable_GetOrCreate_NewSession(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	called := 0

	sess, isNew, err := table.GetOrCreate("1.2.3.4:5000", func() (*UDPSession, error) {
		called++
		c, _ := udpTestConn()
		return &UDPSession{ClientAddr: addr, Upstream: c}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Fatal("expected isNew=true for first creation")
	}
	if called != 1 {
		t.Fatalf("create func called %d times, want 1", called)
	}
	_ = sess
}

func TestUDPSessionTable_GetOrCreate_ExistingSession(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	createCount := 0
	create := func() (*UDPSession, error) {
		createCount++
		c, _ := udpTestConn()
		return &UDPSession{ClientAddr: addr, Upstream: c}, nil
	}

	_, isNew1, _ := table.GetOrCreate("1.2.3.4:5000", create)
	_, isNew2, _ := table.GetOrCreate("1.2.3.4:5000", create)

	if !isNew1 {
		t.Error("first call: expected isNew=true")
	}
	if isNew2 {
		t.Error("second call: expected isNew=false (session already exists)")
	}
	if createCount != 1 {
		t.Errorf("create func called %d times, want 1", createCount)
	}
}

func TestUDPSessionTable_GetOrCreate_CreateError(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	_, _, err := table.GetOrCreate("bad:0", func() (*UDPSession, error) {
		return nil, fmt.Errorf("upstream unreachable")
	})

	if err == nil {
		t.Fatal("expected error from create func, got nil")
	}
}

func TestUDPSessionTable_Delete(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	addr := &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 9999}
	c, _ := udpTestConn()
	sess := &UDPSession{ClientAddr: addr, Upstream: c}
	table.sessions.Store("5.6.7.8:9999", sess)

	table.Delete("5.6.7.8:9999")

	if _, ok := table.sessions.Load("5.6.7.8:9999"); ok {
		t.Error("session still present after Delete")
	}
}

func TestUDPSessionTable_Len(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	if got := table.Len(); got != 0 {
		t.Fatalf("empty table Len()=%d, want 0", got)
	}

	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("10.0.0.%d:1000", i)
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.0.%d", i)), Port: 1000}
		c, _ := udpTestConn()
		table.sessions.Store(key, &UDPSession{ClientAddr: addr, Upstream: c})
	}

	if got := table.Len(); got != 3 {
		t.Fatalf("Len()=%d, want 3", got)
	}
}

func TestUDPSessionTable_Reaper(t *testing.T) {
	timeout := 200 * time.Millisecond
	table := NewUDPSessionTable(timeout)
	// Don't defer table.Close() here — we want the reaper goroutine to do the work.

	addr := &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222}
	c, _ := udpTestConn()
	// Stamp as already expired.
	sess := &UDPSession{ClientAddr: addr, Upstream: c, lastSeen: time.Now().Add(-timeout - time.Second)}
	table.sessions.Store("2.2.2.2:2222", sess)

	// Reaper fires at timeout/2 = 100ms; wait long enough for two cycles.
	time.Sleep(timeout + 150*time.Millisecond)

	if _, ok := table.sessions.Load("2.2.2.2:2222"); ok {
		t.Error("expected idle session to be reaped, but it still exists")
	}
	table.Close()
}

// ── UDPSession Touch / isIdle tests ──────────────────────────────────────────

func TestUDPSession_Touch_ResetsIdleTimer(t *testing.T) {
	c, _ := udpTestConn()
	sess := &UDPSession{
		Upstream: c,
		lastSeen: time.Now().Add(-10 * time.Second),
	}

	// Without Touch, the session is idle.
	if !sess.isIdle(5 * time.Second) {
		t.Fatal("expected session to be idle before Touch")
	}
	sess.Touch()
	if sess.isIdle(5 * time.Second) {
		t.Fatal("expected session to be non-idle after Touch")
	}
}

// ── UDP engine end-to-end smoke test ─────────────────────────────────────────

// TestUDPEngine_ForwardPacket wires up a real loopback UDP socket pair and
// verifies that handleUDPPacket delivers the payload to an upstream echo server
// and the reply makes it back to the client.
func TestUDPEngine_ForwardPacket(t *testing.T) {
	// 1. Start a simple UDP echo server as the "upstream".
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("skipping live UDP test without socket bind permissions: %v", err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], src)
		}
	}()

	// 2. Build a minimal Daemon.
	cfg := &config.Config{
		Version: "1.0",
		Global:  config.GlobalConfig{},
		Services: map[string]config.ServiceConfig{
			"udp-test": {
				Name:      "udp-test",
				Transport: "udp",
				Upstream:  echoAddr.String(),
			},
		},
	}
	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()
	oplog := NewLogger(LevelWarn, nil)
	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)

	d := &Daemon{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		stats:    stats,
		bus:      bus,
		pipeline: pipe,
		oplog:    oplog,
	}

	// 3. Open the shared listen socket (the "warden" side).
	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("skipping live UDP test without socket bind permissions: %v", err)
	}
	defer listenConn.Close()

	// 4. Open a real client socket so the "WriteTo(clientAddr)" reply goes somewhere.
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("skipping live UDP test without socket bind permissions: %v", err)
	}
	defer clientConn.Close()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	svc := cfg.Services["udp-test"]
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	// 5. Wait for the reply on the real client socket.
	replyCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := clientConn.ReadFromUDP(buf)
		if err == nil {
			replyCh <- buf[:n]
		} else {
			replyCh <- nil
		}
	}()

	payload := []byte("hello-udp-engine")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	d.handleUDPPacket(ctx, listenConn, clientAddr, payload, svc, table)

	reply := <-replyCh
	if string(reply) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", reply, payload)
	}
}

// ── MaxSessions guard test ────────────────────────────────────────────────────

func TestUDPEngine_MaxSessions(t *testing.T) {
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("skipping live UDP test without socket bind permissions: %v", err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = src
			_ = n
		}
	}()

	cfg := &config.Config{
		Version: "1.0",
		Services: map[string]config.ServiceConfig{
			"udp-max": {
				Name:      "udp-max",
				Transport: "udp",
				Upstream:  echoAddr.String(),
				UDP:       config.UDPConfig{MaxSessions: 1}, // allow only 1
			},
		},
	}
	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()
	oplog := NewLogger(LevelWarn, nil)
	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)

	d := &Daemon{
		cfg:      cfg,
		banlist:  bl,
		failures: ft,
		limiter:  rl,
		stats:    stats,
		bus:      bus,
		pipeline: pipe,
		oplog:    oplog,
	}

	listenConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("skipping live UDP test without socket bind permissions: %v", err)
	}
	defer listenConn.Close()

	svc := cfg.Services["udp-max"]
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()
	ctx := context.Background()

	// Pre-fill the session table to reach MaxSessions.
	fakeAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	fakeConn, cleanup := udpTestConn()
	defer cleanup()
	table.sessions.Store(fakeAddr.String(), &UDPSession{ClientAddr: fakeAddr, Upstream: fakeConn, lastSeen: time.Now()})

	// Now a second client should be blocked.
	secondClient := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222}
	d.handleUDPPacket(ctx, listenConn, secondClient, []byte("blocked"), svc, table)

	// Verify the second client did NOT create a session.
	if _, ok := table.sessions.Load(secondClient.String()); ok {
		t.Error("second client session was created despite MaxSessions=1")
	}

	// Verify the second client's packet was counted as blocked.
	snap := stats.GetOrCreate("udp-max").Snapshot()
	if snap.BlockedConnections == 0 {
		t.Error("expected BlockedConnections > 0 after MaxSessions exceeded")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// udpTestConn creates a throwaway UDP listen socket for use as a fake Upstream in tests.
// If socket binding is restricted in the test environment, returns nil and a no-op cleanup.
func udpTestConn() (*net.UDPConn, func()) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, func() {}
	}
	return conn, func() { conn.Close() }
}

func TestUDPEngine_MetricsLifecycle(t *testing.T) {
	stats := NewStatsRegistry()
	st := stats.GetOrCreate("udp-svc")
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	if st.Snapshot().ActiveConnections != 0 {
		t.Fatalf("expected 0 active connections initially, got %d", st.Snapshot().ActiveConnections)
	}

	key := "127.0.0.1:54321"
	fakeConn, cleanup := udpTestConn()
	defer cleanup()

	session, isNew, err := table.GetOrCreate(key, func() (*UDPSession, error) {
		return &UDPSession{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321},
			Upstream:   fakeConn,
			onClose:    func() { st.ConnClosed() },
		}, nil
	})
	if err != nil || !isNew {
		t.Fatalf("unexpected GetOrCreate result: isNew=%v, err=%v", isNew, err)
	}
	st.ConnAccepted()

	if st.Snapshot().ActiveConnections != 1 {
		t.Errorf("expected 1 active connection, got %d", st.Snapshot().ActiveConnections)
	}

	_, isNew2, err := table.GetOrCreate(key, func() (*UDPSession, error) {
		return nil, nil
	})
	if err != nil || isNew2 {
		t.Fatalf("expected existing session, isNew=%v, err=%v", isNew2, err)
	}
	if st.Snapshot().ActiveConnections != 1 {
		t.Errorf("expected still 1 active connection, got %d", st.Snapshot().ActiveConnections)
	}

	table.Delete(key)
	if st.Snapshot().ActiveConnections != 0 {
		t.Errorf("expected 0 active connections after delete, got %d", st.Snapshot().ActiveConnections)
	}

	session.close()
	if st.Snapshot().ActiveConnections != 0 {
		t.Errorf("expected 0 active connections after double close, got %d", st.Snapshot().ActiveConnections)
	}
}

func TestAuthFailure_LogLevel(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{
			BanAfterFailures: 10,
		},
		Services: map[string]config.ServiceConfig{
			"test-svc": {Name: "test-svc", Protocol: "tcp"},
		},
	}
	bus := NewEventBus()
	defer bus.Close()
	events, unsub := bus.Subscribe(10)
	defer unsub()

	pipe := NewPipeline(cfg, NewBanList(""), NewFailureTracker(), NewRateLimiter(), bus, NewStatsRegistry(), nil, nil)
	pipe.recordAuthFailure(&config.ServiceConfig{Name: "test-svc"}, "1.2.3.4", geoip.GeoResult{})

	select {
	case ev := <-events:
		if ev.Action != "auth_failure" {
			t.Errorf("expected action auth_failure, got %s", ev.Action)
		}
		if ev.Level != "warn" {
			t.Errorf("expected level warn for auth_failure, got %q", ev.Level)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for security event")
	}
}

func TestUDPEngine_BannedIP_Dropped(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()
	bl.Ban("198.51.100.77", "manual_test", "udp-test", time.Hour)

	stats := NewStatsRegistry()
	bus := NewEventBus()
	defer bus.Close()

	d := &Daemon{
		banlist:  bl,
		stats:    stats,
		bus:      bus,
		pipeline: NewPipeline(&config.Config{}, bl, NewFailureTracker(), NewRateLimiter(), bus, stats, nil, nil),
	}

	st := stats.GetOrCreate("udp-test")
	initialBlocked := st.Snapshot().BlockedConnections

	clientAddr := &net.UDPAddr{IP: net.ParseIP("198.51.100.77"), Port: 12345}
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	d.handleUDPPacket(context.Background(), nil, clientAddr, []byte("ping"), config.ServiceConfig{Name: "udp-test"}, table)

	if st.Snapshot().BlockedConnections <= initialBlocked {
		t.Errorf("expected blocked count to increase for banned UDP client")
	}
	if table.Len() != 0 {
		t.Errorf("expected no session created for banned UDP packet, got %d", table.Len())
	}
}

// UDP-1: Zero-byte UDP packet handled safely
func TestUDPEngine_ZeroBytePacket(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()
	stats := NewStatsRegistry()
	bus := NewEventBus()
	defer bus.Close()

	d := &Daemon{
		cfg:      &config.Config{},
		banlist:  bl,
		stats:    stats,
		bus:      bus,
		limiter:  NewRateLimiter(),
		oplog:    DefaultLogger(),
		pipeline: NewPipeline(&config.Config{}, bl, NewFailureTracker(), NewRateLimiter(), bus, stats, nil, nil),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	// Zero-byte packet should not panic
	d.handleUDPPacket(context.Background(), nil, clientAddr, []byte{}, config.ServiceConfig{Name: "udp-zero", Upstream: "127.0.0.1:0"}, table)
}

// UDP-2: UDP packet from IPv6 address
func TestUDPEngine_IPv6Client(t *testing.T) {
	bl := NewBanList("")
	defer bl.Close()
	stats := NewStatsRegistry()
	bus := NewEventBus()
	defer bus.Close()

	d := &Daemon{
		cfg:      &config.Config{},
		banlist:  bl,
		stats:    stats,
		bus:      bus,
		limiter:  NewRateLimiter(),
		oplog:    DefaultLogger(),
		pipeline: NewPipeline(&config.Config{}, bl, NewFailureTracker(), NewRateLimiter(), bus, stats, nil, nil),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("2001:db8::99"), Port: 5353}
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	d.handleUDPPacket(context.Background(), nil, clientAddr, []byte("hello-ipv6"), config.ServiceConfig{Name: "udp-v6", Upstream: "127.0.0.1:0"}, table)
}

// UDP-3: Concurrent session table access
func TestUDPSessionTable_ConcurrentAccess(t *testing.T) {
	table := NewUDPSessionTable(10 * time.Second)
	defer table.Close()

	workers := 50
	done := make(chan struct{})

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			key := fmt.Sprintf("192.0.2.%d:5000", id%5)
			addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", id%5)), Port: 5000}
			_, _, _ = table.GetOrCreate(key, func() (*UDPSession, error) {
				c, _ := udpTestConn()
				return &UDPSession{ClientAddr: addr, Upstream: c}, nil
			})
			_ = table.Len()
		}(i)
	}

	for i := 0; i < workers; i++ {
		<-done
	}
}

func TestUDPSessionTable_ClosedSessionReplaced(t *testing.T) {
	table := NewUDPSessionTable(5 * time.Second)
	defer table.Close()

	key := "192.0.2.1:5000"
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}

	s1, isNew1, err1 := table.GetOrCreate(key, func() (*UDPSession, error) {
		return &UDPSession{ClientAddr: addr}, nil
	})
	if err1 != nil || !isNew1 || s1 == nil {
		t.Fatalf("failed creating initial session: %v", err1)
	}

	// Manually close s1 as if reaped or deleted
	s1.close()
	if !s1.isClosed() {
		t.Fatal("expected s1.isClosed() to be true")
	}

	// GetOrCreate should detect closed session and return a fresh new session
	s2, _, err2 := table.GetOrCreate(key, func() (*UDPSession, error) {
		return &UDPSession{ClientAddr: addr}, nil
	})
	if err2 != nil {
		t.Fatalf("unexpected error: %v", err2)
	}
	if s2 == s1 {
		t.Fatal("GetOrCreate returned dead/closed session s1 instead of creating new session")
	}
	if s2.isClosed() {
		t.Fatal("expected new session s2 to not be closed")
	}
}


