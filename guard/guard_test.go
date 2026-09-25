package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Global: GlobalPolicy{
			BanAfterFailures:   3,
			BanDurationSeconds: 60,
		},
		Services: []ServiceConfig{
			{
				Name:     "ssh",
				Enabled:  true,
				Listen:   ":2222",
				Upstream: "127.0.0.1:22",
				Protocol: "ssh",
			},
			{
				Name:     "smtp",
				Enabled:  true,
				Listen:   ":2525",
				Upstream: "127.0.0.1:25",
				Protocol: "smtp",
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}

	// Test invalid protocol
	badCfg := &Config{
		Services: []ServiceConfig{
			{Name: "bad", Listen: ":1234", Upstream: "127.0.0.1:1234", Protocol: "invalid_proto"},
		},
	}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected error for invalid protocol, got nil")
	}
}

func TestBanList(t *testing.T) {
	bl := NewBanList()
	ip := "198.51.100.5"

	banned, _ := bl.IsBanned(ip)
	if banned {
		t.Fatalf("expected IP not banned initially")
	}

	bl.Ban(ip, "ssh auth failure", "ssh", 100*time.Millisecond)
	banned, reason := bl.IsBanned(ip)
	if !banned || !strings.Contains(reason, "ssh auth failure") {
		t.Fatalf("expected IP to be banned with reason, got banned=%v reason=%s", banned, reason)
	}

	snaps := bl.Snapshot()
	if len(snaps) != 1 || snaps[0].IP != ip {
		t.Fatalf("expected snapshot to contain %s, got: %+v", ip, snaps)
	}

	bl.Unban(ip)
	banned, _ = bl.IsBanned(ip)
	if banned {
		t.Fatalf("expected IP to be unbanned")
	}
}

func TestFailureTracker(t *testing.T) {
	bl := NewBanList()
	ft := NewFailureTracker(bl)
	ip := "203.0.113.10"

	threshold := 3
	dur := 10 * time.Minute

	ft.Record(ip, "ssh", "auth fail", threshold, dur)
	ft.Record(ip, "ssh", "auth fail", threshold, dur)

	banned, _ := bl.IsBanned(ip)
	if banned {
		t.Fatalf("expected IP not yet banned at 2 failures")
	}

	ft.Record(ip, "ssh", "auth fail", threshold, dur)
	banned, _ = bl.IsBanned(ip)
	if !banned {
		t.Fatalf("expected IP to be banned after 3 failures")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter()
	ip := "192.0.2.1"
	limit := 3

	for i := 0; i < limit; i++ {
		if !rl.AllowConnection(ip, limit) {
			t.Fatalf("connection %d should have been allowed", i+1)
		}
	}

	if rl.AllowConnection(ip, limit) {
		t.Fatalf("connection beyond limit should have been rejected")
	}
}

func TestStatsRegistry(t *testing.T) {
	reg := NewStatsRegistry()
	st := reg.RegisterService("ssh", "ssh", ":2222", "127.0.0.1:22")

	st.TotalConns.Add(10)
	st.ActiveConns.Add(2)
	st.BlockedConns.Add(3)
	st.BytesIn.Add(1000)
	st.BytesOut.Add(2000)

	all, totals, _ := reg.SnapshotAll()
	if totals["total_connections"] != 10 {
		t.Errorf("expected 10 total conns, got %d", totals["total_connections"])
	}
	if totals["blocked_connections"] != 3 {
		t.Errorf("expected 3 blocked conns, got %d", totals["blocked_connections"])
	}
	if all["ssh"].BytesIn != 1000 {
		t.Errorf("expected 1000 bytes in, got %d", all["ssh"].BytesIn)
	}
}

func TestEventBus(t *testing.T) {
	bus := NewEventBus()
	ch, unsub := bus.Subscribe(10)
	defer unsub()

	ev := GuardEvent{
		Type:     "guard_event",
		ClientIP: "1.2.3.4",
		Service:  "ssh",
		Action:   "ALLOW",
	}

	bus.Publish(ev)

	select {
	case received := <-ch:
		if received.ClientIP != "1.2.3.4" || received.Action != "ALLOW" {
			t.Fatalf("unexpected event: %+v", received)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event on EventBus")
	}
}

func TestAPIServer(t *testing.T) {
	cfg := &Config{
		API: APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9099",
		},
		Services: []ServiceConfig{
			{Name: "ssh", Listen: ":2222", Upstream: "127.0.0.1:22", Enabled: true},
		},
	}
	bl := NewBanList()
	bl.Ban("10.0.0.1", "test ban", "ssh", time.Hour)
	stats := NewStatsRegistry()
	stats.RegisterService("ssh", "ssh", ":2222", "127.0.0.1:22")
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/guard/health", api.handleHealth)
	mux.HandleFunc("/api/guard/services", api.handleServices)
	mux.HandleFunc("/api/guard/stats", api.handleStats)
	mux.HandleFunc("/api/guard/banlist", api.handleBanlist)
	mux.HandleFunc("/api/guard/unban", api.handleUnban)

	// Test health
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/guard/health", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health endpoint returned %d", rec.Code)
	}
	var healthResp map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&healthResp)
	if healthResp["status"] != "healthy" {
		t.Errorf("expected healthy status, got %v", healthResp["status"])
	}

	// Test banlist
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/guard/banlist", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("banlist returned %d", rec.Code)
	}
	var banResp struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&banResp)
	if banResp.Count != 1 {
		t.Errorf("expected 1 ban in banlist, got %d", banResp.Count)
	}

	// Test unban
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/guard/unban", strings.NewReader(`{"ip":"10.0.0.1"}`))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban returned %d", rec.Code)
	}
	banned, _ := bl.IsBanned("10.0.0.1")
	if banned {
		t.Errorf("expected 10.0.0.1 to be unbanned")
	}
}

func TestContextCancellation(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Services: []ServiceConfig{
			{Name: "ssh", Listen: "127.0.0.1:0", Upstream: "127.0.0.1:22", Enabled: true, Protocol: "tcp"},
		},
	}
	d, err := NewDaemon(cfg, "")
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- d.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			if strings.Contains(err.Error(), "operation not permitted") {
				t.Skip("skipping network listener test in restricted sandbox")
			}
			t.Errorf("expected clean shutdown on cancel, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not shut down promptly on context cancel")
	}
}
